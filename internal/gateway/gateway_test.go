package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const testPassword = "test-only-password-not-for-production"

func testApp(t *testing.T) (*App, *httptest.Server, *atomic.Int64) {
	t.Helper()
	os.Setenv("BASTION_ALLOW_PRIVATE_UPSTREAMS", "true")
	t.Cleanup(func() { os.Unsetenv("BASTION_ALLOW_PRIVATE_UPSTREAMS") })
	hits := new(atomic.Int64)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Seen-IP", r.Header.Get("X-Forwarded-For"))
		w.Header().Set("X-Seen-Host", r.Host)
		w.Header().Set("X-Seen-Path", r.URL.RequestURI())
		if r.Method == "POST" {
			io.Copy(w, r.Body)
		} else {
			io.WriteString(w, "upstream-ok")
		}
	}))
	t.Cleanup(upstream.Close)
	a, e := New(t.TempDir(), testPassword)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(a.Close)
	c := a.Config()
	c.Routes = []Route{{ID: "test", Name: "Test", Host: "app.example.com", Path: "/", Enabled: true, PreserveHost: true, Upstreams: []string{upstream.URL}, ExcludedRuleIDs: []int{}}}
	if e = a.Update(c, c.Revision); e != nil {
		t.Fatal(e)
	}
	return a, upstream, hits
}
func request(a *App, method, path, body, ct string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://app.example.com"+path, strings.NewReader(body))
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.RemoteAddr = "192.0.2.20:45000"
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func change(t *testing.T, a *App, fn func(*Config)) {
	t.Helper()
	raw, _ := json.Marshal(a.Config())
	var c Config
	json.Unmarshal(raw, &c)
	fn(&c)
	if e := a.Update(c, c.Revision); e != nil {
		t.Fatal(e)
	}
}
func TestProxyAndCRS(t *testing.T) {
	a, _, hits := testApp(t)
	t.Run("legitimate request", func(t *testing.T) {
		w := request(a, "GET", "/hello?name=Alice", "", "")
		if w.Code != 200 || w.Body.String() != "upstream-ok" {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		if w.Header().Get("X-Seen-Host") != "app.example.com" {
			t.Fatal("host not preserved")
		}
		if ev := a.Events.list()[0]; ev.Action != "allowed" || len(ev.RuleIDs) != 0 {
			t.Fatalf("internal CRS flow-control rules counted as detections: %+v", ev)
		}
	})
	attacks := []struct{ name, path, body, ct string }{
		{"SQL injection", "/?id=1%20UNION%20SELECT%20username,password%20FROM%20users", "", ""},
		{"XSS", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "", ""},
		{"path traversal", "/?file=../../../../etc/passwd", "", ""},
		{"JSON body", "/api", `{"search":"<script>alert(1)</script>"}`, "application/json"},
		{"form body", "/form", "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "application/x-www-form-urlencoded"},
	}
	for _, tt := range attacks {
		t.Run(tt.name, func(t *testing.T) {
			method := "GET"
			if tt.body != "" {
				method = "POST"
			}
			before := hits.Load()
			w := request(a, method, tt.path, tt.body, tt.ct)
			if w.Code != 403 {
				t.Fatalf("wanted 403, got %d; events=%+v", w.Code, a.Events.list()[0])
			}
			if hits.Load() != before {
				t.Fatal("attack reached upstream")
			}
			if len(a.Events.list()[0].RuleIDs) == 0 {
				t.Fatal("missing matched rule IDs")
			}
		})
	}
	t.Run("body preserved", func(t *testing.T) {
		body := `{"name":"Alice","count":3}`
		w := request(a, "POST", "/api", body, "application/json")
		if w.Code != 200 || w.Body.String() != body {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	})
	t.Run("detection mode", func(t *testing.T) {
		change(t, a, func(c *Config) { c.Mode = "detection" })
		w := request(a, "GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "", "")
		if w.Code != 200 || a.Events.list()[0].Action != "detected" {
			t.Fatalf("%d %+v", w.Code, a.Events.list()[0])
		}
		change(t, a, func(c *Config) { c.Mode = "blocking" })
	})
	t.Run("unknown host", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = "unknown.example.com"
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal(w.Code)
		}
	})
	t.Run("spoofed forwarded headers", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = "app.example.com"
		r.RemoteAddr = "192.0.2.20:1234"
		r.Header.Set("User-Agent", "Mozilla/5.0")
		r.Header.Set("X-Forwarded-For", "8.8.8.8")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 200 || w.Header().Get("X-Seen-IP") != "192.0.2.20" {
			t.Fatalf("%d: %s", w.Code, w.Header().Get("X-Seen-IP"))
		}
	})
	t.Run("no sensitive query logging", func(t *testing.T) {
		request(a, "GET", "/?token=top-secret-value", "", "")
		b, _ := json.Marshal(a.Events.list())
		if bytes.Contains(b, []byte("top-secret-value")) {
			t.Fatal("query leaked to events")
		}
	})
}
func TestLimitsAndCustomRules(t *testing.T) {
	a, _, hits := testApp(t)
	change(t, a, func(c *Config) {
		c.MaxBodyBytes = 1024
		c.Rules = []Rule{{ID: "admin", Name: "Admin", Field: "path", Value: "/private", Action: "block", Enabled: true}}
	})
	before := hits.Load()
	if w := request(a, "GET", "/private", "", ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if hits.Load() != before {
		t.Fatal("custom block bypassed")
	}
	if w := request(a, "POST", "/", strings.Repeat("a", 1025), "text/plain"); w.Code != 413 {
		t.Fatal(w.Code)
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("a", 1025)))
	r.Host = "app.example.com"
	r.ContentLength = -1
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("chunked body: %d", w.Code)
	}
	change(t, a, func(c *Config) { c.DenyCIDRs = []string{"192.0.2.0/24"} })
	if w := request(a, "GET", "/", "", ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	change(t, a, func(c *Config) { c.DenyCIDRs = nil; c.AllowCIDRs = []string{"198.51.100.0/24"} })
	if w := request(a, "GET", "/", "", ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	change(t, a, func(c *Config) { c.AllowCIDRs = nil; c.RateLimit = 1 })
	a.requestLimit = limiter{}
	if w := request(a, "GET", "/", "", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(a, "GET", "/", "", ""); w.Code != 429 {
		t.Fatal(w.Code)
	}
}
func TestRoutingAndRoundRobin(t *testing.T) {
	a, first, _ := testApp(t)
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("second")) }))
	defer second.Close()
	change(t, a, func(c *Config) {
		c.Routes[0].Upstreams = []string{first.URL, second.URL}
		c.Routes = append(c.Routes, Route{ID: "api", Name: "API", Host: "app.example.com", Path: "/api", Enabled: true, Upstreams: []string{second.URL}})
	})
	if w := request(a, "GET", "/", "", ""); w.Body.String() != "upstream-ok" {
		t.Fatal(w.Body.String())
	}

	if w := request(a, "GET", "/", "", ""); w.Body.String() != "second" {
		t.Fatal(w.Body.String())
	}
	if w := request(a, "GET", "/api/v1", "", ""); w.Body.String() != "second" {
		t.Fatal(w.Body.String())
	}
	if w := request(a, "GET", "/apix", "", ""); w.Body.String() != "upstream-ok" {
		t.Fatal("prefix crossed path boundary")
	}
	change(t, a, func(c *Config) { c.Routes[0].Enabled = false })
	if w := request(a, "GET", "/", "", ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
}
func TestRouteSecurityPolicies(t *testing.T) {
	a, _, hits := testApp(t)
	change(t, a, func(c *Config) {
		c.RateLimit = 10
		c.MaxBodyBytes = 4096
		c.Routes[0].WAFMode = "detection"
		c.Routes[0].RateLimit = 1
		c.Routes[0].MaxBodyBytes = 1024
		c.Routes[0].AllowedMethods = []string{"GET", "POST"}
		c.Routes[0].BotDenyPatterns = []string{"curl", `bad[- ]bot`}
	})
	if w := request(a, "PUT", "/", "", ""); w.Code != 405 || w.Header().Get("Allow") != "GET, POST" {
		t.Fatalf("method policy: %d %q", w.Code, w.Header().Get("Allow"))
	}
	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.RemoteAddr = "192.0.2.21:45000"
	r.Header.Set("User-Agent", "Friendly Curl")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 || !strings.Contains(a.Events.list()[0].Reason, "bot") {
		t.Fatalf("bot policy: %d %+v", w.Code, a.Events.list()[0])
	}
	before := hits.Load()
	if w := request(a, "POST", "/", strings.Repeat("a", 1025), "text/plain"); w.Code != 413 {
		t.Fatalf("route body policy: %d", w.Code)
	}
	if hits.Load() != before {
		t.Fatal("oversized route request reached upstream")
	}
	a.requestLimit = limiter{}
	if w := request(a, "GET", "/", "", ""); w.Code != 200 {
		t.Fatalf("first route request: %d", w.Code)
	}
	if w := request(a, "GET", "/", "", ""); w.Code != 429 {
		t.Fatalf("route rate policy: %d", w.Code)
	}
	// Detection mode is scoped to this route and still records a CRS match.
	a.requestLimit = limiter{}
	if w := request(a, "GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "", ""); w.Code != 200 || a.Events.list()[0].Action != "detected" {
		t.Fatalf("route WAF mode: %d %+v", w.Code, a.Events.list()[0])
	}
}

func TestRoutePolicyBackwardCompatibility(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(`{"revision":1,"mode":"blocking","paranoia":1,"threshold":5,"maxBodyBytes":2097152,"rateLimit":120,"routes":[],"rules":[]}`), &c); err != nil {
		t.Fatal(err)
	}
	normalize(&c)
	if len(c.Routes) != 0 || c.Mode != "blocking" {
		t.Fatalf("legacy config changed: %+v", c)
	}
	c.Routes = []Route{{ID: "legacy", Name: "Legacy", Host: "legacy.example.com", Path: "/", Upstreams: []string{"http://127.0.0.1:8080"}}}
	if err := validate(c, true); err != nil {
		t.Fatalf("legacy route rejected: %v", err)
	}
}

func TestRoutePolicyValidation(t *testing.T) {
	c := DefaultConfig()
	c.Routes = []Route{{ID: "r", Name: "R", Host: "r.example.com", Path: "/", Upstreams: []string{"http://127.0.0.1:8080"}, RateLimit: c.RateLimit + 1}}
	if err := validate(c, true); err == nil {
		t.Fatal("route rate limit weakened global limit")
	}
	c.Routes[0].RateLimit = 0
	c.Routes[0].BotDenyPatterns = []string{"["}
	if err := validate(c, true); err == nil {
		t.Fatal("invalid bot pattern accepted")
	}
}
func TestConfigValidationAndPersistence(t *testing.T) {
	dir := t.TempDir()
	a, e := New(dir, testPassword)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	c := a.Config()
	c.RateLimit = 45
	if e = a.Update(c, c.Revision); e != nil {
		t.Fatal(e)
	}
	if e = a.Update(c, c.Revision); e != errConflict {
		t.Fatal("expected revision conflict")
	}
	saved, e := loadConfig(filepath.Join(dir, "config.json"), true)
	if e != nil || saved.RateLimit != 45 || saved.Revision != 2 {
		t.Fatalf("%+v %v", saved, e)
	}
	change(t, a, func(c *Config) { c.Mode = "detection" })
	bad := a.Config()
	bad.Paranoia = 99
	if e = a.Update(bad, bad.Revision); e == nil {
		t.Fatal("invalid config accepted")
	}
	if a.Config().Paranoia != 1 {
		t.Fatal("bad state activated")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if bytes.Contains(b, []byte(testPassword)) {
		t.Fatal("password persisted")
	}
	bad = a.Config()
	bad.Routes = []Route{{ID: "bad", Name: "bad", Host: "example.com", Path: "/", Upstreams: []string{"http://user:pass@localhost"}}}
	if e = validate(bad, true); e == nil {
		t.Fatal("upstream credentials accepted")
	}
}
func TestAdminAuthCSRFAndConflict(t *testing.T) {
	a, _, _ := testApp(t)
	h := a.AdminHandler(http.NotFoundHandler(), "", false)
	proxied := a.AdminHandler(http.NotFoundHandler(), "https://admin.example.com", true)
	req := func(method, path, body string, cookie *http.Cookie, csrf, origin, revision string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:32100"
		if cookie != nil {
			r.AddCookie(cookie)
		}
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Origin", origin)
		r.Header.Set("If-Match", revision)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := req("GET", "/api/config", "", nil, "", "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := req("POST", "/api/login", `{"password":"wrong"}`, nil, "", "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := req("POST", "/api/login", `{"password":"`+testPassword+`"}`, nil, "", "https://evil.example", ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	proxiedReq := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"password":"`+testPassword+`"}`))
	proxiedReq.Header.Set("Origin", "https://admin.example.com")
	proxiedResp := httptest.NewRecorder()
	proxied.ServeHTTP(proxiedResp, proxiedReq)
	if proxiedResp.Code != 200 {
		t.Fatalf("configured admin origin rejected: %d %s", proxiedResp.Code, proxiedResp.Body.String())
	}
	if cookies := proxiedResp.Result().Cookies(); len(cookies) != 1 || !cookies[0].Secure {
		t.Fatal("reverse-proxy session cookie is not Secure")
	}
	w := req("POST", "/api/login", `{"password":"`+testPassword+`"}`, nil, "", "", "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("insecure cookie")
	}
	cookie := cookies[0]
	var login map[string]string
	json.Unmarshal(w.Body.Bytes(), &login)
	c := a.Config()
	body, _ := json.Marshal(c)
	if w = req("PUT", "/api/config", string(body), cookie, "", "", "2"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w = req("PUT", "/api/config", string(body), cookie, login["csrf"], "", ""); w.Code != 428 {
		t.Fatal(w.Code)
	}
	if w = req("PUT", "/api/config", string(body), cookie, login["csrf"], "", "1"); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if w = req("GET", "/api/config", "", cookie, "", "", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = req("POST", "/api/logout", "", cookie, login["csrf"], "", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = req("GET", "/api/config", "", cookie, "", "", ""); w.Code != 401 {
		t.Fatal("session survived logout")
	}
}
