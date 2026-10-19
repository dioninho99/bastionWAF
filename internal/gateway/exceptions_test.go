package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
)

const exceptionAttack = "?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

func exceptionRequest(a *App, host, path, method, client, forwarded string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+host+path, nil)
	r.URL.Scheme, r.URL.Host = "", ""
	r.RemoteAddr = client
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	if forwarded != "" {
		r.Header.Set("X-Forwarded-For", forwarded)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func TestScopedExceptions(t *testing.T) {
	a, _, _ := testApp(t)
	if w := request(a, "GET", "/editor"+exceptionAttack, "", ""); w.Code != 403 {
		t.Fatalf("baseline: %d", w.Code)
	}
	var ruleIDs []int
	for _, id := range a.Events.list()[0].RuleIDs {
		if tunableRule(id) {
			ruleIDs = append(ruleIDs, id)
		}
	}
	if len(ruleIDs) == 0 {
		t.Fatal("no detection rules found")
	}
	change(t, a, func(c *Config) {
		r := c.Routes[0]
		r.ID, r.Name, r.Host = "other", "Other", "other.example.com"
		c.Routes = append(c.Routes, r)
		c.Exceptions = []WAFException{{ID: "editor", Name: "Editor", Reason: "Intentional markup", Enabled: true, Scope: "hosts", RouteIDs: []string{"test"}, ClientCIDRs: []string{"192.0.2.20"}, Path: "/editor", Match: "exact", Methods: []string{"GET"}, RuleIDs: ruleIDs}}
	})
	check := func(host, path, method, client, forwarded string, want int) {
		t.Helper()
		w := exceptionRequest(a, host, path, method, client, forwarded)
		if w.Code != want {
			t.Fatalf("%s %s %s client=%s: got %d want %d (%s)", host, method, path, client, w.Code, want, w.Body.String())
		}
	}
	check("app.example.com", "/editor"+exceptionAttack, "GET", "192.0.2.20:45000", "", 200)
	ev := a.Events.list()[0]
	if ev.RouteID != "test" || !slices.Equal(ev.ExceptionIDs, []string{"editor"}) {
		t.Fatalf("missing attribution: %+v", ev)
	}
	check("app.example.com", "/editor"+exceptionAttack, "GET", "192.0.2.21:45000", "192.0.2.20", 403)
	check("other.example.com", "/editor"+exceptionAttack, "GET", "192.0.2.20:45000", "", 403)
	check("app.example.com", "/other"+exceptionAttack, "GET", "192.0.2.20:45000", "", 403)
	check("app.example.com", "/editor/child"+exceptionAttack, "GET", "192.0.2.20:45000", "", 403)
	check("app.example.com", "/editor"+exceptionAttack, "POST", "192.0.2.20:45000", "", 403)
	check("app.example.com", "/editor?id=1%20UNION%20SELECT%20username,password%20FROM%20users", "GET", "192.0.2.20:45000", "", 403)
	// Encoded paths use the same decoded semantics in routing and Coraza.
	check("app.example.com", "/ed%69tor"+exceptionAttack, "GET", "192.0.2.20:45000", "", 200)
	change(t, a, func(c *Config) { c.Exceptions[0].Match = "prefix"; c.TrustedProxyCIDRs = []string{"10.0.0.5"} })
	check("app.example.com", "/editor/child"+exceptionAttack, "GET", "10.0.0.5:45000", "192.0.2.20", 200)
	check("app.example.com", "/editor-other"+exceptionAttack, "GET", "192.0.2.20:45000", "", 403)
	change(t, a, func(c *Config) {
		c.Exceptions[0].Scope = "global"
		c.Exceptions[0].RouteIDs = nil
		c.Exceptions[0].ClientCIDRs = nil
		c.Exceptions[0].Methods = nil
	})
	check("other.example.com", "/editor/child"+exceptionAttack, "GET", "192.0.2.21:45000", "", 200)
	// Persistence and normalization survive a restart/config reload.
	loaded, err := loadConfig(a.configPath, true)
	if err != nil || len(loaded.Exceptions) != 1 || loaded.Exceptions[0].Scope != "global" {
		t.Fatalf("reload: %+v %v", loaded.Exceptions, err)
	}
	// Concurrent traffic must never inherit another transaction's exclusions.
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path, want := "/editor", 200
			if i%2 == 0 {
				path, want = "/other", 403
			}
			w := exceptionRequest(a, "app.example.com", path+exceptionAttack, "GET", "192.0.2.20:45000", "")
			if w.Code != want {
				t.Errorf("concurrent %s: got %d want %d", path, w.Code, want)
			}
		}(i)
	}
	wg.Wait()
	change(t, a, func(c *Config) { c.DenyCIDRs = []string{"192.0.2.20/32"} })
	check("app.example.com", "/editor"+exceptionAttack, "GET", "192.0.2.20:45000", "", 403)
	change(t, a, func(c *Config) {
		c.DenyCIDRs = nil
		c.Rules = []Rule{{ID: "custom", Name: "Custom", Enabled: true, Field: "path", Value: "editor", Action: "block"}}
	})
	check("app.example.com", "/editor"+exceptionAttack, "GET", "192.0.2.20:45000", "", 403)
	change(t, a, func(c *Config) { c.Rules = nil; c.Exceptions[0].Enabled = false })
	check("app.example.com", "/editor"+exceptionAttack, "GET", "192.0.2.20:45000", "", 403)
}

func TestExceptionValidation(t *testing.T) {
	base := func() Config {
		c := DefaultConfig()
		c.Routes = []Route{{ID: "test"}}
		c.Exceptions = []WAFException{{ID: "test", Name: "Test", Reason: "Confirmed false positive", Enabled: true, Scope: "hosts", RouteIDs: []string{"test"}, Path: "/editor", Match: "exact", RuleIDs: []int{941100}}}
		return c
	}
	for name, mutate := range map[string]func(*WAFException){
		"empty scope":       func(e *WAFException) { e.Scope = "" },
		"no hosts":          func(e *WAFException) { e.RouteIDs = nil },
		"missing host":      func(e *WAFException) { e.RouteIDs = []string{"missing"} },
		"global with hosts": func(e *WAFException) { e.Scope = "global" },
		"no rules":          func(e *WAFException) { e.RuleIDs = nil },
		"evaluation":        func(e *WAFException) { e.RuleIDs = []int{949110} },
		"setup":             func(e *WAFException) { e.RuleIDs = []int{900000} },
		"duplicate rules":   func(e *WAFException) { e.RuleIDs = []int{941100, 941100} },
		"path injection":    func(e *WAFException) { e.Path = "/\"\nSecAction" },
		"interpolation":     func(e *WAFException) { e.Path = "/%{tx.foo}" },
		"query":             func(e *WAFException) { e.Path = "/editor?x=y" },
		"method injection":  func(e *WAFException) { e.Methods = []string{"GET|POST"} },
		"invalid client":    func(e *WAFException) { e.ClientCIDRs = []string{"bad"} },
		"reason":            func(e *WAFException) { e.Reason = " " },
		"match":             func(e *WAFException) { e.Match = "regex" },
	} {
		t.Run(name, func(t *testing.T) {
			c := base()
			mutate(&c.Exceptions[0])
			if validateExceptions(c) == nil {
				t.Fatal("invalid exception accepted")
			}
		})
	}
	c := base()
	c.Exceptions[0].ClientCIDRs = []string{"192.0.2.20", "2001:db8::1"}
	normalize(&c)
	if err := validateExceptions(c); err != nil {
		t.Fatal(err)
	}
	if !c.Exceptions[0].matches("/editor", "GET", netip.MustParseAddr("2001:db8::1"), nil) {
		t.Fatal("IPv6 mismatch")
	}
	c.Exceptions = append(c.Exceptions, c.Exceptions[0])
	if validateExceptions(c) == nil {
		t.Fatal("duplicate ID accepted")
	}
}

func TestExceptionLiteralPathAndLimits(t *testing.T) {
	a, _, _ := testApp(t)
	change(t, a, func(c *Config) {
		c.Exceptions = []WAFException{{ID: "literal", Name: "Literal", Reason: "Test", Enabled: true, Scope: "global", Path: "/v1.0/a+b", Match: "exact", RuleIDs: []int{941100}}}
	})
	// Ensure regex metacharacters in paths compile as literals.
	directives := exceptionDirectives(a.Config().Exceptions, "test")
	if !strings.Contains(directives, `/v1\.0/a\+b`) {
		t.Fatalf("unescaped path: %s", directives)
	}
	change(t, a, func(c *Config) {
		c.Routes[0].RateLimit = 1
		c.Exceptions[0].Path = "/"
		c.Exceptions[0].Match = "prefix"
	})
	if w := request(a, "GET", "/hello", "", ""); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	if w := request(a, "GET", "/hello", "", ""); w.Code != http.StatusTooManyRequests {
		t.Fatal(w.Code)
	}
}
