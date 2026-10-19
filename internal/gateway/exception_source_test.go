package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestExceptionSourceMatching(t *testing.T) {
	for _, tt := range []struct {
		name, header, match, source, value string
		want                               bool
	}{
		{"origin", "Origin", "exact", "https://portal.example.com", "https://portal.example.com", true},
		{"host case", "Origin", "exact", "https://portal.example.com", "https://PORTAL.EXAMPLE.COM", true},
		{"scheme", "Origin", "exact", "https://portal.example.com", "http://portal.example.com", false},
		{"subdomain suffix", "Origin", "exact", "https://portal.example.com", "https://portal.example.com.evil.test", false},
		{"userinfo", "Origin", "exact", "https://portal.example.com", "https://portal.example.com@evil.test", false},
		{"missing", "Origin", "exact", "https://portal.example.com", "", false},
		{"opaque", "Origin", "exact", "https://portal.example.com", "null", false},
		{"port", "Origin", "exact", "https://portal.example.com:8443", "https://portal.example.com", false},
		{"exact referer", "Referer", "exact", "https://portal.example.com/editor", "https://portal.example.com/editor", true},
		{"exact query", "Referer", "exact", "https://portal.example.com/editor", "https://portal.example.com/editor?x=1", false},
		{"prefix child", "Referer", "prefix", "https://portal.example.com/editor", "https://portal.example.com/editor/item?x=1", true},
		{"prefix query", "Referer", "prefix", "https://portal.example.com/editor", "https://portal.example.com/editor?x=1", true},
		{"prefix boundary", "Referer", "prefix", "https://portal.example.com/editor", "https://portal.example.com/editor-other", false},
		{"path case", "Referer", "prefix", "https://portal.example.com/editor", "https://portal.example.com/Editor", false},
		{"multiple joined", "Referer", "prefix", "https://portal.example.com", "https://portal.example.com/a, https://evil.test/b", false},
		{"literal dot", "Referer", "exact", "https://portal.example.com/v1.0", "https://portal.example.com/v1x0", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := WAFException{SourceHeader: tt.header, SourceMatch: tt.match, SourceURLs: []string{tt.source}}
			h := http.Header{}
			if tt.value != "" {
				h.Set(tt.header, tt.value)
			}
			if got := e.matchesSource(h); got != tt.want {
				t.Fatalf("matched=%v want=%v", got, tt.want)
			}
		})
	}
	e := WAFException{SourceHeader: "Origin", SourceMatch: "exact", SourceURLs: []string{"https://portal.example.com", "https://other.example.com"}, Path: "/", Match: "prefix", ClientCIDRs: []string{"192.0.2.1/32"}}
	h := http.Header{"Origin": []string{"https://other.example.com"}}
	if !e.matches("/api", "POST", netip.MustParseAddr("192.0.2.1"), h) {
		t.Fatal("second source did not match")
	}
	h.Add("Origin", "https://evil.test")
	if e.matchesSource(h) {
		t.Fatal("duplicate headers matched")
	}
	h = http.Header{"Referer": []string{"https://portal.example.com"}}
	if e.matches("/api", "POST", netip.MustParseAddr("192.0.2.1"), h) {
		t.Fatal("unselected header bypassed source condition")
	}
	if !(WAFException{}).matchesSource(nil) {
		t.Fatal("legacy exception should have no source restriction")
	}
}

func TestExceptionSourceValidation(t *testing.T) {
	for _, raw := range []string{"null", "https://*.example.com", "https://user@portal.example.com", "https://portal.example.com?x=1", "https://portal.example.com#x", "https://portal.example.com/%{tx.x}", "https://portal.example.com/\"", "https://portal.example.com/\n", "ftp://portal.example.com", "https://portal.example.com:99999", "https://portal.example.com:"} {
		e := WAFException{SourceHeader: "Referer", SourceMatch: "exact", SourceURLs: []string{raw}}
		if e.validateSource() == nil {
			t.Errorf("accepted invalid source %q", raw)
		}
	}
	for _, e := range []WAFException{
		{SourceURLs: []string{"https://portal.example.com"}},
		{SourceHeader: "Host", SourceMatch: "exact", SourceURLs: []string{"https://portal.example.com"}},
		{SourceHeader: "Origin", SourceMatch: "exact"},
		{SourceHeader: "Origin", SourceMatch: "prefix", SourceURLs: []string{"https://portal.example.com"}},
		{SourceHeader: "Origin", SourceMatch: "exact", SourceURLs: []string{"https://portal.example.com/editor"}},
	} {
		if e.validateSource() == nil {
			t.Errorf("accepted invalid condition %+v", e)
		}
	}
	c := DefaultConfig()
	c.Exceptions = []WAFException{{SourceHeader: "Origin", SourceMatch: "exact", SourceURLs: []string{" https://PORTAL.example.com/ "}}}
	normalize(&c)
	if got := c.Exceptions[0].SourceURLs[0]; got != "https://portal.example.com" {
		t.Fatal(got)
	}
	if err := c.Exceptions[0].validateSource(); err != nil {
		t.Fatal(err)
	}
}

func TestExceptionSourceCRS(t *testing.T) {
	a, _, _ := testApp(t)
	request(a, "GET", "/editor"+exceptionAttack, "", "")
	var ids []int
	for _, id := range a.Events.list()[0].RuleIDs {
		if tunableRule(id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		t.Fatal("no baseline detection rules")
	}
	for _, header := range []string{"Origin", "Referer"} {
		change(t, a, func(c *Config) {
			c.Exceptions = []WAFException{{ID: "source", Name: "Source", Reason: "Reviewed", Enabled: true, Scope: "global", Path: "/editor", Match: "exact", RuleIDs: ids, SourceHeader: header, SourceMatch: "exact", SourceURLs: []string{"https://portal.example.com"}}}
		})
		for _, value := range []string{"https://portal.example.com", "https://portal.example.com.evil.test", ""} {
			r := httptest.NewRequest("GET", "http://app.example.com/editor"+exceptionAttack, nil)
			r.URL.Scheme, r.URL.Host = "", ""
			r.RemoteAddr = "192.0.2.20:45000"
			r.Header.Set("User-Agent", "Mozilla/5.0")
			r.Header.Set("Accept", "*/*")
			if value != "" {
				r.Header.Set(header, value)
			}
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			want := 403
			if value == "https://portal.example.com" {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("%s %q: got %d want %d", header, value, w.Code, want)
			}
			ev := a.Events.list()[0]
			if (len(ev.ExceptionIDs) > 0) != (want == 200) {
				t.Fatalf("attribution differs: %+v", ev)
			}
		}
	}
}
