package gateway

import (
	"errors"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func requestFrom(a *App, remote string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "app.example.com"
	r.RemoteAddr = remote
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func lastReason(a *App) string {
	events := a.Events.list()
	if len(events) == 0 {
		return ""
	}
	return events[0].Reason
}

func TestRouteInternalExternalAccess(t *testing.T) {
	a, _, _ := testApp(t)
	const internal, external = "10.1.2.3:4000", "192.0.2.20:4000"
	change(t, a, func(c *Config) { c.Routes[0].Access = "internal" })
	if w := requestFrom(a, internal); w.Code != 200 {
		t.Fatalf("internal client on internal route: %d", w.Code)
	}
	if w := requestFrom(a, external); w.Code != 403 {
		t.Fatalf("external client on internal route: %d", w.Code)
	}
	change(t, a, func(c *Config) { c.Routes[0].Access = "external" })
	if w := requestFrom(a, internal); w.Code != 403 {
		t.Fatalf("internal client on external route: %d", w.Code)
	}
	if w := requestFrom(a, external); w.Code != 200 {
		t.Fatalf("external client on external route: %d", w.Code)
	}
	// Custom internal networks replace the built-in private ranges.
	change(t, a, func(c *Config) { c.Routes[0].Access = "internal"; c.InternalCIDRs = []string{"192.0.2.0/24"} })
	if w := requestFrom(a, external); w.Code != 200 {
		t.Fatalf("custom internal network: %d", w.Code)
	}
	if w := requestFrom(a, internal); w.Code != 403 {
		t.Fatalf("10/8 must no longer be internal: %d", w.Code)
	}
	c := a.Config()
	c.Routes[0].Access = "lan"
	if err := a.Update(c, c.Revision); err == nil {
		t.Fatal("unknown access mode accepted")
	}
}

func TestRouteIPLists(t *testing.T) {
	a, _, hits := testApp(t)
	change(t, a, func(c *Config) { c.Routes[0].DenyCIDRs = []string{"192.0.2.0/28"} })
	if w := requestFrom(a, "192.0.2.5:1"); w.Code != 403 || lastReason(a) != "route IP deny list" {
		t.Fatalf("route deny: %d %q", w.Code, lastReason(a))
	}
	if w := requestFrom(a, "192.0.2.20:1"); w.Code != 200 {
		t.Fatalf("outside route deny: %d", w.Code)
	}
	change(t, a, func(c *Config) {
		c.Routes[0].DenyCIDRs = []string{"2001:db8::dead/128"}
		c.Routes[0].AllowCIDRs = []string{"2001:db8::/64"}
	})
	if w := requestFrom(a, "[2001:db8::1]:1"); w.Code != 200 {
		t.Fatalf("route allow: %d", w.Code)
	}
	before := hits.Load()
	if w := requestFrom(a, "[2001:db8::dead]:1"); w.Code != 403 {
		t.Fatalf("deny must win over allow: %d", w.Code)
	}
	if w := requestFrom(a, "[2001:db8:1::1]:1"); w.Code != 403 || lastReason(a) != "IP is outside the route allow list" {
		t.Fatalf("outside route allow: %d %q", w.Code, lastReason(a))
	}
	if hits.Load() != before {
		t.Fatal("denied requests reached the upstream")
	}
	// The global allow list still applies to routes with their own allow list.
	change(t, a, func(c *Config) { c.AllowCIDRs = []string{"198.51.100.0/24"} })
	if w := requestFrom(a, "[2001:db8::1]:1"); w.Code != 403 || lastReason(a) != "IP is outside the allow list" {
		t.Fatalf("global allow: %d %q", w.Code, lastReason(a))
	}
}

func TestGeoblocking(t *testing.T) {
	a, _, _ := testApp(t)
	c := a.Config()
	c.GeoDenyCountries = []string{"RU"}
	if err := a.Update(c, c.Revision); !errors.Is(err, errGeoIPMissing) {
		t.Fatalf("geoblocking without a database must be rejected: %v", err)
	}
	countries := map[string]string{"192.0.2.1": "CH", "192.0.2.2": "RU", "192.0.2.3": "DE"}
	a.country = func(ip netip.Addr) string { return countries[ip.String()] }
	change(t, a, func(c *Config) { c.GeoDenyCountries = []string{"RU"} })
	if w := requestFrom(a, "192.0.2.2:1"); w.Code != 403 || lastReason(a) != "geoblocking: country RU is denied" {
		t.Fatalf("denied country: %d %q", w.Code, lastReason(a))
	}
	if w := requestFrom(a, "192.0.2.1:1"); w.Code != 200 {
		t.Fatalf("other country: %d", w.Code)
	}
	if ev := a.Events.list(); ev[0].Country != "CH" {
		t.Fatalf("country not recorded: %+v", ev[0])
	}
	change(t, a, func(c *Config) { c.GeoDenyCountries = nil; c.Routes[0].GeoAllowCountries = []string{"CH", "DE"} })
	for ip, want := range map[string]int{"192.0.2.1": 200, "192.0.2.3": 200, "192.0.2.2": 403, "192.0.2.99": 403, "10.0.0.5": 200} {
		if w := requestFrom(a, ip+":1"); w.Code != want {
			t.Fatalf("%s: got %d, want %d (%s)", ip, w.Code, want, lastReason(a))
		}
	}
	for _, bad := range [][]string{{"ch"}, {"CHE"}, {"CH", "CH"}} {
		c := a.Config()
		c.GeoAllowCountries = bad
		if err := a.Update(c, c.Revision); err == nil || !strings.Contains(err.Error(), "country codes") {
			t.Fatalf("%v accepted: %v", bad, err)
		}
	}
}
