package gateway

import (
	"errors"
	"net/http"
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
	a.country = func(ip netip.Addr) (string, error) { return countries[ip.String()], nil }
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

func TestCountryExceptionsRespectOtherRestrictions(t *testing.T) {
	a, _, _ := testApp(t)
	a.country = func(netip.Addr) (string, error) { return "RU", nil }
	change(t, a, func(c *Config) {
		c.GeoDenyCountries = []string{"RU"}
		c.Routes[0].GeoBypassCIDRs = []string{"192.0.2.20"}
	})
	if w := requestFrom(a, "192.0.2.20:1"); w.Code != 403 {
		t.Fatal("host exception bypassed global restriction")
	}
	change(t, a, func(c *Config) { c.GeoBypassCIDRs = []string{"192.0.2.20"} })
	if w := requestFrom(a, "192.0.2.20:1"); w.Code != 200 {
		t.Fatalf("global exception: %d", w.Code)
	}
	change(t, a, func(c *Config) { c.Routes[0].DenyCIDRs = []string{"192.0.2.20"} })
	if w := requestFrom(a, "192.0.2.20:1"); w.Code != 403 {
		t.Fatal("exception bypassed IP blacklist")
	}
}

func TestTrustedProxyChain(t *testing.T) {
	for _, tc := range []struct {
		peer, xff, want string
		trusted         []string
	}{
		{"192.0.2.1:1", "1.1.1.1", "192.0.2.1", nil},
		{"10.0.0.1:1", "1.1.1.1, 192.0.2.20, 10.0.0.2", "192.0.2.20", []string{"10.0.0.0/24"}},
		{"[::1]:1", "2001:db8::1", "2001:db8::1", []string{"::1/128"}},
		{"10.0.0.1:1", "invalid", "invalid forwarded client IP", []string{"10.0.0.0/24"}},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Forwarded-For", tc.xff)
		if got := proxyClientIP(r, tc.trusted); got != tc.want {
			t.Fatalf("got %q want %q", got, tc.want)
		}
	}
}

func TestMissingGeoIPKeepsAdminAvailable(t *testing.T) {
	a, _, _ := testApp(t)
	a.country = func(netip.Addr) (string, error) { return "CH", nil }
	change(t, a, func(c *Config) { c.GeoAllowCountries = []string{"CH"} })
	t.Setenv("BASTION_GEOIP_DB", "/nonexistent/country.mmdb")
	recovered, err := New(a.dataDir, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if w := requestFrom(recovered, "192.0.2.20:1"); w.Code != 503 {
		t.Fatalf("country requests must fail closed: %d", w.Code)
	}
	w := httptest.NewRecorder()
	recovered.AdminHandler(http.NotFoundHandler(), "", false).ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 200 {
		t.Fatalf("admin unavailable: %d", w.Code)
	}
	c := recovered.Config()
	c.GeoAllowCountries = nil
	if err := recovered.Update(c, c.Revision); err != nil {
		t.Fatalf("cannot disable broken geo policy: %v", err)
	}
}

func TestGeoIPLookupFailureFailsClosed(t *testing.T) {
	a, _, _ := testApp(t)
	a.country = func(netip.Addr) (string, error) { return "", errors.New("decode failed") }
	change(t, a, func(c *Config) { c.GeoDenyCountries = []string{"RU"} })
	if w := requestFrom(a, "192.0.2.20:1"); w.Code != 503 {
		t.Fatalf("lookup failure allowed: %d", w.Code)
	}
}

func TestTrustedProxyDoesNotMakeExternalClientInternal(t *testing.T) {
	a, _, _ := testApp(t)
	change(t, a, func(c *Config) { c.TrustedProxyCIDRs = []string{"10.0.0.1"}; c.Routes[0].Access = "internal" })
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "app.example.com"
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "192.0.2.20")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("public client treated as internal: %d", w.Code)
	}
	if events := a.Events.list(); events[0].Client != "192.0.2.20" {
		t.Fatalf("wrong logged client: %s", events[0].Client)
	}
}
