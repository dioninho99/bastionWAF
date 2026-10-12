package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"
)

// defaultInternalCIDRs classify a client as internal when Config.InternalCIDRs is empty:
// RFC 1918, carrier-grade NAT (also used by Tailscale), loopback, link-local, and IPv6 ULA.
var defaultInternalCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}

var countryCode = regexp.MustCompile(`^[A-Z]{2}$`)

// countryLookup resolves a client address to an ISO 3166-1 alpha-2 code; "" means unknown.
type countryLookup func(netip.Addr) (string, error)

// openGeoIP loads a MaxMind-compatible country database (GeoLite2-Country, DB-IP Country Lite, …).
func openGeoIP(path string) (countryLookup, func(), error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("BASTION_GEOIP_DB: %w", err)
	}
	db, err := maxminddb.OpenBytes(data)
	if err != nil {
		return nil, nil, fmt.Errorf("BASTION_GEOIP_DB: %w", err)
	}
	if err = db.Verify(); err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("BASTION_GEOIP_DB is not a valid MaxMind DB: %w", err)
	}
	databaseType := strings.ToLower(db.Metadata.DatabaseType)
	if !strings.Contains(databaseType, "country") && !strings.Contains(databaseType, "city") {
		db.Close()
		return nil, nil, errors.New("BASTION_GEOIP_DB requires a Country or City database")
	}
	lookup := func(ip netip.Addr) (string, error) {
		var record struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if err := db.Lookup(ip).Decode(&record); err != nil {
			return "", err
		}
		return strings.ToUpper(record.Country.ISOCode), nil
	}
	return lookup, func() { db.Close() }, nil
}

func configuredGeoIP() (countryLookup, func(), error) {
	path := strings.TrimSpace(os.Getenv("BASTION_GEOIP_DB"))
	if path == "" {
		return nil, func() {}, nil
	}
	return openGeoIP(path)
}

// accessPolicy is the precompiled IP/geo policy of the global configuration or one route.
type accessPolicy struct {
	deny, allow           []netip.Prefix
	geoBypass             []netip.Prefix
	geoDeny, geoAllow     map[string]bool
	geoConfigured         bool
	internalOnly, extOnly bool
}

func mustPrefixes(list []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		// Inputs are validated before compilation.
		p, _ := netip.ParsePrefix(s)
		out = append(out, p.Masked())
	}
	return out
}
func countrySet(list []string) map[string]bool {
	out := make(map[string]bool, len(list))
	for _, c := range list {
		out[c] = true
	}
	return out
}
func newAccessPolicy(deny, allow, geoDeny, geoAllow []string, access string) accessPolicy {
	return accessPolicy{deny: mustPrefixes(deny), allow: mustPrefixes(allow), geoDeny: countrySet(geoDeny), geoAllow: countrySet(geoAllow), geoConfigured: len(geoDeny)+len(geoAllow) > 0, internalOnly: access == "internal", extOnly: access == "external"}
}
func prefixesContain(list []netip.Prefix, ip netip.Addr) bool {
	for _, p := range list {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// checkAccess applies the global policy and then the route policy. Every layer must pass,
// so a route can only narrow the global policy. Internal clients skip geo checks because
// private addresses carry no country. It returns the denial reason, or "" when allowed.
func checkAccess(global, route *accessPolicy, ip netip.Addr, internal bool, country string) string {
	switch {
	case prefixesContain(global.deny, ip):
		return "IP deny list"
	case prefixesContain(route.deny, ip):
		return "route IP deny list"
	case len(global.allow) > 0 && !prefixesContain(global.allow, ip):
		return "IP is outside the allow list"
	case len(route.allow) > 0 && !prefixesContain(route.allow, ip):
		return "IP is outside the route allow list"
	case route.internalOnly && !internal:
		return "route is restricted to internal clients"
	case route.extOnly && internal:
		return "route is restricted to external clients"
	}
	if internal {
		return ""
	}
	for _, p := range []*accessPolicy{global, route} {
		if prefixesContain(global.geoBypass, ip) || prefixesContain(p.geoBypass, ip) {
			continue
		}
		if country != "" && p.geoDeny[country] {
			return "geoblocking: country " + country + " is denied"
		}
		if len(p.geoAllow) > 0 && !p.geoAllow[country] {
			if country == "" {
				return "geoblocking: unknown country is outside the allow list"
			}
			return "geoblocking: country " + country + " is outside the allow list"
		}
	}
	return ""
}

func validateCountries(list []string, scope string) error {
	if len(list) > 250 {
		return fmt.Errorf("%s: a maximum of 250 countries is supported", scope)
	}
	seen := map[string]bool{}
	for _, c := range list {
		if !countryCode.MatchString(c) || seen[c] {
			return fmt.Errorf("%s: country codes must be unique uppercase ISO 3166-1 alpha-2 codes such as CH", scope)
		}
		seen[c] = true
	}
	return nil
}
func validateCIDRs(list []string, scope string) error {
	if len(list) > 1000 {
		return fmt.Errorf("%s: too many networks", scope)
	}
	for _, s := range list {
		if p, e := netip.ParsePrefix(s); e != nil || p.Addr().Is4In6() {
			return fmt.Errorf("%s: invalid CIDR: %s", scope, s)
		}
	}
	return nil
}

func usesGeoblocking(c Config) bool {
	if len(c.GeoDenyCountries)+len(c.GeoAllowCountries) > 0 {
		return true
	}
	for _, r := range c.Routes {
		if r.Enabled && len(r.GeoDenyCountries)+len(r.GeoAllowCountries) > 0 {
			return true
		}
	}
	return false
}

var errGeoIPMissing = errors.New("geoblocking requires a country database; set BASTION_GEOIP_DB to a MaxMind-compatible .mmdb file")

func normalizeIPList(list []string) []string {
	out := make([]string, len(list))
	for i, value := range list {
		value = strings.TrimSpace(value)
		if ip, err := netip.ParseAddr(value); err == nil {
			ip = ip.Unmap()
			value = netip.PrefixFrom(ip, ip.BitLen()).String()
		}
		out[i] = value
	}
	return out
}
func proxyClientIP(r *http.Request, trusted []string) string {
	prefixes := mustPrefixes(trusted)
	peer := clientIP(r)
	ip, err := netip.ParseAddr(peer)
	if err != nil || !prefixesContain(prefixes, ip) {
		return peer
	}
	raw := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	if raw == "" {
		return peer
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 32 {
		return "invalid forwarded client IP"
	}
	for i := len(parts) - 1; i >= 0; i-- {
		ip, err = netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil || ip.Zone() != "" {
			return "invalid forwarded client IP"
		}
		ip = ip.Unmap()
		if !prefixesContain(prefixes, ip) || i == 0 {
			return ip.String()
		}
	}
	return peer
}
func needsCountry(global, route *accessPolicy, ip netip.Addr, internal bool) bool {
	if internal || prefixesContain(global.geoBypass, ip) {
		return false
	}
	return global.geoConfigured || route.geoConfigured && !prefixesContain(route.geoBypass, ip)
}
