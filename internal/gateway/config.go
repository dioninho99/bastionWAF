package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Config struct {
	Revision           int64    `json:"revision"`
	Mode               string   `json:"mode"`
	Paranoia           int      `json:"paranoia"`
	Threshold          int      `json:"threshold"`
	MaxBodyBytes       int64    `json:"maxBodyBytes"`
	RateLimit          int      `json:"rateLimit"`
	ResponseInspection bool     `json:"responseInspection"`
	DenyCIDRs          []string `json:"denyCIDRs"`
	AllowCIDRs         []string `json:"allowCIDRs"`
	Routes             []Route  `json:"routes"`
	Rules              []Rule   `json:"rules"`
}
type Route struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Host            string   `json:"host"`
	Path            string   `json:"path"`
	Upstreams       []string `json:"upstreams"`
	Enabled         bool     `json:"enabled"`
	PreserveHost    bool     `json:"preserveHost"`
	ExcludedRuleIDs []int    `json:"excludedRuleIds"`
	WAFMode         string   `json:"wafMode,omitempty"`
	Paranoia        int      `json:"paranoia,omitempty"`
	AnomalyThreshold int     `json:"anomalyThreshold,omitempty"`
	RateLimit       int      `json:"rateLimit,omitempty"`
	MaxBodyBytes    int64    `json:"maxBodyBytes,omitempty"`
	AllowedMethods  []string `json:"allowedMethods,omitempty"`
	BotDenyPatterns []string `json:"botDenyPatterns,omitempty"`
	AllowedContentTypes []string `json:"allowedContentTypes,omitempty"`
	RequireContentType bool `json:"requireContentType,omitempty"`
	SecurityHeaders bool `json:"securityHeaders,omitempty"`
	OIDCProtected bool `json:"oidcProtected,omitempty"`
}
type Rule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Category string `json:"category,omitempty"`
	Field   string `json:"field"`
	Value   string `json:"value"`
	Action  string `json:"action"`
	Enabled bool   `json:"enabled"`
}

func DefaultConfig() Config {
	return Config{Revision: 1, Mode: "blocking", Paranoia: 1, Threshold: 5, MaxBodyBytes: 2 << 20, RateLimit: 120, DenyCIDRs: []string{}, AllowCIDRs: []string{}, Routes: []Route{}, Rules: []Rule{}}
}

func normalize(c *Config) {
	if c.Routes == nil {
		c.Routes = []Route{}
	}
	if c.Rules == nil {
		c.Rules = []Rule{}
	}
	if c.DenyCIDRs == nil {
		c.DenyCIDRs = []string{}
	}
	if c.AllowCIDRs == nil {
		c.AllowCIDRs = []string{}
	}
	for i := range c.Routes {
		if c.Routes[i].ExcludedRuleIDs == nil {
			c.Routes[i].ExcludedRuleIDs = []int{}
		}
		if c.Routes[i].AllowedMethods == nil {
			c.Routes[i].AllowedMethods = []string{}
		}
		if c.Routes[i].BotDenyPatterns == nil {
			c.Routes[i].BotDenyPatterns = []string{}
		}
		if c.Routes[i].AllowedContentTypes == nil {
			c.Routes[i].AllowedContentTypes = []string{}
		}
	}
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var domainName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)
var httpMethod = regexp.MustCompile(`^[A-Z][A-Z0-9-]{0,19}$`)
var owaspCategory = regexp.MustCompile(`^A(0[1-9]|10)$`)

func validate(c Config, allowPrivate bool) error {
	if c.Mode != "blocking" && c.Mode != "detection" {
		return errors.New("mode must be blocking or detection")
	}
	if c.Paranoia < 1 || c.Paranoia > 4 || c.Threshold < 1 || c.Threshold > 100 {
		return errors.New("paranoia must be 1–4 and threshold must be 1–100")
	}
	if c.MaxBodyBytes < 1024 || c.MaxBodyBytes > 32<<20 || c.RateLimit < 1 || c.RateLimit > 100000 {
		return errors.New("body limit: 1 KiB–32 MiB; rate limit: 1–100000/min")
	}
	if len(c.Routes) > 100 || len(c.Rules) > 200 || len(c.DenyCIDRs)+len(c.AllowCIDRs) > 1000 {
		return errors.New("too many configuration entries")
	}
	for _, s := range append(append([]string{}, c.DenyCIDRs...), c.AllowCIDRs...) {
		if _, e := netip.ParsePrefix(s); e != nil {
			return fmt.Errorf("invalid CIDR: %s", s)
		}
	}
	ids, bindings := map[string]bool{}, map[string]bool{}
	for _, r := range c.Routes {
		if !identifier.MatchString(r.ID) || ids[r.ID] {
			return errors.New("route ID is invalid or duplicated")
		}
		ids[r.ID] = true
		if len(r.Name) < 1 || len(r.Name) > 100 || len(r.Host) > 253 || !domainName.MatchString(r.Host) || strings.Contains(r.Host, "..") {
			return errors.New("route name or host is invalid; use exact lowercase hosts")
		}
		if !strings.HasPrefix(r.Path, "/") || strings.ContainsAny(r.Path, "?#\r\n\\") || len(r.Path) > 500 {
			return errors.New("invalid path prefix")
		}
		binding := r.Host + r.Path
		if bindings[binding] {
			return errors.New("host/path already exists")
		}
		bindings[binding] = true
		if len(r.Upstreams) < 1 || len(r.Upstreams) > 16 {
			return errors.New("each route requires 1–16 upstreams")
		}
		for _, s := range r.Upstreams {
			u, e := url.Parse(s)
			if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
				return fmt.Errorf("invalid upstream %q: an HTTP(S) origin without a path or credentials is required", s)
			}
			if u.Port() != "" {
				if _, e = net.LookupPort("tcp", u.Port()); e != nil {
					return errors.New("invalid upstream port")
				}
			}
			if !allowPrivate && upstreamResolvesPrivate(u.Hostname()) {
				return fmt.Errorf("private upstream %q requires BASTION_ALLOW_PRIVATE_UPSTREAMS=true", s)
			}
		}
		if len(r.ExcludedRuleIDs) > 100 {
			return errors.New("a maximum of 100 rule exclusions is allowed per route")
		}
		for _, id := range r.ExcludedRuleIDs {
			if id < 900000 || id > 999999 {
				return errors.New("only CRS rule IDs 900000–999999 can be excluded")
			}
		}
		if r.WAFMode != "" && r.WAFMode != "inherit" && r.WAFMode != "blocking" && r.WAFMode != "detection" {
			return errors.New("route WAF mode must be inherit, blocking, or detection")
		}
		if r.Paranoia < 0 || r.Paranoia > 4 || r.AnomalyThreshold < 0 || r.AnomalyThreshold > 100 {
			return errors.New("route paranoia must be 0–4 and anomaly threshold must be 0–100")
		}
		if r.RateLimit < 0 || r.RateLimit > c.RateLimit {
			return errors.New("route rate limit must be 0 or no greater than the global limit")
		}
		if r.MaxBodyBytes != 0 && (r.MaxBodyBytes < 1024 || r.MaxBodyBytes > c.MaxBodyBytes) {
			return errors.New("route body limit must be 0 or between 1 KiB and the global limit")
		}
		if len(r.AllowedMethods) > 16 {
			return errors.New("a maximum of 16 allowed methods is supported per route")
		}
		methods := map[string]bool{}
		for _, method := range r.AllowedMethods {
			if !httpMethod.MatchString(method) || methods[method] {
				return errors.New("allowed methods must be unique uppercase HTTP method tokens")
			}
			methods[method] = true
		}
		if len(r.BotDenyPatterns) > 32 {
			return errors.New("a maximum of 32 bot user-agent patterns is supported per route")
		}
		for _, pattern := range r.BotDenyPatterns {
			if len(pattern) < 1 || len(pattern) > 128 || strings.ContainsAny(pattern, "\r\n") {
				return errors.New("bot user-agent patterns must be 1–128 characters without line breaks")
			}
			if _, err := regexp.Compile("(?i:" + pattern + ")"); err != nil {
				return fmt.Errorf("invalid bot user-agent pattern: %w", err)
			}
		}
		if len(r.AllowedContentTypes) > 16 {
			return errors.New("a maximum of 16 allowed content types is supported per route")
		}
		for _, contentType := range r.AllowedContentTypes {
			if len(contentType) < 3 || len(contentType) > 128 || strings.ContainsAny(contentType, "\r\n;") || !strings.Contains(contentType, "/") {
				return errors.New("allowed content types must be media types such as application/json")
			}
		}
	}
	ids = map[string]bool{}
	if len(c.Rules) > 64 {
		return errors.New("a maximum of 64 custom rules is supported")
	}
	bodyRules := 0
	for _, r := range c.Rules {
		if !identifier.MatchString(r.ID) || ids[r.ID] || len(r.Name) < 1 || len(r.Name) > 100 {
			return errors.New("custom rule is invalid or duplicated")
		}
		ids[r.ID] = true
		if r.Category != "" && !owaspCategory.MatchString(r.Category) {
			return errors.New("custom rule category must be an OWASP Top 10:2025 identifier such as A05")
		}
		switch r.Field {
		case "path", "query", "header", "user-agent", "method", "body":
			if r.Field == "body" {
				bodyRules++
				if bodyRules > 16 {
					return errors.New("a maximum of 16 body custom rules is supported")
				}
			}
		default:
			return errors.New("rule field must be path, query, header, user-agent, method, or body")
		}
		if r.Action != "block" && r.Action != "log" {
			return errors.New("rule action must be block or log")
		}
		if len(r.Value) < 1 || len(r.Value) > 256 || strings.ContainsAny(r.Value, "\r\n") {
			return errors.New("rule value must be 1–256 characters long")
		}
	}
	return nil
}
func loadConfig(path string, allowPrivate bool) (Config, error) {
	c := DefaultConfig()
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return c, nil
	}
	if e != nil {
		return c, e
	}
	e = json.Unmarshal(b, &c)
	if e != nil {
		return c, e
	}
	normalize(&c)
	return c, validate(c, allowPrivate)
}

func upstreamResolvesPrivate(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return isRestrictedUpstreamIP(ip)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, raw := range ips {
		if ip, ok := netip.AddrFromSlice(raw); ok && isRestrictedUpstreamIP(ip) {
			return true
		}
	}
	return false
}

func isRestrictedUpstreamIP(ip netip.Addr) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
func saveConfig(path string, c Config) error {
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".config-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
