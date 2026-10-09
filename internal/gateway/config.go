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
}
type Rule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
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
	}
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var domainName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)

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
	}
	ids = map[string]bool{}
	for _, r := range c.Rules {
		if !identifier.MatchString(r.ID) || ids[r.ID] || len(r.Name) < 1 || len(r.Name) > 100 {
			return errors.New("custom rule is invalid or duplicated")
		}
		ids[r.ID] = true
		if r.Field != "path" && r.Field != "user-agent" && r.Field != "method" {
			return errors.New("rule field must be path, user-agent, or method")
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
