package gateway

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// WAFException removes selected detection rules, never the surrounding access
// controls or anomaly evaluation. Host, client, path and method constraints AND.
type WAFException struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Reason       string   `json:"reason"`
	Enabled      bool     `json:"enabled"`
	Scope        string   `json:"scope"`
	RouteIDs     []string `json:"routeIds"`
	ClientCIDRs  []string `json:"clientCIDRs"`
	Path         string   `json:"path"`
	Match        string   `json:"match"`
	Methods      []string `json:"methods"`
	RuleIDs      []int    `json:"ruleIds"`
	SourceHeader string   `json:"sourceHeader,omitempty"`
	SourceMatch  string   `json:"sourceMatch,omitempty"`
	SourceURLs   []string `json:"sourceURLs,omitempty"`
}

func tunableRule(id int) bool {
	return id >= 920000 && id < 949000 || id >= 950000 && id < 959000
}

func validateExceptions(c Config) error {
	if len(c.Exceptions) > 100 {
		return errors.New("a maximum of 100 WAF exceptions is allowed")
	}
	routes := map[string]bool{}
	for _, r := range c.Routes {
		routes[r.ID] = true
	}
	ids := map[string]bool{}
	for _, e := range c.Exceptions {
		if !identifier.MatchString(e.ID) || ids[e.ID] {
			return errors.New("exception ID is invalid or duplicated")
		}
		ids[e.ID] = true
		if err := e.validateSource(); err != nil {
			return err
		}
		if strings.TrimSpace(e.Name) == "" || len(e.Name) > 100 || strings.TrimSpace(e.Reason) == "" || len(e.Reason) > 500 {
			return errors.New("exceptions require a name (1–100 bytes) and reason (1–500 bytes)")
		}
		if e.Scope != "global" && e.Scope != "hosts" || e.Scope == "global" && len(e.RouteIDs) != 0 || e.Scope == "hosts" && len(e.RouteIDs) == 0 || len(e.RouteIDs) > 100 {
			return errors.New("exception scope must be global without hosts, or hosts with at least one selected host")
		}
		seen := map[string]bool{}
		for _, id := range e.RouteIDs {
			if !routes[id] || seen[id] {
				return errors.New("exception references an unknown or duplicate host; update its scope before removing a host")
			}
			seen[id] = true
		}
		if len(e.ClientCIDRs) > 100 {
			return errors.New("a maximum of 100 client networks is allowed per exception")
		}
		if err := validateCIDRs(e.ClientCIDRs, "exception clients"); err != nil {
			return err
		}
		if e.Match != "exact" && e.Match != "prefix" {
			return errors.New("exception path match must be exact or prefix")
		}
		// Values are embedded in SecLang quoted strings: reject controls, quotes,
		// interpolation and encoded paths; paths are matched after URL decoding.
		if !strings.HasPrefix(e.Path, "/") || len(e.Path) > 500 || strings.ContainsAny(e.Path, "?#%\\\"'\r\n\t ") || strings.ContainsFunc(e.Path, func(c rune) bool { return c < 32 || c == 127 }) {
			return errors.New("exception path must be a decoded absolute path without query, fragment, whitespace, quotes, or percent escapes")
		}
		if len(e.Methods) > 16 {
			return errors.New("a maximum of 16 methods is allowed per exception")
		}
		methods := map[string]bool{}
		for _, m := range e.Methods {
			if !httpMethod.MatchString(m) || methods[m] {
				return errors.New("exception methods must be unique uppercase HTTP method tokens")
			}
			methods[m] = true
		}
		if len(e.RuleIDs) == 0 || len(e.RuleIDs) > 32 {
			return errors.New("select 1–32 CRS detection rule IDs per exception")
		}
		rules := map[int]bool{}
		for _, id := range e.RuleIDs {
			if !tunableRule(id) || rules[id] {
				return errors.New("exception rule IDs must be unique detection rules (920000–948999 or 950000–958999); anomaly evaluation cannot be excluded")
			}
			rules[id] = true
		}
	}
	return nil
}

func (e WAFException) appliesTo(routeID string) bool {
	return e.Enabled && (e.Scope == "global" || slices.Contains(e.RouteIDs, routeID))
}

func (e WAFException) matches(path, method string, ip netip.Addr, headers http.Header) bool {
	if !e.matchesSource(headers) {
		return false
	}
	if (e.Match == "exact" && path != e.Path) || (e.Match == "prefix" && !pathMatches(path, e.Path)) {
		return false
	}
	if len(e.Methods) > 0 && !slices.Contains(e.Methods, method) {
		return false
	}
	if len(e.ClientCIDRs) > 0 {
		for _, raw := range e.ClientCIDRs {
			prefix, err := netip.ParsePrefix(raw)
			if err == nil && prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	return true
}

// Each chain runs before CRS phase 1, with transaction-local ctl actions on the
// final condition. Immutable WAF engines may safely be shared between requests.
func exceptionDirectives(exceptions []WAFException, routeID string) string {
	var out strings.Builder
	for i, e := range exceptions {
		if !e.appliesTo(routeID) {
			continue
		}
		pattern := "^" + regexp.QuoteMeta(e.Path) + "$"
		if e.Match == "prefix" {
			pattern = "^" + regexp.QuoteMeta(strings.TrimSuffix(e.Path, "/")) + "(?:/|$)"
		}
		conditions := [][2]string{{"REQUEST_FILENAME", "@rx " + pattern}}
		if e.SourceHeader != "" {
			field := "REQUEST_HEADERS:" + e.SourceHeader
			conditions = append(conditions, [2]string{"&" + field, "@eq 1"}, [2]string{field, "@rx " + e.sourcePattern()})
		}
		if len(e.Methods) > 0 {
			conditions = append(conditions, [2]string{"REQUEST_METHOD", "@rx ^(?:" + strings.Join(e.Methods, "|") + ")$"})
		}
		if len(e.ClientCIDRs) > 0 {
			conditions = append(conditions, [2]string{"REMOTE_ADDR", "@ipMatch " + strings.Join(e.ClientCIDRs, ",")})
		}
		for j, cond := range conditions {
			actions := "t:none"
			if j == 0 {
				actions += fmt.Sprintf(",id:%d,phase:1,pass,nolog", 10000+i)
			}
			if j < len(conditions)-1 {
				actions += ",chain"
			} else {
				for _, id := range e.RuleIDs {
					actions += fmt.Sprintf(",ctl:ruleRemoveById=%d", id)
				}
			}
			fmt.Fprintf(&out, "SecRule %s \"%s\" \"%s\"\n", cond[0], cond[1], actions)
		}
	}
	return out.String()
}

func (e WAFException) validateSource() error {
	if e.SourceHeader == "" {
		if len(e.SourceURLs) != 0 || e.SourceMatch != "" {
			return errors.New("select Origin or Referer for a URL source condition")
		}
		return nil
	}
	if e.SourceHeader != "Origin" && e.SourceHeader != "Referer" {
		return errors.New("URL source header must be Origin or Referer")
	}
	if e.SourceMatch != "exact" && e.SourceMatch != "prefix" || e.SourceHeader == "Origin" && e.SourceMatch != "exact" {
		return errors.New("Origin requires exact matching; Referer supports exact or prefix matching")
	}
	if len(e.SourceURLs) < 1 || len(e.SourceURLs) > 16 {
		return errors.New("select 1–16 source URLs")
	}
	seen := map[string]bool{}
	for _, raw := range e.SourceURLs {
		u, err := url.Parse(raw)
		if err != nil || len(raw) > 500 || strings.ContainsAny(raw, "\"'\\%?#") || strings.ContainsFunc(raw, func(c rune) bool { return c <= 32 || c >= 127 }) || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") || !domainName.MatchString(u.Hostname()) || strings.Contains(u.Hostname(), "..") || u.Opaque != "" {
			return errors.New("source URLs must be HTTP(S) URLs with a DNS host, without credentials, query, fragment, escapes, or whitespace")
		}
		if strings.Contains(u.Host, ":") {
			port, err := net.LookupPort("tcp", u.Port())
			if err != nil || port < 1 || port > 65535 {
				return errors.New("invalid source URL port")
			}
		}
		if e.SourceHeader == "Origin" && u.Path != "" {
			return errors.New("Origin URLs contain only scheme and host, without a path")
		}
		if seen[raw] {
			return errors.New("source URLs must be unique")
		}
		seen[raw] = true
	}
	return nil
}

// Only the URL authority is case-insensitive. Referer paths remain literal and
// case-sensitive; the boundary prevents portal.example.com.evil and /edit-other.
func (e WAFException) sourcePattern() string {
	parts := make([]string, 0, len(e.SourceURLs))
	for _, raw := range e.SourceURLs {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		path := u.Path
		ending := "$"
		if e.SourceMatch == "prefix" {
			path = strings.TrimSuffix(path, "/")
			ending = "(?:[/?][^\\x00-\\x20\\x7f,#]*)?$"
		}
		parts = append(parts, "(?i:"+regexp.QuoteMeta(u.Scheme+"://"+u.Host)+")"+regexp.QuoteMeta(path)+ending)
	}
	return "^(?:" + strings.Join(parts, "|") + ")"
}

func (e WAFException) matchesSource(headers http.Header) bool {
	if e.SourceHeader == "" {
		return true
	}
	values := headers.Values(e.SourceHeader)
	if len(values) != 1 {
		return false
	}
	matched, err := regexp.MatchString(e.sourcePattern(), values[0])
	return err == nil && matched
}
