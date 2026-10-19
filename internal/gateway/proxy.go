package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3/types"
)

func randomID() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String()
	}
	return host
}
func hostOnly(h string) string {
	if v, _, err := net.SplitHostPort(h); err == nil {
		h = v
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}
func pathMatches(path, prefix string) bool {
	return prefix == "/" || path == prefix || strings.HasPrefix(path, strings.TrimSuffix(prefix, "/")+"/")
}
func deny(w http.ResponseWriter, status int, id string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	io.WriteString(w, http.StatusText(status)+"\nRequest ID: "+id+"\n")
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.oidc != nil && a.oidc.Proxy && r.URL.Path == "/oauth2/callback" {
		a.oidcCallback(w, r, a.oidc, os.Getenv("BASTION_ADMIN_SECURE_COOKIE") == "true")
		return
	}
	start := time.Now()
	cause := ""
	defer func() { a.runtimeMetrics.observe(time.Since(start), cause) }()
	s := a.state.Load()
	c := s.config
	ev := Event{ID: randomID(), Time: start, Client: proxyClientIP(r, c.TrustedProxyCIDRs), Host: hostOnly(r.Host), Method: r.Method, Path: r.URL.EscapedPath(), Status: 200, Action: "allowed", RuleIDs: []int{}}
	if len(ev.Path) > 512 {
		ev.Path = ev.Path[:512]
	}
	w.Header().Set("X-Request-ID", ev.ID)
	defer func() { ev.Duration = float64(time.Since(start).Microseconds()) / 1000; a.Events.add(ev) }()
	block := func(code int, reason string) {
		ev.Status = code
		ev.Action = "blocked"
		ev.Reason = reason
		deny(w, code, ev.ID)
	}
	requestSlot := false
	defer func() {
		if requestSlot {
			<-a.slots
		}
	}()
	select {
	case a.slots <- struct{}{}:
		requestSlot = true
	default:
		cause = "request_capacity"
		block(503, "capacity limit reached")
		return
	}
	// Absolute-form requests and CONNECT are never accepted: this is not a forward proxy.
	if r.URL.IsAbs() || r.Method == http.MethodConnect {
		block(400, "invalid proxy request")
		return
	}
	var route *routeRuntime
	for _, rt := range s.routes {
		if rt.config.Host == ev.Host && pathMatches(r.URL.Path, rt.config.Path) {
			route = rt
			break
		}
	}
	if route == nil {
		block(404, "no matching route")
		return
	}
	ev.Route = route.config.Name
	ev.RouteID = route.config.ID
	ip, err := netip.ParseAddr(ev.Client)
	if err != nil {
		block(400, "invalid client IP")
		return
	}
	internal := prefixesContain(s.internal, ip)
	if a.country == nil && needsCountry(&s.access, &route.access, ip, internal) {
		cause = "geoip"
		block(503, "GeoIP database unavailable")
		return
	}
	if !internal && a.country != nil {
		var lookupErr error
		ev.Country, lookupErr = a.country(ip)
		if lookupErr != nil && needsCountry(&s.access, &route.access, ip, internal) {
			cause = "geoip"
			block(503, "GeoIP lookup failed")
			return
		}
	}
	if reason := checkAccess(&s.access, &route.access, ip, internal, ev.Country); reason != "" {
		block(403, reason)
		return
	}
	if !a.oidcRouteAuth(w, r, a.oidc, route.config) {
		return
	}
	for _, method := range route.config.AllowedMethods {
		if r.Method == method {
			goto methodAllowed
		}
	}
	if len(route.config.AllowedMethods) > 0 {
		w.Header().Set("Allow", strings.Join(route.config.AllowedMethods, ", "))
		block(405, "method is not allowed for route")
		return
	}
methodAllowed:
	for _, pattern := range route.config.BotDenyPatterns {
		matched, _ := regexp.MatchString("(?i:"+pattern+")", r.UserAgent())
		if matched {
			block(403, "bot user-agent denied by route policy")
			return
		}
	}
	if !a.requestLimit.allow(route.config.ID+":"+ev.Client, route.rateLimit) {
		w.Header().Set("Retry-After", "60")
		block(429, "route rate limit exceeded")
		return
	}
	if r.ContentLength > route.maxBodyBytes {
		block(413, "request body is too large")
		return
	}
	bodyMethod := r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch
	if bodyMethod && (r.ContentLength != 0 || len(r.TransferEncoding) > 0 || r.Header.Get("Transfer-Encoding") != "") {
		contentType := r.Header.Get("Content-Type")
		mediaType, _, parseErr := mime.ParseMediaType(contentType)
		if route.config.RequireContentType && parseErr != nil {
			block(415, "a valid content type is required")
			return
		}
		if len(route.config.AllowedContentTypes) > 0 {
			allowed := false
			for _, candidate := range route.config.AllowedContentTypes {
				if strings.EqualFold(mediaType, candidate) {
					allowed = true
					break
				}
			}
			if !allowed {
				block(415, "content type is not allowed for this route")
				return
			}
		}
	}
	reservation := &inspectionReservation{app: a}
	defer reservation.release()
	if enc := r.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		block(415, "compressed request bodies are not supported")
		return
	}
	tx := route.waf.NewTransaction()
	for _, exception := range c.Exceptions {
		if exception.appliesTo(route.config.ID) && exception.matches(r.URL.Path, r.Method, ip, r.Header) {
			ev.ExceptionIDs = append(ev.ExceptionIDs, exception.ID)
		}
	}

	finishedInspection := false
	finishInspection := func() {
		if finishedInspection {
			return
		}
		finishedInspection = true
		defer func() { tx.Close(); tx = nil }()
		tx.ProcessLogging()
		seen := map[int]bool{}
		for _, m := range tx.MatchedRules() {
			id := m.Rule().ID()
			// Paranoia skip/flow-control rules also "match" but have no message.
			// They must not turn every normal request into a detected attack.
			if id >= 910000 && id < 960000 && m.Message() != "" && !seen[id] {
				seen[id] = true
				ev.RuleIDs = append(ev.RuleIDs, id)
			}
		}
		if len(ev.RuleIDs) > 0 && ev.Action == "allowed" {
			ev.Action = "detected"
			ev.Reason = "OWASP CRS match"
		}
	}
	defer finishInspection()
	_, port, _ := net.SplitHostPort(r.RemoteAddr)
	p, _ := strconv.Atoi(port)
	tx.ProcessConnection(ev.Client, p, "", 0)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	tx.SetServerName(ev.Host)
	tx.AddRequestHeader("Host", r.Host)
	for k, values := range r.Header {
		for _, v := range values {
			tx.AddRequestHeader(k, v)
		}
	}
	for _, v := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", v)
	}
	interrupted := func(it *types.Interruption) bool {
		if it == nil {
			return false
		}
		status := it.Status
		if status < 400 || status > 599 {
			status = 403
		}
		block(status, "OWASP Core Rule Set")
		return true
	}
	if interrupted(tx.ProcessRequestHeaders()) {
		return
	}
	body, err := reservation.readBody(r.Body, route.maxBodyBytes)
	if err != nil {
		if errors.Is(err, errInspectionCapacity) {
			cause = "inspection_capacity"
			block(503, err.Error())
			return
		}
		if errors.Is(err, errBodyTooLarge) {
			block(413, err.Error())
			return
		}
		cause = "request_body"
		block(400, "request body could not be read")
		return
	}
	if int64(len(body)) > route.maxBodyBytes {
		block(413, "request body is too large")
		return
	}
	headers := strings.Builder{}
	for name, values := range r.Header {
		headers.WriteString(name)
		headers.WriteByte(':')
		headers.WriteString(strings.Join(values, ","))
		headers.WriteByte('\n')
	}
	customValues := map[string]string{
		"path":       r.URL.Path,
		"query":      r.URL.RawQuery,
		"header":     headers.String(),
		"user-agent": r.UserAgent(),
		"method":     r.Method,
		"body":       string(body),
	}
	for _, rule := range c.Rules {
		if !rule.Enabled {
			continue
		}
		value := customValues[rule.Field]
		if strings.Contains(strings.ToLower(value), strings.ToLower(rule.Value)) {
			ev.Reason = "custom rule: " + rule.Name
			if rule.Action == "block" && route.mode == "blocking" {
				block(403, ev.Reason)
				return
			}
			ev.Action = "detected"
		}
	}
	if len(body) > 0 {
		it, _, e := tx.WriteRequestBody(body)
		if e != nil {
			block(400, "WAF could not inspect request body")
			return
		}
		if interrupted(it) {
			return
		}
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		block(400, "invalid request body")
		return
	}
	if interrupted(it) {
		return
	}
	r.Body = &inspectionBody{reader: bytes.NewReader(body)}
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	target := route.selectTarget(time.Now())
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
	}
	upgraded := false
	defer func() {
		if upgraded {
			<-a.upgradeSlots
		}
	}()
	proxy := &httputil.ReverseProxy{
		Transport: a.transport, FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target.url)
			if route.config.PreserveHost {
				pr.Out.Host = pr.In.Host
			}
			pr.Out.Header.Del("X-Real-IP")
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")
			pr.Out.Header.Del("X-Authenticated-User")
			pr.Out.Header.Del("X-Authenticated-Role")
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Forwarded-For", ev.Client)
			pr.Out.Header.Set("X-Real-IP", ev.Client)
			pr.Out.Header.Set("X-Request-ID", ev.ID)
			if identity, ok := a.getSession(r); ok && identity.User != "" {
				pr.Out.Header.Set("X-Authenticated-User", identity.User)
				pr.Out.Header.Set("X-Authenticated-Role", identity.Role)
			}
			// Request identity encoding when response inspection is active.
			if c.ResponseInspection {
				pr.Out.Header.Set("Accept-Encoding", "identity")
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			cause = "response_inspection"
			for k, vs := range resp.Header {
				for _, v := range vs {
					tx.AddResponseHeader(k, v)
				}
			}
			reject := func(it *types.Interruption) error {
				if it == nil {
					return nil
				}
				ev.Action = "blocked"
				ev.Reason = "OWASP response rule"
				return errResponseBlocked
			}
			if err := reject(tx.ProcessResponseHeaders(resp.StatusCode, resp.Proto)); err != nil {
				return err
			}
			if c.ResponseInspection && resp.StatusCode != 101 && tx.IsResponseBodyProcessable() {
				if enc := resp.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
					return errors.New("encoded upstream response cannot be inspected")
				}
				data, e := reservation.readBody(resp.Body, 1<<20)
				resp.Body.Close()
				if errors.Is(e, errInspectionCapacity) {
					cause = "inspection_capacity"
					return e
				}
				if errors.Is(e, errBodyTooLarge) {
					return errors.New("response inspection limit exceeded")
				}
				if e != nil {
					return e
				}
				it, _, e := tx.WriteResponseBody(data)
				if e != nil {
					return e
				}
				if e = reject(it); e != nil {
					return e
				}
				resp.Body = io.NopCloser(bytes.NewReader(data))
				resp.ContentLength = int64(len(data))
				resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
				resp.TransferEncoding = nil
			}
			if resp.StatusCode != 101 {
				it, e := tx.ProcessResponseBody()
				if e != nil {
					return e
				}
				if e = reject(it); e != nil {
					return e
				}
			}
			resp.Header.Del("Server")
			resp.Header.Set("X-Request-ID", ev.ID)
			resp.Header.Set("X-Content-Type-Options", "nosniff")
			if route.config.SecurityHeaders {
				resp.Header.Set("Referrer-Policy", "no-referrer")
				resp.Header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
				resp.Header.Set("Content-Security-Policy", "frame-ancestors 'none'")
				if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
					resp.Header.Set("Strict-Transport-Security", "max-age=31536000")
				}
			}
			cause = ""
			if resp.StatusCode == http.StatusSwitchingProtocols {
				select {
				case a.upgradeSlots <- struct{}{}:
					upgraded = true
				default:
					cause = "upgrade_capacity"
					return errUpgradeCapacity
				}
				finishInspection()
				body = nil
				customValues = nil
				r.Body.Close()
				reservation.release()
				<-a.slots
				requestSlot = false
			}
			ev.Status = resp.StatusCode
			now := time.Now()
			if upstreamFailureStatus(resp.StatusCode) {
				cause = "upstream_status"
				target.markFailure(resp.StatusCode, http.StatusText(resp.StatusCode), now)
			} else {
				target.markSuccess(resp.StatusCode, now)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
			ev.Status = 502
			if errors.Is(e, errInspectionCapacity) || errors.Is(e, errUpgradeCapacity) {
				ev.Status = 503
				ev.Action = "blocked"
				ev.Reason = e.Error()
			} else if errors.Is(e, errResponseBlocked) {
				cause = ""
				ev.Status = 403
			} else {
				ev.Action = "error"
				ev.Reason = "upstream unreachable or response cannot be inspected"
				if cause == "" {
					cause = "upstream_transport"
					target.markFailure(0, e.Error(), time.Now())
				}
			}
			deny(w, ev.Status, ev.ID)
		},
	}
	proxy.ServeHTTP(w, r)
}

var errResponseBlocked = errors.New("response blocked by WAF")
