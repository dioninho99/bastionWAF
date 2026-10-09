package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
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
func inCIDRs(ip netip.Addr, list []string) bool {
	for _, s := range list {
		p, _ := netip.ParsePrefix(s)
		if p.Contains(ip) {
			return true
		}
	}
	return false
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
	start := time.Now()
	s := a.state.Load()
	c := s.config
	ev := Event{ID: randomID(), Time: start, Client: clientIP(r), Host: hostOnly(r.Host), Method: r.Method, Path: r.URL.EscapedPath(), Status: 200, Action: "allowed", RuleIDs: []int{}}
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
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		block(503, "Kapazitätslimit")
		return
	}
	// Absolute-form requests and CONNECT are never accepted: this is not a forward proxy.
	if r.URL.IsAbs() || r.Method == http.MethodConnect {
		block(400, "Ungültige Proxy-Anfrage")
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
		block(404, "Keine passende Route")
		return
	}
	ev.Route = route.config.Name
	ip, err := netip.ParseAddr(ev.Client)
	if err != nil {
		block(400, "Ungültige Client-IP")
		return
	}
	if inCIDRs(ip, c.DenyCIDRs) {
		block(403, "IP-Sperrliste")
		return
	}
	if len(c.AllowCIDRs) > 0 && !inCIDRs(ip, c.AllowCIDRs) {
		block(403, "IP außerhalb der Zugriffsliste")
		return
	}
	if !a.requestLimit.allow(route.config.ID+":"+ev.Client, c.RateLimit) {
		w.Header().Set("Retry-After", "60")
		block(429, "Rate Limit")
		return
	}
	if r.ContentLength > c.MaxBodyBytes {
		block(413, "Request-Body zu groß")
		return
	}
	// Reserve conservatively for Go's growing read buffer, Coraza's copy, and response buffering.
	// This bounds payload allocations even when an admin raises the per-request body limit.
	reservation := c.MaxBodyBytes*4 + (4 << 20)
	if !a.bodyMemory.TryAcquire(reservation) {
		block(503, "Prüfspeicher ausgelastet")
		return
	}
	defer a.bodyMemory.Release(reservation)
	if enc := r.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		block(415, "Komprimierte Request-Bodies nicht unterstützt")
		return
	}
	for _, rule := range c.Rules {
		if !rule.Enabled {
			continue
		}
		value := r.URL.Path
		switch rule.Field {
		case "user-agent":
			value = r.UserAgent()
		case "method":
			value = r.Method
		}
		if strings.Contains(strings.ToLower(value), strings.ToLower(rule.Value)) {
			ev.Reason = "Eigene Regel: " + rule.Name
			if rule.Action == "block" && c.Mode == "blocking" {
				block(403, ev.Reason)
				return
			}
			ev.Action = "detected"
		}
	}
	tx := route.waf.NewTransaction()
	defer tx.Close()
	defer func() {
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
			ev.Reason = "OWASP CRS-Treffer"
		}
	}()
	host, port, _ := net.SplitHostPort(r.RemoteAddr)
	p, _ := strconv.Atoi(port)
	tx.ProcessConnection(host, p, "", 0)
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
	body, err := io.ReadAll(io.LimitReader(r.Body, c.MaxBodyBytes+1))
	if err != nil {
		block(400, "Request-Body konnte nicht gelesen werden")
		return
	}
	if int64(len(body)) > c.MaxBodyBytes {
		block(413, "Request-Body zu groß")
		return
	}
	if len(body) > 0 {
		it, _, e := tx.WriteRequestBody(body)
		if e != nil {
			block(400, "WAF konnte Request-Body nicht prüfen")
			return
		}
		if interrupted(it) {
			return
		}
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		block(400, "Ungültiger Request-Body")
		return
	}
	if interrupted(it) {
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	target := route.targets[(route.next.Add(1)-1)%uint64(len(route.targets))]
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
	}
	proxy := &httputil.ReverseProxy{
		Transport: a.transport, FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			if route.config.PreserveHost {
				pr.Out.Host = pr.In.Host
			}
			pr.Out.Header.Del("X-Real-IP")
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Real-IP", ev.Client)
			pr.Out.Header.Set("X-Request-ID", ev.ID)
			// Request identity encoding when response inspection is active.
			if c.ResponseInspection {
				pr.Out.Header.Set("Accept-Encoding", "identity")
			}
		},
		ModifyResponse: func(resp *http.Response) error {
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
				ev.Reason = "OWASP Response-Regel"
				return errResponseBlocked
			}
			if err := reject(tx.ProcessResponseHeaders(resp.StatusCode, resp.Proto)); err != nil {
				return err
			}
			if c.ResponseInspection && resp.StatusCode != 101 && tx.IsResponseBodyProcessable() {
				if enc := resp.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
					return errors.New("encoded upstream response cannot be inspected")
				}
				data, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
				resp.Body.Close()
				if e != nil {
					return e
				}
				if len(data) > 1<<20 {
					return errors.New("response inspection limit exceeded")
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
			ev.Status = resp.StatusCode
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
			ev.Status = 502
			if errors.Is(e, errResponseBlocked) {
				ev.Status = 403
			} else {
				ev.Action = "error"
				ev.Reason = "Upstream nicht erreichbar oder Antwort nicht prüfbar"
			}
			deny(w, ev.Status, ev.ID)
		},
	}
	proxy.ServeHTTP(w, r)
}

var errResponseBlocked = errors.New("response blocked by WAF")
