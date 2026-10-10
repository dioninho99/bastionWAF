package gateway

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type session struct {
	CSRF    string
	Created time.Time
	LastSeen time.Time
	Expires time.Time
	Client  string
	Role    string
	User    string
}

const sessionIdleTimeout = 30 * time.Minute

func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func apiError(w http.ResponseWriter, status int, message string) {
	jsonReply(w, status, map[string]string{"error": message})
}
func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return errors.New("invalid or oversized JSON request")
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return errors.New("only one JSON object is allowed")
	}
	return nil
}
func (a *App) getSession(r *http.Request) (session, bool) {
	c, e := r.Cookie("bastion_session")
	if e != nil {
		return session{}, false
	}
	key := sha256.Sum256([]byte(c.Value))
	a.authMu.Lock()
	defer a.authMu.Unlock()
	s, ok := a.sessions[key]
	now := time.Now()
	if !ok || now.After(s.Expires) || now.Sub(s.LastSeen) > sessionIdleTimeout {
		delete(a.sessions, key)
		return session{}, false
	}
	s.LastSeen = now
	a.sessions[key] = s
	return s, true
}
func (a *App) AdminHandler(assets http.Handler, allowedOrigin string, secureCookie bool) http.Handler {
	allowedOrigin = strings.TrimRight(strings.TrimSpace(allowedOrigin), "/")
	mux := http.NewServeMux()
	if a.oidc != nil && a.oidc.Admin {
		mux.HandleFunc("GET /oauth2/login", func(w http.ResponseWriter, r *http.Request) { a.oidcLogin(w, r, a.oidc, true) })
		mux.HandleFunc("GET /oauth2/callback", func(w http.ResponseWriter, r *http.Request) { a.oidcCallback(w, r, a.oidc, secureCookie) })
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { jsonReply(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		if !a.loginLimit.allow(clientIP(r), 10) {
			apiError(w, 429, "too many login attempts; try again in one minute")
			return
		}
		var body struct {
			Password string `json:"password"`
		}
		if e := readJSON(w, r, &body); e != nil {
			apiError(w, 400, e.Error())
			return
		}
		hash := sha256.Sum256([]byte(body.Password))
		if subtle.ConstantTimeCompare(hash[:], a.password[:]) != 1 {
			apiError(w, 401, "incorrect password")
			return
		}
		token, s, err := a.newSession(r, "admin", "password")
		if err != nil {
			apiError(w, 429, "too many active sessions")
			return
		}
		setSessionCookie(w, r, token, secureCookie)
		jsonReply(w, 200, map[string]string{"csrf": s.CSRF})
	})
	protected := func(fn http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			s, ok := a.getSession(r)
			if !ok {
				if a.oidc != nil && a.oidc.Admin { http.Redirect(w, r, "/oauth2/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound); return }
				apiError(w, 401, "please sign in")
				return
			}
			if r.Method != "GET" && r.Method != "HEAD" && s.Role != "admin" {
				apiError(w, 403, "administrator role required")
				return
			}
			if r.Method != "GET" && r.Method != "HEAD" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) != 1 {
				apiError(w, 403, "CSRF token is missing or invalid")
				return
			}
			fn(w, r)
		}
	}
	adminOnly := func(fn http.HandlerFunc) http.HandlerFunc {
		return protected(func(w http.ResponseWriter, r *http.Request) {
			s, _ := a.getSession(r)
			if s.Role != "admin" {
				apiError(w, http.StatusForbidden, "administrator role required")
				return
			}
			fn(w, r)
		})
	}
	mux.HandleFunc("GET /api/session", protected(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.getSession(r)
		jsonReply(w, 200, map[string]string{"csrf": s.CSRF})
	}))
	mux.HandleFunc("GET /api/users", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		users, err := a.listUsers(r.Context())
		if err != nil { apiError(w, http.StatusInternalServerError, "user database unavailable"); return }
		jsonReply(w, http.StatusOK, users)
	}))
	updateUserRole := func(w http.ResponseWriter, r *http.Request) {
		subject := r.PathValue("subject")
		var body struct { Role string `json:"role"` }
		if err := readJSON(w, r, &body); err != nil { apiError(w, http.StatusBadRequest, err.Error()); return }
		if subject == "" || body.Role == "" { apiError(w, http.StatusBadRequest, "subject and role are required"); return }
		if err := a.setUserRole(r.Context(), subject, body.Role); err != nil {
			if errors.Is(err, sql.ErrNoRows) { apiError(w, http.StatusNotFound, "user not found") } else { apiError(w, http.StatusBadRequest, err.Error()) }
			return
		}
		jsonReply(w, http.StatusOK, map[string]bool{"ok": true})
	}
	mux.HandleFunc("PATCH /api/users/{subject}/role", adminOnly(updateUserRole))
	mux.HandleFunc("PUT /api/users/{subject}/role", adminOnly(updateUserRole))
	mux.HandleFunc("DELETE /api/users/{subject}", adminOnly(func(w http.ResponseWriter, r *http.Request) {
		if err := a.deleteUser(r.Context(), r.PathValue("subject")); err != nil {
			if errors.Is(err, sql.ErrNoRows) { apiError(w, http.StatusNotFound, "user not found") } else { apiError(w, http.StatusBadRequest, err.Error()) }
			return
		}
		jsonReply(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/logout", protected(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("bastion_session")
		a.authMu.Lock()
		delete(a.sessions, sha256.Sum256([]byte(c.Value)))
		a.authMu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "bastion_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secureCookie || r.TLS != nil, SameSite: http.SameSiteStrictMode})
		jsonReply(w, 200, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("GET /api/sessions", protected(func(w http.ResponseWriter, r *http.Request) {
		type sessionInfo struct {
			Created  time.Time `json:"created"`
			LastSeen time.Time `json:"lastSeen"`
			Expires  time.Time `json:"expires"`
			Client   string    `json:"client"`
			Current  bool      `json:"current"`
		}
		c, _ := r.Cookie("bastion_session")
		current := sha256.Sum256([]byte(c.Value))
		a.authMu.Lock()
		defer a.authMu.Unlock()
		now := time.Now()
		result := make([]sessionInfo, 0, len(a.sessions))
		for key, s := range a.sessions {
			if now.After(s.Expires) || now.Sub(s.LastSeen) > sessionIdleTimeout {
				delete(a.sessions, key)
				continue
			}
			result = append(result, sessionInfo{Created: s.Created, LastSeen: s.LastSeen, Expires: s.Expires, Client: s.Client, Current: key == current})
		}
		jsonReply(w, 200, result)
	}))
	mux.HandleFunc("POST /api/sessions/revoke-all", protected(func(w http.ResponseWriter, r *http.Request) {
		a.authMu.Lock()
		a.sessions = map[[32]byte]session{}
		a.authMu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "bastion_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secureCookie || r.TLS != nil, SameSite: http.SameSiteStrictMode})
		jsonReply(w, 200, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("GET /api/config", protected(func(w http.ResponseWriter, r *http.Request) {
		c := a.Config()
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(c.Revision, 10)))
		jsonReply(w, 200, c)
	}))
	mux.HandleFunc("PUT /api/config", protected(func(w http.ResponseWriter, r *http.Request) {
		rev, e := strconv.ParseInt(strings.Trim(r.Header.Get("If-Match"), `"`), 10, 64)
		if e != nil {
			apiError(w, 428, "If-Match with the current revision is required")
			return
		}
		var c Config
		if e = readJSON(w, r, &c); e != nil {
			apiError(w, 400, e.Error())
			return
		}
		if e = a.Update(c, rev); e != nil {
			status := 400
			if errors.Is(e, errConflict) {
				status = 409
			}
			apiError(w, status, e.Error())
			return
		}
		slog.Info("configuration updated", "revision", rev+1, "client", clientIP(r))
		jsonReply(w, 200, a.Config())
	}))
	mux.HandleFunc("GET /api/status", protected(func(w http.ResponseWriter, r *http.Request) {
		stats := a.Events.stats()
		stats["uptimeSeconds"] = int64(time.Since(a.started).Seconds())
		stats["mode"] = a.Config().Mode
		stats["routes"] = len(a.state.Load().routes)
		stats["engine"] = "Coraza + OWASP CRS"
		stats["upstreamHealthIntervalSeconds"] = int64(a.healthInterval / time.Second)
		stats["upstreamAlerts"] = a.alertWebhook != ""
		jsonReply(w, 200, stats)
	}))
	mux.HandleFunc("GET /api/analytics", protected(func(w http.ResponseWriter, r *http.Request) {
		stats := a.Events.stats()
		jsonReply(w, 200, map[string]any{
			"generatedAt": time.Now().UTC(),
			"retention":   "last 1,000 events in memory; audit files rotate at 10 MiB",
			"routes":      stats["routeCounts"],
			"statuses":    stats["statusCounts"],
			"clients":     stats["clientCounts"],
			"series":      stats["series"],
		})
	}))
	mux.HandleFunc("GET /api/upstreams", protected(func(w http.ResponseWriter, r *http.Request) {
		type result struct {
			Route          string     `json:"route"`
			Target         string     `json:"target"`
			Healthy        bool       `json:"healthy"`
			FailureCount   int        `json:"failureCount"`
			UnhealthyUntil *time.Time `json:"unhealthyUntil,omitempty"`
			Status         int        `json:"status,omitempty"`
			Error          string     `json:"error,omitempty"`
			LastCheck      *time.Time `json:"lastCheck,omitempty"`
		}
		results := make([]result, 0)
		now := time.Now()
		for _, route := range a.state.Load().routes {
			for _, target := range route.targets {
				h := target.snapshot(now)
				item := result{Route: route.config.ID, Target: target.url.String(), Healthy: h.Healthy, FailureCount: h.FailureCount, Status: h.LastStatus, Error: h.LastError}
				if !h.UnhealthyUntil.IsZero() {
					item.UnhealthyUntil = &h.UnhealthyUntil
				}
				if !h.LastCheck.IsZero() {
					item.LastCheck = &h.LastCheck
				}
				results = append(results, item)
			}
		}
		jsonReply(w, 200, results)
	}))
	mux.HandleFunc("GET /api/upstreams/status", protected(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		results := make([]map[string]any, 0)
		for _, route := range a.state.Load().routes {
			for _, target := range route.targets {
				h := target.snapshot(now)
				results = append(results, map[string]any{
					"route": route.config.ID, "target": target.url.String(), "healthy": h.Healthy,
					"failureCount": h.FailureCount, "unhealthyUntil": h.UnhealthyUntil,
					"lastStatus": h.LastStatus, "lastError": h.LastError, "lastCheck": h.LastCheck,
				})
			}
		}
		jsonReply(w, 200, results)
	}))
	mux.HandleFunc("GET /api/events", protected(func(w http.ResponseWriter, r *http.Request) {
		events := a.Events.list()
		filtered := make([]Event, 0, len(events))
		q := strings.ToLower(r.URL.Query().Get("q"))
		action := r.URL.Query().Get("action")
		for _, e := range events {
			if action != "" && e.Action != action {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(e.Host+" "+e.Path+" "+e.Client+" "+e.Reason+" "+e.ID), q) {
				continue
			}
			filtered = append(filtered, e)
		}
		if r.URL.Query().Get("download") == "1" {
			w.Header().Set("Content-Disposition", `attachment; filename="bastion-events.json"`)
		}
		jsonReply(w, 200, filtered)
	}))
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		_, sessionOK := a.getSession(r)
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		hash := sha256.Sum256([]byte(token))
		tokenOK := a.metricsTokenSet && subtle.ConstantTimeCompare(hash[:], a.metricsToken[:]) == 1
		if !sessionOK && !tokenOK {
			apiError(w, 401, "authentication required")
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		io.WriteString(w, a.Events.metrics())
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { apiError(w, 404, "API endpoint not found") })
	mux.Handle("/", assets)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.Method != "GET" && r.Method != "HEAD" {
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				apiError(w, 403, "cross-site request rejected")
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				u, e := url.Parse(origin)
				scheme := "http"
				if r.TLS != nil {
					scheme = "https"
				}
				originAllowed := e == nil && u.Host == r.Host && u.Scheme == scheme
				if allowedOrigin != "" && origin == allowedOrigin {
					originAllowed = true
				}
				if !originAllowed {
					apiError(w, 403, "origin not allowed")
					return
				}
			}
		}
		mux.ServeHTTP(w, r)
	})
}
