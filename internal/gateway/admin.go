package gateway

import (
	"crypto/sha256"
	"crypto/subtle"
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
	Expires time.Time
}

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
	if !ok || time.Now().After(s.Expires) {
		delete(a.sessions, key)
		return session{}, false
	}
	return s, true
}
func (a *App) AdminHandler(assets http.Handler) http.Handler {
	mux := http.NewServeMux()
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
		token := randomID()
		s := session{CSRF: randomID(), Expires: time.Now().Add(8 * time.Hour)}
		a.authMu.Lock()
		for k, v := range a.sessions {
			if time.Now().After(v.Expires) {
				delete(a.sessions, k)
			}
		}
		if len(a.sessions) >= 100 {
			a.authMu.Unlock()
			apiError(w, 429, "too many active sessions")
			return
		}
		a.sessions[sha256.Sum256([]byte(token))] = s
		a.authMu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "bastion_session", Value: token, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600})
		jsonReply(w, 200, map[string]string{"csrf": s.CSRF})
	})
	protected := func(fn http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			s, ok := a.getSession(r)
			if !ok {
				apiError(w, 401, "please sign in")
				return
			}
			if r.Method != "GET" && r.Method != "HEAD" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) != 1 {
				apiError(w, 403, "CSRF token is missing or invalid")
				return
			}
			fn(w, r)
		}
	}
	mux.HandleFunc("GET /api/session", protected(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.getSession(r)
		jsonReply(w, 200, map[string]string{"csrf": s.CSRF})
	}))
	mux.HandleFunc("POST /api/logout", protected(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("bastion_session")
		a.authMu.Lock()
		delete(a.sessions, sha256.Sum256([]byte(c.Value)))
		a.authMu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "bastion_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
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
		jsonReply(w, 200, stats)
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
		if !sessionOK && subtle.ConstantTimeCompare(hash[:], a.password[:]) != 1 {
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
				if e != nil || u.Host != r.Host || u.Scheme != scheme {
					apiError(w, 403, "origin not allowed")
					return
				}
			}
		}
		mux.ServeHTTP(w, r)
	})
}
