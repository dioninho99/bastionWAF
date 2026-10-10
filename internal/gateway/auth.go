package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	_ "modernc.org/sqlite"
)

type oidcConfig struct {
	Provider *oidc.Provider
	Verifier *oidc.IDTokenVerifier
	OAuth    oauth2.Config
	Admin    bool
	Proxy    bool
	RoleClaim string
}

type oidcPending struct {
	Nonce string
	Next  string
	Admin bool
	Expires time.Time
}

type authUser struct {
	Subject   string    `json:"subject"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"createdAt"`
	LastLogin time.Time `json:"lastLogin"`
}

func openAuthDB(dir string) (*sql.DB, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "users.db")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil { return nil, err }
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		subject TEXT PRIMARY KEY, email TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '',
		role TEXT NOT NULL CHECK(role IN ('admin','viewer')), created_at INTEGER NOT NULL,
		last_login INTEGER NOT NULL
	)`); err != nil { db.Close(); return nil, err }
	return db, nil
}

func setupOIDC(ctx context.Context, issuer, clientID, secret, redirect string, admin, proxy bool) (*oidcConfig, error) {
	if issuer == "" { return nil, nil }
	if clientID == "" || redirect == "" { return nil, errors.New("OIDC client ID and redirect URI are required") }
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil { return nil, fmt.Errorf("OIDC discovery: %w", err) }
	return &oidcConfig{Provider: p, Verifier: p.Verifier(&oidc.Config{ClientID: clientID}),
		OAuth: oauth2.Config{ClientID: clientID, ClientSecret: secret, Endpoint: p.Endpoint(),
			RedirectURL: redirect, Scopes: []string{oidc.ScopeOpenID, "profile", "email"}},
		Admin: admin, Proxy: proxy, RoleClaim: envOr("BASTION_OIDC_ROLE_CLAIM", "role")}, nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" { return value }
	return fallback
}

func (a *App) upsertOIDCUser(ctx context.Context, subject, email, name, role string) (string, error) {
	if role != "admin" && role != "viewer" { role = envOr("BASTION_OIDC_DEFAULT_ROLE", "viewer") }
	if role != "admin" && role != "viewer" { role = "viewer" }
	_, err := a.users.ExecContext(ctx, `INSERT INTO users(subject,email,name,role,created_at,last_login)
		VALUES(?,?,?,?,?,?) ON CONFLICT(subject) DO UPDATE SET email=excluded.email,name=excluded.name,last_login=excluded.last_login`,
		subject, email, name, role, time.Now().Unix(), time.Now().Unix())
	if err != nil {
		return "", err
	}
	var storedRole string
	if err := a.users.QueryRowContext(ctx, `SELECT role FROM users WHERE subject=?`, subject).Scan(&storedRole); err != nil {
		return "", err
	}
	return storedRole, nil
}

func (a *App) listUsers(ctx context.Context) ([]authUser, error) {
	rows, err := a.users.QueryContext(ctx, `SELECT subject,email,name,role,created_at,last_login FROM users ORDER BY name,subject`)
	if err != nil { return nil, err }
	defer rows.Close()
	users := []authUser{}
	for rows.Next() {
		var u authUser
		var created, login int64
		if err := rows.Scan(&u.Subject, &u.Email, &u.Name, &u.Role, &created, &login); err != nil { return nil, err }
		u.CreatedAt, u.LastLogin = time.Unix(created, 0).UTC(), time.Unix(login, 0).UTC()
		users = append(users, u)
	}
	return users, rows.Err()
}

func validSubject(subject string) bool {
	return len(subject) > 0 && len(subject) <= 512 && !strings.ContainsAny(subject, "\r\n")
}

func (a *App) setUserRole(ctx context.Context, subject, role string) error {
	if !validSubject(subject) || (role != "admin" && role != "viewer") {
		return errors.New("subject and role are invalid")
	}
	if role != "admin" {
		var currentRole string
		if err := a.users.QueryRowContext(ctx, `SELECT role FROM users WHERE subject=?`, subject).Scan(&currentRole); err != nil { return err }
		if currentRole == "admin" {
			var admins int
			if err := a.users.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&admins); err != nil { return err }
			if admins <= 1 { return errors.New("at least one administrator is required") }
		}
	}
	result, err := a.users.ExecContext(ctx, `UPDATE users SET role=? WHERE subject=?`, role, subject)
	if err != nil { return err }
	count, err := result.RowsAffected()
	if err != nil { return err }
	if count == 0 { return sql.ErrNoRows }
	a.authMu.Lock()
	for key, session := range a.sessions {
		if session.User == subject {
			if role == "viewer" { session.Role = role; a.sessions[key] = session } else { session.Role = role; a.sessions[key] = session }
		}
	}
	a.authMu.Unlock()
	return nil
}

func (a *App) deleteUser(ctx context.Context, subject string) error {
	if !validSubject(subject) { return errors.New("subject is invalid") }
	var role string
	if err := a.users.QueryRowContext(ctx, `SELECT role FROM users WHERE subject=?`, subject).Scan(&role); err != nil { return err }
	if role == "admin" {
		var admins int
		if err := a.users.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&admins); err != nil { return err }
		if admins <= 1 { return errors.New("at least one administrator is required") }
	}
	result, err := a.users.ExecContext(ctx, `DELETE FROM users WHERE subject=?`, subject)
	if err != nil { return err }
	count, err := result.RowsAffected()
	if err != nil { return err }
	if count == 0 { return sql.ErrNoRows }
	a.authMu.Lock()
	for key, s := range a.sessions {
		if s.User == subject { delete(a.sessions, key) }
	}
	a.authMu.Unlock()
	return nil
}

func (a *App) newSession(r *http.Request, role, user string) (string, session, error) {
	token := randomID(); now := time.Now()
	s := session{CSRF: randomID(), Created: now, LastSeen: now, Expires: now.Add(8*time.Hour), Client: clientIP(r), Role: role, User: user}
	a.authMu.Lock(); defer a.authMu.Unlock()
	for k, v := range a.sessions { if time.Now().After(v.Expires) { delete(a.sessions, k) } }
	if len(a.sessions) >= 100 { return "", session{}, errors.New("too many active sessions") }
	a.sessions[sha256.Sum256([]byte(token))] = s
	return token, s, nil
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{Name:"bastion_session", Value:token, Path:"/", HttpOnly:true, Secure:secure || r.TLS != nil, SameSite:http.SameSiteLaxMode, MaxAge:8*3600})
}

func (a *App) oidcLogin(w http.ResponseWriter, r *http.Request, cfg *oidcConfig, admin bool) {
	state, nonce := randomID(), randomID()
	a.authMu.Lock()
	if a.oidcPending == nil { a.oidcPending = map[[32]byte]oidcPending{} }
	a.oidcPending[sha256.Sum256([]byte(state))] = oidcPending{Nonce:nonce, Next:r.URL.Query().Get("next"), Admin:admin, Expires:time.Now().Add(10*time.Minute)}
	a.authMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name:"bastion_oidc_state", Value:state, Path:"/", HttpOnly:true, Secure:r.TLS != nil, SameSite:http.SameSiteLaxMode, MaxAge:600})
	http.Redirect(w, r, cfg.OAuth.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

func (a *App) oidcCallback(w http.ResponseWriter, r *http.Request, cfg *oidcConfig, secure bool) {
	state := r.URL.Query().Get("state"); cookie, err := r.Cookie("bastion_oidc_state")
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(cookie.Value)) != 1 { http.Error(w, "invalid OIDC state", 400); return }
	a.authMu.Lock(); pending, ok := a.oidcPending[sha256.Sum256([]byte(state))]; delete(a.oidcPending, sha256.Sum256([]byte(state))); a.authMu.Unlock()
	if !ok || time.Now().After(pending.Expires) { http.Error(w, "expired OIDC state", 400); return }
	token, err := cfg.OAuth.Exchange(r.Context(), r.URL.Query().Get("code")); if err != nil { http.Error(w, "OIDC exchange failed", 401); return }
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" { http.Error(w, "missing ID token", 401); return }
	raw, err := cfg.Verifier.Verify(r.Context(), rawIDToken); if err != nil { http.Error(w, "invalid ID token", 401); return }
	var claims map[string]any
	if err = raw.Claims(&claims); err != nil { http.Error(w, "invalid OIDC claims", 401); return }
	stringClaim := func(name string) string { value, _ := claims[name].(string); return value }
	subject, email, name, nonce := stringClaim("sub"), stringClaim("email"), stringClaim("name"), stringClaim("nonce")
	if subject == "" || nonce != pending.Nonce { http.Error(w, "invalid OIDC claims", 401); return }
	role := stringClaim(cfg.RoleClaim)
	role, err = a.upsertOIDCUser(r.Context(), subject, email, name, role); if err != nil { http.Error(w, "user database unavailable", 500); return }
	if pending.Admin && role != "admin" { http.Error(w, "administrator role required", 403); return }
	sessionToken, _, err := a.newSession(r, role, subject); if err != nil { http.Error(w, err.Error(), 429); return }
	setSessionCookie(w, r, sessionToken, secure)
	next := pending.Next; if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") { next = "/" }
	http.Redirect(w, r, next, http.StatusFound)
}

func (a *App) oidcRouteAuth(w http.ResponseWriter, r *http.Request, cfg *oidcConfig, route Route) bool {
	if !route.OIDCProtected || cfg == nil || !cfg.Proxy { return true }
	if s, ok := a.getSession(r); ok && s.User != "" { return true }
	next := r.URL.RequestURI()
	clone := r.Clone(r.Context())
	clone.URL = clone.URL.Clone()
	query := clone.URL.Query()
	query.Set("next", next)
	clone.URL.RawQuery = query.Encode()
	a.oidcLogin(w, clone, cfg, false); return false
}
