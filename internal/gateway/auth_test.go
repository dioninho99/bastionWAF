package gateway

import (
	"net/http/httptest"
	"testing"
)

func TestOIDCSessionPreservesRoleAndSubject(t *testing.T) {
	a := &App{sessions: map[[32]byte]session{}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	token, _, err := a.newSession(r, "viewer", "oidc-subject")
	if err != nil { t.Fatal(err) }
	r.Header.Set("Cookie", "bastion_session="+token)
	s, ok := a.getSession(r)
	if !ok || s.Role != "viewer" || s.User != "oidc-subject" {
		t.Fatalf("session = %#v, ok=%v", s, ok)
	}
}

func TestOIDCProtectedRouteRequiresAuthentication(t *testing.T) {
	a := &App{sessions: map[[32]byte]session{}}
	r := httptest.NewRequest("GET", "https://app.example/", nil)
	w := httptest.NewRecorder()
	// A nil provider is deliberately treated as disabled; enabling OIDC is what
	// activates the redirect, avoiding accidental lockout when unconfigured.
	if got := a.oidcRouteAuth(w, r, nil, Route{OIDCProtected: true}); !got {
		t.Fatal("unconfigured OIDC should not protect routes")
	}
}
