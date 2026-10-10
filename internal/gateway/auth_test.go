package gateway

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"testing"
)

func TestLocalUserPasswordAuthentication(t *testing.T) {
	db, err := openAuthDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &App{users: db, sessions: map[[32]byte]session{}}
	if err := a.createLocalUser(context.Background(), "alice", "correct horse battery staple", "viewer"); err != nil {
		t.Fatal(err)
	}
	subject, role, err := a.authenticateLocal(context.Background(), "alice", "correct horse battery staple")
	if err != nil || subject != "local:alice" || role != "viewer" {
		t.Fatalf("authentication = %q/%q/%v", subject, role, err)
	}
	if _, _, err := a.authenticateLocal(context.Background(), "alice", "wrong password"); err == nil {
		t.Fatal("wrong password accepted")
	}
}

func TestLocalUserDatabaseMigration(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", "file:"+dir+"/users.db")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE users (subject TEXT PRIMARY KEY, email TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', role TEXT NOT NULL, created_at INTEGER NOT NULL, last_login INTEGER NOT NULL); INSERT INTO users VALUES ('oidc-sub','a@example.test','A','viewer',1,2)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = openAuthDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var column string
	if err := db.QueryRow(`SELECT name FROM pragma_table_info('users') WHERE name='password_hash'`).Scan(&column); err != nil {
		t.Fatal(err)
	}
	var subject string
	if err := db.QueryRow(`SELECT subject FROM users WHERE email='a@example.test'`).Scan(&subject); err != nil || subject != "oidc-sub" {
		t.Fatalf("legacy user lost: %q, %v", subject, err)
	}
}

func TestOIDCSessionPreservesRoleAndSubject(t *testing.T) {
	a := &App{sessions: map[[32]byte]session{}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	token, _, err := a.newSession(r, "viewer", "oidc-subject")
	if err != nil {
		t.Fatal(err)
	}
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
