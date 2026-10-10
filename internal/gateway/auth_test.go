package gateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateCertificatePair(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.test"}, DNSNames: []string{"example.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if cert, err := validateCertificate(certPEM, keyPEM); err != nil || cert.Subject.CommonName != "example.test" {
		t.Fatalf("certificate validation: %v", err)
	}
	db, err := openAuthDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &App{users: db, dataDir: t.TempDir()}
	if err := a.storeCertificate(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := a.saveTLSSettings("manual", "old@example.test", "cloudflare", nil, ""); err != nil {
		t.Fatal(err)
	}
	c, err := a.LoadTLSConfiguration()
	if err != nil || c.Email != "" || c.DNSProvider != "" || c.CertificateFile == "" {
		t.Fatalf("manual switch retained ACME settings: %+v, %v", c, err)
	}

}

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

func TestLoadTLSConfigurationUsesPersistedManualCertificate(t *testing.T) {
	dir := t.TempDir()
	db, err := openAuthDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO tls_settings(id,mode,domains) VALUES(1,'manual','example.test')`); err != nil {
		t.Fatal(err)
	}
	a := &App{users: db, dataDir: dir}
	if err := os.MkdirAll(filepath.Join(dir, "certificates"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "certificates", "cert.pem"), []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := a.LoadTLSConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	if !config.Persisted || config.Mode != "manual" || config.CertificateFile != filepath.Join(dir, "certificates", "cert.pem") {
		t.Fatalf("unexpected persisted TLS configuration: %#v", config)
	}
}

func TestTLSSettingsValidationAndEnvironmentFallback(t *testing.T) {
	db, err := openAuthDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &App{users: db, dataDir: t.TempDir()}
	t.Setenv("BASTION_ACME_EMAIL", "admin@example.test")
	t.Setenv("BASTION_ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("BASTION_ACME_DOMAINS", "example.test")
	t.Setenv("BASTION_ACME_DNS_API_TOKEN", "secret-token")
	settings, err := a.tlsSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings["mode"] != "dns01" || settings["email"] != "admin@example.test" || settings["dnsTokenConfigured"] != true {
		t.Fatalf("environment settings missing: %v", settings)
	}
	for _, tc := range []struct {
		mode, email, provider string
		domains               []string
	}{
		{"dns01", "", "cloudflare", []string{"example.test"}},
		{"dns01", "admin@example.test", "cloudflare", nil},
		{"dns01", "admin@example.test", "", []string{"example.test"}},
		{"http01", "", "", nil},
		{"manual", "", "", nil},
	} {
		if err := a.saveTLSSettings(tc.mode, tc.email, tc.provider, tc.domains, ""); err == nil {
			t.Errorf("accepted invalid settings: %+v", tc)
		}
	}
	if err := a.saveTLSSettings("dns01", "admin@example.test", "cloudflare", []string{"example.test"}, ""); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BASTION_ACME_DNS_API_TOKEN", "")
	c, err := a.LoadTLSConfiguration()
	if err != nil || c.DNSToken != "secret-token" {
		t.Fatal("environment token was not persisted")
	}
	if err := a.saveTLSSettings("http01", "admin@example.test", "cloudflare", nil, ""); err != nil {
		t.Fatal(err)
	}
	c, err = a.LoadTLSConfiguration()
	if err != nil || c.DNSProvider != "" {
		t.Fatal("HTTP-01 retained DNS provider")
	}
}

func TestOIDCSettingsRejectIncompleteConfiguration(t *testing.T) {
	db, err := openAuthDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &App{users: db}
	for _, s := range []oidcSettings{
		{AdminEnabled: true},
		{Issuer: "https://issuer.example.test"},
		{Issuer: "invalid", ClientID: "client", RedirectURI: "https://example.test/callback"},
	} {
		if err := a.saveOIDCSettings(context.Background(), s); err == nil {
			t.Errorf("accepted incomplete OIDC settings: %+v", s)
		}
	}
	if err := a.saveOIDCSettings(context.Background(), oidcSettings{}); err != nil {
		t.Fatal(err)
	}
}
