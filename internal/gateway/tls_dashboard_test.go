package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"golang.org/x/crypto/acme/autocert"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func dashboardPair(t *testing.T, from, to time.Time) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.test"}, DNSNames: []string{"example.test"}, NotBefore: from, NotAfter: to}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
func TestTLSMonitorValidityAndSnapshotIsolation(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name     string
		from, to time.Time
		want     string
	}{
		{"valid", now.Add(-time.Hour), now.Add(90 * 24 * time.Hour), "valid"},
		{"soon", now.Add(-time.Hour), now.Add(time.Hour), "expiring soon"},
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour), "expired"},
		{"future", now.Add(time.Hour), now.Add(90 * 24 * time.Hour), "not yet valid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewTLSMonitor("manual", true)
			m.Observe("example.test", dashboardPair(t, tc.from, tc.to), nil)
			s := m.Snapshot()
			if len(s.Certificates) != 1 || s.Certificates[0].State != tc.want {
				t.Fatalf("unexpected snapshot: %+v", s)
			}
			if s.CanRenew || s.Certificates[0].Fingerprint == "" {
				t.Fatal("invalid metadata")
			}
			s.Certificates[0].DNSNames[0] = "mutated"
			if m.Snapshot().Certificates[0].DNSNames[0] != "example.test" {
				t.Fatal("snapshot aliases internal state")
			}
		})
	}
}

func TestCertificateRenewalRequiresAdminCSRFAndAppliedSettings(t *testing.T) {
	a, _, _ := testApp(t)
	monitor := NewTLSMonitor("dns01", true)
	calls := 0
	monitor.renew = func() error { calls++; return nil }
	a.SetTLSMonitor(monitor)
	config, err := a.LoadTLSConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	a.RecordTLSStartup(config)
	handler := a.AdminHandler(http.NotFoundHandler(), "", false)
	request := func(method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:3456"
		if cookie != nil {
			r.AddCookie(cookie)
		}
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := request("POST", "/api/tls/renew", "", nil, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	login := request("POST", "/api/login", `{"password":"`+testPassword+`"}`, nil, "")
	if login.Code != 200 {
		t.Fatal(login.Body.String())
	}
	cookie := login.Result().Cookies()[0]
	var credentials map[string]string
	if err := json.Unmarshal(login.Body.Bytes(), &credentials); err != nil {
		t.Fatal(err)
	}
	if w := request("POST", "/api/tls/renew", "", cookie, ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request("POST", "/api/tls/renew", "", cookie, credentials["csrf"]); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	if calls != 1 {
		t.Fatal("unexpected renewal count", calls)
	}
	a.RecordTLSStartup(TLSConfiguration{Mode: "http01", Email: "changed@example.test"})
	if w := request("POST", "/api/tls/renew", "", cookie, credentials["csrf"]); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if calls != 1 {
		t.Fatal("pending configuration renewed")
	}
}

func TestCertificateCacheInventoryDoesNotRequestCertificates(t *testing.T) {
	m := NewTLSMonitor("http01", true)
	dir := t.TempDir()
	cache := CertificateCache{Cache: autocert.DirCache(dir), Monitor: m}
	pair := dashboardPair(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	data := append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})...)
	if err := cache.Cache.Put(context.Background(), "example.test", data); err != nil {
		t.Fatal(err)
	}
	cache.LoadInventory(context.Background(), dir)
	snapshot := m.Snapshot()
	if len(snapshot.Certificates) != 1 || snapshot.Certificates[0].Source != "cached" {
		t.Fatalf("unexpected inventory %+v", snapshot)
	}
	encoded, _ := json.Marshal(snapshot)
	if strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatal("key exposed")
	}
	m.Observe("example.test", pair, nil)
	if got := m.Snapshot(); len(got.Certificates) != 1 || got.Certificates[0].Source != "loaded" {
		t.Fatalf("unexpected selected certificate %+v", got)
	}
}

func TestCertificateCacheDeletionClearsInventory(t *testing.T) {
	m := NewTLSMonitor("http01", true)
	cache := CertificateCache{Cache: autocert.DirCache(t.TempDir()), Monitor: m}
	m.Observe("example.test", dashboardPair(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)), nil)
	if err := cache.Delete(context.Background(), "example.test"); err != nil {
		t.Fatal(err)
	}
	if len(m.Snapshot().Certificates) != 0 {
		t.Fatal("deleted certificate still listed")
	}
}
