package acme

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

type Manager struct {
	client  *acme.Client
	dns     *cloudflare
	email   string
	domains []string
	dir     string
	mu      sync.RWMutex
	cert    *tls.Certificate
	cancel  context.CancelFunc
	done    chan struct{}
	wake    chan struct{}
	status  RenewalStatus
}

func NewCloudflare(ctx context.Context, dir, email, token string, domains []string) (*Manager, error) {
	if email == "" || token == "" || len(domains) == 0 {
		return nil, errors.New("ACME DNS-01 requires email, Cloudflare API token, and at least one domain")
	}
	key, err := loadOrCreateKey(filepath.Join(dir, "account.key"))
	if err != nil {
		return nil, err
	}
	directory := os.Getenv("BASTION_ACME_DIRECTORY")
	if directory == "" {
		directory = acme.LetsEncryptURL
	}
	normalized := normalizeDomains(domains)
	if len(normalized) == 0 {
		return nil, errors.New("ACME DNS-01 requires at least one non-empty domain")
	}
	m := &Manager{client: &acme.Client{Key: key, DirectoryURL: directory}, dns: newCloudflare(token), email: email, domains: normalized, dir: dir, done: make(chan struct{}), wake: make(chan struct{}, 1)}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	delay := 12 * time.Hour
	if err := m.loadCached(); err != nil {
		slog.Info("ACME DNS certificate unavailable; requesting in background", "error", err)
		delay = 0
	}
	workerCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	go func() {
		defer close(m.done)
		m.renewLoop(workerCtx, delay, time.Minute, 12*time.Hour, m.obtain)
	}()
	return m, nil
}

func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil {
		return nil, errors.New("ACME certificate is not ready")
	}
	return m.cert, nil
}

// Close cancels in-flight certificate requests and waits for the worker to exit.
func (m *Manager) Close() {
	m.cancel()
	<-m.done
}

func (m *Manager) renewLoop(ctx context.Context, delay, retry, interval time.Duration, obtain func(context.Context) error) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	backoff := retry
	m.mu.Lock()
	m.status.NextAttempt = time.Now().Add(delay).UTC()
	m.mu.Unlock()
	for {
		manual := false
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-m.wake:
			manual = true
		}
		if !manual && m.certificateFresh() {
			m.mu.Lock()
			m.status.NextAttempt = time.Now().Add(interval).UTC()
			m.mu.Unlock()
			timer.Reset(interval)
			continue
		}
		m.mu.Lock()
		select {
		case <-m.wake:
		default:
		}
		m.status.Queued = false
		m.status.Running = true
		m.status.LastAttempt = time.Now().UTC()
		m.status.NextAttempt = time.Time{}
		m.mu.Unlock()
		attempt, cancel := context.WithTimeout(ctx, 5*time.Minute)
		err := obtain(attempt)
		cancel()
		m.mu.Lock()
		m.status.Running = false
		m.status.LastError = ""
		if err != nil {
			m.status.LastError = "Certificate request failed. Check DNS credentials, domain permissions and connectivity; see server logs for details."
			m.status.NextAttempt = time.Now().Add(backoff).UTC()
		} else {
			m.status.LastSuccess = time.Now().UTC()
			m.status.NextAttempt = time.Now().Add(interval).UTC()
		}
		m.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Error("ACME DNS certificate request failed; dashboard remains available", "error", err, "retry_in", backoff)
			timer.Reset(backoff)
			backoff = min(backoff*2, time.Hour)
		} else {
			slog.Info("ACME DNS certificate ready")
			backoff = retry
			timer.Reset(interval)
		}
	}
}

func (m *Manager) loadCached() error {
	certPEM, err := os.ReadFile(filepath.Join(m.dir, "cert.pem"))
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(filepath.Join(m.dir, "key.pem"))
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	if len(cert.Certificate) == 0 {
		return errors.New("cached ACME certificate is empty")
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || time.Now().Before(x509Cert.NotBefore) || time.Now().After(x509Cert.NotAfter) {
		return errors.New("cached ACME certificate expires soon")
	}
	for _, domain := range m.domains {
		covered := false
		for _, name := range x509Cert.DNSNames {
			if strings.EqualFold(name, domain) {
				covered = true
				break
			}
		}
		if !covered {
			return errors.New("cached certificate does not cover configured domains")
		}
	}
	m.mu.Lock()
	m.cert = &cert
	m.mu.Unlock()
	if time.Until(x509Cert.NotAfter) < 30*24*time.Hour {
		return errors.New("cached certificate requires renewal")
	}
	return nil
}

func (m *Manager) obtain(ctx context.Context) error {
	if err := m.ensureAccount(ctx); err != nil {
		return err
	}
	order, err := m.client.AuthorizeOrder(ctx, identifiers(m.domains))
	if err != nil {
		return err
	}
	for _, authURL := range order.AuthzURLs {
		auth, err := m.client.GetAuthorization(ctx, authURL)
		if err != nil {
			return err
		}
		challenge := findDNSChallenge(auth.Challenges)
		if challenge == nil {
			return fmt.Errorf("ACME authorization for %s has no DNS-01 challenge", auth.Identifier.Value)
		}
		recordName := "_acme-challenge." + strings.TrimSuffix(auth.Identifier.Value, ".")
		zoneID, err := m.dns.zone(ctx, auth.Identifier.Value)
		if err != nil {
			return err
		}
		challengeRecord, err := m.client.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			return err
		}
		recordID, err := m.dns.setTXT(ctx, zoneID, recordName, challengeRecord)
		if err != nil {
			return err
		}
		if _, err = m.client.Accept(ctx, challenge); err != nil {
			_ = m.dns.deleteTXT(ctx, zoneID, recordID)
			return err
		}
		if _, err = m.client.WaitAuthorization(ctx, auth.URI); err != nil {
			_ = m.dns.deleteTXT(ctx, zoneID, recordID)
			return err
		}
		if err := m.dns.deleteTXT(ctx, zoneID, recordID); err != nil {
			return err
		}
	}
	order, err = m.client.WaitOrder(ctx, order.URI)
	if err != nil {
		return err
	}
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: m.domains,
	}, certKey)
	if err != nil {
		return err
	}
	der, _, err := m.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return err
	}
	var certPEM []byte
	for _, certificate := range der {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})...)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(certKey)})
	if err := os.WriteFile(filepath.Join(m.dir, "cert.pem"), certPEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.dir, "key.pem"), keyPEM, 0600); err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.cert = &cert
	m.mu.Unlock()
	return nil
}

func (m *Manager) ensureAccount(ctx context.Context) error {
	_, err := m.client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + m.email}}, acme.AcceptTOS)
	if err != nil && !strings.Contains(err.Error(), "already") {
		return err
	}
	return nil
}

func loadOrCreateKey(path string) (*rsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, errors.New("invalid ACME account key")
		}
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return key, os.WriteFile(path, b, 0600)
}

func mustMarshalKey(key crypto.Signer) []byte {
	b, _ := x509.MarshalPKCS8PrivateKey(key)
	return b
}

func identifiers(domains []string) []acme.AuthzID {
	out := make([]acme.AuthzID, 0, len(domains))
	for _, domain := range domains {
		out = append(out, acme.AuthzID{Type: "dns", Value: domain})
	}
	return out
}

func normalizeDomains(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
		if domain != "" {
			out = append(out, domain)
		}
	}
	return out
}

func findDNSChallenge(challenges []*acme.Challenge) *acme.Challenge {
	for _, challenge := range challenges {
		if challenge.Type == "dns-01" {
			return challenge
		}
	}
	return nil
}

// RenewalStatus reports worker progress without exposing provider secrets.
type RenewalStatus struct {
	Queued      bool      `json:"queued"`
	Running     bool      `json:"running"`
	LastAttempt time.Time `json:"lastAttempt"`
	LastSuccess time.Time `json:"lastSuccess"`
	NextAttempt time.Time `json:"nextAttempt"`
	LastError   string    `json:"lastError,omitempty"`
}

func (m *Manager) Status() RenewalStatus { m.mu.RLock(); defer m.mu.RUnlock(); return m.status }

// Renew schedules one request on the existing worker, preserving the active certificate.
func (m *Manager) Renew() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.done:
		return errors.New("certificate manager stopped")
	default:
	}
	if m.status.Queued || m.status.Running || (!m.status.LastAttempt.IsZero() && time.Since(m.status.LastAttempt) < 5*time.Minute) {
		return errors.New("a request is running or was attempted within the last five minutes")
	}
	select {
	case m.wake <- struct{}{}:
		m.status.Queued = true
		return nil
	default:
		return errors.New("certificate request already queued")
	}
}

func (m *Manager) certificateFresh() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil || len(m.cert.Certificate) == 0 {
		return false
	}
	c, err := x509.ParseCertificate(m.cert.Certificate[0])
	return err == nil && time.Now().After(c.NotBefore) && time.Until(c.NotAfter) > 30*24*time.Hour
}
