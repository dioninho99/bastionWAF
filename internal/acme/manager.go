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
	client *acme.Client
	dns *cloudflare
	email string
	domains []string
	dir string
	mu sync.RWMutex
	cert *tls.Certificate
	stop chan struct{}
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
	m := &Manager{client: &acme.Client{Key: key, DirectoryURL: directory}, dns: newCloudflare(token), email: email, domains: normalized, dir: dir, stop: make(chan struct{})}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := m.loadCached(); err != nil {
		slog.Info("ACME DNS certificate unavailable; requesting a new certificate", "error", err)
		if err := m.obtain(ctx); err != nil {
			return nil, err
		}
	}
	go m.renewLoop()
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

func (m *Manager) Close() {
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
}

func (m *Manager) renewLoop() {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		if err := m.obtain(ctx); err != nil {
			slog.Error("ACME DNS certificate renewal failed", "error", err)
		}
		cancel()
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
	if err != nil || time.Until(x509Cert.NotAfter) < 30*24*time.Hour {
		return errors.New("cached ACME certificate expires soon")
	}
	m.mu.Lock()
	m.cert = &cert
	m.mu.Unlock()
	return nil
}

func (m *Manager) obtain(ctx context.Context) error {
	if err := m.ensureAccount(ctx); err != nil {
		return err
	}
	order, err := m.client.CreateOrder(ctx, &acme.Order{Identifiers: identifiers(m.domains)})
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
		recordID, err := m.dns.setTXT(ctx, zoneID, recordName, m.client.DNS01ChallengeRecord(challenge.Token))
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
	der, _, err := m.client.CreateCert(ctx, order.Certificate, certKey, true)
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
