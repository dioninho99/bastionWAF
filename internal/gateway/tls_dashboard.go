package gateway

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	acmeclient "bastionwaf/internal/acme"
)

// TLSMonitor contains only public certificate metadata and process-local status.
// It never requests a certificate when the dashboard is read.
type TLSMonitor struct {
	mu       sync.RWMutex
	mode     string
	enabled  bool
	certs    map[string]CertificateInfo
	failures map[string]string
	dns      func() (*tls.Certificate, error)
	renewal  func() acmeclient.RenewalStatus
	renew    func() error
}
type CertificateInfo struct {
	Source      string    `json:"source"`
	Domain      string    `json:"domain"`
	DNSNames    []string  `json:"dnsNames"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	Fingerprint string    `json:"fingerprint"`
	State       string    `json:"state"`
}
type TLSDashboard struct {
	Mode         string                   `json:"mode"`
	Enabled      bool                     `json:"enabled"`
	Certificates []CertificateInfo        `json:"certificates"`
	Failures     map[string]string        `json:"failures"`
	Renewal      acmeclient.RenewalStatus `json:"renewal"`
	CanRenew     bool                     `json:"canRenew"`
}

func NewTLSMonitor(mode string, enabled bool) *TLSMonitor {
	return &TLSMonitor{mode: mode, enabled: enabled, certs: map[string]CertificateInfo{}, failures: map[string]string{}}
}
func (m *TLSMonitor) Observe(domain string, cert *tls.Certificate, err error) {
	m.observe(domain, cert, err, "loaded")
}
func (m *TLSMonitor) observe(domain string, cert *tls.Certificate, err error, source string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.failures[domain] = "Certificate request failed. Check domain DNS, public ports 80/443 and server logs."
		return
	}
	if cert == nil || len(cert.Certificate) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	if m.mode == "http01" && leaf.PublicKeyAlgorithm == x509.RSA && !strings.HasSuffix(domain, "+rsa") {
		domain += "+rsa"
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	m.certs[domain] = CertificateInfo{Source: source, Domain: domain, DNSNames: append([]string(nil), leaf.DNSNames...), Issuer: leaf.Issuer.String(), NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC(), Fingerprint: hex.EncodeToString(fingerprint[:])}
	delete(m.failures, domain)
}

// SetDNSManager is called once, before starting HTTP listeners.
func (m *TLSMonitor) SetDNSManager(manager *acmeclient.Manager) {
	m.dns = func() (*tls.Certificate, error) { return manager.GetCertificate(nil) }
	m.renewal = manager.Status
	m.renew = manager.Renew
}
func (m *TLSMonitor) Snapshot() TLSDashboard {
	if m.dns != nil {
		if cert, err := m.dns(); err == nil {
			m.Observe("DNS-01 certificate", cert, nil)
		}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := TLSDashboard{Mode: m.mode, Enabled: m.enabled, Certificates: []CertificateInfo{}, Failures: map[string]string{}, CanRenew: m.renew != nil}
	if m.renewal != nil {
		out.Renewal = m.renewal()
		out.CanRenew = out.CanRenew && !out.Renewal.Queued && !out.Renewal.Running && (out.Renewal.LastAttempt.IsZero() || time.Since(out.Renewal.LastAttempt) >= 5*time.Minute)
	}
	now := time.Now()
	for _, c := range m.certs {
		c.DNSNames = append([]string(nil), c.DNSNames...)
		c.State = "valid"
		if now.Before(c.NotBefore) {
			c.State = "not yet valid"
		} else if !now.Before(c.NotAfter) {
			c.State = "expired"
		} else if time.Until(c.NotAfter) < 30*24*time.Hour {
			c.State = "expiring soon"
		}
		out.Certificates = append(out.Certificates, c)
	}
	sort.Slice(out.Certificates, func(i, j int) bool { return out.Certificates[i].Domain < out.Certificates[j].Domain })
	for domain, failure := range m.failures {
		out.Failures[domain] = failure
	}
	return out
}

// SetTLSMonitor connects the dashboard to the TLS manager before listeners start.
func (a *App) SetTLSMonitor(m *TLSMonitor) { a.tlsMonitor = m }
