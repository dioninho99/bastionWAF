package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type certificateStatus struct {
	Present   bool      `json:"present"`
	Subject   string    `json:"subject,omitempty"`
	DNSNames  []string  `json:"dnsNames,omitempty"`
	NotBefore time.Time `json:"notBefore,omitempty"`
	NotAfter  time.Time `json:"notAfter,omitempty"`
	Expired   bool      `json:"expired"`
	Source    string    `json:"source,omitempty"`
}

// TLSConfiguration is the persisted TLS configuration used by the process at startup.
// Secrets are available only to the caller inside the gateway process.
type TLSConfiguration struct {
	Mode, Email, DNSProvider string
	Domains                  []string
	DNSToken                 string
	CertificateFile, KeyFile string
	Persisted                bool
}

func csvDomains(value string) []string {
	var domains []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			domains = append(domains, item)
		}
	}
	return domains
}

// LoadTLSConfiguration returns the persisted GUI TLS settings, falling back to
// environment variables when no GUI settings have been saved.
func (a *App) LoadTLSConfiguration() (TLSConfiguration, error) {
	var c TLSConfiguration
	var domains string
	err := a.users.QueryRow(`SELECT mode,email,dns_provider,domains,dns_token FROM tls_settings WHERE id=1`).Scan(&c.Mode, &c.Email, &c.DNSProvider, &domains, &c.DNSToken)
	if errors.Is(err, sql.ErrNoRows) {
		c.Mode = "manual"
		c.Email = os.Getenv("BASTION_ACME_EMAIL")
		c.DNSProvider = strings.ToLower(strings.TrimSpace(os.Getenv("BASTION_ACME_DNS_PROVIDER")))
		c.Domains = csvDomains(os.Getenv("BASTION_ACME_DOMAINS"))
		c.DNSToken = os.Getenv("BASTION_ACME_DNS_API_TOKEN")
		c.CertificateFile, c.KeyFile = os.Getenv("BASTION_TLS_CERT"), os.Getenv("BASTION_TLS_KEY")
		if c.Email != "" {
			if c.DNSProvider == "cloudflare" {
				c.Mode = "dns01"
			} else {
				c.Mode = "http01"
			}
		}
		return c, nil
	}
	if err != nil {
		return c, err
	}
	c.Persisted = true
	c.Domains = csvDomains(domains)
	if c.Mode == "manual" {
		c.CertificateFile, c.KeyFile = a.manualCertificateFiles()
	}

	return c, nil
}

func validateCertificate(certPEM, keyPEM []byte) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, errors.New("certificate and private key do not match or are invalid")
	}
	if len(pair.Certificate) == 0 {
		return nil, errors.New("certificate chain is empty")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, errors.New("invalid leaf certificate")
	}
	if cert.IsCA {
		return nil, errors.New("a leaf certificate is required")
	}
	return cert, nil
}

func (a *App) manualCertificateFiles() (string, string) {
	cert := filepath.Join(a.dataDir, "certificates", "cert.pem")
	key := filepath.Join(a.dataDir, "certificates", "key.pem")
	if _, err := os.Stat(cert); errors.Is(err, os.ErrNotExist) {
		return os.Getenv("BASTION_TLS_CERT"), os.Getenv("BASTION_TLS_KEY")
	}
	return cert, key
}

func (a *App) certificateStatus() certificateStatus {
	certFile, keyFile := a.manualCertificateFiles()
	source := "uploaded"
	if certFile == os.Getenv("BASTION_TLS_CERT") {
		source = "environment"
	}
	certPEM, err1 := os.ReadFile(certFile)
	keyPEM, err2 := os.ReadFile(keyFile)
	if err1 != nil || err2 != nil {
		return certificateStatus{}
	}
	cert, err := validateCertificate(certPEM, keyPEM)
	if err != nil {
		return certificateStatus{Present: true, Expired: true}
	}
	return certificateStatus{Present: true, Subject: cert.Subject.String(), DNSNames: cert.DNSNames, NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(), Expired: time.Now().After(cert.NotAfter), Source: source}
}

func (a *App) storeCertificate(certPEM, keyPEM []byte) error {
	cert, err := validateCertificate(certPEM, keyPEM)
	if err != nil {
		return err
	}
	if time.Now().Before(cert.NotBefore) {
		return errors.New("certificate is not yet valid")
	}
	if time.Now().After(cert.NotAfter) {
		return errors.New("certificate is already expired")
	}
	dir := filepath.Join(a.dataDir, "certificates")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"cert.pem": certPEM, "key.pem": keyPEM} {
		tmp := filepath.Join(dir, "."+name+".new")
		if err := os.WriteFile(tmp, data, 0600); err != nil {
			return err
		}
		if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) tlsSettings() (map[string]any, error) {
	c, err := a.LoadTLSConfiguration()
	if err != nil {
		return nil, err
	}
	return map[string]any{"mode": c.Mode, "email": c.Email, "dnsProvider": c.DNSProvider, "domains": c.Domains, "dnsTokenConfigured": c.DNSToken != "", "restartRequired": true, "certificate": a.certificateStatus()}, nil
}

func (a *App) saveTLSSettings(mode, email, provider string, domains []string, token string) error {
	email = strings.TrimSpace(email)
	domains = csvDomains(strings.Join(domains, ","))
	if mode != "manual" && mode != "http01" && mode != "dns01" {
		return errors.New("mode must be manual, http01, or dns01")
	}
	if token == "" {
		current, err := a.LoadTLSConfiguration()
		if err != nil {
			return err
		}
		token = current.DNSToken
	}
	if mode == "manual" {
		certFile, keyFile := a.manualCertificateFiles()
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return errors.New("upload a matching certificate and private key before saving manual mode")
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil || cert.IsCA || time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
			return errors.New("a currently valid leaf certificate is required")
		}
		email, provider = "", ""
	} else {
		if email == "" {
			return errors.New("email is required for Let's Encrypt")
		}
		if mode == "http01" {
			provider = ""
		}
		if mode == "dns01" && (provider != "cloudflare" || strings.TrimSpace(token) == "" || len(domains) == 0) {
			return errors.New("DNS-01 requires Cloudflare, an API token, and at least one domain")
		}
	}

	_, err := a.users.Exec(`INSERT INTO tls_settings(id,mode,email,dns_provider,domains,dns_token) VALUES(1,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET mode=excluded.mode,email=excluded.email,dns_provider=excluded.dns_provider,domains=excluded.domains,dns_token=CASE WHEN excluded.dns_token='' THEN tls_settings.dns_token ELSE excluded.dns_token END`, mode, email, provider, strings.Join(domains, ","), token)
	return err
}
