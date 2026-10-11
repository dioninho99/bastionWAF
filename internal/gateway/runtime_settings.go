package gateway

import (
	"crypto/sha256"
	"encoding/json"
	"os"
)

// Runtime fingerprints are process-local and never exposed through the API.
// A saved configuration is active only when it matches the startup snapshot.
func oidcFingerprint(s oidcSettings) [32]byte {
	s.SecretConfigured, s.RestartRequired = false, false
	payload, _ := json.Marshal(struct {
		Settings oidcSettings
		Secret   string
	}{s, s.ClientSecret})
	return sha256.Sum256(payload)
}

func tlsFingerprint(c TLSConfiguration) [32]byte {
	c.Persisted = false
	// Ignore values unused by the selected TLS mode.
	if c.Mode != "dns01" {
		c.DNSToken = ""
		c.Domains = nil
		c.DNSProvider = ""
	}
	payload, _ := json.Marshal(c)
	hash := sha256.New()
	hash.Write(payload)
	if c.Mode == "manual" {
		for _, path := range []string{c.CertificateFile, c.KeyFile} {
			hash.Write([]byte{0})
			data, err := os.ReadFile(path)
			if err != nil {
				hash.Write([]byte("unavailable"))
			} else {
				hash.Write(data)
			}
		}
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

// RecordTLSStartup records exactly the configuration selected by the server.
// Call before exposing the admin handler; this does not verify issuance or health.
func (a *App) RecordTLSStartup(c TLSConfiguration) {
	a.runtimeMu.Lock()
	defer a.runtimeMu.Unlock()
	a.activeTLS = tlsFingerprint(c)
	a.tlsStartupKnown = true
}

func (a *App) tlsRestartRequired(c TLSConfiguration) (bool, bool) {
	a.runtimeMu.RLock()
	defer a.runtimeMu.RUnlock()
	return a.tlsStartupKnown && a.activeTLS != tlsFingerprint(c), a.tlsStartupKnown
}
