package gateway

import (
	"context"
	"crypto/tls"
	"os"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

// CertificateCache observes the manager's cache without initiating ACME requests.
// Cached certificates are explicitly distinguished from certificates selected for TLS.
type CertificateCache struct {
	autocert.Cache
	Monitor *TLSMonitor
}

func (c CertificateCache) observe(key string, data []byte) {
	if key == "acme_account+key" || strings.HasSuffix(key, "+token") {
		return
	}
	pair, err := tls.X509KeyPair(data, data)
	if err != nil {
		return
	}
	c.Monitor.observe(key, &pair, nil, "cached")
}
func (c CertificateCache) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := c.Cache.Get(ctx, key)
	if err == nil {
		c.observe(key, data)
	}
	return data, err
}
func (c CertificateCache) Put(ctx context.Context, key string, data []byte) error {
	if err := c.Cache.Put(ctx, key, data); err != nil {
		return err
	}
	c.observe(key, data)
	return nil
}

// LoadInventory reads only existing cache files. Invalid files and account keys
// are ignored; autocert remains responsible for validating the cached key pair.
func (c CertificateCache) LoadInventory(ctx context.Context, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			_, _ = c.Get(ctx, entry.Name())
		}
	}
}

func (c CertificateCache) Delete(ctx context.Context, key string) error {
	if err := c.Cache.Delete(ctx, key); err != nil {
		return err
	}
	c.Monitor.mu.Lock()
	defer c.Monitor.mu.Unlock()
	delete(c.Monitor.certs, key)
	return nil
}
