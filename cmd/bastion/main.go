package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	acmeclient "bastionwaf/internal/acme"
	"bastionwaf/internal/gateway"
	"bastionwaf/web"
	"golang.org/x/crypto/acme/autocert"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func server(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 65 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
}
func main() {
	if err := run(); err != nil {
		slog.Error("bastion stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		client := &http.Client{Timeout: 3 * time.Second}
		resp, e := client.Get("http://127.0.0.1:9090/healthz")
		if e != nil {
			return e
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return errors.New("unhealthy")
		}
		return nil
	}
	password := os.Getenv("BASTION_ADMIN_PASSWORD")
	if path := os.Getenv("BASTION_ADMIN_PASSWORD_FILE"); path != "" {
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		password = strings.TrimSpace(string(b))
	}
	data := env("BASTION_DATA_DIR", "data")
	app, err := gateway.New(data, password)
	if err != nil {
		return err
	}

	defer app.Close()
	admin := server(env("BASTION_ADMIN_ADDR", "127.0.0.1:9090"), app.AdminHandler(web.Handler(), os.Getenv("BASTION_ADMIN_ORIGIN"), os.Getenv("BASTION_ADMIN_SECURE_COOKIE") == "true"))
	tlsConfig, err := app.LoadTLSConfiguration()
	if err != nil {
		return fmt.Errorf("load persisted TLS configuration: %w", err)
	}
	cert, key := tlsConfig.CertificateFile, tlsConfig.KeyFile
	email, dnsProvider, dnsDomains := tlsConfig.Email, tlsConfig.DNSProvider, tlsConfig.Domains
	if tlsConfig.Persisted && tlsConfig.Mode == "manual" && (cert == "" || key == "") {
		return errors.New("persisted manual TLS configuration has no certificate and key")
	}
	if (cert == "") != (key == "") {
		return errors.New("TLS_CERT and TLS_KEY must be set together")
	}
	if cert != "" && email != "" {
		return errors.New("choose either manual TLS certificates or ACME")
	}
	if dnsProvider != "" && dnsProvider != "cloudflare" {
		return errors.New("BASTION_ACME_DNS_PROVIDER must be cloudflare")
	}
	if dnsProvider != "" && email == "" {
		return errors.New("BASTION_ACME_EMAIL is required for DNS-01 ACME")
	}
	tlsEnabled := cert != "" || email != ""
	httpHandler := http.Handler(app)
	var manager *autocert.Manager
	var dnsManager *acmeclient.Manager
	if dnsProvider == "cloudflare" {
		dnsManager, err = acmeclient.NewCloudflare(context.Background(), filepath.Join(data, "acme-dns"), email, tlsConfig.DNSToken, dnsDomains)
		if err != nil {
			return err
		}
		defer dnsManager.Close()
	}
	if tlsEnabled {
		httpHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.Host
			if h, _, e := net.SplitHostPort(host); e == nil {
				host = h
			}
			host = strings.ToLower(host)
			if !app.HostAllowed(host) {
				http.NotFound(w, r)
				return
			}
			http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
		})
		if email != "" && dnsManager == nil {
			manager = &autocert.Manager{Prompt: autocert.AcceptTOS, Email: email, Cache: autocert.DirCache(filepath.Join(data, "acme")), HostPolicy: func(ctx context.Context, host string) error {
				if app.HostAllowed(host) {
					return nil
				}
				return fmt.Errorf("host not configured")
			}}
			httpHandler = manager.HTTPHandler(httpHandler)
		}
	}
	public := server(env("BASTION_HTTP_ADDR", ":8080"), httpHandler)
	servers := []*http.Server{admin, public}
	errs := make(chan error, 3)
	go func() { slog.Info("admin listening", "address", admin.Addr); errs <- admin.ListenAndServe() }()
	go func() { slog.Info("proxy listening", "address", public.Addr); errs <- public.ListenAndServe() }()
	if tlsEnabled {
		secure := server(env("BASTION_HTTPS_ADDR", ":8443"), app)
		if manager != nil {
			secure.TLSConfig = manager.TLSConfig()
			secure.TLSConfig.MinVersion = tls.VersionTLS12
		}
		if dnsManager != nil {
			secure.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: dnsManager.GetCertificate}
		}
		servers = append(servers, secure)
		go func() {
			slog.Info("TLS proxy listening", "address", secure.Addr)
			errs <- secure.ListenAndServeTLS(cert, key)
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, s := range servers {
		if e := s.Shutdown(shutdown); e != nil {
			s.Close()
		}
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func splitCSV(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
