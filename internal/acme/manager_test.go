package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCloudflareStartupDoesNotWaitForCertificate(t *testing.T) {
	entered := make(chan struct{}, 1)
	directory := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer directory.Close()
	t.Setenv("BASTION_ACME_DIRECTORY", directory.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		m   *Manager
		err error
	}
	ready := make(chan result, 1)
	go func() {
		m, err := NewCloudflare(ctx, t.TempDir(), "admin@example.com", "test-token", []string{"example.com"})
		ready <- result{m, err}
	}()
	var m *Manager
	select {
	case r := <-ready:
		if r.err != nil {
			t.Fatal(r.err)
		}
		m = r.m
	case <-time.After(5 * time.Second):
		t.Fatal("startup blocked on certificate request")
	}
	defer m.Close()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("background request did not start")
	}
	if cert, err := m.GetCertificate(nil); err == nil || cert != nil {
		t.Fatal("HTTPS must fail closed while certificate is unavailable")
	}
	closed := make(chan struct{})
	go func() { m.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not cancel in-flight request")
	}
}

func TestCertificateWorkerRetriesAndRecovers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := make(chan int, 10)
	done := make(chan struct{})
	m := &Manager{}
	go func() {
		defer close(done)
		count := 0
		m.renewLoop(ctx, 0, time.Millisecond, time.Hour, func(ctx context.Context) error {
			count++
			attempts <- count
			if count < 3 {
				return errors.New("DNS unavailable")
			}
			return nil
		})
	}()
	for expected := 1; expected <= 3; expected++ {
		select {
		case got := <-attempts:
			if got != expected {
				t.Fatalf("got attempt %d, want %d", got, expected)
			}
		case <-time.After(time.Second):
			t.Fatal("certificate request was not retried")
		}
	}
	select {
	case <-attempts:
		t.Fatal("successful request kept retrying immediately")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
}

func TestManualRenewalQueuesOnceAndTracksFailure(t *testing.T) {
	m := &Manager{wake: make(chan struct{}, 1), done: make(chan struct{})}
	if err := m.Renew(); err != nil {
		t.Fatal(err)
	}
	if err := m.Renew(); err == nil {
		t.Fatal("duplicate request accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	completed := make(chan struct{})
	go func() {
		defer close(completed)
		m.renewLoop(ctx, time.Hour, time.Hour, time.Hour, func(context.Context) error { return errors.New("secret-provider-token") })
	}()
	deadline := time.Now().Add(time.Second)
	for m.Status().LastError == "" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	status := m.Status()
	if status.LastError == "" || status.Running || status.LastAttempt.IsZero() || status.NextAttempt.IsZero() {
		t.Fatalf("missing failure status: %+v", status)
	}
	if strings.Contains(status.LastError, "secret-provider-token") {
		t.Fatal("provider details leaked")
	}
	if err := m.Renew(); err == nil {
		t.Fatal("cooldown not enforced")
	}
	cancel()
	<-completed
}

func TestFreshCertificateSkipsAutomaticIssuanceButCanRenewManually(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{cert: &tls.Certificate{Certificate: [][]byte{der}}, wake: make(chan struct{}, 1), done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := make(chan struct{}, 2)
	go func() {
		defer close(m.done)
		m.renewLoop(ctx, 0, time.Hour, time.Hour, func(context.Context) error { attempts <- struct{}{}; return nil })
	}()
	select {
	case <-attempts:
		t.Fatal("fresh certificate renewed automatically")
	case <-time.After(30 * time.Millisecond):
	}
	if err := m.Renew(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-attempts:
	case <-time.After(time.Second):
		t.Fatal("manual request did not run")
	}
	cancel()
	<-m.done
	if m.Status().LastSuccess.IsZero() {
		t.Fatal("success not recorded")
	}
}
