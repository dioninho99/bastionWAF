package acme

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
