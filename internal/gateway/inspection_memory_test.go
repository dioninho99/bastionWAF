package gateway

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

func TestInspectionReservation(t *testing.T) {
	for _, tc := range []struct {
		name, body    string
		limit, budget int64
		want          error
	}{
		{"empty", "", 32 << 20, 0, nil},
		{"small", "hello", 32 << 20, 30, nil},
		{"exact limit", strings.Repeat("x", 65536), 65536, 6 * 65536, nil},
		{"oversized", "12345", 4, 100, errBodyTooLarge},
		{"capacity", "12345", 100, 29, errInspectionCapacity},
		{"growth exhaustion", strings.Repeat("x", 65536), 65536, 6 * 32768, errInspectionCapacity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &App{bodyMemory: semaphore.NewWeighted(tc.budget)}
			r := &inspectionReservation{app: a}
			data, err := r.readBody(strings.NewReader(tc.body), tc.limit)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if err == nil && string(data) != tc.body {
				t.Fatal("body changed")
			}
			if a.inspectionBytes.Load() > tc.budget {
				t.Fatal("budget exceeded")
			}
			r.release()
			r.release()
			if a.inspectionBytes.Load() != 0 || !a.bodyMemory.TryAcquire(tc.budget) {
				t.Fatal("reservation leaked")
			}
		})
	}
}

func TestSmallRequestsIgnoreConfiguredMaximum(t *testing.T) {
	a, _, _ := testApp(t)
	change(t, a, func(c *Config) { c.MaxBodyBytes = 32 << 20 })
	// An empty request works even with all payload capacity reserved elsewhere.
	if !a.bodyMemory.TryAcquire(inspectionBudget) {
		t.Fatal("reserve")
	}
	w := request(a, "GET", "/", "", "")
	a.bodyMemory.Release(inspectionBudget)
	if w.Code != 200 {
		t.Fatalf("empty GET: %d %s", w.Code, w.Body.String())
	}
	if a.inspectionBytes.Load() != 0 {
		t.Fatal("memory leaked")
	}
}

func TestCapacityMetricsAndCleanup(t *testing.T) {
	a, _, hits := testApp(t)
	for i := 0; i < cap(a.slots); i++ {
		a.slots <- struct{}{}
	}
	if w := request(a, "GET", "/", "", ""); w.Code != 503 {
		t.Fatalf("slots: %d", w.Code)
	}
	for len(a.slots) > 0 {
		<-a.slots
	}
	a.bodyMemory.TryAcquire(inspectionBudget)
	if w := request(a, "POST", "/", "hello", "text/plain"); w.Code != 503 {
		t.Fatalf("memory: %d %s", w.Code, w.Body.String())
	}
	a.bodyMemory.Release(inspectionBudget)
	if hits.Load() != 0 {
		t.Fatal("rejected requests reached backend")
	}
	if len(a.slots) != 0 || a.inspectionBytes.Load() != 0 {
		t.Fatal("resources leaked")
	}
	metrics := a.metrics()
	for _, line := range []string{
		"bastion_request_failures_total{cause=\"request_capacity\"} 1",
		"bastion_request_failures_total{cause=\"inspection_capacity\"} 1",
		"bastion_request_duration_seconds_count 2",
		"bastion_active_requests 0",
		"bastion_inspection_reserved_bytes 0",
	} {
		if !strings.Contains(metrics, line) {
			t.Fatalf("missing %s\n%s", line, metrics)
		}
	}
}

func TestResponseInspectionCapacityDoesNotPenalizeBackend(t *testing.T) {
	a, _, _ := testApp(t)
	change(t, a, func(c *Config) { c.ResponseInspection = true })
	a.bodyMemory.TryAcquire(inspectionBudget)
	w := request(a, "GET", "/", "", "")
	a.bodyMemory.Release(inspectionBudget)
	if w.Code != 503 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if a.state.Load().routes[0].targets[0].snapshot(time.Now()).FailureCount != 0 {
		t.Fatal("local failure penalized backend")
	}
	if a.inspectionBytes.Load() != 0 {
		t.Fatal("memory leaked")
	}
}

func TestChunkedBodyLimit(t *testing.T) {
	a, _, hits := testApp(t)
	change(t, a, func(c *Config) { c.MaxBodyBytes = 1024 })
	r := httptest.NewRequest(http.MethodPost, "http://app.example.com/", io.NopCloser(strings.NewReader(strings.Repeat("x", 1025))))
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.ContentLength = -1
	r.TransferEncoding = []string{"chunked"}
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if hits.Load() != 0 || a.inspectionBytes.Load() != 0 {
		t.Fatal("forwarded oversized body or leaked reservation")
	}
}

func TestLatencyHistogram(t *testing.T) {
	a := &App{Events: &EventStore{}}
	a.runtimeMetrics.observe(10*time.Millisecond, "")
	a.runtimeMetrics.observe(70*time.Second, "upstream_transport")
	for _, line := range []string{
		"bastion_request_duration_seconds_bucket{le=\"0.005\"} 0",
		"bastion_request_duration_seconds_bucket{le=\"0.01\"} 1",
		"bastion_request_duration_seconds_bucket{le=\"+Inf\"} 2",
		"bastion_request_duration_seconds_count 2",
	} {
		if !strings.Contains(a.metrics(), line) {
			t.Fatal("missing", line)
		}
	}
}

func TestLiveInspectionMetrics(t *testing.T) {
	a, _, _ := testApp(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(entered)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	change(t, a, func(c *Config) { c.Routes[0].Upstreams = []string{backend.URL} })
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- request(a, "POST", "/", "a=hello", "application/x-www-form-urlencoded") }()
	select {
	case <-entered:
	case w := <-done:
		close(release)
		t.Fatalf("request ended before backend: %d %s", w.Code, w.Body.String())
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("backend not reached")
	}
	active := len(a.slots)
	reserved := a.inspectionBytes.Load()
	metrics := a.metrics()
	close(release)
	w := <-done
	if active != 1 || reserved != 42 {
		t.Fatalf("active=%d reserved=%d", active, reserved)
	}
	if !strings.Contains(metrics, "bastion_inspection_reserved_bytes 42") {
		t.Fatal(metrics)
	}
	if w.Code != 204 || len(a.slots) != 0 || a.inspectionBytes.Load() != 0 {
		t.Fatal("request failed or leaked resources")
	}
}

func TestResponseFailureMetrics(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		encoding   string
		wantStatus int
		cause      string
		unhealthy  bool
	}{
		{"upstream status", 503, "", 503, "upstream_status", true},
		{"encoded response", 200, "gzip", 502, "response_inspection", false},
		{"upgrade capacity", 101, "", 503, "upgrade_capacity", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _ := testApp(t)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				if tc.encoding != "" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				if tc.status == 101 {
					w.Header().Set("Connection", "Upgrade")
					w.Header().Set("Upgrade", "websocket")
				}
				w.WriteHeader(tc.status)
				if tc.status != 101 {
					io.WriteString(w, "ok")
				}
			}))
			defer backend.Close()
			change(t, a, func(c *Config) { c.ResponseInspection = true; c.Routes[0].Upstreams = []string{backend.URL} })
			if tc.status == 101 {
				for i := 0; i < cap(a.upgradeSlots); i++ {
					a.upgradeSlots <- struct{}{}
				}
			}
			w := request(a, "GET", "/", "", "")
			if tc.status == 101 {
				for len(a.upgradeSlots) > 0 {
					<-a.upgradeSlots
				}
			}
			if w.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(a.metrics(), "bastion_request_failures_total{cause=\""+tc.cause+"\"} 1") {
				t.Fatal(a.metrics())
			}
			unhealthy := a.state.Load().routes[0].targets[0].snapshot(time.Now()).FailureCount > 0
			if unhealthy != tc.unhealthy {
				t.Fatalf("unhealthy=%v", unhealthy)
			}
			if a.inspectionBytes.Load() != 0 || len(a.slots) != 0 {
				t.Fatal("resources leaked")
			}
		})
	}
}
