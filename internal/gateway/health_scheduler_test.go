package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestActiveHealthCheckTreatsNon5xxResponsesAsReachable(t *testing.T) {
	a, _, _ := testApp(t)
	status := 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("health check method = %s, want HEAD", r.Method)
		}
		w.WriteHeader(status)
	}))
	defer server.Close()
	targetURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := &upstreamTarget{url: targetURL}

	a.checkUpstream(target)
	health := target.snapshot(time.Now())
	if !health.Healthy || health.LastStatus != status || health.LastError != "" {
		t.Fatalf("reachable response marked unhealthy: %+v", health)
	}

	status = http.StatusServiceUnavailable
	a.checkUpstream(target)
	health = target.snapshot(time.Now())
	if health.Healthy || health.LastStatus != status || health.LastError == "" {
		t.Fatalf("5xx response was not marked unhealthy: %+v", health)
	}
}

func TestConfiguredHealthIntervalBounds(t *testing.T) {
	t.Setenv("BASTION_UPSTREAM_HEALTH_INTERVAL", "10")
	got, err := configuredHealthInterval()
	if err != nil || got != 10*time.Second {
		t.Fatalf("configured interval = %s, %v", got, err)
	}

	func TestConfiguredAlertWebhookValidation(t *testing.T) {
		t.Setenv("BASTION_ALERT_WEBHOOK_URL", "https://alerts.example.test/hook")
		got, err := configuredAlertWebhook()
		if err != nil || got == "" {
			t.Fatalf("valid webhook rejected: %q, %v", got, err)
		}
		for _, value := range []string{
			"ftp://alerts.example.test/hook",
			"https://user:pass@alerts.example.test/hook",
			"https://alerts.example.test/hook?secret=1",
		} {
			t.Setenv("BASTION_ALERT_WEBHOOK_URL", value)
			if _, err := configuredAlertWebhook(); err == nil {
				t.Fatalf("invalid webhook %q was accepted", value)
			}
		}
	}
	for _, value := range []string{"4", "301", "not-a-number"} {
		t.Setenv("BASTION_UPSTREAM_HEALTH_INTERVAL", value)
		if _, err := configuredHealthInterval(); err == nil {
			t.Fatalf("invalid interval %q was accepted", value)
		}
	}
}
