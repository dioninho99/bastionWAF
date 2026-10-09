package gateway

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestUpstreamSelectionPreservesRoundRobinAndSkipsCoolingTargets(t *testing.T) {
	first, _ := url.Parse("http://first.example")
	second, _ := url.Parse("http://second.example")
	route := &routeRuntime{targets: []*upstreamTarget{{url: first}, {url: second}}}
	now := time.Now()
	if got := route.selectTarget(now).url.Host; got != "first.example" {
		t.Fatalf("first target = %s", got)
	}
	if got := route.selectTarget(now).url.Host; got != "second.example" {
		t.Fatalf("second target = %s", got)
	}
	route.targets[1].markFailure(http.StatusBadGateway, "bad gateway", now)
	if got := route.selectTarget(now).url.Host; got != "first.example" {
		t.Fatalf("cooling target was selected: %s", got)
	}
}

func TestUpstreamHealthCooldownAndRecovery(t *testing.T) {
	target := &upstreamTarget{}
	now := time.Now()
	target.markFailure(http.StatusServiceUnavailable, "unavailable", now)
	h := target.snapshot(now)
	if h.Healthy || h.FailureCount != 1 || h.LastStatus != http.StatusServiceUnavailable {
		t.Fatalf("unexpected failure state: %+v", h)
	}
	if target.snapshot(now.Add(upstreamBaseCooldown - time.Millisecond)).Healthy {
		t.Fatal("target recovered before cooldown elapsed")
	}
	if !target.snapshot(now.Add(upstreamBaseCooldown + time.Millisecond)).Healthy {
		t.Fatal("target did not recover after cooldown")
	}
	target.markSuccess(http.StatusOK, now.Add(time.Second))
	h = target.snapshot(now.Add(time.Second))
	if !h.Healthy || h.FailureCount != 0 || h.LastStatus != http.StatusOK || h.LastError != "" {
		t.Fatalf("unexpected recovery state: %+v", h)
	}
}

func TestUpstreamHealthConcurrentAccess(t *testing.T) {
	target := &upstreamTarget{}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			now := time.Now()
			if i%2 == 0 {
				target.markFailure(http.StatusGatewayTimeout, "timeout", now)
			} else {
				target.markSuccess(http.StatusOK, now)
			}
			_ = target.snapshot(now)
		}(i)
	}
	wg.Wait()
}
