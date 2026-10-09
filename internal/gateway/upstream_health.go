package gateway

import (
	"net/http"
	"time"
)

const (
	upstreamBaseCooldown = time.Second
	upstreamMaxCooldown  = 30 * time.Second
	upstreamMaxFailures  = 8
)

func (t *upstreamTarget) healthy(now time.Time) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return !now.Before(t.unhealthyUntil)
}

func (t *upstreamTarget) markSuccess(status int, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failureCount = 0
	t.unhealthyUntil = time.Time{}
	t.lastStatus = status
	t.lastError = ""
	t.lastCheck = now
}

func (t *upstreamTarget) markFailure(status int, message string, now time.Time) {
	if len(message) > 256 {
		message = message[:256]
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failureCount < upstreamMaxFailures {
		t.failureCount++
	}
	cooldown := upstreamBaseCooldown << (t.failureCount - 1)
	if cooldown > upstreamMaxCooldown {
		cooldown = upstreamMaxCooldown
	}
	t.unhealthyUntil = now.Add(cooldown)
	t.lastStatus = status
	t.lastError = message
	t.lastCheck = now
}

func (t *upstreamTarget) snapshot(now time.Time) upstreamHealth {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return upstreamHealth{
		Healthy:        !now.Before(t.unhealthyUntil),
		FailureCount:   t.failureCount,
		UnhealthyUntil: t.unhealthyUntil,
		LastStatus:     t.lastStatus,
		LastError:      t.lastError,
		LastCheck:      t.lastCheck,
	}
}

type upstreamHealth struct {
	Healthy        bool
	FailureCount   int
	UnhealthyUntil time.Time
	LastStatus     int
	LastError      string
	LastCheck      time.Time
}

func upstreamFailureStatus(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func (r *routeRuntime) selectTarget(now time.Time) *upstreamTarget {
	start := r.next.Add(1) - 1
	var fallback *upstreamTarget
	var fallbackUntil time.Time
	for i := 0; i < len(r.targets); i++ {
		target := r.targets[(start+uint64(i))%uint64(len(r.targets))]
		if target.healthy(now) {
			return target
		}
		target.mu.RLock()
		until := target.unhealthyUntil
		target.mu.RUnlock()
		if fallback == nil || until.Before(fallbackUntil) {
			fallback, fallbackUntil = target, until
		}
	}
	return fallback
}
