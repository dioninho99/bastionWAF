package gateway

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

var latencyBounds = [...]float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60}

type runtimeMetrics struct {
	mu      sync.Mutex
	count   uint64
	sum     float64
	buckets [13]uint64
	causes  map[string]uint64
}

func (m *runtimeMetrics) observe(elapsed time.Duration, cause string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seconds := elapsed.Seconds()
	m.count++
	m.sum += seconds
	for i, bound := range latencyBounds {
		if seconds <= bound {
			m.buckets[i]++
		}
	}
	if cause != "" {
		if m.causes == nil {
			m.causes = map[string]uint64{}
		}
		m.causes[cause]++
	}
}
func (a *App) metrics() string {
	var b strings.Builder
	b.WriteString(a.Events.metrics())
	for _, g := range []struct {
		name  string
		value int64
	}{
		{"bastion_active_requests", int64(len(a.slots))},
		{"bastion_active_upgrades", int64(len(a.upgradeSlots))},
		{"bastion_inspection_reserved_bytes", a.inspectionBytes.Load()},
		{"bastion_inspection_budget_bytes", inspectionBudget},
	} {
		fmt.Fprintf(&b, "# TYPE %s gauge\n%s %d\n", g.name, g.name, g.value)
	}
	m := &a.runtimeMetrics
	m.mu.Lock()
	defer m.mu.Unlock()
	b.WriteString("# HELP bastion_request_duration_seconds Completed request lifetime, including upgraded connections.\n# TYPE bastion_request_duration_seconds histogram\n")
	for i, bound := range latencyBounds {
		fmt.Fprintf(&b, "bastion_request_duration_seconds_bucket{le=\"%g\"} %d\n", bound, m.buckets[i])
	}
	fmt.Fprintf(&b, "bastion_request_duration_seconds_bucket{le=\"+Inf\"} %d\nbastion_request_duration_seconds_sum %g\nbastion_request_duration_seconds_count %d\n", m.count, m.sum, m.count)
	b.WriteString("# TYPE bastion_request_failures_total counter\n")
	for _, cause := range []string{"request_capacity", "inspection_capacity", "upgrade_capacity", "upstream_transport", "upstream_status", "response_inspection", "request_body", "geoip"} {
		fmt.Fprintf(&b, "bastion_request_failures_total{cause=\"%s\"} %d\n", cause, m.causes[cause])
	}
	return b.String()
}
