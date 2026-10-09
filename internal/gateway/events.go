package gateway

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Client   string    `json:"client"`
	Host     string    `json:"host"`
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	Route    string    `json:"route"`
	Status   int       `json:"status"`
	Action   string    `json:"action"`
	Reason   string    `json:"reason"`
	RuleIDs  []int     `json:"ruleIds"`
	Duration float64   `json:"duration"`
}
type Bucket struct {
	Minute   int64  `json:"minute"`
	Requests uint64 `json:"requests"`
	Blocked  uint64 `json:"blocked"`
}
type EventStore struct {
	mu                               sync.Mutex
	events                           []Event
	total, blocked, detected, failed uint64
	buckets                          [60]Bucket
	path                             string
	file                             *os.File
	size                             int64
	logError                         string
}

func newEvents(dir string) (*EventStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	e := &EventStore{events: make([]Event, 0, 1000), path: filepath.Join(dir, "events.jsonl")}
	f, err := os.OpenFile(e.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	e.file = f
	if info, err := f.Stat(); err == nil {
		e.size = info.Size()
	}
	return e, nil
}
func (e *EventStore) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file != nil {
		e.file.Close()
	}
}
func (e *EventStore) add(v Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.total++
	if v.Action == "blocked" {
		e.blocked++
	}
	if v.Action == "detected" {
		e.detected++
	}
	if v.Status >= 500 {
		e.failed++
	}
	minute := v.Time.Unix() / 60
	b := &e.buckets[minute%60]
	if b.Minute != minute {
		*b = Bucket{Minute: minute}
	}
	b.Requests++
	if v.Action == "blocked" {
		b.Blocked++
	}
	if len(e.events) == 1000 {
		copy(e.events, e.events[1:])
		e.events = e.events[:999]
	}
	e.events = append(e.events, v)
	// No query strings, payloads, cookies, rule matched-data, or authorization headers are retained.
	data, _ := json.Marshal(v)
	data = append(data, '\n')
	if err := e.append(data); err != nil {
		e.logError = "Audit-Log nicht beschreibbar"
		slog.Error("audit write failed", "error", err)
	} else {
		e.logError = ""
	}
}
func (e *EventStore) append(data []byte) error {
	if e.size+int64(len(data)) > 10<<20 {
		if e.file != nil {
			e.file.Close()
			e.file = nil
		}
		if err := os.Remove(e.path + ".1"); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(e.path, e.path+".1"); err != nil && !os.IsNotExist(err) {
			return err
		}
		e.size = 0
	}
	if e.file == nil {
		f, err := os.OpenFile(e.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		e.file = f
	}
	n, err := e.file.Write(data)
	e.size += int64(n)
	return err
}
func (e *EventStore) list() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Event, 0, len(e.events))
	for i := len(e.events) - 1; i >= 0; i-- {
		out = append(out, e.events[i])
	}
	return out
}
func (e *EventStore) stats() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	series := make([]Bucket, 60)
	now := time.Now().Unix() / 60
	for i := range series {
		m := now - 59 + int64(i)
		b := e.buckets[m%60]
		if b.Minute != m {
			b = Bucket{Minute: m}
		}
		series[i] = b
	}
	return map[string]any{"requests": e.total, "blocked": e.blocked, "detected": e.detected, "errors": e.failed, "series": series, "auditError": e.logError}
}
func (e *EventStore) metrics() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return fmt.Sprintf("# HELP bastion_requests_total Completed proxy requests since startup.\n# TYPE bastion_requests_total counter\nbastion_requests_total %d\n# TYPE bastion_blocked_total counter\nbastion_blocked_total %d\n# TYPE bastion_detected_total counter\nbastion_detected_total %d\n# TYPE bastion_upstream_errors_total counter\nbastion_upstream_errors_total %d\n", e.total, e.blocked, e.detected, e.failed)
}

type rateEntry struct {
	count int
	until time.Time
}
type limiter struct {
	mu      sync.Mutex
	entries map[string]rateEntry
}

func (l *limiter) allow(key string, limit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.entries == nil {
		l.entries = map[string]rateEntry{}
	}
	if len(l.entries) >= 10000 {
		for k, v := range l.entries {
			if !now.Before(v.until) {
				delete(l.entries, k)
			}
		}
	}
	v, ok := l.entries[key]
	if !ok && len(l.entries) >= 10000 {
		return false
	}
	if !now.Before(v.until) {
		v = rateEntry{until: now.Add(time.Minute)}
	}
	v.count++
	l.entries[key] = v
	return v.count <= limit
}
