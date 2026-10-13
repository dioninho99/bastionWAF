package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
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
	Country  string    `json:"country,omitempty"`
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
	mu                                                               sync.Mutex
	events                                                           []Event
	total, blocked, detected, failed                                 uint64
	buckets                                                          [60]Bucket
	path                                                             string
	file                                                             *os.File
	size                                                             int64
	logError                                                         string
	historyWarning                                                   string
	restoredTotal, restoredBlocked, restoredDetected, restoredFailed uint64
	next                                                             int
}

func newEvents(dir string) (*EventStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	e := &EventStore{events: make([]Event, 0, 1000), path: filepath.Join(dir, "events.jsonl")}
	for _, path := range []string{e.path + ".1", e.path} {
		if err := e.restore(path); err != nil {
			e.historyWarning = "Some audit history could not be restored"
			slog.Warn("audit history restore failed", "error", err)
		}
	}
	e.restoredTotal, e.restoredBlocked, e.restoredDetected, e.restoredFailed = e.total, e.blocked, e.detected, e.failed
	f, err := os.OpenFile(e.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	e.file = f
	if info, err := f.Stat(); err == nil {
		e.size = info.Size()
	}
	// Separate a truncated last record from future writes after an abrupt stop.
	if e.size > 0 {
		tail, err := os.Open(e.path)
		if err != nil {
			f.Close()
			return nil, err
		}
		var last [1]byte
		_, err = tail.ReadAt(last[:], e.size-1)
		tail.Close()
		if err != nil {
			f.Close()
			return nil, err
		}
		if last[0] != '\n' {
			if _, err = f.Write([]byte{'\n'}); err != nil {
				f.Close()
				return nil, err
			}
			e.size++
		}
	}
	return e, nil
}

func (e *EventStore) restore(path string) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	// Audit files are bounded by rotation. Limit recovery work for damaged files.
	reader := bufio.NewReader(io.LimitReader(f, (10<<20)+1))
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			var event Event
			if len(line) > 64<<10 || json.Unmarshal(line, &event) != nil || event.ID == "" || event.Time.IsZero() || event.Time.Unix() < 0 {
				e.historyWarning = "Some damaged audit entries were skipped during recovery"
			} else {
				e.remember(event)
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
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
	e.remember(v)
	// No query strings, payloads, cookies, rule matched-data, or authorization headers are retained.
	data, _ := json.Marshal(v)
	data = append(data, '\n')
	if err := e.append(data); err != nil {
		e.logError = "audit log is not writable"
		slog.Error("audit write failed", "error", err)
	} else {
		e.logError = ""
	}
}
func (e *EventStore) remember(v Event) {
	if v.RuleIDs == nil {
		v.RuleIDs = []int{}
	}
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
	// A long-lived request can complete after newer minute buckets have arrived.
	if minute >= b.Minute {
		if b.Minute != minute {
			*b = Bucket{Minute: minute}
		}
		b.Requests++
		if v.Action == "blocked" {
			b.Blocked++
		}
	}
	if len(e.events) < 1000 {
		e.events = append(e.events, v)
	} else {
		e.events[e.next] = v
		e.next = (e.next + 1) % 1000
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
		out = append(out, e.events[(e.next+i)%len(e.events)])
	}
	return out
}
func (e *EventStore) stats() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	series := make([]Bucket, 60)
	routeCounts := map[string]uint64{}
	statusCounts := map[string]uint64{}
	clientCounts := map[string]uint64{}
	now := time.Now().Unix() / 60
	for i := range series {
		m := now - 59 + int64(i)
		b := e.buckets[m%60]
		if b.Minute != m {
			b = Bucket{Minute: m}
		}
		series[i] = b
	}
	for _, event := range e.events {
		routeCounts[event.Route]++
		statusCounts[fmt.Sprintf("%dxx", event.Status/100)]++
		clientCounts[event.Client]++
	}
	return map[string]any{"requests": e.total, "blocked": e.blocked, "detected": e.detected, "errors": e.failed, "series": series, "routeCounts": routeCounts, "statusCounts": statusCounts, "clientCounts": clientCounts, "auditError": e.logError, "historyWarning": e.historyWarning, "restoredEvents": e.restoredTotal}
}
func (e *EventStore) metrics() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return fmt.Sprintf("# HELP bastion_requests_total Completed proxy requests since startup.\n# TYPE bastion_requests_total counter\nbastion_requests_total %d\n# TYPE bastion_blocked_total counter\nbastion_blocked_total %d\n# TYPE bastion_detected_total counter\nbastion_detected_total %d\n# TYPE bastion_upstream_errors_total counter\nbastion_upstream_errors_total %d\n", e.total-e.restoredTotal, e.blocked-e.restoredBlocked, e.detected-e.restoredDetected, e.failed-e.restoredFailed)
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
