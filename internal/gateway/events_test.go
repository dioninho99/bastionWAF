package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditHistorySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	e, err := newEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < 1100; i++ {
		e.add(Event{ID: fmt.Sprint(i), Time: now, Action: "blocked", Status: 403, Route: "app", RuleIDs: []int{942100}})
	}
	e.close()
	before, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	e, err = newEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	events := e.list()
	if len(events) != 1000 || events[0].ID != "1099" || events[999].ID != "100" {
		t.Fatal("history order or retention lost")
	}
	stats := e.stats()
	if stats["requests"] != uint64(1100) || stats["blocked"] != uint64(1100) || stats["restoredEvents"] != uint64(1100) {
		t.Fatal(stats)
	}
	if !strings.Contains(e.metrics(), "bastion_requests_total 0\n") {
		t.Fatal("historical events polluted process counters")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if string(before) != string(after) {
		t.Fatal("recovery rewrote audit records")
	}
	e.add(Event{ID: "new", Time: now, Action: "allowed", Status: 200})
	if e.list()[0].ID != "new" || !strings.Contains(e.metrics(), "bastion_requests_total 1\n") {
		t.Fatal("new events not counted")
	}
	series := e.stats()["series"].([]Bucket)
	if series[59].Requests != 1101 || series[59].Blocked != 1100 {
		t.Fatal("chart not restored")
	}
}

func TestAuditRecoveryRotationAndDamagedTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	record := func(id string) string {
		data, _ := json.Marshal(Event{ID: id, Time: time.Now(), Status: 200, Action: "allowed"})
		return string(data)
	}
	if err := os.WriteFile(path+".1", []byte(record("old")+"\nnot json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(record("current")+"\n{\"id\":"), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := newEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.list(); len(got) != 2 || got[0].ID != "current" || got[1].ID != "old" {
		t.Fatal(got)
	}
	if e.stats()["historyWarning"] == "" {
		t.Fatal("missing recovery warning")
	}
	e.add(Event{ID: "after", Time: time.Now(), Status: 200, Action: "allowed"})
	e.close()
	e, err = newEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	if got := e.list(); len(got) != 3 || got[0].ID != "after" {
		t.Fatal("truncated tail swallowed new event", got)
	}
}

func TestAuditRotationRestoresBothFiles(t *testing.T) {
	dir := t.TempDir()
	e, err := newEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	e.add(Event{ID: "before", Time: time.Now(), Status: 200})
	e.size = 10 << 20 // Force the next append through the production rotation path.
	e.add(Event{ID: "after", Time: time.Now(), Status: 502, Action: "error"})
	e.close()
	e, err = newEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	if len(e.list()) != 2 || e.stats()["errors"] != uint64(1) {
		t.Fatal(e.stats())
	}
}

func TestLateEventDoesNotEraseRecentTraffic(t *testing.T) {
	e, err := newEvents(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	now := time.Now()
	e.add(Event{ID: "recent", Time: now, Status: 200})
	e.add(Event{ID: "long-upgrade", Time: now.Add(-time.Hour), Status: 101})
	series := e.stats()["series"].([]Bucket)
	if series[59].Requests != 1 {
		t.Fatal("late event erased current traffic")
	}
	if e.list()[0].RuleIDs == nil {
		t.Fatal("rule IDs must remain a JSON array")
	}
}
