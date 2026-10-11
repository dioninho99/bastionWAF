package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const (
	activeHealthTimeout     = 2 * time.Second
	activeHealthConcurrency = 16
)

type upstreamAlert struct {
	Target  string    `json:"target"`
	Healthy bool      `json:"healthy"`
	Status  int       `json:"status,omitempty"`
	Error   string    `json:"error,omitempty"`
	Time    time.Time `json:"time"`
}

func (a *App) healthLoop() {
	defer a.healthWG.Done()
	ticker := time.NewTicker(a.healthInterval)
	defer ticker.Stop()
	a.checkUpstreams()
	for {
		select {
		case <-a.healthStop:
			return
		case <-ticker.C:
			a.checkUpstreams()
		}
	}
}

func (a *App) checkUpstreams() {
	type probe struct {
		target *upstreamTarget
	}
	probes := make([]probe, 0)
	for _, route := range a.state.Load().routes {
		if !route.config.Enabled {
			continue
		}
		for _, target := range route.targets {
			probes = append(probes, probe{target: target})
		}
	}
	sem := make(chan struct{}, activeHealthConcurrency)
	var done sync.WaitGroup
	for _, item := range probes {
		item := item
		done.Add(1)
		go func() {
			defer done.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			a.checkUpstream(item.target)
		}()
	}
	done.Wait()
}

func (a *App) checkUpstream(target *upstreamTarget) {
	before := target.snapshot(time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), activeHealthTimeout)
	defer cancel()
	probeURL := *target.url
	probeURL.Path = "/"
	probeURL.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, probeURL.String(), nil)
	if err != nil {
		target.markFailure(0, err.Error(), time.Now())
		a.queueAlert(target, before)
		return
	}
	resp, err := a.transport.RoundTrip(req)
	now := time.Now()
	if err != nil {
		target.markFailure(0, err.Error(), now)
		slog.Warn("upstream health check failed", "target", target.url.String(), "error", err)
		a.queueAlert(target, before)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		target.markFailure(resp.StatusCode, fmt.Sprintf("health check returned %s", resp.Status), now)
		a.queueAlert(target, before)
		return
	}
	target.markSuccess(resp.StatusCode, now)
	a.queueAlert(target, before)
}

func (a *App) queueAlert(target *upstreamTarget, before upstreamHealth) {
	if a.alertWebhook == "" {
		return
	}
	after := target.snapshot(time.Now())
	if before.LastCheck.IsZero() || before.Healthy == after.Healthy {
		return
	}
	alert := upstreamAlert{Target: target.url.String(), Healthy: after.Healthy, Status: after.LastStatus, Error: after.LastError, Time: after.LastCheck.UTC()}
	select {
	case a.alerts <- alert:
	default:
		slog.Warn("upstream alert queue full", "target", alert.Target)
	}
}

func (a *App) alertLoop() {
	defer a.alertWG.Done()
	client := &http.Client{Timeout: 3 * time.Second}
	for alert := range a.alerts {
		body, err := json.Marshal(alert)
		if err != nil {
			continue
		}
		req, err := http.NewRequest(http.MethodPost, a.alertWebhook, bytes.NewReader(body))
		if err != nil {
			slog.Error("upstream alert request failed", "error", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			slog.Warn("upstream alert delivery failed", "error", err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			slog.Warn("upstream alert rejected", "status", resp.Status)
		}
	}
}
