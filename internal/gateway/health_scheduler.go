package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const (
	activeHealthTimeout = 2 * time.Second
	activeHealthConcurrency = 16
)

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
	ctx, cancel := context.WithTimeout(context.Background(), activeHealthTimeout)
	defer cancel()
	probeURL := *target.url
	probeURL.Path = "/"
	probeURL.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, probeURL.String(), nil)
	if err != nil {
		target.markFailure(0, err.Error(), time.Now())
		return
	}
	resp, err := a.transport.RoundTrip(req)
	now := time.Now()
	if err != nil {
		target.markFailure(0, err.Error(), now)
		slog.Warn("upstream health check failed", "target", target.url.String(), "error", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		target.markFailure(resp.StatusCode, fmt.Sprintf("health check returned %s", resp.Status), now)
		return
	}
	target.markSuccess(resp.StatusCode, now)
}
