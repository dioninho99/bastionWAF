package gateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	crs "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"golang.org/x/sync/semaphore"
)

type routeRuntime struct {
	config  Route
	targets []*upstreamTarget
	next    atomic.Uint64
	waf     coraza.WAF
	mode    string
	paranoia int
	threshold int
	maxBodyBytes int64
	rateLimit int
}
type upstreamTarget struct {
	url *url.URL
	mu sync.RWMutex
	failureCount int
	unhealthyUntil time.Time
	lastStatus int
	lastError string
	lastCheck time.Time
}
type snapshot struct {
	config Config
	routes []*routeRuntime
}
type App struct {
	state        atomic.Pointer[snapshot]
	edit         sync.Mutex
	configPath   string
	Events       *EventStore
	started      time.Time
	password     [32]byte
	metricsToken  [32]byte
	metricsTokenSet bool
	authMu       sync.Mutex
	sessions     map[[32]byte]session
	loginLimit   limiter
	requestLimit limiter
	transport    *http.Transport
	slots        chan struct{}
	bodyMemory   *semaphore.Weighted
	allowPrivateUpstreams bool
	healthInterval time.Duration
	healthStop chan struct{}
	healthWG sync.WaitGroup
	alertWebhook string
	alerts chan upstreamAlert
	alertWG sync.WaitGroup
}

func New(dir, password string) (*App, error) {
	if len(password) < 20 {
		return nil, errors.New("BASTION_ADMIN_PASSWORD must be at least 20 characters long")
	}
	metricsToken := strings.TrimSpace(os.Getenv("BASTION_METRICS_TOKEN"))
	if metricsToken != "" && len(metricsToken) < 32 {
		return nil, errors.New("BASTION_METRICS_TOKEN must be at least 32 characters long")
	}
	allowPrivate := os.Getenv("BASTION_ALLOW_PRIVATE_UPSTREAMS") == "true"
	healthInterval, err := configuredHealthInterval()
	if err != nil {
		return nil, err
	}
	alertWebhook, err := configuredAlertWebhook()
	if err != nil {
		return nil, err
	}
	a := &App{configPath: filepath.Join(dir, "config.json"), started: time.Now(), password: sha256.Sum256([]byte(password)), metricsToken: sha256.Sum256([]byte(metricsToken)), metricsTokenSet: metricsToken != "", sessions: map[[32]byte]session{}, slots: make(chan struct{}, 128), allowPrivateUpstreams: allowPrivate, healthInterval: healthInterval, healthStop: make(chan struct{}), alertWebhook: alertWebhook, alerts: make(chan upstreamAlert, 32)}
	a.bodyMemory = semaphore.NewWeighted(256 << 20)
	a.transport = http.DefaultTransport.(*http.Transport).Clone()
	a.transport.Proxy = nil
	a.transport.ResponseHeaderTimeout = 20 * time.Second
	a.transport.TLSHandshakeTimeout = 10 * time.Second
	a.transport.MaxIdleConns = 128
	a.transport.MaxIdleConnsPerHost = 32
	a.transport.MaxConnsPerHost = 128
	a.transport.DisableCompression = true
	if !allowPrivate {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		a.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := net.LookupIP(host)
			if err != nil {
				return nil, fmt.Errorf("upstream DNS lookup failed: %w", err)
			}
			for _, raw := range ips {
				ip, ok := netip.AddrFromSlice(raw)
				if !ok || isRestrictedUpstreamIP(ip) {
					continue
				}
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				err = dialErr
			}
			return nil, errors.New("upstream destination is not allowed")
		}
	}
	c, e := loadConfig(a.configPath, allowPrivate)
	if e != nil {
		return nil, e
	}
	s, e := compile(c, allowPrivate)
	if e != nil {
		return nil, e
	}
	a.state.Store(s)
	a.Events, e = newEvents(dir)
	if e != nil {
		return nil, e
	}
	a.healthWG.Add(1)
	go a.healthLoop()
	if a.alertWebhook != "" {
		a.alertWG.Add(1)
		go a.alertLoop()
	}
	return a, nil
}
func (a *App) Close()         { close(a.healthStop); a.healthWG.Wait(); close(a.alerts); a.alertWG.Wait(); a.transport.CloseIdleConnections(); a.Events.close() }
func (a *App) Config() Config { return a.state.Load().config }
func (a *App) HostAllowed(host string) bool {
	for _, r := range a.state.Load().routes {
		if r.config.Host == host {
			return true
		}
	}
	return false
}
func compile(c Config, allowPrivate bool) (*snapshot, error) {
	if err := validate(c, allowPrivate); err != nil {
		return nil, err
	}
	s := &snapshot{config: c}
	// Share one immutable engine between routes with the same exclusion set.
	engines := map[string]coraza.WAF{}
	for _, r := range c.Routes {
		if !r.Enabled {
			continue
		}
		mode := c.Mode
		if r.WAFMode != "" && r.WAFMode != "inherit" {
			mode = r.WAFMode
		}
		paranoia, threshold := c.Paranoia, c.Threshold
		if r.Paranoia != 0 {
			paranoia = r.Paranoia
		}
		if r.AnomalyThreshold != 0 {
			threshold = r.AnomalyThreshold
		}
		maxBodyBytes, rateLimit := c.MaxBodyBytes, c.RateLimit
		if r.MaxBodyBytes != 0 {
			maxBodyBytes = r.MaxBodyBytes
		}
		if r.RateLimit != 0 {
			rateLimit = r.RateLimit
		}
		rt := &routeRuntime{config: r, mode: mode, paranoia: paranoia, threshold: threshold, maxBodyBytes: maxBodyBytes, rateLimit: rateLimit}
		for _, raw := range r.Upstreams {
			u, _ := url.Parse(raw)
			rt.targets = append(rt.targets, &upstreamTarget{url: u})
		}
		cacheKey := fmt.Sprintf("%s|%d|%d|%d|%t", mode, paranoia, threshold, maxBodyBytes, c.ResponseInspection)
		exclusions := ""
		for _, id := range r.ExcludedRuleIDs {
			exclusions += fmt.Sprintf("SecRuleRemoveById %d\n", id)
		}
		cacheKey += "|" + exclusions
		waf, ok := engines[cacheKey]
		if !ok {
			engine := "On"
			if mode == "detection" {
				engine = "DetectionOnly"
			}
			response := "Off"
			if c.ResponseInspection {
				response = "On"
			}
			setup := fmt.Sprintf("SecRuleEngine %s\nSecRequestBodyAccess On\nSecRequestBodyLimit %d\nSecRequestBodyNoFilesLimit %d\nSecRequestBodyInMemoryLimit %d\nSecRequestBodyLimitAction Reject\nSecResponseBodyAccess %s\nSecResponseBodyLimit 1048576\nSecResponseBodyLimitAction Reject\nSecAuditEngine Off\nSecAction \"id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=4\"\n", engine, maxBodyBytes, maxBodyBytes, maxBodyBytes, response, paranoia, paranoia, threshold)
			var err error
			waf, err = coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS).WithDirectivesFromFile("@coraza.conf-recommended").WithDirectivesFromFile("@crs-setup.conf.example").WithDirectives(setup).WithDirectivesFromFile("@owasp_crs/*.conf").WithDirectives(exclusions))
			if err != nil {
				return nil, fmt.Errorf("WAF configuration: %w", err)
			}
			engines[cacheKey] = waf
		}
		rt.waf = waf
		s.routes = append(s.routes, rt)
	}
	sort.SliceStable(s.routes, func(i, j int) bool { return len(s.routes[i].config.Path) > len(s.routes[j].config.Path) })
	return s, nil
}
func (a *App) Update(c Config, revision int64) error {
	a.edit.Lock()
	defer a.edit.Unlock()
	if a.Config().Revision != revision {
		return errConflict
	}
	c.Revision = revision + 1
	normalize(&c)
	next, err := compile(c, a.allowPrivateUpstreams)
	if err != nil {
		return err
	}
	if err = saveConfig(a.configPath, c); err != nil {
		return err
	}
	a.state.Store(next)
	return nil
}

var errConflict = errors.New("configuration changed meanwhile; please reload")

const (
	defaultHealthInterval = 30 * time.Second
	minHealthInterval = 5 * time.Second
	maxHealthInterval = 5 * time.Minute
)

func configuredHealthInterval() (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv("BASTION_UPSTREAM_HEALTH_INTERVAL"))
	if raw == "" {
		return defaultHealthInterval, nil
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds < int(minHealthInterval/time.Second) || seconds > int(maxHealthInterval/time.Second) {
		return 0, fmt.Errorf("BASTION_UPSTREAM_HEALTH_INTERVAL must be between %d and %d seconds", int(minHealthInterval/time.Second), int(maxHealthInterval/time.Second))
	}
	return time.Duration(seconds) * time.Second, nil
}

func configuredAlertWebhook() (string, error) {
	raw := strings.TrimSpace(os.Getenv("BASTION_ALERT_WEBHOOK_URL"))
	if raw == "" {
		return "", nil
	}
	if len(raw) > 2048 {
		return "", errors.New("BASTION_ALERT_WEBHOOK_URL must be at most 2048 characters")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("BASTION_ALERT_WEBHOOK_URL must be an HTTP(S) URL without credentials, query, or fragment")
	}
	return raw, nil
}
