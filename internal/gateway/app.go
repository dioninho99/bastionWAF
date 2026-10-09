package gateway

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	crs "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"golang.org/x/sync/semaphore"
)

type routeRuntime struct {
	config  Route
	targets []*url.URL
	next    atomic.Uint64
	waf     coraza.WAF
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
	authMu       sync.Mutex
	sessions     map[[32]byte]session
	loginLimit   limiter
	requestLimit limiter
	transport    *http.Transport
	slots        chan struct{}
	bodyMemory   *semaphore.Weighted
}

func New(dir, password string) (*App, error) {
	if len(password) < 20 {
		return nil, errors.New("BASTION_ADMIN_PASSWORD muss mindestens 20 Zeichen lang sein")
	}
	a := &App{configPath: filepath.Join(dir, "config.json"), started: time.Now(), password: sha256.Sum256([]byte(password)), sessions: map[[32]byte]session{}, slots: make(chan struct{}, 128)}
	a.bodyMemory = semaphore.NewWeighted(256 << 20)
	a.transport = http.DefaultTransport.(*http.Transport).Clone()
	a.transport.Proxy = nil
	a.transport.ResponseHeaderTimeout = 20 * time.Second
	a.transport.TLSHandshakeTimeout = 10 * time.Second
	a.transport.MaxIdleConns = 128
	a.transport.MaxIdleConnsPerHost = 32
	a.transport.MaxConnsPerHost = 128
	a.transport.DisableCompression = true
	c, e := loadConfig(a.configPath)
	if e != nil {
		return nil, e
	}
	s, e := compile(c)
	if e != nil {
		return nil, e
	}
	a.state.Store(s)
	a.Events, e = newEvents(dir)
	if e != nil {
		return nil, e
	}
	return a, nil
}
func (a *App) Close()         { a.transport.CloseIdleConnections(); a.Events.close() }
func (a *App) Config() Config { return a.state.Load().config }
func (a *App) HostAllowed(host string) bool {
	for _, r := range a.state.Load().routes {
		if r.config.Host == host {
			return true
		}
	}
	return false
}
func compile(c Config) (*snapshot, error) {
	if err := validate(c); err != nil {
		return nil, err
	}
	s := &snapshot{config: c}
	// Share one immutable engine between routes with the same exclusion set.
	engines := map[string]coraza.WAF{}
	for _, r := range c.Routes {
		if !r.Enabled {
			continue
		}
		rt := &routeRuntime{config: r}
		for _, raw := range r.Upstreams {
			u, _ := url.Parse(raw)
			rt.targets = append(rt.targets, u)
		}
		exclusions := ""
		for _, id := range r.ExcludedRuleIDs {
			exclusions += fmt.Sprintf("SecRuleRemoveById %d\n", id)
		}
		waf, ok := engines[exclusions]
		if !ok {
			engine := "On"
			if c.Mode == "detection" {
				engine = "DetectionOnly"
			}
			response := "Off"
			if c.ResponseInspection {
				response = "On"
			}
			setup := fmt.Sprintf("SecRuleEngine %s\nSecRequestBodyAccess On\nSecRequestBodyLimit %d\nSecRequestBodyNoFilesLimit %d\nSecRequestBodyInMemoryLimit %d\nSecRequestBodyLimitAction Reject\nSecResponseBodyAccess %s\nSecResponseBodyLimit 1048576\nSecResponseBodyLimitAction Reject\nSecAuditEngine Off\nSecAction \"id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=4\"\n", engine, c.MaxBodyBytes, c.MaxBodyBytes, c.MaxBodyBytes, response, c.Paranoia, c.Paranoia, c.Threshold)
			var err error
			waf, err = coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS).WithDirectivesFromFile("@coraza.conf-recommended").WithDirectivesFromFile("@crs-setup.conf.example").WithDirectives(setup).WithDirectivesFromFile("@owasp_crs/*.conf").WithDirectives(exclusions))
			if err != nil {
				return nil, fmt.Errorf("WAF-Konfiguration: %w", err)
			}
			engines[exclusions] = waf
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
	next, err := compile(c)
	if err != nil {
		return err
	}
	if err = saveConfig(a.configPath, c); err != nil {
		return err
	}
	a.state.Store(next)
	return nil
}

var errConflict = errors.New("Konfiguration wurde zwischenzeitlich geändert; bitte neu laden")
