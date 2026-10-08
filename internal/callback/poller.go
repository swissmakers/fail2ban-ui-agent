// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package callback

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/config"
	"github.com/swissmakers/fail2ban-ui-agent/internal/model"
)

const (
	maxQueuedEvents = 1000
	eventTTL        = time.Hour
	postTimeout     = 5 * time.Second
	maxPostBackoff  = 5 * time.Minute
)

// JailReader fetches current jail / banned-IP state (fail2ban-client).
type JailReader interface {
	GetJailInfos(ctx context.Context) ([]model.JailInfo, error)
}

type event struct {
	id string
	// "ban" or "unban"
	kind      string
	jail, ip  string
	serverID  string
	firstSeen time.Time
}

type Stats struct {
	LastTick   time.Time `json:"lastTick,omitzero"`
	LastPostOK time.Time `json:"lastPostOk,omitzero"`
	LastError  string    `json:"lastError,omitempty"`
	Pending    int       `json:"pending"`
	Dropped    int       `json:"dropped"`
	Rejected   int       `json:"rejected"`
}

// Poller periodically diffs banned IPs and POSTs /api/ban and /api/unban to Fail2ban-UI.
type Poller struct {
	configRoot string
	env        config.CallbackRuntimeConfig
	interval   time.Duration
	svc        JailReader
	httpClient *http.Client
	log        *log.Logger
	now        func() time.Time

	// Owned by the Run goroutine.
	prev        map[string]map[string]struct{}
	queue       []event
	active      config.CallbackRuntimeConfig
	failures    int
	nextAttempt time.Time

	mu    sync.Mutex
	stats Stats
}

// NewPoller builds a poller. A cfg.CallbackPollInterval of 0 disables it; URL and secret are resolved on every tick.
func NewPoller(cfg config.Config, svc JailReader, logger *log.Logger) *Poller {
	if logger == nil {
		logger = log.Default()
	}
	return &Poller{
		configRoot: cfg.ConfigRoot,
		env:        cfg.EnvCallback,
		interval:   cfg.CallbackPollInterval,
		svc:        svc,
		// Redirects are not followed: they would carry X-Callback-Secret to another location.
		httpClient: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		log:        logger,
		now:        func() time.Time { return time.Now().UTC() },
	}
}

// Run blocks until ctx is cancelled. The first observation establishes a baseline (no callbacks).
func (p *Poller) Run(ctx context.Context) {
	if p.interval <= 0 {
		return
	}
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		p.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (p *Poller) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats
}

func (p *Poller) tick(ctx context.Context) {
	now := p.now()
	var tickErr string
	rt, source, err := config.ResolveCallback(p.configRoot, p.env)
	if err != nil || source == config.CallbackSourceNone {
		// Unconfigured: forget everything so a later configuration starts from a fresh baseline.
		p.prev, p.queue, p.active, p.failures, p.nextAttempt = nil, nil, config.CallbackRuntimeConfig{}, 0, time.Time{}
		if err != nil {
			tickErr = err.Error()
		}
		p.updateStats(now, tickErr, 0, 0)
		return
	}
	if rt != p.active {
		p.queue = keepServer(p.queue, rt.ServerID)
		p.active, p.failures, p.nextAttempt = rt, 0, time.Time{}
	}

	var dropped, rejected int
	busy := false
	if service, ok := p.svc.(interface{ Busy() bool }); ok {
		busy = service.Busy()
	}
	if busy {
		// Keep the last observation while the command owns the daemon socket.
		// Already queued callback deliveries can still be flushed below.
	} else if infos, err := p.svc.GetJailInfos(ctx); err != nil {
		tickErr = "read jails: " + err.Error()
	} else {
		cur := snapshotFromJailInfos(infos)
		if p.prev != nil {
			var n int
			p.queue, n = enqueue(p.queue, newEvents(rt.ServerID, cur, p.prev, now), maxQueuedEvents)
			dropped += n
		}
		p.prev = cur
	}
	var expired int
	p.queue, expired = dropExpired(p.queue, now, eventTTL)
	dropped += expired

	if !now.Before(p.nextAttempt) {
		n, err := p.flush(ctx, rt, now)
		rejected += n
		if err != nil {
			tickErr = err.Error()
		}
	}
	p.updateStats(now, tickErr, dropped, rejected)
}

// Sends queued events in order until one needs a retry; the batch then waits interval·2^(failures-1).
func (p *Poller) flush(ctx context.Context, rt config.CallbackRuntimeConfig, now time.Time) (rejected int, err error) {
	for len(p.queue) > 0 {
		e := p.queue[0]
		status, postErr := p.post(ctx, rt, e)
		switch classify(status, postErr) {
		case outcomeDelivered:
			p.queue = p.queue[1:]
			p.failures = 0
			p.mu.Lock()
			p.stats.LastPostOK = now
			p.mu.Unlock()
		case outcomeRejected:
			p.queue = p.queue[1:]
			rejected++
			p.log.Printf("callback poller: %s %s/%s rejected by Fail2ban-UI (HTTP %d), dropping it", e.kind, e.jail, e.ip, status)
		default:
			p.failures++
			p.nextAttempt = now.Add(retryBackoff(p.interval, p.failures))
			if postErr == nil {
				postErr = fmt.Errorf("HTTP %d", status)
			}
			return rejected, fmt.Errorf("%s %s/%s: %w", e.kind, e.jail, e.ip, postErr)
		}
	}
	return rejected, nil
}

func (p *Poller) updateStats(now time.Time, tickErr string, dropped, rejected int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stats.LastTick = now
	p.stats.Pending = len(p.queue)
	p.stats.Dropped += dropped
	p.stats.Rejected += rejected
	switch {
	case tickErr != "":
		if tickErr != p.stats.LastError {
			p.log.Printf("callback poller: %s", tickErr)
		}
		p.stats.LastError = tickErr
	case len(p.queue) == 0:
		p.stats.LastError = ""
	}
}

func (p *Poller) post(ctx context.Context, rt config.CallbackRuntimeConfig, e event) (int, error) {
	body := map[string]string{"ip": e.ip, "jail": e.jail, "serverId": e.serverID}
	if hn := callbackHostname(rt); hn != "" {
		body["hostname"] = hn
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, postTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(rt.CallbackURL, "/")+"/api/"+e.kind, bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Callback-Secret", rt.CallbackSecret)
	req.Header.Set("X-Callback-Event-ID", e.id)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	return resp.StatusCode, nil
}

func callbackHostname(rt config.CallbackRuntimeConfig) string {
	if rt.CallbackHost != "" {
		return rt.CallbackHost
	}
	hn, _ := os.Hostname()
	return hn
}

type outcome int

const (
	outcomeRetry outcome = iota
	outcomeDelivered
	outcomeRejected
)

// Auth failures and throttling are retried (the UI may be mid-reconfiguration); other 4xx will never succeed.
func classify(status int, err error) outcome {
	switch {
	case err != nil:
		return outcomeRetry
	case status >= 200 && status < 300:
		return outcomeDelivered
	case status == http.StatusRequestTimeout, status == http.StatusTooEarly, status == http.StatusTooManyRequests,
		status == http.StatusUnauthorized, status == http.StatusForbidden:
		return outcomeRetry
	case status >= 400 && status < 500:
		return outcomeRejected
	}
	return outcomeRetry
}

func retryBackoff(interval time.Duration, failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	if d := interval << (failures - 1); d > 0 && d < maxPostBackoff {
		return d
	}
	return maxPostBackoff
}

// Stable across retries so the UI can drop duplicates of the same observation.
func eventID(serverID, kind, jail, ip string, firstSeen time.Time) string {
	sum := sha256.Sum256([]byte(serverID + "|" + kind + "|" + jail + "|" + ip + "|" + strconv.FormatInt(firstSeen.UnixNano(), 10)))
	return hex.EncodeToString(sum[:])[:32]
}

func newEvents(serverID string, cur, prev map[string]map[string]struct{}, now time.Time) []event {
	bans, unbans := diffSnapshots(prev, cur)
	out := make([]event, 0, len(bans)+len(unbans))
	for _, group := range []struct {
		kind  string
		edges []edge
	}{{"ban", bans}, {"unban", unbans}} {
		for _, e := range group.edges {
			out = append(out, event{
				id:   eventID(serverID, group.kind, e.jail, e.ip, now),
				kind: group.kind, jail: e.jail, ip: e.ip, serverID: serverID, firstSeen: now,
			})
		}
	}
	return out
}

// Appends events, dropping the oldest beyond max; returns how many were dropped.
func enqueue(queue, events []event, max int) ([]event, int) {
	queue = append(queue, events...)
	if over := len(queue) - max; over > 0 {
		return append([]event(nil), queue[over:]...), over
	}
	return queue, 0
}

func dropExpired(queue []event, now time.Time, ttl time.Duration) ([]event, int) {
	kept := queue[:0]
	for _, e := range queue {
		if now.Sub(e.firstSeen) < ttl {
			kept = append(kept, e)
		}
	}
	return kept, len(queue) - len(kept)
}

func keepServer(queue []event, serverID string) []event {
	kept := queue[:0]
	for _, e := range queue {
		if e.serverID == serverID {
			kept = append(kept, e)
		}
	}
	return kept
}

type edge struct {
	jail, ip string
}

func snapshotFromJailInfos(infos []model.JailInfo) map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{})
	for _, j := range infos {
		name := strings.TrimSpace(j.JailName)
		if name == "" {
			continue
		}
		set := make(map[string]struct{})
		for _, ip := range j.BannedIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				set[ip] = struct{}{}
			}
		}
		out[name] = set
	}
	return out
}

// Only jails present in both snapshots are compared, so a jail vanishing or appearing across a reload is not a mass ban/unban.
func diffSnapshots(prev, cur map[string]map[string]struct{}) (bans, unbans []edge) {
	for jail, ips := range cur {
		oldSet, ok := prev[jail]
		if !ok {
			continue
		}
		for ip := range ips {
			if _, ok := oldSet[ip]; !ok {
				bans = append(bans, edge{jail: jail, ip: ip})
			}
		}
		for ip := range oldSet {
			if _, ok := ips[ip]; !ok {
				unbans = append(unbans, edge{jail: jail, ip: ip})
			}
		}
	}
	sortEdges(bans)
	sortEdges(unbans)
	return bans, unbans
}

func sortEdges(edges []edge) {
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].jail != edges[j].jail {
			return edges[i].jail < edges[j].jail
		}
		return edges[i].ip < edges[j].ip
	})
}
