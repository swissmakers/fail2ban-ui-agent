// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU General Public License, Version 3 (GPL-3.0)
// You may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/gpl-3.0.en.html
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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/config"
	"github.com/swissmakers/fail2ban-ui-agent/internal/model"
)

// JailReader fetches current jail / banned-IP state (fail2ban-client).
type JailReader interface {
	GetJailInfos(ctx context.Context) ([]model.JailInfo, error)
}

type callbackRuntime struct {
	url      string
	secret   string
	serverID string
	hostname string
}

// Poller periodically diffs banned IPs and POSTs /api/ban and /api/unban to Fail2ban-UI.
type Poller struct {
	configRoot string

	fallbackURL      string
	fallbackSecret   string
	fallbackServerID string
	fallbackHostname string

	interval   time.Duration
	svc        JailReader
	httpClient *http.Client
	log        *log.Logger
}

// NewPoller builds a poller. cfg.CallbackPollInterval must be > 0; caller should also ensure URL and secret are set.
func NewPoller(cfg config.Config, svc JailReader, logger *log.Logger) *Poller {
	if logger == nil {
		logger = log.Default()
	}
	hn := cfg.CallbackHostname
	if hn == "" {
		var err error
		hn, err = os.Hostname()
		if err != nil {
			hn = ""
		}
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.CallbackURL), "/")
	return &Poller{
		configRoot: cfg.ConfigRoot,

		fallbackURL:      base,
		fallbackSecret:   cfg.CallbackSecret,
		fallbackServerID: cfg.CallbackServerID,
		fallbackHostname: hn,

		interval:   cfg.CallbackPollInterval,
		svc:        svc,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		log:        logger,
	}
}

// Run blocks until ctx is cancelled. The first observation establishes a baseline (no callbacks).
func (p *Poller) Run(ctx context.Context) {
	if p.interval <= 0 {
		return
	}
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	var prev map[string]map[string]struct{}
	for {
		p.tick(ctx, &prev)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (p *Poller) tick(ctx context.Context, prev *map[string]map[string]struct{}) {
	rt, ok := p.currentCallbackRuntime()
	if !ok {
		return
	}
	infos, err := p.svc.GetJailInfos(ctx)
	if err != nil {
		p.log.Printf("callback poller: GetJailInfos: %v", err)
		return
	}
	cur := snapshotFromJailInfos(infos)
	if *prev == nil {
		*prev = cur
		return
	}
	bans, unbans := diffSnapshots(*prev, cur)
	*prev = cur

	for _, e := range bans {
		if err := p.postBan(ctx, rt, e.jail, e.ip); err != nil {
			p.log.Printf("callback poller: ban notify %s %s: %v", e.jail, e.ip, err)
		}
	}
	for _, e := range unbans {
		if err := p.postUnban(ctx, rt, e.jail, e.ip); err != nil {
			p.log.Printf("callback poller: unban notify %s %s: %v", e.jail, e.ip, err)
		}
	}
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

func diffSnapshots(prev, cur map[string]map[string]struct{}) (bans, unbans []edge) {
	for jail, ips := range cur {
		oldSet := prev[jail]
		for ip := range ips {
			if _, ok := oldSet[ip]; !ok {
				bans = append(bans, edge{jail: jail, ip: ip})
			}
		}
	}
	for jail, ips := range prev {
		newSet := cur[jail]
		for ip := range ips {
			if _, ok := newSet[ip]; !ok {
				unbans = append(unbans, edge{jail: jail, ip: ip})
			}
		}
	}
	return bans, unbans
}

func (p *Poller) postBan(ctx context.Context, rt callbackRuntime, jail, ip string) error {
	body := map[string]string{
		"ip":   ip,
		"jail": jail,
	}
	if rt.serverID != "" {
		body["serverId"] = rt.serverID
	}
	if rt.hostname != "" {
		body["hostname"] = rt.hostname
	}
	return p.postJSON(ctx, rt, "/api/ban", body)
}

func (p *Poller) postUnban(ctx context.Context, rt callbackRuntime, jail, ip string) error {
	body := map[string]string{
		"ip":   ip,
		"jail": jail,
	}
	if rt.serverID != "" {
		body["serverId"] = rt.serverID
	}
	if rt.hostname != "" {
		body["hostname"] = rt.hostname
	}
	return p.postJSON(ctx, rt, "/api/unban", body)
}

func (p *Poller) postJSON(ctx context.Context, rt callbackRuntime, endpoint string, body map[string]string) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := strings.TrimRight(rt.url, "/") + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Callback-Secret", rt.secret)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	return nil
}

func shouldStartPoller(cfg config.Config) bool {
	if cfg.CallbackPollInterval <= 0 {
		return false
	}
	return true
}

// StartPoller runs NewPoller(...).Run in a goroutine if polling is enabled.
func StartPoller(ctx context.Context, cfg config.Config, svc JailReader, logger *log.Logger) {
	if logger == nil {
		logger = log.Default()
	}
	if !shouldStartPoller(cfg) {
		return
	}
	p := NewPoller(cfg, svc, logger)
	go p.Run(ctx)
}

func (p *Poller) currentCallbackRuntime() (callbackRuntime, bool) {
	stored, err := config.LoadCallbackRuntimeConfig(p.configRoot)
	if err != nil {
		p.log.Printf("callback poller: cannot read callback runtime config: %v", err)
	}
	rt := callbackRuntime{
		url:      strings.TrimSpace(stored.CallbackURL),
		secret:   strings.TrimSpace(stored.CallbackSecret),
		serverID: strings.TrimSpace(stored.ServerID),
		hostname: strings.TrimSpace(stored.CallbackHost),
	}
	if rt.url == "" {
		rt.url = p.fallbackURL
	}
	if rt.secret == "" {
		rt.secret = p.fallbackSecret
	}
	if rt.serverID == "" {
		rt.serverID = p.fallbackServerID
	}
	if rt.hostname == "" {
		rt.hostname = p.fallbackHostname
	}
	if rt.url == "" || rt.secret == "" || rt.serverID == "" {
		return callbackRuntime{}, false
	}
	return rt, true
}
