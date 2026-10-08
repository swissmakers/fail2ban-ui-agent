// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/model"
)

const (
	maxRemediationAttempts = 5
	maxRemediationBackoff  = 30 * time.Minute
	remediationTimeout     = 60 * time.Second
	stoppedByAdminNote     = "skipped: stopped by administrator"

	actionNone    = ""
	actionReload  = "reload"
	actionRestart = "restart"
)

type Fail2banOps interface {
	Ping(ctx context.Context) error
	Reload(ctx context.Context) (string, error)
	Restart(ctx context.Context) (string, error)
	StoppedByAdmin(ctx context.Context) bool
	Environment() model.Environment
}

type Policy struct {
	Interval    time.Duration
	MaxRetries  int
	AutoReload  bool
	AutoRestart bool
}

type Supervisor struct {
	ops    Fail2banOps
	policy Policy
	now    func() time.Time

	mu    sync.RWMutex
	state model.HealthState
	wake  chan struct{}
}

// The zero state is not ready: nothing counts as healthy before the first successful check.
func New(ops Fail2banOps, p Policy) *Supervisor {
	if p.MaxRetries < 1 {
		p.MaxRetries = 1
	}
	return &Supervisor{ops: ops, policy: p, wake: make(chan struct{}, 1), now: func() time.Time { return time.Now().UTC() }}
}

// Wake refreshes daemon health promptly after a long command releases its
// gate. Coalescing avoids a backlog of probes after closely spaced writes.
func (s *Supervisor) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Supervisor) Start(ctx context.Context) {
	t := time.NewTicker(s.policy.Interval)
	defer t.Stop()
	s.check(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.check(ctx)
		case <-s.wake:
			s.checkWithRemediation(ctx, false)
		}
	}
}

func (s *Supervisor) State() model.HealthState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *Supervisor) Interval() time.Duration { return s.policy.Interval }

// Probes run outside the lock so State() never waits on fail2ban-client.
func (s *Supervisor) check(ctx context.Context) {
	s.checkWithRemediation(ctx, true)
}

func (s *Supervisor) checkWithRemediation(ctx context.Context, allowRemediation bool) {
	// Ping uses the same daemon socket as reload. A known operation may keep
	// that socket occupied without any loss of transport or daemon health.
	if busy, ok := s.ops.(interface{ Busy() bool }); ok && busy.Busy() {
		return
	}
	pingErr := s.ops.Ping(ctx)
	if busy, ok := s.ops.(interface{ Busy() bool }); ok && busy.Busy() {
		return
	}
	env := s.ops.Environment()
	stopped := pingErr != nil && s.ops.StoppedByAdmin(ctx)
	now := s.now()

	s.mu.Lock()
	st := &s.state
	st.LastCheck = now
	st.Env = env
	st.StoppedByAdmin = stopped
	if pingErr == nil {
		st.PingOK = true
		st.LastSuccess = now
		st.LastError = ""
		st.ConsecutiveFails = 0
		st.RemediationAttempts = 0
		st.RemediationSuspended = false
		s.mu.Unlock()
		return
	}
	st.PingOK = false
	st.LastError = pingErr.Error()
	st.ConsecutiveFails++
	if stopped && st.ConsecutiveFails >= s.policy.MaxRetries {
		st.LastRemediation = stoppedByAdminNote
	}
	action := planRemediation(*st, now, s.policy)
	s.mu.Unlock()

	if action != actionNone && allowRemediation {
		s.remediate(ctx, action)
	}
}

func (s *Supervisor) remediate(ctx context.Context, action string) {
	if busy, ok := s.ops.(interface{ Busy() bool }); ok && busy.Busy() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, remediationTimeout)
	defer cancel()
	result := action
	var err error
	if action == actionReload {
		_, err = s.ops.Reload(ctx)
	} else {
		var mode string
		if mode, err = s.ops.Restart(ctx); mode != "" {
			result = mode
		}
	}
	if err != nil {
		result = fmt.Sprintf("%s failed: %v", result, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.RemediationAttempts++
	s.state.LastRemediationAt = s.now()
	s.state.LastRemediation = result
	s.state.RemediationSuspended = s.state.RemediationAttempts >= maxRemediationAttempts
}

// Reload first, restart on later attempts, with exponential backoff; nothing while stopped by an admin or suspended.
func planRemediation(st model.HealthState, now time.Time, p Policy) string {
	if st.PingOK || st.ConsecutiveFails < p.MaxRetries || st.StoppedByAdmin ||
		st.RemediationSuspended || st.RemediationAttempts >= maxRemediationAttempts {
		return actionNone
	}
	if st.RemediationAttempts > 0 && now.Before(st.LastRemediationAt.Add(remediationBackoff(p.Interval, st.RemediationAttempts))) {
		return actionNone
	}
	switch {
	case p.AutoReload && (st.RemediationAttempts == 0 || !p.AutoRestart):
		return actionReload
	case p.AutoRestart:
		return actionRestart
	}
	return actionNone
}

func remediationBackoff(interval time.Duration, attempts int) time.Duration {
	if d := interval << attempts; d > 0 && d < maxRemediationBackoff {
		return d
	}
	return maxRemediationBackoff
}

// Ready is true only for a fresh check (< 3 intervals old) that saw pong and all host prerequisites.
func Ready(st model.HealthState, now time.Time, interval time.Duration) (bool, model.ReadyChecks) {
	c := model.ReadyChecks{
		Ping:           st.PingOK,
		ConfigWritable: st.Env.ConfigWritable,
		Fail2banClient: st.Env.Fail2banClient,
		Fail2banRegex:  st.Env.Fail2banRegex,
		Fresh:          !st.LastCheck.IsZero() && now.Sub(st.LastCheck) < 3*interval,
	}
	return c.Ping && c.ConfigWritable && c.Fail2banClient && c.Fail2banRegex && c.Fresh, c
}
