// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU General Public License, Version 3 (GPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/gpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package health

import (
	"context"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/model"
)

type Fail2banOps interface {
	Ping(ctx context.Context) error
	Reload(ctx context.Context) error
	Restart(ctx context.Context) error
}

type Supervisor struct {
	ops         Fail2banOps
	interval    time.Duration
	autoReload  bool
	autoRestart bool
	maxRetries  int

	mu    sync.RWMutex
	state model.HealthState
}

func New(ops Fail2banOps, interval time.Duration, autoReload, autoRestart bool, maxRetries int) *Supervisor {
	if maxRetries < 1 {
		maxRetries = 1
	}
	return &Supervisor{
		ops:         ops,
		interval:    interval,
		autoReload:  autoReload,
		autoRestart: autoRestart,
		maxRetries:  maxRetries,
		state: model.HealthState{
			Healthy: true,
		},
	}
}

func (s *Supervisor) Start(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	s.check(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.check(ctx)
		}
	}
}

func (s *Supervisor) State() model.HealthState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *Supervisor) check(ctx context.Context) {
	checkTime := time.Now().UTC()
	err := s.ops.Ping(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.LastCheck = checkTime
	if err == nil {
		s.state.Healthy = true
		s.state.LastError = ""
		s.state.ConsecutiveFails = 0
		s.state.LastSuccess = checkTime
		return
	}

	s.state.Healthy = false
	s.state.LastError = err.Error()
	s.state.ConsecutiveFails++
	if s.state.ConsecutiveFails < s.maxRetries {
		return
	}

	if s.autoReload {
		if rErr := s.ops.Reload(ctx); rErr == nil {
			s.state.LastRemediation = "reload"
			s.state.ConsecutiveFails = 0
			return
		}
	}
	if s.autoRestart {
		if rsErr := s.ops.Restart(ctx); rsErr == nil {
			s.state.LastRemediation = "restart"
			s.state.ConsecutiveFails = 0
			return
		}
	}
}
