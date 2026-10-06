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
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/model"
)

// Plain fields are set before the supervisor starts; counters are atomic since remediation runs on its goroutine.
type fakeOps struct {
	pingErr        error
	stopped        bool
	restartBlock   chan struct{}
	restartEntered chan struct{}
	reloads        atomic.Int32
	restarts       atomic.Int32
}

var allPresent = model.Environment{ConfigWritable: true, Fail2banClient: true, Fail2banRegex: true}

func (f *fakeOps) Ping(context.Context) error             { return f.pingErr }
func (f *fakeOps) StoppedByAdmin(context.Context) bool    { return f.stopped }
func (f *fakeOps) Environment() model.Environment         { return allPresent }
func (f *fakeOps) Reload(context.Context) (string, error) { f.reloads.Add(1); return "", nil }
func (f *fakeOps) Restart(ctx context.Context) (string, error) {
	f.restarts.Add(1)
	if f.restartEntered != nil {
		close(f.restartEntered)
	}
	if f.restartBlock != nil {
		select {
		case <-f.restartBlock:
		case <-ctx.Done():
		}
	}
	return "restart", nil
}

func newTestSupervisor(ops *fakeOps, p Policy, clock *time.Time) *Supervisor {
	s := New(ops, p)
	s.now = func() time.Time { return *clock }
	return s
}

func TestPlanRemediation(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	both := Policy{Interval: 30 * time.Second, MaxRetries: 2, AutoReload: true, AutoRestart: true}
	failing := func(fails, attempts int, since time.Duration) model.HealthState {
		return model.HealthState{ConsecutiveFails: fails, RemediationAttempts: attempts, LastRemediationAt: now.Add(-since)}
	}
	cases := []struct {
		name string
		st   model.HealthState
		p    Policy
		want string
	}{
		{"healthy", model.HealthState{PingOK: true, ConsecutiveFails: 9}, both, actionNone},
		{"below max retries", failing(1, 0, 0), both, actionNone},
		{"first attempt reloads", failing(2, 0, 0), both, actionReload},
		{"first attempt restarts without auto-reload", failing(2, 0, 0), Policy{Interval: time.Minute, MaxRetries: 2, AutoRestart: true}, actionRestart},
		{"later attempt restarts after backoff", failing(5, 1, time.Minute), both, actionRestart},
		{"later attempt waits for backoff", failing(5, 1, time.Minute-time.Nanosecond), both, actionNone},
		{"later attempt reloads without auto-restart", failing(5, 2, 2*time.Minute), Policy{Interval: 30 * time.Second, MaxRetries: 2, AutoReload: true}, actionReload},
		{"backoff capped at 30 minutes", failing(9, 4, 30*time.Minute), Policy{Interval: 10 * time.Minute, MaxRetries: 1, AutoRestart: true}, actionRestart},
		{"capped backoff still waits", failing(9, 4, 29*time.Minute), Policy{Interval: 10 * time.Minute, MaxRetries: 1, AutoRestart: true}, actionNone},
		{"both disabled", failing(9, 0, 0), Policy{Interval: time.Minute, MaxRetries: 1}, actionNone},
		{"stopped by administrator", model.HealthState{ConsecutiveFails: 9, StoppedByAdmin: true}, both, actionNone},
		{"suspended", model.HealthState{ConsecutiveFails: 9, RemediationSuspended: true}, both, actionNone},
		{"attempt budget exhausted", failing(9, maxRemediationAttempts, time.Hour), both, actionNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := planRemediation(tc.st, now, tc.p); got != tc.want {
				t.Fatalf("planRemediation = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRemediationBackoff(t *testing.T) {
	cases := []struct {
		interval time.Duration
		attempts int
		want     time.Duration
	}{
		{30 * time.Second, 1, time.Minute},
		{30 * time.Second, 4, 8 * time.Minute},
		{10 * time.Minute, 2, maxRemediationBackoff},
		{time.Hour, 60, maxRemediationBackoff},
	}
	for _, tc := range cases {
		if got := remediationBackoff(tc.interval, tc.attempts); got != tc.want {
			t.Errorf("remediationBackoff(%v, %d) = %v, want %v", tc.interval, tc.attempts, got, tc.want)
		}
	}
}

func TestReady(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	interval := 30 * time.Second
	good := model.HealthState{PingOK: true, Env: allPresent, LastCheck: now.Add(-interval)}
	cases := []struct {
		name   string
		mutate func(*model.HealthState)
		want   bool
	}{
		{"fresh and complete", func(*model.HealthState) {}, true},
		{"never checked", func(st *model.HealthState) { st.LastCheck = time.Time{} }, false},
		{"stale", func(st *model.HealthState) { st.LastCheck = now.Add(-3 * interval) }, false},
		{"no pong", func(st *model.HealthState) { st.PingOK = false }, false},
		{"config root read-only", func(st *model.HealthState) { st.Env.ConfigWritable = false }, false},
		{"fail2ban-client missing", func(st *model.HealthState) { st.Env.Fail2banClient = false }, false},
		{"fail2ban-regex missing", func(st *model.HealthState) { st.Env.Fail2banRegex = false }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := good
			tc.mutate(&st)
			if got, _ := Ready(st, now, interval); got != tc.want {
				t.Fatalf("Ready = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestInitialStateIsNotReady(t *testing.T) {
	s := New(&fakeOps{}, Policy{Interval: time.Minute})
	if ready, _ := Ready(s.State(), time.Now(), s.Interval()); ready {
		t.Fatal("a supervisor that has not checked yet must not be ready")
	}
}

func TestSupervisorRemediationSequence(t *testing.T) {
	clock := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	ops := &fakeOps{pingErr: errors.New("ping failed")}
	p := Policy{Interval: 30 * time.Second, MaxRetries: 2, AutoReload: true, AutoRestart: true}
	s := newTestSupervisor(ops, p, &clock)
	ctx := context.Background()

	s.check(ctx)
	if ops.reloads.Load() != 0 || ops.restarts.Load() != 0 {
		t.Fatal("remediated before reaching max retries")
	}
	s.check(ctx)
	if ops.reloads.Load() != 1 || s.State().LastRemediation != "reload" {
		t.Fatalf("first remediation must be a reload: %+v", s.State())
	}
	s.check(ctx)
	if ops.restarts.Load() != 0 {
		t.Fatal("restart ignored the backoff")
	}
	clock = clock.Add(2 * p.Interval)
	s.check(ctx)
	if ops.restarts.Load() != 1 || s.State().RemediationAttempts != 2 {
		t.Fatalf("second remediation must be a restart: %+v", s.State())
	}

	ops.pingErr = nil
	s.check(ctx)
	st := s.State()
	if !st.PingOK || st.ConsecutiveFails != 0 || st.RemediationAttempts != 0 || st.LastError != "" {
		t.Fatalf("successful ping must reset the failure state: %+v", st)
	}
}

func TestSupervisorSuspendsAfterMaxAttempts(t *testing.T) {
	clock := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	ops := &fakeOps{pingErr: errors.New("down")}
	s := newTestSupervisor(ops, Policy{Interval: time.Second, MaxRetries: 1, AutoRestart: true}, &clock)
	for i := 0; i < 10; i++ {
		s.check(context.Background())
		clock = clock.Add(time.Hour)
	}
	if got := ops.restarts.Load(); got != maxRemediationAttempts {
		t.Fatalf("restarts = %d, want %d", got, maxRemediationAttempts)
	}
	if !s.State().RemediationSuspended {
		t.Fatal("remediation not suspended after the attempt budget")
	}
	ops.pingErr = nil
	s.check(context.Background())
	if s.State().RemediationSuspended {
		t.Fatal("a successful ping must lift the suspension")
	}
}

func TestSupervisorSkipsWhenStoppedByAdmin(t *testing.T) {
	clock := time.Now()
	ops := &fakeOps{pingErr: errors.New("down"), stopped: true}
	s := newTestSupervisor(ops, Policy{Interval: time.Second, MaxRetries: 1, AutoReload: true, AutoRestart: true}, &clock)
	s.check(context.Background())
	if ops.reloads.Load() != 0 || ops.restarts.Load() != 0 {
		t.Fatal("remediated a service the administrator stopped")
	}
	if got := s.State().LastRemediation; got != stoppedByAdminNote {
		t.Fatalf("lastRemediation = %q", got)
	}
}

func TestStateNotBlockedDuringRemediation(t *testing.T) {
	ops := &fakeOps{
		pingErr:        errors.New("down"),
		restartBlock:   make(chan struct{}),
		restartEntered: make(chan struct{}),
	}
	s := New(ops, Policy{Interval: time.Second, MaxRetries: 1, AutoRestart: true})
	done := make(chan struct{})
	go func() {
		s.check(context.Background())
		close(done)
	}()
	<-ops.restartEntered

	got := make(chan model.HealthState, 1)
	go func() { got <- s.State() }()
	select {
	case st := <-got:
		if st.ConsecutiveFails != 1 {
			t.Errorf("state during remediation = %+v", st)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("State() blocked while remediation was running")
	}
	close(ops.restartBlock)
	<-done
}
