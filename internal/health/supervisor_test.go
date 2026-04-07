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
	"errors"
	"testing"
	"time"
)

type fakeOps struct {
	pingErr   error
	reloaded  bool
	restarted bool
}

func (f *fakeOps) Ping(ctx context.Context) error { return f.pingErr }
func (f *fakeOps) Reload(ctx context.Context) error {
	f.reloaded = true
	return nil
}
func (f *fakeOps) Restart(ctx context.Context) error {
	f.restarted = true
	return nil
}

func TestSupervisorHealthy(t *testing.T) {
	ops := &fakeOps{}
	s := New(ops, 10*time.Millisecond, true, true, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go s.Start(ctx)
	time.Sleep(25 * time.Millisecond)
	cancel()
	state := s.State()
	if !state.Healthy {
		t.Fatalf("expected healthy state, got %+v", state)
	}
}

func TestSupervisorRemediation(t *testing.T) {
	ops := &fakeOps{pingErr: errors.New("ping failed")}
	s := New(ops, 10*time.Millisecond, true, true, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go s.Start(ctx)
	time.Sleep(25 * time.Millisecond)
	cancel()
	if !ops.reloaded {
		t.Fatal("expected reload remediation")
	}
}
