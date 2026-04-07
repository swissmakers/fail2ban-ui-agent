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
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/config"
	"github.com/swissmakers/fail2ban-ui-agent/internal/model"
)

func TestDiffSnapshots(t *testing.T) {
	prev := map[string]map[string]struct{}{
		"ssh": {"1.1.1.1": {}, "2.2.2.2": {}},
	}
	cur := map[string]map[string]struct{}{
		"ssh": {"2.2.2.2": {}, "3.3.3.3": {}},
	}
	bans, unbans := diffSnapshots(prev, cur)
	wantBans := []edge{{jail: "ssh", ip: "3.3.3.3"}}
	wantUnbans := []edge{{jail: "ssh", ip: "1.1.1.1"}}
	if !reflect.DeepEqual(bans, wantBans) {
		t.Errorf("bans = %#v, want %#v", bans, wantBans)
	}
	if !reflect.DeepEqual(unbans, wantUnbans) {
		t.Errorf("unbans = %#v, want %#v", unbans, wantUnbans)
	}
}

func TestSnapshotFromJailInfos(t *testing.T) {
	s := snapshotFromJailInfos([]model.JailInfo{
		{JailName: "ssh", BannedIPs: []string{" 10.0.0.1 ", ""}},
		{JailName: "", BannedIPs: []string{"9.9.9.9"}},
	})
	if len(s) != 1 || len(s["ssh"]) != 1 {
		t.Fatalf("snapshot = %#v", s)
	}
	if _, ok := s["ssh"]["10.0.0.1"]; !ok {
		t.Fatal("expected 10.0.0.1 in ssh")
	}
}

type fakeReader struct{}

func (fakeReader) GetJailInfos(ctx context.Context) ([]model.JailInfo, error) {
	return nil, nil
}

func TestShouldStartPoller(t *testing.T) {
	baseCfg := config.Config{
		CallbackPollInterval: 4 * time.Second,
	}
	if got := shouldStartPoller(baseCfg); !got {
		t.Fatal("expected poller to start for baseline config")
	}

	withNoInterval := baseCfg
	withNoInterval.CallbackPollInterval = 0
	if got := shouldStartPoller(withNoInterval); got {
		t.Fatal("expected poller disabled when interval is 0")
	}
}

func TestCurrentCallbackRuntimePrefersStoredConfig(t *testing.T) {
	root := t.TempDir()
	if err := config.SaveCallbackRuntimeConfig(root, config.CallbackRuntimeConfig{
		ServerID:       "srv-stored",
		CallbackURL:    "http://stored-ui",
		CallbackSecret: "stored-secret",
		CallbackHost:   "stored-host",
	}); err != nil {
		t.Fatal(err)
	}
	p := &Poller{
		configRoot:       root,
		fallbackURL:      "http://fallback",
		fallbackSecret:   "fallback-secret",
		fallbackServerID: "srv-fallback",
		fallbackHostname: "fallback-host",
	}
	rt, ok := p.currentCallbackRuntime()
	if !ok {
		t.Fatal("expected runtime config to be available")
	}
	if rt.serverID != "srv-stored" || rt.url != "http://stored-ui" || rt.secret != "stored-secret" || rt.hostname != "stored-host" {
		t.Fatalf("unexpected runtime config: %+v", rt)
	}
}

func TestCurrentCallbackRuntimeUsesFallbackWhenStoreMissing(t *testing.T) {
	p := &Poller{
		configRoot:       t.TempDir(),
		fallbackURL:      "http://fallback",
		fallbackSecret:   "fallback-secret",
		fallbackServerID: "srv-fallback",
		fallbackHostname: "fallback-host",
	}
	rt, ok := p.currentCallbackRuntime()
	if !ok {
		t.Fatal("expected fallback runtime config")
	}
	if rt.serverID != "srv-fallback" || rt.url != "http://fallback" || rt.secret != "fallback-secret" || rt.hostname != "fallback-host" {
		t.Fatalf("unexpected runtime config: %+v", rt)
	}
}
