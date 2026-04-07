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

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/config"
	"github.com/swissmakers/fail2ban-ui-agent/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui-agent/internal/health"
)

func TestAuthRequired(t *testing.T) {
	svc := fail2ban.NewService(t.TempDir(), "/var/run/fail2ban", "/var/log")
	hs := health.New(svc, time.Hour, false, false, 1)
	s := New("secret", t.TempDir(), svc, hs)

	req := httptest.NewRequest(http.MethodPost, "/v1/actions/reload", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHealthEndpoint(t *testing.T) {
	svc := fail2ban.NewService(t.TempDir(), "/var/run/fail2ban", "/var/log")
	hs := health.New(svc, time.Hour, false, false, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go hs.Start(ctx)
	defer cancel()
	time.Sleep(10 * time.Millisecond)

	s := New("secret", t.TempDir(), svc, hs)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK && rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected status %d", rr.Code)
	}
}

func TestLogpathResolutionEndpointShape(t *testing.T) {
	cfgRoot := t.TempDir()
	logRoot := filepath.Join(t.TempDir(), "logs")
	if err := os.MkdirAll(logRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logRoot, "auth.log"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	svc := fail2ban.NewService(cfgRoot, "/var/run/fail2ban", logRoot)
	hs := health.New(svc, time.Hour, false, false, 1)
	s := New("secret", cfgRoot, svc, hs)

	body := `{"logpath":"/var/log/auth.log"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/jails/test-logpath-with-resolution", strings.NewReader(body))
	req.Header.Set("X-F2B-Token", "secret")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Original string   `json:"original_logpath"`
		Resolved string   `json:"resolved_logpath"`
		Files    []string `json:"files"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp.Original == "" || resp.Resolved == "" {
		t.Fatalf("missing fields: %+v", resp)
	}
}

func TestCallbackConfigEndpointPersists(t *testing.T) {
	cfgRoot := t.TempDir()
	svc := fail2ban.NewService(cfgRoot, "/var/run/fail2ban", "/var/log")
	hs := health.New(svc, time.Hour, false, false, 1)
	s := New("secret", cfgRoot, svc, hs)

	body := `{"serverId":"srv-abc","callbackUrl":"http://ui/dev","callbackSecret":"cb-secret","callbackHostname":"agent-host"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/callback/config", strings.NewReader(body))
	req.Header.Set("X-F2B-Token", "secret")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	got, err := config.LoadCallbackRuntimeConfig(cfgRoot)
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerID != "srv-abc" || got.CallbackURL == "" || got.CallbackSecret == "" {
		t.Fatalf("persisted callback config mismatch: %+v", got)
	}
}

func TestEnsureStructureEndpointUsesProvidedContent(t *testing.T) {
	cfgRoot := t.TempDir()
	svc := fail2ban.NewService(cfgRoot, "/var/run/fail2ban", "/var/log")
	hs := health.New(svc, time.Hour, false, false, 1)
	s := New("secret", cfgRoot, svc, hs)

	body := `{"content":"[DEFAULT]\nenabled = true\naction = ui-custom-action\n"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/jails/ensure-structure", strings.NewReader(body))
	req.Header.Set("X-F2B-Token", "secret")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(cfgRoot, "jail.local"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if !strings.Contains(got, "enabled = true") {
		t.Fatalf("expected provided content to be written: %s", got)
	}
	if strings.Contains(got, "ui-custom-action") {
		t.Fatalf("legacy action should be stripped: %s", got)
	}
}
