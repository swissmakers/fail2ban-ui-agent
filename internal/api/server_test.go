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
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON body: %v", err)
	}
	if got, _ := payload["code"].(string); got != "auth_invalid_token" {
		t.Fatalf("code=%q want %q", got, "auth_invalid_token")
	}
}

func TestEmptySecretFailsClosed(t *testing.T) {
	svc := fail2ban.NewService(t.TempDir(), "/var/run/fail2ban", "/var/log")
	hs := health.New(svc, time.Hour, false, false, 1)
	s := New("", t.TempDir(), svc, hs) // no secret configured

	// An empty token must NOT authenticate when the secret is empty.
	req := httptest.NewRequest(http.MethodPost, "/v1/actions/reload", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("empty secret authenticated a request (status=%d)", rr.Code)
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestRequestBodyIsBounded(t *testing.T) {
	cfgRoot := t.TempDir()
	svc := fail2ban.NewService(cfgRoot, "/var/run/fail2ban", "/var/log")
	hs := health.New(svc, time.Hour, false, false, 1)
	s := New("secret", cfgRoot, svc, hs)

	// A body larger than maxRequestBodyBytes must be rejected, not written.
	huge := `{"name":"okjail","content":"` + strings.Repeat("A", maxRequestBodyBytes+1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/jails", strings.NewReader(huge))
	req.Header.Set("X-F2B-Token", "secret")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code == http.StatusCreated || rr.Code == http.StatusOK {
		t.Fatalf("oversized body accepted (status=%d)", rr.Code)
	}
	if _, err := os.Stat(filepath.Join(cfgRoot, "jail.d", "okjail.local")); err == nil {
		t.Fatal("oversized body was written to disk")
	}
}

func TestCreateJailRejectsTraversalName(t *testing.T) {
	cfgRoot := t.TempDir()
	svc := fail2ban.NewService(cfgRoot, "/var/run/fail2ban", "/var/log")
	hs := health.New(svc, time.Hour, false, false, 1)
	s := New("secret", cfgRoot, svc, hs)

	body := `{"name":"../../../../../../tmp/f2b-agent-pwn","content":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/jails", strings.NewReader(body))
	req.Header.Set("X-F2B-Token", "secret")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code == http.StatusCreated || rr.Code == http.StatusOK {
		t.Fatalf("traversal jail name accepted (status=%d)", rr.Code)
	}
	if _, err := os.Stat("/tmp/f2b-agent-pwn.local"); err == nil {
		os.Remove("/tmp/f2b-agent-pwn.local")
		t.Fatal("traversal escaped the config root")
	}
}

func TestHealthRedactsErrorForAnonymous(t *testing.T) {
	svc := fail2ban.NewService(t.TempDir(), "/var/run/fail2ban", "/var/log")
	hs := health.New(svc, time.Hour, false, false, 1)
	s := New("secret", t.TempDir(), svc, hs)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil) // no token
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	var state map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &state)
	if _, present := state["lastError"]; present {
		t.Fatal("anonymous /healthz leaked lastError")
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

func TestEnsureStructureEndpointRejectsInvalidJSON(t *testing.T) {
	cfgRoot := t.TempDir()
	svc := fail2ban.NewService(cfgRoot, "/var/run/fail2ban", "/var/log")
	hs := health.New(svc, time.Hour, false, false, 1)
	s := New("secret", cfgRoot, svc, hs)

	req := httptest.NewRequest(http.MethodPost, "/v1/jails/ensure-structure", strings.NewReader("{invalid"))
	req.Header.Set("X-F2B-Token", "secret")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid JSON") {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func TestActionReloadReturnsOutput(t *testing.T) {
	cfgRoot := t.TempDir()
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(binDir, "fail2ban-client")
	script := "#!/usr/bin/env sh\nif [ \"$1\" = \"reload\" ]; then\n  echo \"reload-ok\"\n  exit 0\nfi\nexit 1\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	svc := fail2ban.NewService(cfgRoot, "/var/run/fail2ban", "/var/log")
	hs := health.New(svc, time.Hour, false, false, 1)
	s := New("secret", cfgRoot, svc, hs)

	req := httptest.NewRequest(http.MethodPost, "/v1/actions/reload", nil)
	req.Header.Set("X-F2B-Token", "secret")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK     bool   `json:"ok"`
		Output string `json:"output"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected ok=true, got %+v", resp)
	}
	if !strings.Contains(resp.Output, "reload-ok") {
		t.Fatalf("expected reload output in response, got: %q", resp.Output)
	}
}
