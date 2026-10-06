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
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/callback"
	"github.com/swissmakers/fail2ban-ui-agent/internal/config"
	"github.com/swissmakers/fail2ban-ui-agent/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui-agent/internal/health"
	"github.com/swissmakers/fail2ban-ui-agent/internal/version"
)

const testSecret = "test-agent-secret-0123456789"

// Installs fake tools as the only PATH entry, so the host's real fail2ban and service managers are never reached.
func fakeTools(t *testing.T, scripts map[string]string) {
	t.Helper()
	bin := t.TempDir()
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
}

// fail2ban-client answering pong, a version and one jail with one ban; "-c <root>" is dropped first.
const fakeClient = `[ "$1" = "-c" ] && shift 2
case "$1" in
ping) echo "Server replied: pong" ;;
version) echo "1.1.0" ;;
reload) echo "reload-ok" ;;
status) if [ -n "$2" ]; then echo "Currently banned: 1"; echo "Banned IP list: 192.0.2.1"; else echo "Jail list: sshd"; fi ;;
*) exit 1 ;;
esac
`

type harness struct {
	s    *Server
	root string
	hs   *health.Supervisor
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	cfg := config.Config{Secret: testSecret, ConfigRoot: root, LogRoot: "/var/log", CallbackPollInterval: 4 * time.Second}
	svc := fail2ban.NewService(root, "/var/log")
	hs := health.New(svc, health.Policy{Interval: time.Hour, MaxRetries: 1})
	return &harness{s: New(cfg, svc, hs, callback.NewPoller(cfg, svc, log.New(io.Discard, "", 0))), root: root, hs: hs}
}

func (h *harness) do(method, path, body string, authed bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if authed {
		req.Header.Set("X-F2B-Token", testSecret)
	}
	rr := httptest.NewRecorder()
	h.s.mux.ServeHTTP(rr, req)
	return rr
}

// Runs the supervisor until it has recorded its first check.
func (h *harness) startSupervisor(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go h.hs.Start(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for h.hs.State().LastCheck.IsZero() {
		if time.Now().After(deadline) {
			t.Fatal("supervisor never checked")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func decode(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON body %q: %v", rr.Body.String(), err)
	}
	return out
}

func TestAuthRequired(t *testing.T) {
	h := newHarness(t)
	rr := h.do(http.MethodPost, "/v1/actions/reload", "", false)
	if rr.Code != http.StatusUnauthorized || decode(t, rr)["code"] != "auth_invalid_token" {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestEmptySecretFailsClosed(t *testing.T) {
	root := t.TempDir()
	svc := fail2ban.NewService(root, "/var/log")
	// no secret configured
	cfg := config.Config{ConfigRoot: root}
	s := New(cfg, svc, health.New(svc, health.Policy{Interval: time.Hour}), callback.NewPoller(cfg, svc, nil))

	// An empty token must NOT authenticate when the secret is empty.
	rr := httptest.NewRecorder()
	s.mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/actions/reload", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestRequestBodyIsBounded(t *testing.T) {
	h := newHarness(t)
	// A body larger than maxRequestBodyBytes must be rejected, not written.
	huge := `{"name":"okjail","content":"` + strings.Repeat("A", maxRequestBodyBytes+1024) + `"}`
	if rr := h.do(http.MethodPost, "/v1/jails", huge, true); rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: status=%d", rr.Code)
	}
	if _, err := os.Stat(filepath.Join(h.root, "jail.d", "okjail.local")); err == nil {
		t.Fatal("oversized body was written to disk")
	}
}

func TestCreateJailRejectsTraversalName(t *testing.T) {
	h := newHarness(t)
	rr := h.do(http.MethodPost, "/v1/jails", `{"name":"../../../../../../tmp/f2b-agent-pwn","content":"x"}`, true)
	if rr.Code != http.StatusBadRequest || decode(t, rr)["code"] != "invalid_name" {
		t.Fatalf("traversal jail name: status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat("/tmp/f2b-agent-pwn.local"); err == nil {
		os.Remove("/tmp/f2b-agent-pwn.local")
		t.Fatal("traversal escaped the config root")
	}
}

func TestRouting(t *testing.T) {
	fakeTools(t, map[string]string{"fail2ban-client": fakeClient})
	h := newHarness(t)
	cases := []struct {
		method, path, body string
		authed             bool
		wantStatus         int
		wantKey            string
	}{
		{"GET", "/healthz", "", false, 200, "status"},
		{"GET", "/readyz", "", false, 503, "ready"},
		{"GET", "/v1/health", "", false, 401, "code"},
		{"GET", "/v1/jails", "", true, 200, "jails"},
		{"PATCH", "/v1/jails", "", true, 405, ""},
		{"GET", "/v1/jails/all", "", true, 200, "jails"},
		{"GET", "/v1/jails/check-integrity", "", true, 200, "exists"},
		{"GET", "/v1/jails/sshd", "", true, 200, "bannedIPs"},
		{"DELETE", "/v1/jails/all", "", true, 400, "code"},
		{"DELETE", "/v1/jails/CHECK-INTEGRITY", "", true, 400, "code"},
		{"GET", "/v1/jails/a%2Fb", "", true, 400, "code"},
		{"DELETE", "/v1/jails/missing", "", true, 404, "code"},
		{"GET", "/v1/jails/sshd/config", "", true, 200, "filePath"},
		{"POST", "/v1/jails/sshd/ban", `{"ip":"nope"}`, true, 400, "code"},
		{"POST", "/v1/jails/sshd/unban", `{"ip":"192.0.2.1"}`, true, 500, "error"},
		{"GET", "/v1/filters", "", true, 200, "filters"},
		{"GET", "/v1/filters/test", "", true, 404, "code"},
		{"POST", "/v1/filters/test", `{}`, true, 400, "code"},
		{"GET", "/v1/actions/validate", "", true, 405, ""},
		{"GET", "/v1/nope", "", true, 404, ""},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rr := h.do(tc.method, tc.path, tc.body, tc.authed)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status=%d want %d body=%s", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.wantKey != "" {
				if _, ok := decode(t, rr)[tc.wantKey]; !ok {
					t.Fatalf("body %s lacks %q", rr.Body.String(), tc.wantKey)
				}
			}
		})
	}
}

func TestErrorStatus(t *testing.T) {
	cases := []struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		{fmt.Errorf("x: %w", fail2ban.ErrInvalidName), 400, "invalid_name"},
		{fail2ban.ErrInvalidIP, 400, "invalid_ip"},
		{config.ErrCallbackInvalid, 400, "callback_invalid"},
		{fail2ban.ErrLogpathInvalid, 400, "logpath_invalid"},
		{fail2ban.ErrLogpathInaccessible, 422, "logpath_inaccessible"},
		{fail2ban.ErrLogpathUnresolved, 422, "logpath_unresolved"},
		{fail2ban.ErrConfigInvalid, 422, "config_invalid"},
		{fail2ban.ErrNotFound, 404, "not_found"},
		{errors.New("fail2ban-client status failed"), 500, ""},
	}
	for _, tc := range cases {
		if status, code := errorStatus(tc.err); status != tc.wantStatus || code != tc.wantCode {
			t.Errorf("errorStatus(%v) = %d %q, want %d %q", tc.err, status, code, tc.wantStatus, tc.wantCode)
		}
	}
}

// The unauthenticated endpoints must expose only the verdict, never the supervisor's error text.
func TestPublicHealthEndpointsRevealNothing(t *testing.T) {
	fakeTools(t, map[string]string{"fail2ban-client": `echo "leaky-detail /run/fail2ban/fail2ban.sock"; exit 255`})
	h := newHarness(t)
	h.startSupervisor(t)
	if !strings.Contains(h.hs.State().LastError, "leaky-detail") {
		t.Fatalf("precondition: supervisor error not recorded: %+v", h.hs.State())
	}
	cases := []struct {
		path       string
		wantStatus int
		want       map[string]any
	}{
		{"/healthz", 200, map[string]any{"status": "ok"}},
		{"/readyz", 503, map[string]any{"ready": false}},
	}
	for _, tc := range cases {
		// no token
		rr := h.do(http.MethodGet, tc.path, "", false)
		if got := decode(t, rr); rr.Code != tc.wantStatus || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s = %d %v, want %d %v", tc.path, rr.Code, got, tc.wantStatus, tc.want)
		}
	}
}

func TestHealthDetail(t *testing.T) {
	fakeTools(t, map[string]string{"fail2ban-client": fakeClient, "fail2ban-regex": "exit 0\n"})
	h := newHarness(t)
	cb := config.CallbackRuntimeConfig{ServerID: "srv-1", CallbackURL: "https://ui.example.com", CallbackSecret: "cb-secret-123"}
	if err := config.SaveCallbackRuntimeConfig(h.root, cb); err != nil {
		t.Fatal(err)
	}
	h.startSupervisor(t)

	rr := h.do(http.MethodGet, "/v1/health", "", true)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), cb.CallbackSecret) || strings.Contains(rr.Body.String(), testSecret) {
		t.Fatal("health detail leaked a secret")
	}
	var got struct {
		Ready  bool            `json:"ready"`
		Checks map[string]bool `json:"checks"`
		Agent  struct {
			Version string `json:"version"`
			Go      string `json:"go"`
		} `json:"agent"`
		Fail2ban struct {
			Version string   `json:"version"`
			Jails   []string `json:"jails"`
			Error   string   `json:"error"`
		} `json:"fail2ban"`
		Supervisor map[string]any `json:"supervisor"`
		Callback   map[string]any `json:"callback"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Ready || len(got.Checks) != 5 || got.Agent.Version != version.Version || got.Agent.Go == "" {
		t.Fatalf("readiness/agent: %s", rr.Body.String())
	}
	if got.Fail2ban.Version != "1.1.0" || !reflect.DeepEqual(got.Fail2ban.Jails, []string{"sshd"}) || got.Fail2ban.Error != "" {
		t.Fatalf("fail2ban block: %+v", got.Fail2ban)
	}
	if _, ok := got.Supervisor["consecutiveFails"]; !ok {
		t.Fatalf("supervisor block: %v", got.Supervisor)
	}
	wantCallback := map[string]any{
		"configured": true, "source": "store", "serverId": "srv-1",
		"fingerprint":  config.CallbackFingerprint(testSecret, cb),
		"pollInterval": "4s", "pending": 0.0, "dropped": 0.0, "rejected": 0.0,
	}
	if !reflect.DeepEqual(got.Callback, wantCallback) {
		t.Fatalf("callback block = %v, want %v", got.Callback, wantCallback)
	}

	h.s.cfg.CallbackPollInterval = 0
	rr = h.do(http.MethodGet, "/v1/health", "", true)
	if !strings.Contains(rr.Body.String(), "callback polling is disabled") {
		t.Fatalf("disabled polling must surface as a callback error: %s", rr.Body.String())
	}
}

func TestHealthDetailSkipsFail2banWhenPingFailed(t *testing.T) {
	fakeTools(t, map[string]string{})
	h := newHarness(t)
	rr := h.do(http.MethodGet, "/v1/health", "", true)
	body := decode(t, rr)
	f2b, _ := body["fail2ban"].(map[string]any)
	if rr.Code != http.StatusOK || body["ready"] != false || !strings.HasPrefix(fmt.Sprint(f2b["error"]), "skipped") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestActionEndpoints(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		tools      map[string]string
		wantStatus int
		want       map[string]any
	}{
		{"reload returns output", "/v1/actions/reload", map[string]string{"fail2ban-client": fakeClient}, 200,
			map[string]any{"ok": true, "output": "reload-ok\n"}},
		{"restart falls back to reload", "/v1/actions/restart", map[string]string{"fail2ban-client": fakeClient}, 200,
			map[string]any{"ok": true, "mode": "reload"}},
		{"restart via service manager", "/v1/actions/restart", map[string]string{"fail2ban-client": fakeClient, "systemctl": "exit 0\n"}, 200,
			map[string]any{"ok": true, "mode": "restart"}},
		{"validate ok", "/v1/actions/validate", map[string]string{"fail2ban-client": "echo 'OK: configuration test is successful'\n"}, 200,
			map[string]any{"ok": true, "output": "OK: configuration test is successful\n"}},
		{"validate invalid", "/v1/actions/validate", map[string]string{"fail2ban-client": "echo 'ERROR: bad jail'; exit 255\n"}, 422,
			map[string]any{"ok": false, "code": "config_invalid", "error": "fail2ban configuration test failed (exit status 255)", "output": "ERROR: bad jail\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeTools(t, tc.tools)
			rr := newHarness(t).do(http.MethodPost, tc.path, "", true)
			if got := decode(t, rr); rr.Code != tc.wantStatus || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("%s = %d %v, want %d %v", tc.path, rr.Code, got, tc.wantStatus, tc.want)
			}
		})
	}
	t.Run("validate can not run", func(t *testing.T) {
		fakeTools(t, map[string]string{})
		rr := newHarness(t).do(http.MethodPost, "/v1/actions/validate", "", true)
		if body := decode(t, rr); rr.Code != 500 || body["ok"] != false || body["code"] != nil {
			t.Fatalf("status=%d body=%v", rr.Code, body)
		}
	})
}

func TestPutCallbackConfig(t *testing.T) {
	cases := []struct {
		name, body string
		wantStatus int
	}{
		{"valid", `{"serverId":"srv-abc","callbackUrl":"https://ui.example.com/f2b","callbackSecret":"cb-secret","callbackHostname":"agent-host"}`, 200},
		{"credentials in url", `{"serverId":"srv-abc","callbackUrl":"https://u:p@ui.example.com","callbackSecret":"cb-secret"}`, 400},
		{"bad server id", `{"serverId":"srv abc","callbackUrl":"https://ui.example.com","callbackSecret":"cb-secret"}`, 400},
		{"missing secret", `{"serverId":"srv-abc","callbackUrl":"https://ui.example.com"}`, 400},
		{"invalid json", `{"serverId":`, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			rr := h.do(http.MethodPut, "/v1/callback/config", tc.body, true)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			got, err := config.LoadCallbackRuntimeConfig(h.root)
			if err != nil {
				t.Fatal(err)
			}
			if stored := got.ServerID != ""; stored != (tc.wantStatus == 200) {
				t.Fatalf("stored=%v for status %d", stored, rr.Code)
			}
			if tc.wantStatus == 400 && tc.name != "invalid json" && decode(t, rr)["code"] != "callback_invalid" {
				t.Fatalf("body=%s", rr.Body.String())
			}
		})
	}
}

func TestDeleteCallbackConfig(t *testing.T) {
	h := newHarness(t)
	if err := config.SaveCallbackRuntimeConfig(h.root, config.CallbackRuntimeConfig{
		ServerID: "srv-abc", CallbackURL: "https://ui.example.com", CallbackSecret: "cb-secret",
	}); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		query      string
		wantStatus int
		want       map[string]any
	}{
		{"?serverId=srv-other", 200, map[string]any{"ok": true, "cleared": false, "reason": "server_mismatch"}},
		{"", 400, map[string]any{"code": "callback_invalid"}},
		{"?serverId=srv-abc", 200, map[string]any{"ok": true, "cleared": true}},
		{"?serverId=srv-abc", 200, map[string]any{"ok": true, "cleared": false, "reason": "not_configured"}},
	}
	for _, st := range steps {
		rr := h.do(http.MethodDelete, "/v1/callback/config"+st.query, "", true)
		got := decode(t, rr)
		delete(got, "error")
		if rr.Code != st.wantStatus || !reflect.DeepEqual(got, st.want) {
			t.Fatalf("DELETE %s = %d %v, want %d %v", st.query, rr.Code, got, st.wantStatus, st.want)
		}
	}
}

func TestEnsureStructureEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		existing string
		body     string
		want     map[string]any
		wantFile string
	}{
		{"writes provided content", "", `{"content":"[DEFAULT]\nenabled = true\naction = ui-custom-action\n"}`,
			map[string]any{"ok": true, "skipped": false}, "[DEFAULT]\nenabled = true\n# managed by fail2ban-ui-agent\n"},
		{"skips a user file", "[DEFAULT]\nbantime = 1d\n", `{"content":"[DEFAULT]\n"}`,
			map[string]any{"ok": true, "skipped": true, "reason": "unmanaged"}, "[DEFAULT]\nbantime = 1d\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			p := filepath.Join(h.root, "jail.local")
			if tc.existing != "" {
				if err := os.WriteFile(p, []byte(tc.existing), 0644); err != nil {
					t.Fatal(err)
				}
			}
			rr := h.do(http.MethodPost, "/v1/jails/ensure-structure", tc.body, true)
			if got := decode(t, rr); rr.Code != 200 || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("status=%d body=%v", rr.Code, got)
			}
			if raw, err := os.ReadFile(p); err != nil || string(raw) != tc.wantFile {
				t.Fatalf("jail.local = %q, %v", raw, err)
			}
		})
	}
	if rr := newHarness(t).do(http.MethodPost, "/v1/jails/ensure-structure", "{invalid", true); rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON: status=%d", rr.Code)
	}
}

func TestLogpathEndpoints(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		path, logpath string
		wantStatus    int
		wantCode      string
	}{
		{"/v1/jails/test-logpath", "var/log/auth.log", 400, "logpath_invalid"},
		{"/v1/jails/test-logpath", "/var/log/../../etc/shadow", 400, "logpath_invalid"},
		{"/v1/jails/test-logpath-with-resolution", "%(no_such_variable)s", 422, "logpath_unresolved"},
		{"/v1/jails/test-logpath-with-resolution", "/var/log/$(id)", 400, "logpath_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.path+" "+tc.logpath, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"logpath": tc.logpath})
			rr := h.do(http.MethodPost, tc.path, string(body), true)
			if got := decode(t, rr); rr.Code != tc.wantStatus || got["code"] != tc.wantCode {
				t.Fatalf("status=%d body=%v", rr.Code, got)
			}
		})
	}
}

func TestLogpathResolutionEndpointShape(t *testing.T) {
	logRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(logRoot, "auth.log"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cfg := config.Config{Secret: testSecret, ConfigRoot: root, LogRoot: logRoot}
	svc := fail2ban.NewService(root, logRoot)
	s := New(cfg, svc, health.New(svc, health.Policy{Interval: time.Hour}), callback.NewPoller(cfg, svc, nil))

	req := httptest.NewRequest(http.MethodPost, "/v1/jails/test-logpath-with-resolution", strings.NewReader(`{"logpath":"/var/log/auth.log"}`))
	req.Header.Set("X-F2B-Token", testSecret)
	rr := httptest.NewRecorder()
	s.mux.ServeHTTP(rr, req)
	want := map[string]any{
		"original_logpath": "/var/log/auth.log",
		"resolved_logpath": filepath.Join(logRoot, "auth.log"),
		"files":            []any{filepath.Join(logRoot, "auth.log")},
	}
	if got := decode(t, rr); rr.Code != 200 || !reflect.DeepEqual(got, want) {
		t.Fatalf("status=%d body=%v", rr.Code, got)
	}
}

func TestFiltersTestEndpoint(t *testing.T) {
	cases := []struct {
		name       string
		tools      map[string]string
		wantStatus int
		wantExit   any
	}{
		{"match run", map[string]string{"fail2ban-regex": "echo 'Lines: 1 lines, 1 matched'\n"}, 200, 0.0},
		{"regex error is still a result", map[string]string{"fail2ban-regex": "echo 'ERROR: No failure-id group'; exit 255\n"}, 200, 255.0},
		{"fail2ban-regex missing", map[string]string{}, 500, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeTools(t, tc.tools)
			h := newHarness(t)
			body := `{"filterName":"sshd","logLines":["x"],"filterContent":"[Definition]\nfailregex = ^<HOST>$\n"}`
			rr := h.do(http.MethodPost, "/v1/filters/test", body, true)
			got := decode(t, rr)
			if rr.Code != tc.wantStatus || got["exitCode"] != tc.wantExit || got["filterPath"] == "" {
				t.Fatalf("status=%d body=%v", rr.Code, got)
			}
		})
	}
}
