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

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testSecret = "test-agent-secret-0123456789"

var agentEnvKeys = []string{
	"AGENT_BIND_ADDRESS", "AGENT_PORT", "AGENT_SECRET", "AGENT_TLS_CERT_FILE", "AGENT_TLS_KEY_FILE",
	"AGENT_FAIL2BAN_CONFIG_DIR", "AGENT_FAIL2BAN_RUN_DIR", "AGENT_LOG_ROOT",
	"AGENT_HEALTH_INTERVAL", "AGENT_HEALTH_AUTO_RELOAD", "AGENT_HEALTH_AUTO_RESTART", "AGENT_HEALTH_MAX_RETRIES",
	"AGENT_CALLBACK_URL", "AGENT_CALLBACK_SECRET", "AGENT_CALLBACK_SERVER_ID", "AGENT_CALLBACK_HOSTNAME",
	"AGENT_CALLBACK_POLL_INTERVAL",
}

// Blanks every AGENT_* variable (empty counts as unset) and applies the given overrides.
func setAgentEnv(t *testing.T, kv ...string) {
	t.Helper()
	for _, k := range agentEnvKeys {
		t.Setenv(k, "")
	}
	for i := 0; i+1 < len(kv); i += 2 {
		t.Setenv(kv[i], kv[i+1])
	}
}

func TestLoadDefaults(t *testing.T) {
	setAgentEnv(t, "AGENT_SECRET", testSecret)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Port != 9700 || cfg.BindAddress != "0.0.0.0" || cfg.ConfigRoot != "/etc/fail2ban" {
		t.Fatalf("defaults = %+v", cfg)
	}
	if cfg.CallbackPollInterval != 4*time.Second || !cfg.HealthAutoReload || !cfg.HealthAutoRestart {
		t.Fatalf("defaults = %+v", cfg)
	}
}

func TestValidateSecret(t *testing.T) {
	cases := []struct {
		secret string
		ok     bool
	}{
		{"", false},
		{"short-secret", false},
		{"0123456789abcde", false},
		{"0123456789abcdef", true},
		{"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", true},
		{"agent-secret-change-me", false},
		{"change-me-to-a-long-random-value", false},
		{"CHANGE_ME_CHANGE_ME_1234", false},
		{"replace-me-with-something-long", false},
		{"your-secret-goes-here-1234", false},
		{"placeholder-secret-value-1", false},
	}
	for _, tc := range cases {
		t.Run(tc.secret, func(t *testing.T) {
			if err := validateSecret(tc.secret); (err == nil) != tc.ok {
				t.Fatalf("validateSecret(%q) = %v, want ok=%v", tc.secret, err, tc.ok)
			}
		})
	}
}

func TestLoadRefusesWeakSecret(t *testing.T) {
	for _, secret := range []string{"", "x", "agent-secret-change-me"} {
		setAgentEnv(t, "AGENT_SECRET", secret)
		if _, err := Load(); err == nil {
			t.Fatalf("Load accepted AGENT_SECRET=%q", secret)
		}
	}
}

func TestParseBool(t *testing.T) {
	cases := []struct {
		in    string
		want  bool
		valid bool
	}{
		{"1", true, true}, {"true", true, true}, {"YES", true, true}, {" on ", true, true},
		{"0", false, true}, {"false", false, true}, {"No", false, true}, {"off", false, true},
		{"maybe", false, false}, {"2", false, false}, {"enabled", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseBool(tc.in)
			if (err == nil) != tc.valid || got != tc.want {
				t.Fatalf("parseBool(%q) = %v, %v", tc.in, got, err)
			}
		})
	}
}

func TestParseEnvRejectsInvalidValues(t *testing.T) {
	cases := []struct {
		name string
		kv   []string
		want string
	}{
		{"port not a number", []string{"AGENT_PORT", "97OO"}, "AGENT_PORT"},
		{"port out of range", []string{"AGENT_PORT", "70000"}, "AGENT_PORT"},
		{"bind not an IP", []string{"AGENT_BIND_ADDRESS", "localhost"}, "AGENT_BIND_ADDRESS"},
		{"bad duration", []string{"AGENT_HEALTH_INTERVAL", "30"}, "AGENT_HEALTH_INTERVAL"},
		{"bad bool", []string{"AGENT_HEALTH_AUTO_RESTART", "maybe"}, "AGENT_HEALTH_AUTO_RESTART"},
		{"bad retries", []string{"AGENT_HEALTH_MAX_RETRIES", "three"}, "AGENT_HEALTH_MAX_RETRIES"},
		{"poll below 1s", []string{"AGENT_CALLBACK_POLL_INTERVAL", "500ms"}, "AGENT_CALLBACK_POLL_INTERVAL"},
		{"negative poll", []string{"AGENT_CALLBACK_POLL_INTERVAL", "-4s"}, "AGENT_CALLBACK_POLL_INTERVAL"},
		{"invalid poll", []string{"AGENT_CALLBACK_POLL_INTERVAL", "not-a-duration"}, "AGENT_CALLBACK_POLL_INTERVAL"},
		{"relative config dir", []string{"AGENT_FAIL2BAN_CONFIG_DIR", "etc/fail2ban"}, "AGENT_FAIL2BAN_CONFIG_DIR"},
		{"TLS cert without key", []string{"AGENT_TLS_CERT_FILE", "/tmp/cert.pem"}, "AGENT_TLS_KEY_FILE"},
		{"env callback with credentials", []string{
			"AGENT_CALLBACK_URL", "https://user:pw@ui.example.com", "AGENT_CALLBACK_SECRET", "cb-secret", "AGENT_CALLBACK_SERVER_ID", "srv-1",
		}, "credentials"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setAgentEnv(t, append([]string{"AGENT_SECRET", testSecret}, tc.kv...)...)
			_, err := ParseEnv()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseEnv() error = %v, want mention of %s", err, tc.want)
			}
		})
	}
}

func TestParseEnvReportsAllErrors(t *testing.T) {
	setAgentEnv(t, "AGENT_PORT", "x", "AGENT_HEALTH_AUTO_RELOAD", "maybe", "AGENT_HEALTH_INTERVAL", "soon")
	_, err := ParseEnv()
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, k := range []string{"AGENT_PORT", "AGENT_HEALTH_AUTO_RELOAD", "AGENT_HEALTH_INTERVAL"} {
		if !strings.Contains(err.Error(), k) {
			t.Errorf("error %q does not mention %s", err, k)
		}
	}
}

func TestLoadHealthIntervalFloor(t *testing.T) {
	setAgentEnv(t, "AGENT_SECRET", testSecret, "AGENT_HEALTH_INTERVAL", "1s")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.HealthInterval != 5*time.Second {
		t.Fatalf("interval floor mismatch: %v", cfg.HealthInterval)
	}
}

func TestLoadCallbackPollZeroDisables(t *testing.T) {
	setAgentEnv(t, "AGENT_SECRET", testSecret, "AGENT_CALLBACK_POLL_INTERVAL", "0")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CallbackPollInterval != 0 {
		t.Fatalf("poll = %v, want 0", cfg.CallbackPollInterval)
	}
}

func TestLoadDoesNotCopyStoreIntoConfig(t *testing.T) {
	root := t.TempDir()
	setAgentEnv(t, "AGENT_SECRET", testSecret, "AGENT_FAIL2BAN_CONFIG_DIR", root)
	if err := SaveCallbackRuntimeConfig(root, validCallback("srv-stored")); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.EnvCallback != (CallbackRuntimeConfig{}) {
		t.Fatalf("stored callback leaked into the startup config: %+v", cfg.EnvCallback)
	}
}

func validCallback(serverID string) CallbackRuntimeConfig {
	return CallbackRuntimeConfig{
		ServerID:       serverID,
		CallbackURL:    "https://ui.example.com/fail2ban",
		CallbackSecret: "cb-secret-" + serverID,
		CallbackHost:   "agent-host",
	}
}

func TestValidateCallbackConfig(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*CallbackRuntimeConfig)
		ok     bool
	}{
		{"valid", func(*CallbackRuntimeConfig) {}, true},
		{"http loopback with port", func(c *CallbackRuntimeConfig) { c.CallbackURL = "http://127.0.0.1:8080" }, true},
		{"ipv6 host", func(c *CallbackRuntimeConfig) { c.CallbackURL = "https://[2001:db8::1]:8443/" }, true},
		{"no hostname is fine", func(c *CallbackRuntimeConfig) { c.CallbackHost = "" }, true},
		{"ftp scheme", func(c *CallbackRuntimeConfig) { c.CallbackURL = "ftp://ui.example.com" }, false},
		{"relative url", func(c *CallbackRuntimeConfig) { c.CallbackURL = "/api" }, false},
		{"missing host", func(c *CallbackRuntimeConfig) { c.CallbackURL = "https://:8080" }, false},
		{"userinfo", func(c *CallbackRuntimeConfig) { c.CallbackURL = "https://admin@ui.example.com" }, false},
		{"query", func(c *CallbackRuntimeConfig) { c.CallbackURL = "https://ui.example.com/?x=1" }, false},
		{"fragment", func(c *CallbackRuntimeConfig) { c.CallbackURL = "https://ui.example.com/#x" }, false},
		{"port out of range", func(c *CallbackRuntimeConfig) { c.CallbackURL = "https://ui.example.com:70000" }, false},
		{"empty server id", func(c *CallbackRuntimeConfig) { c.ServerID = "" }, false},
		{"server id with slash", func(c *CallbackRuntimeConfig) { c.ServerID = "srv/1" }, false},
		{"server id leading dot", func(c *CallbackRuntimeConfig) { c.ServerID = ".srv" }, false},
		{"server id too long", func(c *CallbackRuntimeConfig) { c.ServerID = strings.Repeat("a", 65) }, false},
		{"empty secret", func(c *CallbackRuntimeConfig) { c.CallbackSecret = "" }, false},
		{"secret with space", func(c *CallbackRuntimeConfig) { c.CallbackSecret = "a b" }, false},
		{"secret with newline", func(c *CallbackRuntimeConfig) { c.CallbackSecret = "ab\ncd" }, false},
		{"secret non-ascii", func(c *CallbackRuntimeConfig) { c.CallbackSecret = "sécret" }, false},
		{"secret too long", func(c *CallbackRuntimeConfig) { c.CallbackSecret = strings.Repeat("s", 513) }, false},
		{"hostname with a space", func(c *CallbackRuntimeConfig) { c.CallbackHost = "web server 1" }, true},
		{"hostname with control char", func(c *CallbackRuntimeConfig) { c.CallbackHost = "host\x1b[31m" }, false},
		{"hostname with newline", func(c *CallbackRuntimeConfig) { c.CallbackHost = "host\nforged" }, false},
		{"hostname too long", func(c *CallbackRuntimeConfig) { c.CallbackHost = strings.Repeat("h", 254) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validCallback("srv-1")
			tc.mutate(&c)
			err := ValidateCallbackConfig(c)
			if (err == nil) != tc.ok {
				t.Fatalf("ValidateCallbackConfig = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrCallbackInvalid) {
				t.Fatalf("error does not wrap ErrCallbackInvalid: %v", err)
			}
			if err != nil && c.CallbackSecret != "" && strings.Contains(err.Error(), c.CallbackSecret) {
				t.Fatal("validation error echoes the secret")
			}
		})
	}
}

func TestCallbackFingerprint(t *testing.T) {
	c := CallbackRuntimeConfig{ServerID: "srv-1", CallbackURL: "https://ui.example.com", CallbackSecret: "cb-secret-123"}
	// Pinned: the UI computes the same value to detect callback drift.
	const want = "9563176e6c67afcc7e2efa9843f91808"
	if got := CallbackFingerprint("agent-token-0123456789", c); got != want {
		t.Fatalf("fingerprint = %s, want %s", got, want)
	}
	c.CallbackURL += "/"
	if got := CallbackFingerprint("agent-token-0123456789", c); got != want {
		t.Fatalf("trailing slash changed the fingerprint: %s", got)
	}
	if CallbackFingerprint("other-token-0123456789", c) == want {
		t.Fatal("fingerprint must depend on the agent token")
	}
}

func TestResolveCallback(t *testing.T) {
	env := validCallback("srv-env")
	cases := []struct {
		name       string
		store      *CallbackRuntimeConfig
		raw        string
		env        CallbackRuntimeConfig
		wantSource string
		wantID     string
		wantHost   string
		wantErr    bool
	}{
		{name: "store wins over env", store: ptr(validCallback("srv-store")), env: env, wantSource: CallbackSourceStore, wantID: "srv-store"},
		{name: "env when store absent", env: env, wantSource: CallbackSourceEnv, wantID: "srv-env"},
		{name: "env when store incomplete", raw: `{"serverId":"srv-store"}`, env: env, wantSource: CallbackSourceEnv, wantID: "srv-env"},
		{name: "incomplete env ignored", env: CallbackRuntimeConfig{CallbackURL: env.CallbackURL}, wantSource: CallbackSourceNone},
		{name: "nothing configured", wantSource: CallbackSourceNone},
		{name: "env hostname fills a store without one", raw: `{"serverId":"srv-store","callbackUrl":"https://ui.example.com","callbackSecret":"cb-secret-1"}`, env: CallbackRuntimeConfig{CallbackHost: "web01"}, wantSource: CallbackSourceStore, wantID: "srv-store", wantHost: "web01"},
		{name: "store hostname beats env", store: ptr(validCallback("srv-store")), env: CallbackRuntimeConfig{CallbackHost: "web01"}, wantSource: CallbackSourceStore, wantID: "srv-store", wantHost: "agent-host"},
		{name: "invalid store does not fall back", raw: `{"serverId":"srv-x","callbackUrl":"https://u:p@ui","callbackSecret":"s"}`, env: env, wantSource: CallbackSourceNone, wantErr: true},
		{name: "corrupt store does not fall back", raw: `{not json`, env: env, wantSource: CallbackSourceNone, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.store != nil {
				if err := SaveCallbackRuntimeConfig(root, *tc.store); err != nil {
					t.Fatal(err)
				}
			}
			if tc.raw != "" {
				if err := os.WriteFile(CallbackConfigPath(root), []byte(tc.raw), 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, source, err := ResolveCallback(root, tc.env)
			if (err != nil) != tc.wantErr || source != tc.wantSource || got.ServerID != tc.wantID || (tc.wantHost != "" && got.CallbackHost != tc.wantHost) {
				t.Fatalf("ResolveCallback = (%+v, %q, %v), want source %q id %q err=%v", got, source, err, tc.wantSource, tc.wantID, tc.wantErr)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

func TestSaveCallbackRuntimeConfig(t *testing.T) {
	root := t.TempDir()
	if err := SaveCallbackRuntimeConfig(root, validCallback("srv-1")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(CallbackConfigPath(root))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("store must be 0600: %v %v", info, err)
	}
	bad := validCallback("srv-1")
	bad.CallbackURL = "javascript:alert(1)"
	if err := SaveCallbackRuntimeConfig(root, bad); !errors.Is(err, ErrCallbackInvalid) {
		t.Fatalf("invalid config saved: %v", err)
	}
}

func TestDeleteCallbackRuntimeConfig(t *testing.T) {
	cases := []struct {
		name        string
		stored      string
		serverID    string
		wantCleared bool
		wantReason  string
		wantErr     error
	}{
		{name: "matching server clears", stored: "srv-1", serverID: "srv-1", wantCleared: true},
		{name: "other server keeps store", stored: "srv-1", serverID: "srv-2", wantReason: "server_mismatch"},
		{name: "nothing stored", serverID: "srv-1", wantReason: "not_configured"},
		{name: "missing server id", stored: "srv-1", serverID: "", wantErr: ErrCallbackInvalid},
		{name: "invalid server id", stored: "srv-1", serverID: "../srv-1", wantErr: ErrCallbackInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.stored != "" {
				if err := SaveCallbackRuntimeConfig(root, validCallback(tc.stored)); err != nil {
					t.Fatal(err)
				}
			}
			cleared, reason, err := DeleteCallbackRuntimeConfig(root, tc.serverID)
			if cleared != tc.wantCleared || reason != tc.wantReason || !errors.Is(err, tc.wantErr) {
				t.Fatalf("Delete = (%v, %q, %v), want (%v, %q, %v)", cleared, reason, err, tc.wantCleared, tc.wantReason, tc.wantErr)
			}
			_, statErr := os.Stat(CallbackConfigPath(root))
			if gone := os.IsNotExist(statErr); gone != (tc.wantCleared || tc.stored == "") {
				t.Fatalf("store present=%v after delete", !gone)
			}
		})
	}
}

func TestCallbackConfigPath(t *testing.T) {
	got := CallbackConfigPath("/etc/fail2ban")
	want := filepath.Join("/etc/fail2ban", "fail2ban-ui-agent.id")
	if got != want {
		t.Fatalf("path = %q want %q", got, want)
	}
}
