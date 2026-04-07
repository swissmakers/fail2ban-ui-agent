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

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaultsAndValidation(t *testing.T) {
	t.Setenv("AGENT_SECRET", "testsecret")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Port != 9700 {
		t.Fatalf("default port = %d", cfg.Port)
	}
	if cfg.BindAddress != "0.0.0.0" {
		t.Fatalf("default bind = %s", cfg.BindAddress)
	}
}

func TestLoadMissingSecret(t *testing.T) {
	_ = os.Unsetenv("AGENT_SECRET")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing AGENT_SECRET")
	}
}

func TestLoadAllowNoSecret(t *testing.T) {
	_ = os.Unsetenv("AGENT_SECRET")
	cfg, err := LoadAllowNoSecret()
	if err != nil {
		t.Fatalf("LoadAllowNoSecret error: %v", err)
	}
	if cfg.BindAddress == "" {
		t.Fatal("expected defaults to be loaded")
	}
}

func TestLoadHealthIntervalFloor(t *testing.T) {
	t.Setenv("AGENT_SECRET", "x")
	t.Setenv("AGENT_HEALTH_INTERVAL", "1s")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.HealthInterval != 5*time.Second {
		t.Fatalf("interval floor mismatch: %v", cfg.HealthInterval)
	}
}

func TestLoadTLSPairValidation(t *testing.T) {
	t.Setenv("AGENT_SECRET", "x")
	t.Setenv("AGENT_TLS_CERT_FILE", "/tmp/cert.pem")
	t.Setenv("AGENT_TLS_KEY_FILE", "")
	_, err := Load()
	if err == nil {
		t.Fatal("expected TLS pair validation error")
	}
}

func TestLoadCallbackPollDefaultWhenURLAndSecret(t *testing.T) {
	t.Setenv("AGENT_SECRET", "x")
	t.Setenv("AGENT_CALLBACK_URL", "http://127.0.0.1:8080/")
	t.Setenv("AGENT_CALLBACK_SECRET", "cbsecret")
	t.Setenv("AGENT_CALLBACK_POLL_INTERVAL", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CallbackPollInterval != 4*time.Second {
		t.Fatalf("default poll = %v", cfg.CallbackPollInterval)
	}
}

func TestLoadCallbackPollZeroDisables(t *testing.T) {
	t.Setenv("AGENT_SECRET", "x")
	t.Setenv("AGENT_CALLBACK_URL", "http://127.0.0.1:8080/")
	t.Setenv("AGENT_CALLBACK_SECRET", "cbsecret")
	t.Setenv("AGENT_CALLBACK_POLL_INTERVAL", "0")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CallbackPollInterval != 0 {
		t.Fatalf("poll = %v, want 0", cfg.CallbackPollInterval)
	}
}

func TestLoadCallbackPollInvalidDuration(t *testing.T) {
	t.Setenv("AGENT_SECRET", "x")
	t.Setenv("AGENT_CALLBACK_URL", "http://127.0.0.1:8080/")
	t.Setenv("AGENT_CALLBACK_SECRET", "cbsecret")
	t.Setenv("AGENT_CALLBACK_POLL_INTERVAL", "not-a-duration")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid AGENT_CALLBACK_POLL_INTERVAL")
	}
}

func TestLoadReadsPersistedCallbackConfig(t *testing.T) {
	t.Setenv("AGENT_SECRET", "x")
	root := t.TempDir()
	t.Setenv("AGENT_FAIL2BAN_CONFIG_DIR", root)
	if err := SaveCallbackRuntimeConfig(root, CallbackRuntimeConfig{
		ServerID:       "srv-123",
		CallbackURL:    "http://ui.example.local",
		CallbackSecret: "secret",
		CallbackHost:   "host-1",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CallbackServerID != "srv-123" || cfg.CallbackURL == "" || cfg.CallbackSecret == "" {
		t.Fatalf("persisted callback config not loaded: %+v", cfg)
	}
}

func TestLoadEnvOverridesPersistedCallbackConfig(t *testing.T) {
	t.Setenv("AGENT_SECRET", "x")
	root := t.TempDir()
	t.Setenv("AGENT_FAIL2BAN_CONFIG_DIR", root)
	if err := SaveCallbackRuntimeConfig(root, CallbackRuntimeConfig{
		ServerID:       "srv-old",
		CallbackURL:    "http://old",
		CallbackSecret: "old-secret",
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_CALLBACK_SERVER_ID", "srv-new")
	t.Setenv("AGENT_CALLBACK_URL", "http://new")
	t.Setenv("AGENT_CALLBACK_SECRET", "new-secret")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CallbackServerID != "srv-new" || cfg.CallbackURL != "http://new" || cfg.CallbackSecret != "new-secret" {
		t.Fatalf("env override failed: %+v", cfg)
	}
}

func TestCallbackConfigPath(t *testing.T) {
	got := CallbackConfigPath("/etc/fail2ban")
	want := filepath.Join("/etc/fail2ban", "fail2ban-ui-agent.id")
	if got != want {
		t.Fatalf("path = %q want %q", got, want)
	}
}
