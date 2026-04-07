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
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	BindAddress string
	Port        int
	Secret      string
	TLSCertFile string
	TLSKeyFile  string

	ConfigRoot string
	RunRoot    string
	LogRoot    string

	HealthInterval    time.Duration
	HealthAutoReload  bool
	HealthAutoRestart bool
	HealthMaxRetries  int

	// Callback to Fail2ban-UI (ban/unban notifications via poller).
	// Values are loaded from persisted callback store first, then env vars override for compatibility.
	CallbackURL          string
	CallbackSecret       string
	CallbackServerID     string
	CallbackHostname     string
	CallbackPollInterval time.Duration // 0 disables the poller; default 4s when env unset
}

func Load() (Config, error) {
	return load(true)
}

func LoadAllowNoSecret() (Config, error) {
	return load(false)
}

func load(requireSecret bool) (Config, error) {
	cfg := Config{
		BindAddress:       envOr("AGENT_BIND_ADDRESS", "0.0.0.0"),
		Port:              envInt("AGENT_PORT", 9700),
		Secret:            strings.TrimSpace(os.Getenv("AGENT_SECRET")),
		TLSCertFile:       strings.TrimSpace(os.Getenv("AGENT_TLS_CERT_FILE")),
		TLSKeyFile:        strings.TrimSpace(os.Getenv("AGENT_TLS_KEY_FILE")),
		ConfigRoot:        envOr("AGENT_FAIL2BAN_CONFIG_DIR", "/etc/fail2ban"),
		RunRoot:           envOr("AGENT_FAIL2BAN_RUN_DIR", "/var/run/fail2ban"),
		LogRoot:           envOr("AGENT_LOG_ROOT", "/var/log"),
		HealthInterval:    envDuration("AGENT_HEALTH_INTERVAL", 30*time.Second),
		HealthAutoReload:  envBool("AGENT_HEALTH_AUTO_RELOAD", true),
		HealthAutoRestart: envBool("AGENT_HEALTH_AUTO_RESTART", true),
		HealthMaxRetries:  envInt("AGENT_HEALTH_MAX_RETRIES", 3),
	}
	if net.ParseIP(cfg.BindAddress) == nil {
		return cfg, fmt.Errorf("invalid AGENT_BIND_ADDRESS: %s", cfg.BindAddress)
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return cfg, fmt.Errorf("invalid AGENT_PORT: %d", cfg.Port)
	}
	if requireSecret && cfg.Secret == "" {
		return cfg, fmt.Errorf("AGENT_SECRET is required")
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return cfg, fmt.Errorf("AGENT_TLS_CERT_FILE and AGENT_TLS_KEY_FILE must be set together")
	}
	if cfg.HealthInterval < 5*time.Second {
		cfg.HealthInterval = 5 * time.Second
	}
	if cfg.HealthMaxRetries < 1 {
		cfg.HealthMaxRetries = 1
	}

	stored, err := LoadCallbackRuntimeConfig(cfg.ConfigRoot)
	if err != nil {
		return cfg, fmt.Errorf("failed to load callback runtime config: %w", err)
	}
	cfg.CallbackURL = stored.CallbackURL
	cfg.CallbackSecret = stored.CallbackSecret
	cfg.CallbackServerID = stored.ServerID
	cfg.CallbackHostname = stored.CallbackHost

	// Backward compatibility: env variables override persisted values when set.
	if v := strings.TrimSpace(os.Getenv("AGENT_CALLBACK_URL")); v != "" {
		cfg.CallbackURL = v
	}
	if v := strings.TrimSpace(os.Getenv("AGENT_CALLBACK_SECRET")); v != "" {
		cfg.CallbackSecret = v
	}
	if v := strings.TrimSpace(os.Getenv("AGENT_CALLBACK_SERVER_ID")); v != "" {
		cfg.CallbackServerID = v
	}
	if v := strings.TrimSpace(os.Getenv("AGENT_CALLBACK_HOSTNAME")); v != "" {
		cfg.CallbackHostname = v
	}

	rawPoll := strings.TrimSpace(os.Getenv("AGENT_CALLBACK_POLL_INTERVAL"))
	if rawPoll == "" {
		cfg.CallbackPollInterval = 4 * time.Second
	} else {
		d, err := time.ParseDuration(rawPoll)
		if err != nil {
			return cfg, fmt.Errorf("invalid AGENT_CALLBACK_POLL_INTERVAL: %w", err)
		}
		cfg.CallbackPollInterval = d
	}

	return cfg, nil
}

func Addr(cfg Config) string {
	return net.JoinHostPort(cfg.BindAddress, strconv.Itoa(cfg.Port))
}

func envOr(k, d string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	return v
}

func envInt(k string, d int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return d
	}
	return i
}

func envBool(k string, d bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if v == "" {
		return d
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func envDuration(k string, d time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return d
	}
	return parsed
}
