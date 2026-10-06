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
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const minSecretLength = 16

// Normalized (lower-case, no separators) fragments of documentation/example secrets.
var placeholderSecretMarkers = []string{"changeme", "replaceme", "yoursecret", "placeholder"}

type Config struct {
	BindAddress string
	Port        int
	Secret      string
	TLSCertFile string
	TLSKeyFile  string

	ConfigRoot string
	LogRoot    string

	HealthInterval    time.Duration
	HealthAutoReload  bool
	HealthAutoRestart bool
	HealthMaxRetries  int

	// Callback to Fail2ban-UI (ban/unban notifications via poller).
	// AGENT_CALLBACK_* fallback; the store pushed by Fail2ban-UI wins (see ResolveCallback).
	EnvCallback CallbackRuntimeConfig
	// 0 disables the poller; default 4s when env unset
	CallbackPollInterval time.Duration
}

func Load() (Config, error) {
	cfg, err := ParseEnv()
	if err != nil {
		return cfg, err
	}
	if err := validateSecret(cfg.Secret); err != nil {
		return cfg, err
	}
	if os.Getenv("AGENT_FAIL2BAN_RUN_DIR") != "" {
		log.Printf("WARNING: AGENT_FAIL2BAN_RUN_DIR is no longer supported and is ignored; fail2ban-client always runs with -c %s", cfg.ConfigRoot)
	}
	// AGENT_CALLBACK_HOSTNAME alone is a valid override for UI-pushed callbacks.
	routing := cfg.EnvCallback
	routing.CallbackHost = ""
	if routing != (CallbackRuntimeConfig{}) && !routing.complete() {
		log.Printf("WARNING: ignoring AGENT_CALLBACK_*: AGENT_CALLBACK_URL, AGENT_CALLBACK_SECRET and AGENT_CALLBACK_SERVER_ID must be set together")
	}
	return cfg, nil
}

// ParseEnv parses and validates every AGENT_* variable except the secret strength, reporting all errors at once.
func ParseEnv() (Config, error) {
	var errs []error
	cfg := Config{
		BindAddress:       envOr("AGENT_BIND_ADDRESS", "0.0.0.0"),
		Port:              envInt("AGENT_PORT", 9700, &errs),
		Secret:            strings.TrimSpace(os.Getenv("AGENT_SECRET")),
		TLSCertFile:       strings.TrimSpace(os.Getenv("AGENT_TLS_CERT_FILE")),
		TLSKeyFile:        strings.TrimSpace(os.Getenv("AGENT_TLS_KEY_FILE")),
		ConfigRoot:        envOr("AGENT_FAIL2BAN_CONFIG_DIR", "/etc/fail2ban"),
		LogRoot:           envOr("AGENT_LOG_ROOT", "/var/log"),
		HealthInterval:    envDuration("AGENT_HEALTH_INTERVAL", 30*time.Second, &errs),
		HealthAutoReload:  envBool("AGENT_HEALTH_AUTO_RELOAD", true, &errs),
		HealthAutoRestart: envBool("AGENT_HEALTH_AUTO_RESTART", true, &errs),
		HealthMaxRetries:  envInt("AGENT_HEALTH_MAX_RETRIES", 3, &errs),
		EnvCallback: CallbackRuntimeConfig{
			ServerID:       strings.TrimSpace(os.Getenv("AGENT_CALLBACK_SERVER_ID")),
			CallbackURL:    strings.TrimSpace(os.Getenv("AGENT_CALLBACK_URL")),
			CallbackSecret: strings.TrimSpace(os.Getenv("AGENT_CALLBACK_SECRET")),
			CallbackHost:   strings.TrimSpace(os.Getenv("AGENT_CALLBACK_HOSTNAME")),
		},
		CallbackPollInterval: envDuration("AGENT_CALLBACK_POLL_INTERVAL", 4*time.Second, &errs),
	}
	if net.ParseIP(cfg.BindAddress) == nil {
		errs = append(errs, fmt.Errorf("invalid AGENT_BIND_ADDRESS %q: must be an IP address", cfg.BindAddress))
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		errs = append(errs, fmt.Errorf("invalid AGENT_PORT %d: must be 1-65535", cfg.Port))
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		errs = append(errs, errors.New("AGENT_TLS_CERT_FILE and AGENT_TLS_KEY_FILE must be set together"))
	}
	if !filepath.IsAbs(cfg.ConfigRoot) {
		errs = append(errs, fmt.Errorf("invalid AGENT_FAIL2BAN_CONFIG_DIR %q: must be an absolute path", cfg.ConfigRoot))
	}
	if !filepath.IsAbs(cfg.LogRoot) {
		errs = append(errs, fmt.Errorf("invalid AGENT_LOG_ROOT %q: must be an absolute path", cfg.LogRoot))
	}
	if cfg.CallbackPollInterval != 0 && cfg.CallbackPollInterval < time.Second {
		errs = append(errs, fmt.Errorf("invalid AGENT_CALLBACK_POLL_INTERVAL %s: use 0 to disable or at least 1s", cfg.CallbackPollInterval))
	}
	if cfg.EnvCallback.complete() {
		if err := ValidateCallbackConfig(cfg.EnvCallback); err != nil {
			errs = append(errs, fmt.Errorf("AGENT_CALLBACK_*: %w", err))
		}
	}
	if cfg.HealthInterval < 5*time.Second {
		cfg.HealthInterval = 5 * time.Second
	}
	if cfg.HealthMaxRetries < 1 {
		cfg.HealthMaxRetries = 1
	}
	return cfg, errors.Join(errs...)
}

func validateSecret(secret string) error {
	if secret == "" {
		return errors.New("AGENT_SECRET is required (generate one with: openssl rand -hex 32)")
	}
	if len(secret) < minSecretLength {
		return fmt.Errorf("AGENT_SECRET must be at least %d characters (generate one with: openssl rand -hex 32)", minSecretLength)
	}
	normalized := strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "", ".", "").Replace(secret))
	for _, marker := range placeholderSecretMarkers {
		if strings.Contains(normalized, marker) {
			return errors.New("AGENT_SECRET is a placeholder value; set a random secret (generate one with: openssl rand -hex 32)")
		}
	}
	return nil
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

func envInt(k string, d int, errs *[]error) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("invalid %s %q: not an integer", k, v))
		return d
	}
	return i
}

func envBool(k string, d bool, errs *[]error) bool {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	b, err := parseBool(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("invalid %s: %w", k, err))
		return d
	}
	return b
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("%q is not a boolean (use true/false, yes/no, on/off or 1/0)", v)
}

func envDuration(k string, d time.Duration, errs *[]error) time.Duration {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("invalid %s %q: not a duration (e.g. 30s, 5m)", k, v))
		return d
	}
	return parsed
}
