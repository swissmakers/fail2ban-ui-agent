// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
//
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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/swissmakers/fail2ban-ui-agent/internal/fsutil"
)

const (
	CallbackSourceStore = "store"
	CallbackSourceEnv   = "env"
	CallbackSourceNone  = "none"

	maxCallbackSecretLength = 512
	maxCallbackHostLength   = 253
)

var (
	ErrCallbackInvalid = errors.New("invalid callback configuration")

	// Serializes store writes so a DELETE cannot remove a PUT that landed between its read and its remove.
	storeMu sync.Mutex

	// Same rule as the UI's shared.ValidateServerID.
	serverIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// CallbackRuntimeConfig holds persisted callback routing/auth settings pushed from Fail2ban-UI.
type CallbackRuntimeConfig struct {
	ServerID       string `json:"serverId"`
	CallbackURL    string `json:"callbackUrl"`
	CallbackSecret string `json:"callbackSecret"`
	CallbackHost   string `json:"callbackHostname,omitempty"`
}

func (c CallbackRuntimeConfig) complete() bool {
	return c.ServerID != "" && c.CallbackURL != "" && c.CallbackSecret != ""
}

// CallbackConfigPath is where the agent stores callback identity/config on disk.
func CallbackConfigPath(configRoot string) string {
	root := strings.TrimSpace(configRoot)
	if root == "" {
		root = "/etc/fail2ban"
	}
	return filepath.Join(root, "fail2ban-ui-agent.id")
}

// ValidateCallbackConfig checks every field without echoing values, so errors are safe to return and log.
func ValidateCallbackConfig(c CallbackRuntimeConfig) error {
	var problems []string
	if err := validateCallbackURL(c.CallbackURL); err != nil {
		problems = append(problems, err.Error())
	}
	if !serverIDPattern.MatchString(c.ServerID) {
		problems = append(problems, "serverId must be 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit")
	}
	if !validCallbackSecret(c.CallbackSecret) {
		problems = append(problems, fmt.Sprintf("callbackSecret must be 1-%d printable ASCII characters without whitespace", maxCallbackSecretLength))
	}
	if !validCallbackHost(c.CallbackHost) {
		problems = append(problems, fmt.Sprintf("callbackHostname must be at most %d characters without control characters", maxCallbackHostLength))
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrCallbackInvalid, strings.Join(problems, "; "))
	}
	return nil
}

func validateCallbackURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return errors.New("callbackUrl must be an absolute http(s) URL with a host")
	}
	if u.User != nil {
		return errors.New("callbackUrl must not contain credentials")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("callbackUrl must not contain a query or fragment")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return errors.New("callbackUrl port must be 1-65535")
		}
	}
	return nil
}

func validCallbackSecret(secret string) bool {
	if secret == "" || len(secret) > maxCallbackSecretLength {
		return false
	}
	for i := 0; i < len(secret); i++ {
		if secret[i] < 0x21 || secret[i] > 0x7e {
			return false
		}
	}
	return true
}

func validCallbackHost(host string) bool {
	if len(host) > maxCallbackHostLength {
		return false
	}
	for _, r := range host {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Binds the agent token to the effective callback config so the UI can detect drift without the agent revealing the secret.
func CallbackFingerprint(agentToken string, c CallbackRuntimeConfig) string {
	mac := hmac.New(sha256.New, []byte(agentToken))
	mac.Write([]byte(c.ServerID + "\n" + strings.TrimRight(c.CallbackURL, "/") + "\n" + c.CallbackSecret))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// ResolveCallback returns the effective callback config: a complete store beats AGENT_CALLBACK_*, which is only a fallback.
func ResolveCallback(configRoot string, env CallbackRuntimeConfig) (CallbackRuntimeConfig, string, error) {
	stored, err := LoadCallbackRuntimeConfig(configRoot)
	if err != nil {
		return CallbackRuntimeConfig{}, CallbackSourceNone, fmt.Errorf("read %s: %w", CallbackConfigPath(configRoot), err)
	}
	if stored.complete() {
		if err := ValidateCallbackConfig(stored); err != nil {
			return CallbackRuntimeConfig{}, CallbackSourceNone, fmt.Errorf("%s: %w", CallbackConfigPath(configRoot), err)
		}
		// AGENT_CALLBACK_HOSTNAME still names the host when the UI leaves the hostname empty.
		if stored.CallbackHost == "" {
			stored.CallbackHost = env.CallbackHost
		}
		return stored, CallbackSourceStore, nil
	}
	if env.complete() {
		if err := ValidateCallbackConfig(env); err != nil {
			return CallbackRuntimeConfig{}, CallbackSourceNone, fmt.Errorf("AGENT_CALLBACK_*: %w", err)
		}
		return env, CallbackSourceEnv, nil
	}
	return CallbackRuntimeConfig{}, CallbackSourceNone, nil
}

func SaveCallbackRuntimeConfig(configRoot string, cfg CallbackRuntimeConfig) error {
	cfg.ServerID = strings.TrimSpace(cfg.ServerID)
	cfg.CallbackURL = strings.TrimSpace(cfg.CallbackURL)
	cfg.CallbackSecret = strings.TrimSpace(cfg.CallbackSecret)
	cfg.CallbackHost = strings.TrimSpace(cfg.CallbackHost)
	if err := ValidateCallbackConfig(cfg); err != nil {
		return err
	}

	path := CallbackConfigPath(configRoot)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.ReplaceFile(path, raw, 0600)
}

// Removes the store only when it belongs to serverID; reason is "not_configured" or "server_mismatch" otherwise.
func DeleteCallbackRuntimeConfig(configRoot, serverID string) (cleared bool, reason string, err error) {
	if !serverIDPattern.MatchString(serverID) {
		return false, "", fmt.Errorf("%w: serverId query parameter is missing or invalid", ErrCallbackInvalid)
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	stored, err := LoadCallbackRuntimeConfig(configRoot)
	if err != nil {
		return false, "", err
	}
	if stored.ServerID == "" {
		return false, "not_configured", nil
	}
	if stored.ServerID != serverID {
		return false, "server_mismatch", nil
	}
	if err := os.Remove(CallbackConfigPath(configRoot)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, "not_configured", nil
		}
		return false, "", err
	}
	return true, "", nil
}

func LoadCallbackRuntimeConfig(configRoot string) (CallbackRuntimeConfig, error) {
	path := CallbackConfigPath(configRoot)
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return CallbackRuntimeConfig{}, nil
		}
		return CallbackRuntimeConfig{}, err
	}
	var out CallbackRuntimeConfig
	if err := json.Unmarshal(raw, &out); err != nil {
		return CallbackRuntimeConfig{}, err
	}
	out.ServerID = strings.TrimSpace(out.ServerID)
	out.CallbackURL = strings.TrimSpace(out.CallbackURL)
	out.CallbackSecret = strings.TrimSpace(out.CallbackSecret)
	out.CallbackHost = strings.TrimSpace(out.CallbackHost)
	return out, nil
}
