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

package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// CallbackRuntimeConfig holds persisted callback routing/auth settings pushed from Fail2ban-UI.
type CallbackRuntimeConfig struct {
	ServerID       string `json:"serverId"`
	CallbackURL    string `json:"callbackUrl"`
	CallbackSecret string `json:"callbackSecret"`
	CallbackHost   string `json:"callbackHostname,omitempty"`
}

// CallbackConfigPath is where the agent stores callback identity/config on disk.
func CallbackConfigPath(configRoot string) string {
	root := strings.TrimSpace(configRoot)
	if root == "" {
		root = "/etc/fail2ban"
	}
	return filepath.Join(root, "fail2ban-ui-agent.id")
}

func SaveCallbackRuntimeConfig(configRoot string, cfg CallbackRuntimeConfig) error {
	cfg.ServerID = strings.TrimSpace(cfg.ServerID)
	cfg.CallbackURL = strings.TrimSpace(cfg.CallbackURL)
	cfg.CallbackSecret = strings.TrimSpace(cfg.CallbackSecret)
	cfg.CallbackHost = strings.TrimSpace(cfg.CallbackHost)

	path := CallbackConfigPath(configRoot)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0600)
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
