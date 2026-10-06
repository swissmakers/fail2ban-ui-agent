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

package model

import "time"

type JailInfo struct {
	JailName      string   `json:"jailName"`
	TotalBanned   int      `json:"totalBanned"`
	NewInLastHour int      `json:"newInLastHour"`
	BannedIPs     []string `json:"bannedIPs"`
	Enabled       bool     `json:"enabled"`
}

// The json-tagged fields form the supervisor block of /v1/health.
type HealthState struct {
	PingOK         bool        `json:"-"`
	Env            Environment `json:"-"`
	StoppedByAdmin bool        `json:"-"`

	LastCheck            time.Time `json:"lastCheck,omitzero"`
	LastSuccess          time.Time `json:"lastSuccess,omitzero"`
	LastError            string    `json:"lastError,omitempty"`
	ConsecutiveFails     int       `json:"consecutiveFails"`
	LastRemediation      string    `json:"lastRemediation,omitempty"`
	LastRemediationAt    time.Time `json:"lastRemediationAt,omitzero"`
	RemediationAttempts  int       `json:"remediationAttempts"`
	RemediationSuspended bool      `json:"remediationSuspended"`
}

// Host prerequisites checked alongside each ping.
type Environment struct {
	ConfigWritable bool
	Fail2banClient bool
	Fail2banRegex  bool
}

type ReadyChecks struct {
	Ping           bool `json:"ping"`
	ConfigWritable bool `json:"configWritable"`
	Fail2banClient bool `json:"fail2banClient"`
	Fail2banRegex  bool `json:"fail2banRegex"`
	Fresh          bool `json:"fresh"`
}
