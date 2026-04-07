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

package model

import "time"

type JailInfo struct {
	JailName      string   `json:"jailName"`
	TotalBanned   int      `json:"totalBanned"`
	NewInLastHour int      `json:"newInLastHour"`
	BannedIPs     []string `json:"bannedIPs"`
	Enabled       bool     `json:"enabled"`
}

type HealthState struct {
	Healthy          bool      `json:"healthy"`
	LastCheck        time.Time `json:"lastCheck"`
	LastSuccess      time.Time `json:"lastSuccess"`
	LastError        string    `json:"lastError,omitempty"`
	LastRemediation  string    `json:"lastRemediation,omitempty"`
	ConsecutiveFails int       `json:"consecutiveFails"`
}
