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

package fail2ban

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// The agent runs as root and drives fail2ban-client plus writes into
// /etc/fail2ban. The trust boundary is the network: an authenticated caller
// must never be able to escape the config tree or inject fail2ban-client flags.
// The main UI already validates these, but the agent must NOT trust its caller,
// so every name/IP is re-validated here. The strict allowlist (no '/', no '.',
// no whitespace, no shell/flag metacharacters) makes path traversal and argument
// injection impossible by construction.

// The name must start with an alphanumeric so it can never be interpreted as a
// flag (e.g. "--help", "-s") when passed to fail2ban-client as an argument.
var configNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

var reservedJailNames = map[string]bool{
	"DEFAULT":  true,
	"INCLUDES": true,
}

// ValidateJailName enforces the fail2ban jail-name allowlist.
func ValidateJailName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("jail name cannot be empty")
	}
	if reservedJailNames[strings.ToUpper(name)] {
		return fmt.Errorf("jail name %q is reserved", name)
	}
	if !configNamePattern.MatchString(name) {
		return fmt.Errorf("jail name %q contains invalid characters (only letters, digits, '-' and '_' are allowed)", name)
	}
	return nil
}

// ValidateFilterName enforces the fail2ban filter-name allowlist.
func ValidateFilterName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("filter name cannot be empty")
	}
	if !configNamePattern.MatchString(name) {
		return fmt.Errorf("filter name %q contains invalid characters (only letters, digits, '-' and '_' are allowed)", name)
	}
	return nil
}

// ValidateIP ensures an IP/CIDR is well-formed before it is passed to
// fail2ban-client as an argument.
func ValidateIP(ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("IP address cannot be empty")
	}
	if net.ParseIP(ip) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(ip); err == nil {
		return nil
	}
	return fmt.Errorf("invalid IP address or CIDR: %q", ip)
}
