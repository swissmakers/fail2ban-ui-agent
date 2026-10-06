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
	"errors"
	"fmt"
	"net"
	"path/filepath"
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

var (
	ErrInvalidName         = errors.New("invalid name")
	ErrInvalidIP           = errors.New("invalid IP address")
	ErrNotFound            = errors.New("not found")
	ErrLogpathInvalid      = errors.New("invalid logpath")
	ErrLogpathInaccessible = errors.New("logpath directory not accessible to the agent")
	ErrLogpathUnresolved   = errors.New("logpath variables could not be resolved")
	ErrConfigInvalid       = errors.New("fail2ban configuration test failed")
)

// Never starts with '-', so a name can not be read as a fail2ban-client flag (mirrors the UI's paths.go).
var configNamePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]*$`)

// DEFAULT/INCLUDES are fail2ban sections; ALL/CHECK-INTEGRITY would be shadowed by GET /v1/jails/{all,check-integrity}.
var reservedJailNames = map[string]bool{
	"DEFAULT":         true,
	"INCLUDES":        true,
	"ALL":             true,
	"CHECK-INTEGRITY": true,
}

// ValidateJailName enforces the fail2ban jail-name allowlist.
func ValidateJailName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("%w: jail name cannot be empty", ErrInvalidName)
	}
	if reservedJailNames[strings.ToUpper(name)] {
		return fmt.Errorf("%w: jail name %q is reserved", ErrInvalidName, name)
	}
	if !configNamePattern.MatchString(name) {
		return fmt.Errorf("%w: jail name %q contains invalid characters (only letters, digits, '-' and '_' are allowed, not starting with '-')", ErrInvalidName, name)
	}
	return nil
}

// ValidateFilterName enforces the fail2ban filter-name allowlist.
func ValidateFilterName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("%w: filter name cannot be empty", ErrInvalidName)
	}
	if !configNamePattern.MatchString(name) {
		return fmt.Errorf("%w: filter name %q contains invalid characters (only letters, digits, '-' and '_' are allowed, not starting with '-')", ErrInvalidName, name)
	}
	return nil
}

// ValidateIP ensures an IP/CIDR is well-formed before it is passed to
// fail2ban-client as an argument.
func ValidateIP(ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("%w: IP address cannot be empty", ErrInvalidIP)
	}
	if net.ParseIP(ip) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(ip); err == nil {
		return nil
	}
	return fmt.Errorf("%w: %q is neither an IP address nor a CIDR", ErrInvalidIP, ip)
}

// Same charset as the UI's sanitizeLogpath: absolute path characters plus the glob metacharacters.
var safeLogpathPattern = regexp.MustCompile(`^[A-Za-z0-9 ._/*?\[\]-]+$`)

// ValidateLogpath returns the trimmed logpath or ErrLogpathInvalid; empty input stays empty.
func ValidateLogpath(logpath string) (string, error) {
	logpath = strings.TrimSpace(logpath)
	if logpath == "" {
		return "", nil
	}
	if !filepath.IsAbs(logpath) {
		return "", fmt.Errorf("%w: %q must be absolute", ErrLogpathInvalid, logpath)
	}
	if !safeLogpathPattern.MatchString(logpath) {
		return "", fmt.Errorf("%w: %q contains unsupported characters", ErrLogpathInvalid, logpath)
	}
	if strings.Contains(logpath, "..") {
		return "", fmt.Errorf("%w: %q must not contain '..'", ErrLogpathInvalid, logpath)
	}
	return logpath, nil
}

// Reports whether an [INCLUDES] entry is a plain filter.d file name (<name>.conf or <name>.local).
func validIncludeName(name string) bool {
	base, ok := strings.CutSuffix(name, ".conf")
	if !ok {
		base, ok = strings.CutSuffix(name, ".local")
	}
	return ok && configNamePattern.MatchString(base)
}
