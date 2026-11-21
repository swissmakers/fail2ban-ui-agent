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
	"os"
	"path/filepath"
	"strings"

	"github.com/swissmakers/fail2ban-ui-agent/internal/fsutil"
)

const nftablesFixFile = "nftables.local"

// Same marker and content as Fail2ban-UI writes over SSH, so either side recognizes the file.
const nftablesFixMarker = "# Managed by Fail2ban-UI: nftables grep fix"

// Fail2ban reads nftables.local after nftables.conf and nftables-common.local for every nftables action.
const nftablesFixContent = nftablesFixMarker + `
#
# The nftables action of fail2ban 1.1.0 runs "grep -P". Busybox grep (Alpine based
# containers) has no -P, and SELinux denies it to fail2ban. When a jail stops, the
# failed grep makes the action delete the whole table with the sets of all other
# jails. These are the fixed commands from fail2ban 1.1.1. Fail2ban-UI removes this
# file once nftables.conf stops using "grep -P".

[Definition]

_nft_get_handle_id = sed -nE 's/.*@<addr_set>\s+.*\s+\#\s*(handle\s+[0-9]+)$/\1/p'

_nft_shutdown_table = { <nftables> list table <table_family> <table> | grep -qE '^\s+set\s+'; } || {
                        <nftables> delete table <table_family> <table>
                      }
`

// Reports whether the stock nftables.conf still runs grep -P in the commands the fix replaces.
func nftablesNeedsGrepFix(stock string) bool {
	return strings.Contains(stock, "_nft_shutdown_table") &&
		(strings.Contains(stock, "grep -oP") || strings.Contains(stock, "grep -qP"))
}

// Writes action.d/nftables.local while the stock action needs it and removes it afterwards.
func (s *Service) ensureNftablesFix() error {
	dir := filepath.Join(s.configRoot, "action.d")
	stock, err := os.ReadFile(filepath.Join(dir, "nftables.conf"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fixPath := filepath.Join(dir, nftablesFixFile)
	current, err := os.ReadFile(fixPath)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	owned := exists && strings.Contains(string(current), nftablesFixMarker)
	if !nftablesNeedsGrepFix(string(stock)) {
		if owned {
			return os.Remove(fixPath)
		}
		return nil
	}
	if exists && !owned {
		return fmt.Errorf("%s exists and is not managed by Fail2ban-UI", fixPath)
	}
	if string(current) == nftablesFixContent {
		return nil
	}
	return fsutil.WriteConfig(fixPath, []byte(nftablesFixContent), 0644)
}
