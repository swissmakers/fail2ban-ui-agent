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
	"context"
	"fmt"
	"log"
	"regexp"
	"slices"
	"strings"
)

var configuredActionPattern = regexp.MustCompile(`^\['set', '([^']+)', 'addaction', '([^']+)'`)

// Reads the actions every jail is configured with from a "fail2ban-client -d" dump.
func parseConfiguredActions(dump string) (jails []string, actions map[string][]string) {
	actions = make(map[string][]string)
	for line := range strings.SplitSeq(dump, "\n") {
		m := configuredActionPattern.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		if _, seen := actions[m[1]]; !seen {
			jails = append(jails, m[1])
		}
		actions[m[1]] = append(actions[m[1]], m[2])
	}
	return jails, actions
}

// Action names from "fail2ban-client get <jail> actions"; the list is the last line.
func parseRunningActions(output string) []string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var names []string
	for name := range strings.SplitSeq(lines[len(lines)-1], ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// Running jails that lack one of their configured actions. Jails absent from running are not judged.
func jailsMissingActions(dump string, running map[string][]string) []string {
	var missing []string
	jails, configured := parseConfiguredActions(dump)
	for _, jail := range jails {
		active, ok := running[jail]
		if !ok {
			continue
		}
		for _, action := range configured[jail] {
			if !slices.Contains(active, action) {
				missing = append(missing, jail)
				break
			}
		}
	}
	return missing
}

// Fail2ban drops an action that a reload adds to a running jail, which leaves the jail
// without its firewall or callback action. Restart only those jails so the action loads.
// Returns the output of the restarts, because Fail2ban reports jail errors there with exit code 0.
func (s *Service) restartJailsMissingActions(ctx context.Context) (string, error) {
	dump, err := s.client(ctx, shortCommandTimeout, "-d")
	if err != nil {
		log.Printf("warning: could not verify the jail actions after the reload: %v", err)
		return "", nil
	}
	jails, _ := parseConfiguredActions(dump)
	running := make(map[string][]string, len(jails))
	for _, jail := range jails {
		// A jail that is not running has no action list to compare.
		if out, err := s.client(ctx, shortCommandTimeout, "get", jail, "actions"); err == nil {
			running[jail] = parseRunningActions(out)
		}
	}
	var output []string
	for _, jail := range jailsMissingActions(dump, running) {
		log.Printf("jail %s runs without a configured action after the reload; restarting the jail", jail)
		out, err := s.client(ctx, max(longCommandTimeout, mutationCommandTimeout(ctx)), "reload", "--restart", jail)
		if err != nil {
			return strings.Join(output, "\n"), fmt.Errorf("restarting jail %s to load its actions failed: %w", jail, err)
		}
		output = append(output, out)
	}
	return strings.Join(output, "\n"), nil
}
