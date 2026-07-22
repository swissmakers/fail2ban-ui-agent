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
	"os"
	"path/filepath"
	"testing"
)

func TestValidateJailNameRejectsTraversalAndInjection(t *testing.T) {
	bad := []string{
		"", "   ",
		"../../../etc/cron.d/pwn",
		"..", "../foo", "foo/bar", "foo/../bar",
		"a b", "a;b", "a$(id)", "a`id`", "a|b", "a&b",
		"--help", "-s", "a\nb", "a\tb",
		"DEFAULT", "default", "INCLUDES",
	}
	for _, name := range bad {
		if err := ValidateJailName(name); err == nil {
			t.Errorf("ValidateJailName(%q) accepted an invalid name", name)
		}
	}
	for _, name := range []string{"sshd", "nginx-http-auth", "my_jail", "Jail1"} {
		if err := ValidateJailName(name); err != nil {
			t.Errorf("ValidateJailName(%q) rejected a valid name: %v", name, err)
		}
	}
}

func TestValidateFilterNameRejectsTraversal(t *testing.T) {
	for _, name := range []string{"../../etc/passwd", "a/b", "..", "a b", "a;rm -rf"} {
		if err := ValidateFilterName(name); err == nil {
			t.Errorf("ValidateFilterName(%q) accepted an invalid name", name)
		}
	}
	if err := ValidateFilterName("sshd"); err != nil {
		t.Errorf("ValidateFilterName rejected a valid name: %v", err)
	}
}

// TestSetJailConfigBlocksTraversalWrite ensures a traversal name can never write
// outside the config tree (the pre-fix behaviour was arbitrary-file-write as root).
func TestSetJailConfigBlocksTraversalWrite(t *testing.T) {
	root := t.TempDir()
	svc := NewService(root, "/run/fail2ban", "/var/log")

	victim := filepath.Join(t.TempDir(), "cron.d")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	target := "../../../../../../../../.." + filepath.Join(victim, "pwn")

	if err := svc.SetJailConfig(target, "* * * * * root id\n"); err == nil {
		t.Fatal("SetJailConfig accepted a traversal jail name")
	}
	if _, err := os.Stat(filepath.Join(victim, "pwn.local")); !os.IsNotExist(err) {
		t.Fatal("traversal write escaped the config root")
	}
}

func TestValidateIP(t *testing.T) {
	for _, ip := range []string{"1.2.3.4", "::1", "10.0.0.0/8"} {
		if err := ValidateIP(ip); err != nil {
			t.Errorf("ValidateIP(%q) rejected a valid value: %v", ip, err)
		}
	}
	for _, ip := range []string{"", "not-an-ip", "1.2.3.4; rm -rf /", "--help"} {
		if err := ValidateIP(ip); err == nil {
			t.Errorf("ValidateIP(%q) accepted an invalid value", ip)
		}
	}
}
