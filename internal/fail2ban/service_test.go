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

package fail2ban

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSetEnabledValue(t *testing.T) {
	got := setEnabledValue("[sshd]\nport = ssh\n", "sshd", false)
	if !containsLine(got, "enabled = false") {
		t.Fatalf("enabled not inserted: %q", got)
	}
	got2 := setEnabledValue("[sshd]\nenabled = false\n", "sshd", true)
	if !containsLine(got2, "enabled = true") {
		t.Fatalf("enabled not replaced: %q", got2)
	}
}

func containsLine(s, line string) bool {
	return strings.Contains(s, line)
}

func TestCleanupLegacyUICustomAction(t *testing.T) {
	root := t.TempDir()
	jailLocal := filepath.Join(root, "jail.local")
	content := "[DEFAULT]\n# managed by fail2ban-ui-agent\naction = ui-custom-action\nbanaction = iptables-multiport\n"
	if err := os.WriteFile(jailLocal, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewService(root, "/var/run/fail2ban", "/var/log")
	if err := s.CleanupLegacyUICustomAction(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(jailLocal)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if strings.Contains(got, "ui-custom-action") {
		t.Fatalf("legacy action still present: %s", got)
	}
	if !strings.Contains(got, "managed by fail2ban-ui-agent") {
		t.Fatalf("managed marker missing: %s", got)
	}
}

func TestTestLogpathWithResolutionVariable(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "paths-common.conf.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "paths-common.conf"), []byte("apache_error_log = /var/log/httpd/error_log\n"), 0644); err != nil {
		t.Fatal(err)
	}
	logRoot := t.TempDir()
	target := filepath.Join(logRoot, "httpd", "error_log")
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewService(root, "/var/run/fail2ban", logRoot)
	orig, resolved, files, err := s.TestLogpathWithResolution("%(apache_error_log)s")
	if err != nil {
		t.Fatal(err)
	}
	if orig != "%(apache_error_log)s" {
		t.Fatalf("orig=%q", orig)
	}
	if !strings.HasPrefix(resolved, logRoot) {
		t.Fatalf("resolved not mapped to logRoot: %q", resolved)
	}
	if len(files) != 1 || files[0] != target {
		t.Fatalf("files=%v target=%s", files, target)
	}
}

func TestTestLogpathDirectoryReturnsFiles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc")
	if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	a := filepath.Join(dir, "a.conf")
	b := filepath.Join(dir, "b.log")
	if err := os.WriteFile(a, []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("b"), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewService(root, "/var/run/fail2ban", "/var/log")
	got, err := s.TestLogpath(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{a, b}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestEnsureJailLocalStructureWithContentStripsUIAction(t *testing.T) {
	root := t.TempDir()
	s := NewService(root, "/var/run/fail2ban", "/var/log")
	content := `[DEFAULT]
enabled = true
# Custom Fail2Ban action for UI callbacks
action_mwlg = %(action_)s
             ui-custom-action[logpath="%(logpath)s", chain="%(chain)s"]
# Custom Fail2Ban action applied by fail2ban-ui
action = %(action_mwlg)s
`
	if err := s.EnsureJailLocalStructureWithContent(content); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "jail.local"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if strings.Contains(got, "ui-custom-action") || strings.Contains(got, "action_mwlg") {
		t.Fatalf("unexpected legacy action block: %s", got)
	}
	if !strings.Contains(got, "enabled = true") {
		t.Fatalf("expected defaults content in jail.local: %s", got)
	}
}
