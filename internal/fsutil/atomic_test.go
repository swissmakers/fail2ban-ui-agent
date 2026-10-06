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

package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteConfigPreservesBackupOnRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jail.local")
	old := "[sshd]\nenabled = false\n"
	if err := os.WriteFile(path, []byte(old), 0640); err != nil {
		t.Fatal(err)
	}
	// independent of the test runner's umask
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := WriteConfig(path, []byte("[sshd]\nenabled = true\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "[sshd]\nenabled = true\n" {
		t.Fatalf("target not replaced: %q %v", got, err)
	}
	backup, err := os.ReadFile(path + ".f2bui.bak")
	if err != nil || string(backup) != old {
		t.Fatalf("previous configuration lost: %s %v", backup, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatal("existing permissions were not preserved")
	}
	info, err = os.Stat(path + ".f2bui.bak")
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("backup must be private")
	}
}

func TestWriteConfigNewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sshd.local")
	if err := WriteConfig(path, []byte("[sshd]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("new file mode: %v %v", info, err)
	}
	if _, err := os.Stat(path + ".f2bui.bak"); !os.IsNotExist(err) {
		t.Fatal("a new file must not get a backup")
	}
}

// A dangling symlink must be followed and its target created, leaving the link intact.
func TestWriteConfigCreatesDanglingSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "managed", "jail.local")
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "jail.local")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteConfig(link, []byte("new\n"), 0644); err != nil {
		t.Fatalf("write through dangling symlink: %v", err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "new\n" {
		t.Fatalf("symlink target not written: %q %v", got, err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced by a regular file")
	}
}

func TestReplaceFileForcesModeWithoutBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fail2ban-ui-agent.id")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "new" {
		t.Fatalf("content: %q %v", got, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("mode not forced to 0600: %v %v", info, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected only the target file (no backup/temp leftovers), got %v %v", entries, err)
	}
}
