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

package fail2ban

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadJailConfigWithFallbackConfOnly(t *testing.T) {
	root := t.TempDir()
	jd := filepath.Join(root, "jail.d")
	if err := os.MkdirAll(jd, 0755); err != nil {
		t.Fatal(err)
	}
	want := "[airsonic-auth]\nenabled = false\n"
	if err := os.WriteFile(filepath.Join(jd, "airsonic-auth.conf"), []byte(want), 0644); err != nil {
		t.Fatal(err)
	}
	got, path, err := readJailConfigWithFallback("airsonic-auth", root)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("content = %q want %q", got, want)
	}
	if !strings.HasSuffix(path, "airsonic-auth.conf") {
		t.Fatalf("path = %s", path)
	}
}

func TestEnsureJailLocalFileCopiesFromConf(t *testing.T) {
	root := t.TempDir()
	jd := filepath.Join(root, "jail.d")
	if err := os.MkdirAll(jd, 0755); err != nil {
		t.Fatal(err)
	}
	want := "[j]\nfilter = f\n"
	if err := os.WriteFile(filepath.Join(jd, "j.conf"), []byte(want), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ensureJailLocalFile("j", root); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(jd, "j.local")
	raw, err := os.ReadFile(local)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != want {
		t.Fatalf("local = %q", raw)
	}
}

func TestApplyJailEnabledInContent(t *testing.T) {
	in := "[sshd]\nport = ssh\n"
	got := applyJailEnabledInContent(in, "sshd", true)
	if !strings.Contains(got, "enabled = true") {
		t.Fatalf("%q", got)
	}
}

func TestServiceGetJailConfigConfOnly(t *testing.T) {
	root := t.TempDir()
	jd := filepath.Join(root, "jail.d")
	if err := os.MkdirAll(jd, 0755); err != nil {
		t.Fatal(err)
	}
	want := "[x]\nenabled = true\n"
	if err := os.WriteFile(filepath.Join(jd, "x.conf"), []byte(want), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewService(root, "/tmp", "/var/log")
	got, path, err := s.GetJailConfig("x")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %q", got)
	}
	if !strings.HasSuffix(path, "x.conf") {
		t.Fatalf("path %s", path)
	}
}

func TestServiceUpdateJailEnabledStatesFromConfOnly(t *testing.T) {
	root := t.TempDir()
	jd := filepath.Join(root, "jail.d")
	if err := os.MkdirAll(jd, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jd, "z.conf"), []byte("[z]\nenabled = false\n"), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewService(root, "/tmp", "/var/log")
	if err := s.UpdateJailEnabledStates(map[string]bool{"z": true}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(jd, "z.local"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "enabled = true") {
		t.Fatalf("%s", raw)
	}
}
