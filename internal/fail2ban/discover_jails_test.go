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
	"testing"
)

func TestDiscoverJailsFromFiles(t *testing.T) {
	root := t.TempDir()
	jd := filepath.Join(root, "jail.d")
	if err := os.MkdirAll(jd, 0755); err != nil {
		t.Fatal(err)
	}
	content := `[sshd]
enabled = true
`
	if err := os.WriteFile(filepath.Join(jd, "sshd.local"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	jails, err := DiscoverJailsFromFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(jails) != 1 || jails[0].JailName != "sshd" || !jails[0].Enabled {
		t.Fatalf("got %#v", jails)
	}
}

func TestDiscoverJailsFromFilesPrefersLocalOverConf(t *testing.T) {
	root := t.TempDir()
	jd := filepath.Join(root, "jail.d")
	if err := os.MkdirAll(jd, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(jd, "x.conf"), []byte("[x]\nenabled = true\n"), 0644)
	_ = os.WriteFile(filepath.Join(jd, "x.local"), []byte("[x]\nenabled = false\n"), 0644)
	jails, err := DiscoverJailsFromFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(jails) != 1 || jails[0].JailName != "x" || jails[0].Enabled {
		t.Fatalf("expected disabled from .local, got %#v", jails)
	}
}
