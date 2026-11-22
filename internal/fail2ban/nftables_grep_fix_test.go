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
	"os"
	"path/filepath"
	"testing"
)

const (
	stockNftables110 = `_nft_get_handle_id = grep -oP '@<addr_set>\s+.*\s+\Khandle\s+(\d+)$'
_nft_shutdown_table = { <nftables> list table <table_family> <table> | grep -qP '^\s+set\s+'; } || {
`
	stockNftables111 = `_nft_get_handle_id = sed -nE 's/.*@<addr_set>\s+.*\s+\#\s*(handle\s+[0-9]+)$/\1/p'
_nft_shutdown_table = { <nftables> list table <table_family> <table> | grep -qE '^\s+set\s+'; } || {
`
	adminNftablesLocal = "[Init]\ntable = f2b-admin\n"
)

func TestNftablesNeedsGrepFix(t *testing.T) {
	cases := []struct {
		name  string
		stock string
		want  bool
	}{
		{"fail2ban 1.1.0", stockNftables110, true},
		{"fail2ban 1.1.1", stockNftables111, false},
		{"no nftables.conf", "", false},
		{"other layout with grep -P", "actionstop = nft list table | grep -qP x\n", false},
	}
	for _, c := range cases {
		if got := nftablesNeedsGrepFix(c.stock); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// Writes action.d with the given nftables.conf and nftables.local; an empty string skips the file.
func nftablesFixRoot(t *testing.T, stock, existing string) (root, fixPath string) {
	t.Helper()
	root = t.TempDir()
	dir := filepath.Join(root, "action.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fixPath = filepath.Join(dir, nftablesFixFile)
	for path, content := range map[string]string{filepath.Join(dir, "nftables.conf"): stock, fixPath: existing} {
		if content == "" {
			continue
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, fixPath
}

func TestEnsureNftablesFix(t *testing.T) {
	cases := []struct {
		name     string
		stock    string
		existing string
		want     string
		wantErr  bool
	}{
		{"writes the fix for 1.1.0", stockNftables110, "", nftablesFixContent, false},
		{"keeps a current fix", stockNftables110, nftablesFixContent, nftablesFixContent, false},
		{"replaces an outdated fix", stockNftables110, nftablesFixMarker + "\nold\n", nftablesFixContent, false},
		{"leaves an admin file alone", stockNftables110, adminNftablesLocal, adminNftablesLocal, true},
		{"removes the fix once fail2ban is fixed", stockNftables111, nftablesFixContent, "", false},
		{"leaves an admin file alone on a fixed fail2ban", stockNftables111, adminNftablesLocal, adminNftablesLocal, false},
		{"does nothing without nftables.conf", "", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root, fixPath := nftablesFixRoot(t, c.stock, c.existing)
			if err := NewService(root, "/var/log").ensureNftablesFix(); (err != nil) != c.wantErr {
				t.Errorf("err = %v, wantErr %v", err, c.wantErr)
			}
			got, err := os.ReadFile(fixPath)
			if c.want == "" {
				if !os.IsNotExist(err) {
					t.Errorf("nftables.local must not exist, got %q (err %v)", got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Errorf("nftables.local = %q, want %q", got, c.want)
			}
		})
	}
}

// Every way the agent applies configuration puts the fix in place before fail2ban reads it.
func TestApplyingConfigurationWritesNftablesFix(t *testing.T) {
	ctx := context.Background()
	for name, apply := range map[string]func(s *Service) error{
		"reload":         func(s *Service) error { _, err := s.Reload(ctx); return err },
		"reload-restart": func(s *Service) error { _, err := s.ReloadRestart(ctx); return err },
		"restart":        func(s *Service) error { _, err := s.Restart(ctx); return err },
	} {
		t.Run(name, func(t *testing.T) {
			root, fixPath := nftablesFixRoot(t, stockNftables110, "")
			check := `[ -f "` + fixPath + `" ] || exit 9`
			fakeTools(t, map[string]string{
				"fail2ban-client": fakeClient(root, "reload) "+check+" ;;\n-d) ;;"),
				"systemctl":       check + "\n",
			})
			if err := apply(NewService(root, "/var/log")); err != nil {
				t.Fatalf("fail2ban ran before the fix was written: %v", err)
			}
		})
	}
}
