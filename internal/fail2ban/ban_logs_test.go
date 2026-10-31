// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
//
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
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseMonitoredLogpaths(t *testing.T) {
	out := "Current monitored log file(s):\n|- /var/log/auth.log\n`- /var/log/nginx/access.log\n"
	want := []string{"/var/log/auth.log", "/var/log/nginx/access.log"}
	if got := parseMonitoredLogpaths(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("parseMonitoredLogpaths = %v, want %v", got, want)
	}
	if got := parseMonitoredLogpaths("No file is currently monitored\n"); len(got) != 0 {
		t.Fatalf("no monitored files must give no paths, got %v", got)
	}
}

func TestContainsWordMatchesWholeAddressesOnly(t *testing.T) {
	cases := map[string]bool{
		"Failed password for root from 192.0.2.1 port 22":  true,
		"client=[192.0.2.1]:443":                           true,
		"192.0.2.1":                                        true,
		"Failed password for root from 192.0.2.10 port 22": false,
		"id_192.0.2.1":                                     false,
	}
	for line, want := range cases {
		if got := containsWord(line, "192.0.2.1"); got != want {
			t.Errorf("containsWord(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestTailLinesNewestFirstDropsCutLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(path, []byte("first line\nsecond line\nthird line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, want := tailLinesNewestFirst(path, 1<<20), []string{"third line", "second line", "first line"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("full read = %v, want %v", got, want)
	}
	if got, want := tailLinesNewestFirst(path, 20), []string{"third line"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("tail read must drop the cut line: %v, want %v", got, want)
	}
	if got := tailLinesNewestFirst(t.TempDir(), 1<<20); got != nil {
		t.Fatalf("a directory must give no lines, got %v", got)
	}
}

func TestCollectBanLogMatchesPerIPWithLimit(t *testing.T) {
	lines := []string{
		"newest from 192.0.2.1",
		"other host 198.51.100.7",
		"from 192.0.2.10 must not count",
		"older from 192.0.2.1",
		"oldest from 192.0.2.1",
	}
	got := collectBanLogMatches(lines, []string{"192.0.2.1", "198.51.100.7", "203.0.113.9"}, 2)
	if want := []string{"newest from 192.0.2.1", "older from 192.0.2.1"}; !reflect.DeepEqual(got["192.0.2.1"], want) {
		t.Fatalf("matches = %v, want %v", got["192.0.2.1"], want)
	}
	if len(got["198.51.100.7"]) != 1 || len(got["203.0.113.9"]) != 0 {
		t.Fatalf("unexpected matches: %v", got)
	}
}

func TestSanitizeLogTextKeepsPrintableASCII(t *testing.T) {
	in := "ok\tline\r\nbell\x07 esc\x1b[31m endé"
	if got, want := sanitizeLogText(in), "ok\tline\r\nbell esc[31m end"; got != want {
		t.Fatalf("sanitizeLogText = %q, want %q", got, want)
	}
	if strings.ContainsAny(sanitizeLogText("\x00\x7f"), "\x00\x7f") {
		t.Fatal("control characters must be removed")
	}
}

func TestJournalLinesKeepsLinesReadBeforeScanError(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf 'newest from 192.0.2.1\\nolder from 192.0.2.1\\n'\nhead -c 1100000 /dev/zero | tr '\\000' a\necho\n"
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	lines, err := journalLinesNewestFirst(context.Background())
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("an oversized journal line must be reported, got %v", err)
	}
	if want := []string{"newest from 192.0.2.1", "older from 192.0.2.1"}; !reflect.DeepEqual(lines, want) {
		t.Fatalf("lines before the error = %v, want %v", lines, want)
	}
}
