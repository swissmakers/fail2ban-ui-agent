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
	"strings"
	"testing"
)

func writeConfigFile(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", name, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestResolveLogpathVariables(t *testing.T) {
	t.Run("no variables passes through unchanged", func(t *testing.T) {
		got, err := ResolveLogpathVariables("/var/log/auth.log", t.TempDir())
		if err != nil || got != "/var/log/auth.log" {
			t.Fatalf("got %q, err %v", got, err)
		}
	})

	t.Run("empty logpath", func(t *testing.T) {
		got, err := ResolveLogpathVariables("", t.TempDir())
		if err != nil || got != "" {
			t.Fatalf("got %q, err %v", got, err)
		}
	})

	// Regression: values with regexp replacement metacharacters must be substituted verbatim.
	t.Run("dollar signs in values survive substitution", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, root, "vars.local", "dollar_dir = /var/log/$1/${site}\nnested = %(dollar_dir)s/x\n")

		got, err := ResolveLogpathVariables("%(dollar_dir)s/app.log", root)
		if err != nil || got != "/var/log/$1/${site}/app.log" {
			t.Fatalf("got %q, err %v", got, err)
		}
		got, err = ResolveLogpathVariables("%(nested)s", root)
		if err != nil || got != "/var/log/$1/${site}/x" {
			t.Fatalf("nested: got %q, err %v", got, err)
		}
	})

	t.Run(".local shadows .conf", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, root, "paths.conf", "logdir = /from-conf\n")
		writeConfigFile(t, root, "paths.local", "logdir = /from-local\n")

		got, err := ResolveLogpathVariables("%(logdir)s/app.log", root)
		if err != nil || got != "/from-local/app.log" {
			t.Fatalf(".local must win over .conf, got %q, err %v", got, err)
		}
	})

	t.Run("falls back to .conf when no .local defines it", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, root, "paths.conf", "logdir = /from-conf\n")

		got, err := ResolveLogpathVariables("%(logdir)s/app.log", root)
		if err != nil || got != "/from-conf/app.log" {
			t.Fatalf("got %q, err %v", got, err)
		}
	})

	t.Run("searches subdirectories", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, root, "jail.d/custom.local", "deepvar = /deep/path\n")

		got, err := ResolveLogpathVariables("%(deepvar)s/x.log", root)
		if err != nil || got != "/deep/path/x.log" {
			t.Fatalf("got %q, err %v", got, err)
		}
	})

	t.Run("nested variable references resolve", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, root, "paths.local", "base = /var/log\nappdir = %(base)s/app\n")

		got, err := ResolveLogpathVariables("%(appdir)s/access.log", root)
		if err != nil || got != "/var/log/app/access.log" {
			t.Fatalf("got %q, err %v", got, err)
		}
	})

	t.Run("multiple variables in one logpath", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, root, "paths.local", "d1 = /a\nd2 = /b\n")

		got, err := ResolveLogpathVariables("%(d1)s/x %(d2)s/y", root)
		if err != nil || got != "/a/x /b/y" {
			t.Fatalf("got %q, err %v", got, err)
		}
	})

	t.Run("multiline continuation is joined", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, root, "paths.local", "multi = /one/a.log\n         /two/b.log\n\nother = x\n")

		got, err := ResolveLogpathVariables("%(multi)s", root)
		if err != nil || !strings.Contains(got, "/one/a.log") || !strings.Contains(got, "/two/b.log") {
			t.Fatalf("both continuation lines must be present, got %q, err %v", got, err)
		}
	})

	t.Run("undefined variable is an error", func(t *testing.T) {
		if _, err := ResolveLogpathVariables("%(nope)s/x.log", t.TempDir()); err == nil {
			t.Fatal("expected an error for an undefined variable")
		}
	})

	t.Run("circular reference is an error, not a hang", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, root, "loop.local", "a = %(b)s\nb = %(a)s\n")

		if _, err := ResolveLogpathVariables("%(a)s", root); err == nil {
			t.Fatal("expected an error for a circular reference")
		}
	})

	t.Run("missing config root is an error", func(t *testing.T) {
		if _, err := ResolveLogpathVariables("%(x)s", filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
			t.Fatal("expected an error when the config root is absent")
		}
	})
}

func TestSearchVariableInFileReportsScannerErrors(t *testing.T) {
	root := t.TempDir()
	// A single line beyond bufio.Scanner's 64 KiB token limit.
	writeConfigFile(t, root, "huge.local", "other = "+strings.Repeat("x", 70*1024)+"\n")
	if _, err := searchVariableInFile(filepath.Join(root, "huge.local"), "wanted"); err == nil {
		t.Fatal("scanner error was swallowed")
	}
}

func TestExtractVariablesFromString(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"/var/log/auth.log", nil},
		{"%(a)s", []string{"a"}},
		{"%(a)s/%(b)s", []string{"a", "b"}},
		{"prefix-%(with_underscore)s-suffix", []string{"with_underscore"}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := extractVariablesFromString(tc.in)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("extractVariablesFromString(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
