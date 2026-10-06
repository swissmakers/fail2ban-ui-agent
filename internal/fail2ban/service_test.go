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
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// Installs fake tools as the only PATH entry, so the host's real fail2ban and service managers are never reached.
func fakeTools(t *testing.T, scripts map[string]string) {
	t.Helper()
	bin := t.TempDir()
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
}

// A fake fail2ban-client that only answers when called with -c <root>.
func fakeClient(root, cases string) string {
	return `[ "$1" = "-c" ] && [ "$2" = "` + root + `" ] || { echo "missing -c root" >&2; exit 64; }
shift 2
case "$1" in
` + cases + `
*) exit 1 ;;
esac
`
}

func TestPingRequiresPong(t *testing.T) {
	cases := []struct {
		name    string
		reply   string
		wantErr bool
	}{
		{"pong", `ping) echo "Server replied: pong" ;;`, false},
		{"unexpected reply", `ping) echo "Server replied: busy" ;;`, true},
		{"command fails", `ping) echo "Failed to access socket path" ; exit 255 ;;`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			fakeTools(t, map[string]string{"fail2ban-client": fakeClient(root, tc.reply)})
			if err := NewService(root, "/var/log").Ping(context.Background()); (err != nil) != tc.wantErr {
				t.Fatalf("Ping() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestReloadReturnsCommandOutput(t *testing.T) {
	root := t.TempDir()
	fakeTools(t, map[string]string{"fail2ban-client": fakeClient(root, `reload) echo "reload-ok" ;;`)})
	out, err := NewService(root, "/var/log").Reload(context.Background())
	if err != nil || !strings.Contains(out, "reload-ok") {
		t.Fatalf("Reload() = %q, %v", out, err)
	}
}

func TestRestartMode(t *testing.T) {
	cases := []struct {
		name        string
		managers    map[string]string
		reloadFails bool
		wantMode    string
		wantErr     bool
	}{
		{"systemctl restarts", map[string]string{"systemctl": "exit 0\n"}, false, "restart", false},
		{"falls through to service", map[string]string{"systemctl": "exit 1\n", "service": "exit 0\n"}, false, "restart", false},
		{"no service manager reloads", map[string]string{}, false, "reload", false},
		{"failed restart reloads", map[string]string{"rc-service": "exit 1\n"}, false, "reload", false},
		{"everything fails", map[string]string{"systemctl": "exit 1\n"}, true, "reload", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			reload := `reload) echo OK ;;`
			if tc.reloadFails {
				reload = `reload) exit 255 ;;`
			}
			tools := map[string]string{"fail2ban-client": fakeClient(root, reload)}
			for k, v := range tc.managers {
				tools[k] = v
			}
			fakeTools(t, tools)
			mode, err := NewService(root, "/var/log").Restart(context.Background())
			if mode != tc.wantMode || (err != nil) != tc.wantErr {
				t.Fatalf("Restart() = %q, %v; want %q, err=%v", mode, err, tc.wantMode, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "rc-service") {
				t.Fatalf("service managers that are not installed must not be tried: %v", err)
			}
		})
	}
}

func TestRestartTimeoutDoesNotTryNextManager(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "second-restart")
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep not available")
	}
	fakeTools(t, map[string]string{
		"fail2ban-client": fakeClient(root, `reload) echo OK ;;`),
		"systemctl":       "exec " + sleepBin + " 5\n",
		"service":         ": > " + marker + "\n",
	})
	defer func(d time.Duration) { restartTimeout = d }(restartTimeout)
	restartTimeout = 300 * time.Millisecond
	if _, err := NewService(root, "/var/log").Restart(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Restart() err = %v, want deadline exceeded", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a second service manager was started while the first restart was still running")
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name        string
		client      string
		wantInvalid bool
		wantErr     bool
		wantOutput  string
	}{
		{"valid", `echo "OK: configuration test is successful"`, false, false, "OK: configuration test"},
		{"invalid", `echo "ERROR: No section: 'Definition'"; exit 255`, true, true, "No section"},
		{"not installed", "", false, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tools := map[string]string{}
			if tc.client != "" {
				tools["fail2ban-client"] = `[ "$1 $2 $3" = "-c ` + root + ` -t" ] || exit 64
` + tc.client + "\n"
			}
			fakeTools(t, tools)
			out, err := NewService(root, "/var/log").Validate(context.Background())
			if (err != nil) != tc.wantErr || errors.Is(err, ErrConfigInvalid) != tc.wantInvalid {
				t.Fatalf("Validate() err = %v, want err=%v invalid=%v", err, tc.wantErr, tc.wantInvalid)
			}
			if !strings.Contains(out, tc.wantOutput) {
				t.Fatalf("output = %q, want %q", out, tc.wantOutput)
			}
		})
	}
}

func TestCapOutput(t *testing.T) {
	if got := capOutput([]byte("short"), 10); got != "short" {
		t.Fatalf("capOutput kept %q", got)
	}
	got := capOutput([]byte(strings.Repeat("x", 20)), 10)
	if !strings.HasPrefix(got, strings.Repeat("x", 10)+"\n") || strings.Count(got, "x") != 10 {
		t.Fatalf("capOutput = %q", got)
	}
}

func TestStoppedByAdmin(t *testing.T) {
	cases := []struct {
		name  string
		tools map[string]string
		want  bool
	}{
		{"inactive", map[string]string{"systemctl": `[ "$1 $2" = "show fail2ban" ] && printf 'LoadState=loaded\nActiveState=inactive\n'`}, true},
		{"failed", map[string]string{"systemctl": `printf 'LoadState=loaded\nActiveState=failed\n'`}, false},
		{"active", map[string]string{"systemctl": `printf 'LoadState=loaded\nActiveState=active\n'`}, false},
		{"unit unknown", map[string]string{"systemctl": `printf 'LoadState=not-found\nActiveState=inactive\n'`}, false},
		{"no systemd", map[string]string{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeTools(t, tc.tools)
			if got := NewService(t.TempDir(), "/var/log").StoppedByAdmin(context.Background()); got != tc.want {
				t.Fatalf("StoppedByAdmin() = %v, want %v", got, tc.want)
			}
		})
	}
}

// Lists the directory fail2ban-regex was pointed at, so tests can see which includes were staged.
const listFilterDir = `for f in "${2%/*}"/*; do echo "staged:${f##*/}"; done
exit ${F2B_EXIT:-0}
`

func TestTestFilterStagesIncludes(t *testing.T) {
	root := t.TempDir()
	fd := filepath.Join(root, "filter.d")
	files := map[string]string{
		"common.conf":  "[INCLUDES]\nafter = extra.conf\n[DEFAULT]\n_daemon = \\S*\n",
		"common.local": "[DEFAULT]\n_daemon = sshd\n",
		"extra.conf":   "[DEFAULT]\n",
		"d1.conf":      "[INCLUDES]\nbefore = d2.conf\n",
		"d2.conf":      "[INCLUDES]\nbefore = d3.conf\n",
		"d3.conf":      "[INCLUDES]\nbefore = d4.conf\n",
		"d4.conf":      "[DEFAULT]\n",
		"sshd.conf":    "[Definition]\nfailregex = old\n",
	}
	for name, content := range files {
		writeConfigFile(t, fd, name, content)
	}
	writeConfigFile(t, root, "escape.conf", "[DEFAULT]\n")
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	fakeTools(t, map[string]string{"fail2ban-regex": listFilterDir})

	content := "[INCLUDES]\nbefore = common.conf ../escape.conf ../../etc/passwd\n         d1.conf\nafter = sshd.conf evil.sh\n[Definition]\nfailregex = ^<HOST>$\n"
	out, path, code, err := NewService(root, "/var/log").TestFilter(context.Background(), "sshd", []string{"1.2.3.4"}, content)
	if err != nil || code != 0 {
		t.Fatalf("TestFilter() = code %d, err %v", code, err)
	}
	if filepath.Base(path) != testFilterFile {
		t.Fatalf("filterPath = %s", path)
	}
	for _, want := range []string{"common.conf", "common.local", "extra.conf", "d1.conf", "d2.conf", "d3.conf", testFilterFile, "test.log"} {
		if !strings.Contains(out, "staged:"+want+"\n") {
			t.Errorf("%s not staged:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"d4.conf", "passwd", "evil.sh", "sshd.conf", "escape.conf"} {
		if strings.Contains(out, "staged:"+unwanted+"\n") {
			t.Errorf("%s must not be staged:\n%s", unwanted, out)
		}
	}
	if _, err := os.Stat(filepath.Join(tmp, "escape.conf")); err == nil {
		t.Error("an include name escaped the staging directory")
	}
}

func TestTestFilterExitCodes(t *testing.T) {
	root := t.TempDir()
	writeConfigFile(t, filepath.Join(root, "filter.d"), "sshd.conf", "[Definition]\nfailregex = x\n")
	s := NewService(root, "/var/log")

	fakeTools(t, map[string]string{"fail2ban-regex": "echo 'ERROR: No failure-id group'; exit 255\n"})
	out, path, code, err := s.TestFilter(context.Background(), "sshd", []string{"line"}, "")
	if err != nil || code != 255 || !strings.Contains(out, "failure-id") || path != filepath.Join(root, "filter.d", "sshd.conf") {
		t.Fatalf("normal non-zero exit: out=%q path=%s code=%d err=%v", out, path, code, err)
	}

	fakeTools(t, map[string]string{})
	if _, _, _, err := s.TestFilter(context.Background(), "sshd", []string{"line"}, ""); err == nil {
		t.Fatal("missing fail2ban-regex must be an error")
	}
	if _, _, _, err := s.TestFilter(context.Background(), "nope", nil, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown filter: %v", err)
	}
}

func TestParseFilterIncludes(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{"none", "[Definition]\nfailregex = x\n", nil},
		{"before and after", "[INCLUDES]\nbefore = common.conf\nafter = extra.local\n", []string{"common.conf", "extra.local"}},
		{"several per line and continuation", "[INCLUDES]\nbefore = a.conf b.conf\n    c.conf\n", []string{"a.conf", "b.conf", "c.conf"}},
		{"case-insensitive section", "[includes]\nBefore = a.conf\n", []string{"a.conf"}},
		{"only inside INCLUDES", "[Definition]\nbefore = x.conf\n[INCLUDES]\nafter = y.conf\n[Init]\nafter = z.conf\n", []string{"y.conf"}},
		{"comments and other keys ignored", "[INCLUDES]\n# before = no.conf\nfoo = bar.conf\n  cont.conf\nbefore = yes.conf\n", []string{"yes.conf"}},
		{"CRLF", "[INCLUDES]\r\nbefore = common.conf\r\n", []string{"common.conf"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseFilterIncludes(tc.content); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseFilterIncludes = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFilterNamesFromEntries(t *testing.T) {
	fsys := fstest.MapFS{
		"sshd.conf":            {},
		"sshd.local":           {},
		"nginx-http-auth.conf": {},
		"_custom.local":        {},
		".sshd.local.swp":      {},
		".hidden.conf":         {},
		".f2bui-123":           {},
		"README":               {},
		"bad name.conf":        {},
		"a.b.conf":             {},
		"sshd.local.f2bui.bak": {},
		"ignorecommands/x":     {},
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"_custom", "nginx-http-auth", "sshd"}
	if got := filterNamesFromEntries(entries); !reflect.DeepEqual(got, want) {
		t.Fatalf("filterNamesFromEntries = %v, want %v", got, want)
	}
}

func TestGetFiltersMissingDirIsEmpty(t *testing.T) {
	got, err := NewService(t.TempDir(), "/var/log").GetFilters()
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("GetFilters() = %#v, %v", got, err)
	}
}

func TestEnsureSectionHeader(t *testing.T) {
	cases := []struct {
		name, content, want string
	}{
		{"empty", "", "[sshd]\n"},
		{"whitespace only", "  \n", "[sshd]\n"},
		{"missing header", "enabled = true\n", "[sshd]\nenabled = true\n"},
		{"header present", "[sshd]\nenabled = true\n", "[sshd]\nenabled = true\n"},
		{"header after DEFAULT", "[DEFAULT]\nx = 1\n [sshd] \n", "[DEFAULT]\nx = 1\n [sshd] \n"},
		{"other section only", "[nginx]\nenabled = true\n", "[sshd]\n[nginx]\nenabled = true\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ensureSectionHeader("sshd", tc.content); got != tc.want {
				t.Fatalf("ensureSectionHeader = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCreateJailAddsSectionHeader(t *testing.T) {
	root := t.TempDir()
	if err := NewService(root, "/var/log").CreateJail("myjail", "enabled = true\n"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "jail.d", "myjail.local"))
	if err != nil || string(raw) != "[myjail]\nenabled = true\n" {
		t.Fatalf("jail file = %q, %v", raw, err)
	}
}

func TestIsManagedJailLocal(t *testing.T) {
	cases := []struct {
		content string
		want    bool
	}{
		{"[DEFAULT]\n# managed by fail2ban-ui-agent\n", true},
		{"[DEFAULT]\naction_mwlg = %(action_)s\n  ui-custom-action[logpath=x]\n", true},
		{"[DEFAULT]\nbantime = 1h\n", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isManagedJailLocal(tc.content); got != tc.want {
			t.Errorf("isManagedJailLocal(%q) = %v, want %v", tc.content, got, tc.want)
		}
	}
}

func TestEnsureJailLocalStructure(t *testing.T) {
	legacy := "[DEFAULT]\nenabled = true\n# Custom Fail2Ban action for UI callbacks\naction_mwlg = %(action_)s\n             ui-custom-action[logpath=\"%(logpath)s\", chain=\"%(chain)s\"]\n# Custom Fail2Ban action applied by fail2ban-ui\naction = %(action_mwlg)s\n"
	cases := []struct {
		name       string
		existing   *string
		content    string
		wantReason string
		check      func(t *testing.T, got string)
	}{
		{name: "creates missing file", content: "[DEFAULT]\nbantime = 1h\n", check: func(t *testing.T, got string) {
			if !strings.Contains(got, "bantime = 1h") || !strings.Contains(got, agentManagedMarker) {
				t.Fatalf("content = %q", got)
			}
		}},
		{name: "rewrites a legacy UI file", existing: &legacy, content: legacy, check: func(t *testing.T, got string) {
			if strings.Contains(got, "ui-custom-action") || strings.Contains(got, "action_mwlg") || !strings.Contains(got, "enabled = true") {
				t.Fatalf("legacy action block survived: %q", got)
			}
		}},
		{name: "never touches a user file", existing: ptr("[DEFAULT]\nbantime = 1d\n"), content: "[DEFAULT]\n", wantReason: "unmanaged", check: func(t *testing.T, got string) {
			if got != "[DEFAULT]\nbantime = 1d\n" {
				t.Fatalf("user file modified: %q", got)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			p := filepath.Join(root, "jail.local")
			if tc.existing != nil {
				if err := os.WriteFile(p, []byte(*tc.existing), 0644); err != nil {
					t.Fatal(err)
				}
			}
			reason, err := NewService(root, "/var/log").EnsureJailLocalStructure(tc.content)
			if err != nil || reason != tc.wantReason {
				t.Fatalf("EnsureJailLocalStructure = %q, %v", reason, err)
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, string(raw))
		})
	}
}

func ptr[T any](v T) *T { return &v }

func TestRemapLogRoot(t *testing.T) {
	cases := []struct {
		p, logRoot, want string
	}{
		{"/var/log/auth.log", "/remotelogs", "/remotelogs/auth.log"},
		{"/var/log/httpd/*.log", "/remotelogs", "/remotelogs/httpd/*.log"},
		{"/var/log", "/remotelogs", "/remotelogs"},
		{"/var/logfoo/x.log", "/remotelogs", "/var/logfoo/x.log"},
		{"/opt/app/app.log", "/remotelogs", "/opt/app/app.log"},
		{"/var/log/auth.log", "/var/log", "/var/log/auth.log"},
		{"/var/log/auth.log", "", "/var/log/auth.log"},
	}
	for _, tc := range cases {
		if got := remapLogRoot(tc.p, tc.logRoot); got != tc.want {
			t.Errorf("remapLogRoot(%q, %q) = %q, want %q", tc.p, tc.logRoot, got, tc.want)
		}
	}
}

func TestTestLogpathWithResolutionVariable(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "paths-common.conf"), []byte("apache_error_log = /var/log/httpd/error_log\n"), 0644); err != nil {
		t.Fatal(err)
	}
	logRoot := t.TempDir()
	target := filepath.Join(logRoot, "httpd", "error_log")
	writeConfigFile(t, filepath.Dir(target), "error_log", "x")
	orig, resolved, files, err := NewService(root, logRoot).TestLogpathWithResolution("%(apache_error_log)s")
	if err != nil {
		t.Fatal(err)
	}
	if orig != "%(apache_error_log)s" || resolved != target {
		t.Fatalf("orig=%q resolved=%q", orig, resolved)
	}
	if len(files) != 1 || files[0] != target {
		t.Fatalf("files=%v target=%s", files, target)
	}
}

func TestTestLogpathErrors(t *testing.T) {
	locked := filepath.Join(t.TempDir(), "locked")
	writeConfigFile(t, locked, "app.log", "x")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0755) })

	cases := []struct {
		name    string
		logpath string
		want    error
	}{
		{"relative", "var/log/auth.log", ErrLogpathInvalid},
		{"traversal", "/var/log/../../etc/shadow", ErrLogpathInvalid},
		{"shell characters", "/var/log/$(id).log", ErrLogpathInvalid},
		{"unresolved variable", "%(no_such_var)s", ErrLogpathUnresolved},
		{"file in unreadable dir", filepath.Join(locked, "app.log"), ErrLogpathInaccessible},
		{"unreadable dir", locked, ErrLogpathInaccessible},
		{"glob in unreadable dir", filepath.Join(locked, "*.log"), ErrLogpathInaccessible},
	}
	s := NewService(t.TempDir(), "/var/log")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.want == ErrLogpathInaccessible && os.Geteuid() == 0 {
				t.Skip("root bypasses directory permissions")
			}
			if _, _, _, err := s.TestLogpathWithResolution(tc.logpath); !errors.Is(err, tc.want) {
				t.Fatalf("TestLogpathWithResolution(%q) = %v, want %v", tc.logpath, err, tc.want)
			}
		})
	}
}

func TestTestLogpathDirectoryReturnsFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etc")
	writeConfigFile(t, dir, "a.conf", "a")
	writeConfigFile(t, dir, "b.log", "b")
	if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	got, err := NewService(t.TempDir(), "/var/log").TestLogpath(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(dir, "a.conf"), filepath.Join(dir, "b.log")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestDeleteFilterRemovesLocalAndConf(t *testing.T) {
	root := t.TempDir()
	filterDir := filepath.Join(root, "filter.d")
	for _, name := range []string{"apache.local", "apache.conf", "apache.local.f2bui.bak", "apache.conf.f2bui.bak"} {
		writeConfigFile(t, filterDir, name, "")
	}

	if err := NewService(root, "/var/log").DeleteFilter("apache"); err != nil {
		t.Fatalf("DeleteFilter failed: %v", err)
	}
	for _, name := range []string{"apache.local", "apache.conf", "apache.local.f2bui.bak", "apache.conf.f2bui.bak"} {
		if _, err := os.Stat(filepath.Join(filterDir, name)); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed", name)
		}
	}
}

func TestDeleteReturnsNotFound(t *testing.T) {
	s := NewService(t.TempDir(), "/var/log")
	if err := s.DeleteFilter("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteFilter: %v", err)
	}
	if err := s.DeleteJail("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteJail: %v", err)
	}
}
