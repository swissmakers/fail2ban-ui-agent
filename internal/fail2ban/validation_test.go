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
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateJailName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"sshd", true}, {"nginx-http-auth", true}, {"my_jail", true}, {"Jail1", true}, {"_private", true},
		{"", false}, {"   ", false},
		{"../../../etc/cron.d/pwn", false}, {"..", false}, {"../foo", false}, {"foo/bar", false}, {"foo/../bar", false},
		{"a b", false}, {"a;b", false}, {"a$(id)", false}, {"a`id`", false}, {"a|b", false}, {"a&b", false},
		{"--help", false}, {"-s", false}, {"a\nb", false}, {"a\tb", false}, {"a.b", false},
		{"DEFAULT", false}, {"default", false}, {"INCLUDES", false},
		{"all", false}, {"ALL", false}, {"check-integrity", false}, {"Check-Integrity", false},
		{"all-web", true}, {"check-integrity2", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateJailName(tc.name)
			if (err == nil) != tc.ok {
				t.Fatalf("ValidateJailName(%q) = %v, want ok=%v", tc.name, err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrInvalidName) {
				t.Fatalf("error does not wrap ErrInvalidName: %v", err)
			}
		})
	}
}

func TestValidateFilterName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"sshd", true}, {"_custom", true}, {"all", true}, {"test", true},
		{"../../etc/passwd", false}, {"a/b", false}, {"..", false}, {"a b", false}, {"a;rm -rf", false}, {"-x", false}, {"", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateFilterName(tc.name); (err == nil) != tc.ok {
				t.Fatalf("ValidateFilterName(%q) = %v, want ok=%v", tc.name, err, tc.ok)
			}
		})
	}
}

func TestValidateLogpath(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"", "", true},
		{"  /var/log/auth.log  ", "/var/log/auth.log", true},
		{"/var/log/httpd/*_log", "/var/log/httpd/*_log", true},
		{"/var/log/app-[0-9].log", "/var/log/app-[0-9].log", true},
		{"/var/log/a.log /var/log/b.log", "/var/log/a.log /var/log/b.log", true},
		{"var/log/auth.log", "", false},
		{"/var/log/../../etc/shadow", "", false},
		{"/var/log/a..b", "", false},
		{"/var/log/$(id)", "", false},
		{"/var/log/a;b", "", false},
		{"/var/log/a\nb", "", false},
		{"/var/log/a\x00b", "", false},
		{"%(sshd_log)s", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ValidateLogpath(tc.in)
			if (err == nil) != tc.ok || got != tc.want {
				t.Fatalf("ValidateLogpath(%q) = %q, %v", tc.in, got, err)
			}
			if err != nil && !errors.Is(err, ErrLogpathInvalid) {
				t.Fatalf("error does not wrap ErrLogpathInvalid: %v", err)
			}
		})
	}
}

func TestValidIncludeName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"common.conf", true}, {"common.local", true}, {"apache-common.conf", true}, {"_x.conf", true},
		{"common", false}, {"common.sh", false}, {"../common.conf", false}, {"/etc/fail2ban/filter.d/common.conf", false},
		{"a.b.conf", false}, {".conf", false}, {"-x.conf", false}, {"%(x)s.conf", false},
	}
	for _, tc := range cases {
		if got := validIncludeName(tc.name); got != tc.ok {
			t.Errorf("validIncludeName(%q) = %v, want %v", tc.name, got, tc.ok)
		}
	}
}

// Traversal names must never write outside the config tree (the pre-fix behaviour was arbitrary-file-write as root).
func TestSetJailConfigBlocksTraversalWrite(t *testing.T) {
	root := t.TempDir()
	svc := NewService(root, "/var/log")

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
		if err := ValidateIP(ip); !errors.Is(err, ErrInvalidIP) {
			t.Errorf("ValidateIP(%q) = %v, want ErrInvalidIP", ip, err)
		}
	}
}
