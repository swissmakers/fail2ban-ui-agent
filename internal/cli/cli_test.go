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

package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestRunHelp(t *testing.T) {
	handled, code := Run([]string{"--help"})
	if !handled || code != 0 {
		t.Fatalf("Run(--help) = handled=%v code=%d", handled, code)
	}
}

func TestTestConnectionReachabilityOnly(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enabled":false}`))
	}))
	defer ts.Close()

	code := testConnection([]string{"--callback-url", ts.URL, "--json"})
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
}

func TestTestConnectionWithSecretPing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/status":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		case "/api/healthcheck/callback":
			if r.Header.Get("X-Callback-Secret") != "good" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	t.Setenv("CALLBACK_URL", "")
	t.Setenv("CALLBACK_SECRET", "")
	code := testConnection([]string{"--callback-url", ts.URL, "--callback-secret", "good", "--json"})
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
}

func TestTestConnectionWrongSecret(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/status" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if r.URL.Path == "/api/healthcheck/callback" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	code := testConnection([]string{"--callback-url", ts.URL, "--callback-secret", "bad"})
	if code == 0 {
		t.Fatal("expected non-zero exit")
	}
}

func TestTestConnectionRequiresURL(t *testing.T) {
	_ = os.Unsetenv("CALLBACK_URL")
	code := testConnection(nil)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}
