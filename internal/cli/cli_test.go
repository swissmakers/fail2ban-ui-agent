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

package cli

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/swissmakers/fail2ban-ui-agent/internal/config"
)

// Points the CLI at an empty config root and clears the AGENT_* secret, listen, TLS and callback inputs it reads.
func isolateEnv(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, k := range []string{"AGENT_SECRET", "AGENT_BIND_ADDRESS", "AGENT_PORT", "AGENT_TLS_CERT_FILE", "AGENT_TLS_KEY_FILE",
		"AGENT_CALLBACK_URL", "AGENT_CALLBACK_SECRET", "AGENT_CALLBACK_SERVER_ID", "AGENT_CALLBACK_HOSTNAME"} {
		t.Setenv(k, "")
	}
	t.Setenv("AGENT_FAIL2BAN_CONFIG_DIR", root)
	return root
}

func TestRun(t *testing.T) {
	cases := []struct {
		args        []string
		wantHandled bool
		wantCode    int
	}{
		{nil, false, 0},
		{[]string{"--help"}, true, 0},
		{[]string{"helth-check"}, true, 2},
		{[]string{"--port", "9700"}, true, 2},
		{[]string{"test"}, true, 2},
		{[]string{"test", "connectoin"}, true, 2},
	}
	for _, tc := range cases {
		handled, code := Run(tc.args)
		if handled != tc.wantHandled || code != tc.wantCode {
			t.Errorf("Run(%q) = handled=%v code=%d, want %v %d", tc.args, handled, code, tc.wantHandled, tc.wantCode)
		}
	}
}

func TestDefaultAgentURL(t *testing.T) {
	cases := []struct {
		bind string
		port int
		tls  bool
		want string
	}{
		{"0.0.0.0", 9700, false, "http://127.0.0.1:9700"},
		{"::", 9700, true, "https://127.0.0.1:9700"},
		{"", 9443, false, "http://127.0.0.1:9443"},
		{"127.0.0.1", 9700, true, "https://127.0.0.1:9700"},
		{"10.0.0.5", 9700, false, "http://10.0.0.5:9700"},
		{"fd00::5", 9700, true, "https://[fd00::5]:9700"},
	}
	for _, tc := range cases {
		if got := defaultAgentURL(tc.bind, tc.port, tc.tls); got != tc.want {
			t.Errorf("defaultAgentURL(%q, %d, %v) = %q, want %q", tc.bind, tc.port, tc.tls, got, tc.want)
		}
	}
}

func TestHealthCheck(t *testing.T) {
	isolateEnv(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/readyz":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"ready":false}`))
		case "/v1/health":
			if r.Header.Get("X-F2B-Token") != "agent-token-0123456789" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"ready":false}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"liveness", []string{"--url", ts.URL, "--json"}, 0},
		{"readiness failing", []string{"--ready", "--url", ts.URL}, 1},
		{"detail with token", []string{"--detail", "--url", ts.URL, "--secret", "agent-token-0123456789"}, 0},
		{"detail with wrong token", []string{"--detail", "--url", ts.URL, "--secret", "wrong-token-0123456789"}, 1},
		{"detail without token", []string{"--detail", "--url", ts.URL}, 2},
		{"unknown flag", []string{"--url", ts.URL, "--verbose"}, 2},
		{"missing flag value", []string{"--url"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := healthCheck(tc.args); got != tc.want {
				t.Fatalf("healthCheck(%q) = %d, want %d", tc.args, got, tc.want)
			}
		})
	}
}

func TestResolveTestTarget(t *testing.T) {
	stored := config.CallbackRuntimeConfig{ServerID: "srv-store", CallbackURL: "https://store.example.com", CallbackSecret: "store-secret"}
	cases := []struct {
		name                string
		flagURL, flagSecret string
		store               bool
		envURL              string
		wantURL, wantSource string
		wantSecret          string
		wantErr             bool
	}{
		{name: "flags win", flagURL: "https://flag.example.com", store: true, envURL: "https://env.example.com", wantURL: "https://flag.example.com", wantSource: "flags"},
		{name: "store beats env", store: true, envURL: "https://env.example.com", wantURL: stored.CallbackURL, wantSecret: stored.CallbackSecret, wantSource: config.CallbackSourceStore},
		{name: "env fallback", envURL: "https://env.example.com", wantURL: "https://env.example.com", wantSecret: "env-secret", wantSource: config.CallbackSourceEnv},
		{name: "nothing configured", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := isolateEnv(t)
			if tc.store {
				if err := config.SaveCallbackRuntimeConfig(root, stored); err != nil {
					t.Fatal(err)
				}
			}
			if tc.envURL != "" {
				t.Setenv("AGENT_CALLBACK_URL", tc.envURL)
				t.Setenv("AGENT_CALLBACK_SECRET", "env-secret")
				t.Setenv("AGENT_CALLBACK_SERVER_ID", "srv-env")
			}
			gotURL, gotSecret, source, err := resolveTestTarget(tc.flagURL, tc.flagSecret)
			if (err != nil) != tc.wantErr || gotURL != tc.wantURL || gotSecret != tc.wantSecret || source != tc.wantSource {
				t.Fatalf("resolveTestTarget = (%q, %q, %q, %v)", gotURL, gotSecret, source, err)
			}
		})
	}
}

func fakeUI(t *testing.T, secretOK *atomic.Bool) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/status":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"enabled":false}`))
		case "/api/healthcheck/callback":
			if r.Header.Get("X-Callback-Secret") != "good" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			secretOK.Store(true)
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestTestConnection(t *testing.T) {
	var secretOK atomic.Bool
	ts := fakeUI(t, &secretOK)
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"reachability only", []string{"--callback-url", ts.URL, "--json"}, 0},
		{"good secret", []string{"--callback-url", ts.URL, "--callback-secret", "good"}, 0},
		{"wrong secret", []string{"--callback-url", ts.URL, "--callback-secret", "bad"}, 1},
		{"nothing configured", nil, 2},
		{"unknown flag", []string{"--callback-url", ts.URL, "--insecure"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateEnv(t)
			if got := testConnection(tc.args); got != tc.want {
				t.Fatalf("testConnection(%q) = %d, want %d", tc.args, got, tc.want)
			}
		})
	}
}

func TestTestConnectionUsesStoredCallback(t *testing.T) {
	var secretOK atomic.Bool
	ts := fakeUI(t, &secretOK)
	root := isolateEnv(t)
	if err := config.SaveCallbackRuntimeConfig(root, config.CallbackRuntimeConfig{ServerID: "srv-1", CallbackURL: ts.URL, CallbackSecret: "good"}); err != nil {
		t.Fatal(err)
	}
	if code := testConnection(nil); code != 0 || !secretOK.Load() {
		t.Fatalf("exit=%d secretVerified=%v", code, secretOK.Load())
	}
}
