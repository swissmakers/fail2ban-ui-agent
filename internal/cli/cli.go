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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/config"
)

const usageText = `fail2ban-ui-agent: API agent for Fail2ban-UI (manages local fail2ban via fail2ban-client).

With no subcommand, starts the API server. Requires AGENT_SECRET (at least 16 characters, see README).

Subcommands:
  health-check          Query the agent's health endpoints (exit 0 when healthy).
  test connection       Check reachability of the Fail2ban-UI callback URL and, optionally, the callback secret.

Global:
  -h, --help            Show this help.

health-check:
  (default)             GET /healthz: the agent process answers.
  --ready               GET /readyz: fail2ban answers and the agent can manage it (container HEALTHCHECK).
  --detail              GET /v1/health with X-F2B-Token: full JSON report.
  --url <url>           Agent base URL (default: derived from AGENT_BIND_ADDRESS, AGENT_PORT and AGENT_TLS_CERT_FILE)
  --secret <token>      Agent token for --detail (default: AGENT_SECRET)
  --json                Print JSON result

test connection:
  --callback-url, --url <url>   Fail2ban-UI base URL (same as CALLBACK_URL in the UI settings)
  --callback-secret, --secret   Optional. When set, verifies X-Callback-Secret via GET .../api/healthcheck/callback
  --json                        Print JSON result

Without --callback-url, test connection uses the callback configuration pushed by Fail2ban-UI
(${AGENT_FAIL2BAN_CONFIG_DIR}/fail2ban-ui-agent.id), then AGENT_CALLBACK_URL/_SECRET/_SERVER_ID.

Environment (server mode): AGENT_SECRET, AGENT_BIND_ADDRESS, AGENT_PORT, AGENT_TLS_CERT_FILE, AGENT_TLS_KEY_FILE,
AGENT_FAIL2BAN_CONFIG_DIR, AGENT_LOG_ROOT, AGENT_HEALTH_*, AGENT_CALLBACK_URL, AGENT_CALLBACK_SECRET,
AGENT_CALLBACK_SERVER_ID, AGENT_CALLBACK_HOSTNAME, AGENT_CALLBACK_POLL_INTERVAL, see README.
`

// PrintUsage writes full help to w.
func PrintUsage(w io.Writer) {
	_, _ = io.WriteString(w, usageText)
}

// Run handles CLI subcommands. Returns handled=false to run the HTTP server.
func Run(args []string) (handled bool, exitCode int) {
	if len(args) == 0 {
		return false, 0
	}
	switch args[0] {
	case "-h", "--help":
		PrintUsage(os.Stdout)
		return true, 0
	case "health-check":
		if len(args) > 1 && (args[1] == "-h" || args[1] == "--help") {
			PrintUsage(os.Stdout)
			return true, 0
		}
		return true, healthCheck(args[1:])
	case "test":
		if len(args) > 1 && args[1] == "connection" {
			if len(args) > 2 && (args[2] == "-h" || args[2] == "--help") {
				PrintUsage(os.Stdout)
				return true, 0
			}
			return true, testConnection(args[2:])
		}
		fmt.Fprintln(os.Stderr, "usage: fail2ban-ui-agent test connection [--callback-url <url>] [--callback-secret <token>] [--json]")
		return true, 2
	}
	fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
	PrintUsage(os.Stderr)
	return true, 2
}

// Agent URL health-check uses when --url is absent; wildcard binds are reached via loopback.
func defaultAgentURL(bind string, port int, tls bool) string {
	host := bind
	if ip := net.ParseIP(bind); bind == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	scheme := "http"
	if tls {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
}

func healthCheck(args []string) int {
	var (
		baseURL  string
		secret   = strings.TrimSpace(os.Getenv("AGENT_SECRET"))
		endpoint = "/healthz"
		asJSON   bool
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ready":
			endpoint = "/readyz"
		case "--detail":
			endpoint = "/v1/health"
		case "--url", "--secret":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "health-check: %s needs a value\n", args[i])
				return 2
			}
			if args[i] == "--url" {
				baseURL = args[i+1]
			} else {
				secret = args[i+1]
			}
			i++
		case "--json":
			asJSON = true
		default:
			fmt.Fprintf(os.Stderr, "health-check: unknown flag %q\n", args[i])
			return 2
		}
	}
	if endpoint == "/v1/health" && secret == "" {
		fmt.Fprintln(os.Stderr, "health-check: --detail needs --secret or AGENT_SECRET")
		return 2
	}

	client := &http.Client{Timeout: 10 * time.Second}
	if baseURL == "" {
		cfg, err := config.ParseEnv()
		if err != nil {
			fmt.Fprintf(os.Stderr, "health-check: %v\n", err)
			return 2
		}
		baseURL = defaultAgentURL(cfg.BindAddress, cfg.Port, cfg.TLSCertFile != "")
		// The certificate names the public host, not 127.0.0.1; skip verification only for this derived loopback URL.
		if u, err := url.Parse(baseURL); err == nil && u.Scheme == "https" {
			if ip := net.ParseIP(u.Hostname()); ip != nil && ip.IsLoopback() {
				client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
			}
		}
	}

	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(baseURL, "/")+endpoint, nil)
	if err != nil {
		return printResult("health-check", asJSON, false, err.Error(), 1)
	}
	if endpoint == "/v1/health" {
		req.Header.Set("X-F2B-Token", secret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return printResult("health-check", asJSON, false, err.Error(), 1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	msg := fmt.Sprintf("status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return printResult("health-check", asJSON, true, msg, 0)
	}
	return printResult("health-check", asJSON, false, msg, 1)
}

// Flags win; otherwise the callback the running agent would use (store, then AGENT_CALLBACK_*).
func resolveTestTarget(flagURL, flagSecret string) (callbackURL, secret, source string, err error) {
	if strings.TrimSpace(flagURL) != "" {
		return strings.TrimSpace(flagURL), strings.TrimSpace(flagSecret), "flags", nil
	}
	cfg, err := config.ParseEnv()
	if err != nil {
		return "", "", "", err
	}
	cb, source, err := config.ResolveCallback(cfg.ConfigRoot, cfg.EnvCallback)
	if err != nil {
		return "", "", "", err
	}
	if source == config.CallbackSourceNone {
		return "", "", "", fmt.Errorf("no callback configured: pass --callback-url, or let Fail2ban-UI push its configuration")
	}
	return cb.CallbackURL, cb.CallbackSecret, source, nil
}

func testConnection(args []string) int {
	var (
		flagURL, flagSecret string
		asJSON              bool
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--callback-url", "--url", "--callback-secret", "--secret":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "test connection: %s needs a value\n", args[i])
				return 2
			}
			if args[i] == "--callback-url" || args[i] == "--url" {
				flagURL = args[i+1]
			} else {
				flagSecret = args[i+1]
			}
			i++
		case "--json":
			asJSON = true
		default:
			fmt.Fprintf(os.Stderr, "test connection: unknown flag %q\n", args[i])
			return 2
		}
	}
	callbackURL, callbackSecret, source, err := resolveTestTarget(flagURL, flagSecret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "test connection: %v\n", err)
		return 2
	}
	base := strings.TrimRight(callbackURL, "/")
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		fmt.Fprintln(os.Stderr, "test connection: invalid callback URL")
		return 2
	}

	client := &http.Client{Timeout: 10 * time.Second}
	parts := []string{"source=" + source}

	resp, err := client.Get(base + "/auth/status")
	if err != nil {
		return printResult("connection-test", asJSON, false, strings.Join(parts, "; ")+"; auth/status: "+err.Error(), 1)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if readErr != nil {
		return printResult("connection-test", asJSON, false, strings.Join(parts, "; ")+"; auth/status: "+readErr.Error(), 1)
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.Join(parts, "; ") + fmt.Sprintf("; auth/status: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
		return printResult("connection-test", asJSON, false, msg, 1)
	}
	parts = append(parts, fmt.Sprintf("auth/status OK (status=%d)", resp.StatusCode))

	if callbackSecret != "" {
		req, err := http.NewRequest(http.MethodGet, base+"/api/healthcheck/callback", nil)
		if err != nil {
			return printResult("connection-test", asJSON, false, strings.Join(parts, "; ")+"; ping: "+err.Error(), 1)
		}
		req.Header.Set("X-Callback-Secret", callbackSecret)
		resp2, err := client.Do(req)
		if err != nil {
			return printResult("connection-test", asJSON, false, strings.Join(parts, "; ")+"; healthcheck/callback: "+err.Error(), 1)
		}
		body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
		_ = resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			msg := strings.Join(parts, "; ") + fmt.Sprintf("; healthcheck/callback FAIL (status=%d body=%s)", resp2.StatusCode, strings.TrimSpace(string(body2)))
			return printResult("connection-test", asJSON, false, msg, 1)
		}
		parts = append(parts, fmt.Sprintf("healthcheck/callback OK (status=%d body=%s)", resp2.StatusCode, strings.TrimSpace(string(body2))))
	}

	return printResult("connection-test", asJSON, true, strings.Join(parts, "; "), 0)
}

func printResult(label string, asJSON, ok bool, message string, code int) int {
	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"ok":      ok,
			"message": message,
		})
	} else if ok {
		fmt.Printf("%s: OK (%s)\n", label, message)
	} else {
		fmt.Fprintf(os.Stderr, "%s: FAIL (%s)\n", label, message)
	}
	return code
}
