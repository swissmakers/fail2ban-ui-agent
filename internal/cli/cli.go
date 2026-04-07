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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const usageText = `fail2ban-ui-agent — API agent for Fail2ban-UI (manages local fail2ban via fail2ban-client).

With no subcommand, starts the API server. Requires AGENT_SECRET (see README).

Subcommands:
  health-check          GET the agent's /healthz endpoint (optional X-F2B-Token).
  test connection       Check reachability to Fail2ban-UI callback base URL and optionally the callback secret.

Global:
  -h, --help            Show this help.

health-check:
  --url <url>           Agent base URL (default: AGENT_URL or http://127.0.0.1:9700)
  --secret <token>      AGENT_SECRET value for X-F2B-Token (default: AGENT_SECRET env)
  --json                Print JSON result

test connection:
  --callback-url, --url <url>   Fail2ban-UI base URL (same as CALLBACK_URL in server config)
  --callback-secret, --secret   Optional. When set, verifies X-Callback-Secret via GET .../api/healthcheck/callback
  --json                        Print JSON result

Without --callback-secret: only checks GET {base}/auth/status.
With --callback-secret: checks auth/status then GET {base}/api/healthcheck/callback with X-Callback-Secret.

Environment (server mode): AGENT_SECRET, AGENT_BIND_ADDRESS, AGENT_PORT, AGENT_FAIL2BAN_*,
AGENT_CALLBACK_URL, AGENT_CALLBACK_SECRET, AGENT_CALLBACK_SERVER_ID, AGENT_CALLBACK_HOSTNAME,
AGENT_CALLBACK_POLL_INTERVAL — see README.
`

// PrintUsage writes full help to w.
func PrintUsage(w io.Writer) {
	_, _ = io.WriteString(w, usageText)
}

// Run handles CLI subcommands. Returns handled=false to run the HTTP server.
func Run(args []string) (handled bool, exitCode int) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		PrintUsage(os.Stdout)
		return true, 0
	}
	if len(args) == 0 {
		return false, 0
	}
	switch args[0] {
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
		fmt.Fprintln(os.Stderr, "usage: fail2ban-ui-agent test connection --callback-url <url> [--callback-secret <token>] [--json]")
		return true, 2
	default:
		return false, 0
	}
}

func healthCheck(args []string) int {
	var (
		baseURL = strings.TrimSpace(os.Getenv("AGENT_URL"))
		secret  = strings.TrimSpace(os.Getenv("AGENT_SECRET"))
		asJSON  bool
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--url":
			if i+1 < len(args) {
				baseURL = args[i+1]
				i++
			}
		case "--secret":
			if i+1 < len(args) {
				secret = args[i+1]
				i++
			}
		case "--json":
			asJSON = true
		}
	}
	if baseURL == "" {
		baseURL = "http://127.0.0.1:9700"
	}
	reqURL := strings.TrimRight(baseURL, "/") + "/healthz"
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return printConnResult(asJSON, false, err.Error(), 1)
	}
	if secret != "" {
		req.Header.Set("X-F2B-Token", secret)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return printConnResult(asJSON, false, err.Error(), 1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	ok := resp.StatusCode < 400
	msg := fmt.Sprintf("status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	if ok {
		return printConnResult(asJSON, true, msg, 0)
	}
	return printConnResult(asJSON, false, msg, 1)
}

func testConnection(args []string) int {
	var (
		callbackURL    = strings.TrimSpace(os.Getenv("CALLBACK_URL"))
		callbackSecret = strings.TrimSpace(os.Getenv("CALLBACK_SECRET"))
		asJSON         bool
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--callback-url", "--url":
			if i+1 < len(args) {
				callbackURL = args[i+1]
				i++
			}
		case "--callback-secret", "--secret":
			if i+1 < len(args) {
				callbackSecret = args[i+1]
				i++
			}
		case "--json":
			asJSON = true
		}
	}
	if strings.TrimSpace(callbackURL) == "" {
		fmt.Fprintln(os.Stderr, "test connection requires --callback-url")
		return 2
	}
	base := strings.TrimRight(strings.TrimSpace(callbackURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		fmt.Fprintln(os.Stderr, "invalid --callback-url")
		return 2
	}

	client := &http.Client{Timeout: 10 * time.Second}

	statusURL := base + "/auth/status"
	req, err := http.NewRequest(http.MethodGet, statusURL, nil)
	if err != nil {
		return printConnResult(asJSON, false, err.Error(), 1)
	}
	resp, err := client.Do(req)
	if err != nil {
		return printConnResult(asJSON, false, "auth/status: "+err.Error(), 1)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if readErr != nil {
		return printConnResult(asJSON, false, "auth/status: "+readErr.Error(), 1)
	}
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("auth/status: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
		return printConnResult(asJSON, false, msg, 1)
	}
	parts := []string{fmt.Sprintf("auth/status OK (status=%d)", resp.StatusCode)}

	if callbackSecret != "" {
		pingURL := base + "/api/healthcheck/callback"
		req2, err := http.NewRequest(http.MethodGet, pingURL, nil)
		if err != nil {
			return printConnResult(asJSON, false, strings.Join(parts, "; ")+"; ping: "+err.Error(), 1)
		}
		req2.Header.Set("X-Callback-Secret", callbackSecret)
		resp2, err := client.Do(req2)
		if err != nil {
			return printConnResult(asJSON, false, strings.Join(parts, "; ")+"; healthcheck/callback: "+err.Error(), 1)
		}
		body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
		_ = resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			msg := strings.Join(parts, "; ") + fmt.Sprintf("; healthcheck/callback FAIL (status=%d body=%s)", resp2.StatusCode, strings.TrimSpace(string(body2)))
			return printConnResult(asJSON, false, msg, 1)
		}
		parts = append(parts, fmt.Sprintf("healthcheck/callback OK (status=%d body=%s)", resp2.StatusCode, strings.TrimSpace(string(body2))))
	}

	return printConnResult(asJSON, true, strings.Join(parts, "; "), 0)
}

func printConnResult(asJSON, ok bool, message string, code int) int {
	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"ok":      ok,
			"message": message,
		})
	} else {
		if ok {
			fmt.Printf("connection-test: OK (%s)\n", message)
		} else {
			fmt.Fprintf(os.Stderr, "connection-test: FAIL (%s)\n", message)
		}
	}
	return code
}
