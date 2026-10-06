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

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/swissmakers/fail2ban-ui-agent/internal/api"
	"github.com/swissmakers/fail2ban-ui-agent/internal/callback"
	"github.com/swissmakers/fail2ban-ui-agent/internal/cli"
	"github.com/swissmakers/fail2ban-ui-agent/internal/config"
	"github.com/swissmakers/fail2ban-ui-agent/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui-agent/internal/health"
)

func main() {
	if handled, code := cli.Run(os.Args[1:]); handled {
		os.Exit(code)
	}
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	svc := fail2ban.NewService(cfg.ConfigRoot, cfg.LogRoot)
	supervisor := health.New(svc, health.Policy{
		Interval:    cfg.HealthInterval,
		MaxRetries:  cfg.HealthMaxRetries,
		AutoReload:  cfg.HealthAutoReload,
		AutoRestart: cfg.HealthAutoRestart,
	})
	poller := callback.NewPoller(cfg, svc, nil)
	server := api.New(cfg, svc, supervisor, poller)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go supervisor.Start(ctx)
	go poller.Run(ctx)

	if err := server.ListenAndServe(ctx, config.Addr(cfg), cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
