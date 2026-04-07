// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU General Public License, Version 3 (GPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/gpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/config"
	"github.com/swissmakers/fail2ban-ui-agent/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui-agent/internal/health"
)

type Server struct {
	secret     string
	configRoot string
	svc        *fail2ban.Service
	health     *health.Supervisor
	mux        *http.ServeMux
}

func New(secret string, configRoot string, svc *fail2ban.Service, hs *health.Supervisor) *Server {
	s := &Server{
		secret:     secret,
		configRoot: configRoot,
		svc:        svc,
		health:     hs,
		mux:        http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/readyz", s.handleReady)

	s.mux.HandleFunc("/v1/callback/config", s.auth(s.handleCallbackConfig))
	s.mux.HandleFunc("/v1/actions/reload", s.auth(s.handleActionReload))
	s.mux.HandleFunc("/v1/actions/restart", s.auth(s.handleActionRestart))

	s.mux.HandleFunc("/v1/jails", s.auth(s.handleJailsRoot))
	s.mux.HandleFunc("/v1/jails/", s.auth(s.handleJailsSub))
	s.mux.HandleFunc("/v1/jails/all", s.auth(s.handleJailsAll))
	s.mux.HandleFunc("/v1/jails/update-enabled", s.auth(s.handleJailsUpdateEnabled))
	s.mux.HandleFunc("/v1/jails/test-logpath", s.auth(s.handleJailsTestLogpath))
	s.mux.HandleFunc("/v1/jails/test-logpath-with-resolution", s.auth(s.handleJailsTestLogpathWithResolution))
	s.mux.HandleFunc("/v1/jails/check-integrity", s.auth(s.handleCheckIntegrity))
	s.mux.HandleFunc("/v1/jails/ensure-structure", s.auth(s.handleEnsureStructure))

	s.mux.HandleFunc("/v1/filters", s.auth(s.handleFiltersRoot))
	s.mux.HandleFunc("/v1/filters/", s.auth(s.handleFiltersSub))
	s.mux.HandleFunc("/v1/filters/test", s.auth(s.handleFiltersTest))
}

func (s *Server) ListenAndServe(ctx context.Context, addr, tlsCertFile, tlsKeyFile string) error {
	server := &http.Server{
		Addr:              addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("fail2ban-ui-agent listening on %s", addr)
		var err error
		if tlsCertFile != "" && tlsKeyFile != "" {
			log.Printf("TLS enabled for agent API")
			err = server.ListenAndServeTLS(tlsCertFile, tlsKeyFile)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shCtx)
	case err := <-errCh:
		return err
	}
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-F2B-Token")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.secret)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	state := s.health.State()
	code := http.StatusOK
	if !state.Healthy {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, state)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	state := s.health.State()
	if !state.Healthy {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ready": false, "state": state})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ready": true, "state": state})
}

func (s *Server) handleActionReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if err := s.svc.Reload(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleActionRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if err := s.svc.Restart(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleCallbackConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		ServerID       string `json:"serverId"`
		CallbackURL    string `json:"callbackUrl"`
		CallbackSecret string `json:"callbackSecret"`
		CallbackHost   string `json:"callbackHostname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	req.ServerID = strings.TrimSpace(req.ServerID)
	req.CallbackURL = strings.TrimSpace(req.CallbackURL)
	req.CallbackSecret = strings.TrimSpace(req.CallbackSecret)
	req.CallbackHost = strings.TrimSpace(req.CallbackHost)
	if req.ServerID == "" || req.CallbackURL == "" || req.CallbackSecret == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "serverId, callbackUrl and callbackSecret are required"})
		return
	}
	if err := config.SaveCallbackRuntimeConfig(s.configRoot, config.CallbackRuntimeConfig{
		ServerID:       req.ServerID,
		CallbackURL:    req.CallbackURL,
		CallbackSecret: req.CallbackSecret,
		CallbackHost:   req.CallbackHost,
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	_ = s.svc.CleanupLegacyUICustomAction()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleJailsRoot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jails, err := s.svc.GetJailInfos(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"jails": jails})
	case http.MethodPost:
		var req struct {
			Name    string `json:"name"`
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
			return
		}
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name is required"})
			return
		}
		if err := s.svc.CreateJail(req.Name, req.Content); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (s *Server) handleJailsAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	jails, err := s.svc.GetAllJailsForManage(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jails": jails})
}

func (s *Server) handleJailsUpdateEnabled(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var updates map[string]bool
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if err := s.svc.UpdateJailEnabledStates(updates); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleJailsTestLogpath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		Logpath string `json:"logpath"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	files, err := s.svc.TestLogpath(req.Logpath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": files})
}

func (s *Server) handleJailsTestLogpathWithResolution(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		Logpath string `json:"logpath"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	orig, resolved, files, err := s.svc.TestLogpathWithResolution(req.Logpath)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"original_logpath": orig,
			"resolved_logpath": resolved,
			"files":            []string{},
			"error":            err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"original_logpath": orig,
		"resolved_logpath": resolved,
		"files":            files,
	})
}

func (s *Server) handleCheckIntegrity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	exists, managed, hasLegacyUIAction, err := s.svc.CheckJailLocalState()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"exists":      exists,
		"hasUIAction": hasLegacyUIAction,
		"managed":     managed,
	})
}

func (s *Server) handleEnsureStructure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		Content string `json:"content"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := s.svc.EnsureJailLocalStructureWithContent(req.Content); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleJailsSub(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/v1/jails/")
	parts := splitPath(tail)
	if len(parts) == 1 && r.Method == http.MethodDelete {
		if err := s.svc.DeleteJail(parts[0]); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		ips, total, err := s.svc.GetBannedIPs(r.Context(), parts[0])
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"jail":        parts[0],
			"bannedIPs":   ips,
			"totalBanned": total,
		})
		return
	}
	if len(parts) == 2 && parts[1] == "config" {
		switch r.Method {
		case http.MethodGet:
			cfg, path, err := s.svc.GetJailConfig(parts[0])
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "filePath": path})
			return
		case http.MethodPut:
			var req struct {
				Config string `json:"config"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
				return
			}
			if err := s.svc.SetJailConfig(parts[0], req.Config); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
			return
		}
	}
	if len(parts) == 2 && parts[1] == "ban" && r.Method == http.MethodPost {
		var req struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
			return
		}
		if ip := net.ParseIP(strings.TrimSpace(req.IP)); ip == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid IP"})
			return
		}
		if err := s.svc.BanIP(r.Context(), parts[0], req.IP); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if len(parts) == 2 && parts[1] == "unban" && r.Method == http.MethodPost {
		var req struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
			return
		}
		if ip := net.ParseIP(strings.TrimSpace(req.IP)); ip == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid IP"})
			return
		}
		if err := s.svc.UnbanIP(r.Context(), parts[0], req.IP); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": fmt.Sprintf("not found: %s", r.URL.Path)})
}

func (s *Server) handleFiltersRoot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		filters, err := s.svc.GetFilters()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"filters": filters})
	case http.MethodPost:
		var req struct {
			Name    string `json:"name"`
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
			return
		}
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name is required"})
			return
		}
		if err := s.svc.CreateFilter(req.Name, req.Content); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (s *Server) handleFiltersSub(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/v1/filters/")
	parts := splitPath(tail)
	if len(parts) != 1 {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	name := parts[0]
	switch r.Method {
	case http.MethodGet:
		cfg, path, err := s.svc.GetFilterConfig(name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "filePath": path})
	case http.MethodPut:
		var req struct {
			Config string `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
			return
		}
		if err := s.svc.SetFilterConfig(name, req.Config); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case http.MethodDelete:
		if err := s.svc.DeleteFilter(name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (s *Server) handleFiltersTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		FilterName    string   `json:"filterName"`
		LogLines      []string `json:"logLines"`
		FilterContent string   `json:"filterContent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if strings.TrimSpace(req.FilterName) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "filterName is required"})
		return
	}
	out, path, err := s.svc.TestFilter(r.Context(), req.FilterName, req.LogLines, req.FilterContent)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":      err.Error(),
			"output":     out,
			"filterPath": path,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": out, "filterPath": path})
}

func splitPath(s string) []string {
	s = strings.Trim(s, "/")
	if s == "" {
		return nil
	}
	return strings.Split(s, "/")
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
