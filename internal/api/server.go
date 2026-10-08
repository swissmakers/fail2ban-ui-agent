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

package api

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/callback"
	"github.com/swissmakers/fail2ban-ui-agent/internal/config"
	"github.com/swissmakers/fail2ban-ui-agent/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui-agent/internal/health"
	"github.com/swissmakers/fail2ban-ui-agent/internal/model"
	"github.com/swissmakers/fail2ban-ui-agent/internal/operations"
	"github.com/swissmakers/fail2ban-ui-agent/internal/version"
)

const (
	maxRequestBodyBytes = 5 << 20
	// Below the UI's 60 s request timeout, so the result still reaches it.
	actionTimeout      = 55 * time.Second
	healthProbeTimeout = 5 * time.Second
)

type Server struct {
	cfg        config.Config
	svc        *fail2ban.Service
	health     *health.Supervisor
	poller     *callback.Poller
	mux        *http.ServeMux
	operations *operations.Manager
}

func New(cfg config.Config, svc *fail2ban.Service, hs *health.Supervisor, poller *callback.Poller) *Server {
	s := &Server{cfg: cfg, svc: svc, health: hs, poller: poller, mux: http.NewServeMux()}
	s.operations = operations.New(filepath.Join(cfg.ConfigRoot, ".fail2ban-ui-operations"), operationRunner{svc: svc, health: hs})
	s.routes()
	return s
}

// Literal segments beat {name}; only GET /v1/jails/{all,check-integrity} shadow a jail, hence the reserved names.
func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /readyz", s.handleReadyz)

	s.mux.HandleFunc("GET /v1/health", s.auth(s.handleHealthDetail))
	s.mux.HandleFunc("GET /v1/operations/capabilities", s.auth(s.handleOperationCapabilities))
	s.mux.HandleFunc("POST /v1/operations", s.auth(s.handleSubmitOperation))
	s.mux.HandleFunc("GET /v1/operations/{id}", s.auth(s.handleGetOperation))
	s.mux.HandleFunc("POST /v1/operations/{id}/reconcile", s.auth(s.handleReconcileOperation))
	s.mux.HandleFunc("POST /v1/config/snapshots", s.auth(s.handleBackupConfiguration))
	s.mux.HandleFunc("POST /v1/config/snapshots/{id}/restore", s.auth(s.handleRestoreConfiguration))
	s.mux.HandleFunc("DELETE /v1/config/snapshots/{id}", s.auth(s.handleDeleteConfigurationBackup))
	s.mux.HandleFunc("PUT /v1/callback/config", s.auth(s.handlePutCallbackConfig))
	s.mux.HandleFunc("DELETE /v1/callback/config", s.auth(s.handleDeleteCallbackConfig))
	s.mux.HandleFunc("POST /v1/actions/reload", s.auth(s.handleActionReload))
	s.mux.HandleFunc("POST /v1/actions/restart", s.auth(s.handleActionRestart))
	s.mux.HandleFunc("POST /v1/actions/validate", s.auth(s.handleActionValidate))

	s.mux.HandleFunc("GET /v1/jails", s.auth(s.handleListJails))
	s.mux.HandleFunc("POST /v1/jails", s.auth(s.handleCreateJail))
	s.mux.HandleFunc("GET /v1/jails/all", s.auth(s.handleJailsAll))
	s.mux.HandleFunc("POST /v1/jails/update-enabled", s.auth(s.handleJailsUpdateEnabled))
	s.mux.HandleFunc("POST /v1/jails/test-logpath", s.auth(s.handleJailsTestLogpath))
	s.mux.HandleFunc("POST /v1/jails/test-logpath-with-resolution", s.auth(s.handleJailsTestLogpathWithResolution))
	s.mux.HandleFunc("GET /v1/jails/check-integrity", s.auth(s.handleCheckIntegrity))
	s.mux.HandleFunc("POST /v1/jails/ensure-structure", s.auth(s.handleEnsureStructure))
	s.mux.HandleFunc("GET /v1/jails/{name}", s.auth(s.handleJailBanned))
	s.mux.HandleFunc("DELETE /v1/jails/{name}", s.auth(s.handleDeleteJail))
	s.mux.HandleFunc("GET /v1/jails/{name}/config", s.auth(s.handleGetJailConfig))
	s.mux.HandleFunc("PUT /v1/jails/{name}/config", s.auth(s.handlePutJailConfig))
	s.mux.HandleFunc("POST /v1/jails/{name}/ban", s.auth(s.handleJailIP("ban")))
	s.mux.HandleFunc("POST /v1/jails/{name}/unban", s.auth(s.handleJailIP("unban")))

	s.mux.HandleFunc("GET /v1/filters", s.auth(s.handleListFilters))
	s.mux.HandleFunc("POST /v1/filters", s.auth(s.handleCreateFilter))
	s.mux.HandleFunc("POST /v1/filters/test", s.auth(s.handleFiltersTest))
	s.mux.HandleFunc("GET /v1/filters/{name}", s.auth(s.handleGetFilter))
	s.mux.HandleFunc("PUT /v1/filters/{name}", s.auth(s.handlePutFilter))
	s.mux.HandleFunc("DELETE /v1/filters/{name}", s.auth(s.handleDeleteFilter))
}

func (s *Server) ListenAndServe(ctx context.Context, addr, tlsCertFile, tlsKeyFile string) error {
	defer s.operations.Close()
	server := &http.Server{
		Addr:              addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		// Match the UI-side connector, which also pins TLS 1.2 as the floor.
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	tlsEnabled := tlsCertFile != "" && tlsKeyFile != ""
	if host, _, err := net.SplitHostPort(addr); !tlsEnabled && (err != nil || !isLoopbackHost(host)) {
		// The agent bearer token and the pushed callback secret would travel in
		// cleartext. Warn loudly so this is never done unknowingly in production.
		log.Printf("WARNING: agent is binding a non-loopback address (%s) WITHOUT TLS - the agent token and callback secret will be transmitted in cleartext. Set AGENT_TLS_CERT_FILE/AGENT_TLS_KEY_FILE, or bind to localhost behind a TLS-terminating proxy.", addr)
	}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("fail2ban-ui-agent %s listening on %s", version.Version, addr)
		var err error
		if tlsEnabled {
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
		if s.cfg.Secret == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": "server misconfigured: no agent secret set",
				"code":  "auth_not_configured",
			})
			return
		}
		token := r.Header.Get("X-F2B-Token")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.Secret)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "unauthorized",
				"code":  "auth_invalid_token",
			})
			return
		}
		// Bound the request body for every authenticated (body-carrying) route.
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		if operationMutation(r) {
			release, err := s.operations.AcquireMutation()
			if err != nil {
				writeOperationError(w, err)
				return
			}
			defer release()
			r = r.WithContext(fail2ban.ManagedOperationContext(r.Context()))
		}
		next(w, r)
	}
}

func (s *Server) readiness() (model.HealthState, bool, model.ReadyChecks) {
	st := s.health.State()
	ready, checks := health.Ready(st, time.Now(), s.health.Interval())
	return st, ready, checks
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// Unauthenticated, so it reveals nothing beyond the verdict.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	_, ready, _ := s.readiness()
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"ready": ready})
}

type healthDetail struct {
	Ready      bool              `json:"ready"`
	Checks     model.ReadyChecks `json:"checks"`
	Agent      agentInfo         `json:"agent"`
	Fail2ban   fail2banInfo      `json:"fail2ban"`
	Supervisor model.HealthState `json:"supervisor"`
	Callback   callbackInfo      `json:"callback"`
	Busy       bool              `json:"busy"`
}

type agentInfo struct {
	Version string `json:"version"`
	Go      string `json:"go"`
}

type fail2banInfo struct {
	Version string   `json:"version,omitempty"`
	Jails   []string `json:"jails"`
	Error   string   `json:"error,omitempty"`
}

type callbackInfo struct {
	Configured   bool   `json:"configured"`
	Source       string `json:"source"`
	ServerID     string `json:"serverId,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	PollInterval string `json:"pollInterval"`
	callback.Stats
}

func (s *Server) handleHealthDetail(w http.ResponseWriter, r *http.Request) {
	st, ready, checks := s.readiness()
	writeJSON(w, http.StatusOK, healthDetail{
		Ready:      ready,
		Checks:     checks,
		Agent:      agentInfo{Version: version.Version, Go: runtime.Version()},
		Fail2ban:   s.fail2banInfo(r.Context(), st.PingOK),
		Supervisor: st,
		Callback:   s.callbackInfo(),
		Busy:       s.operations.Busy() || s.svc.Busy(),
	})
}

// Queried live, but only when the last ping answered, so a hung daemon can not stall the endpoint.
func (s *Server) fail2banInfo(ctx context.Context, pingOK bool) fail2banInfo {
	info := fail2banInfo{Jails: []string{}}
	if s.operations.Busy() || s.svc.Busy() {
		info.Error = "service operation is active; live daemon queries are deferred"
		return info
	}
	if !pingOK {
		info.Error = "skipped: fail2ban did not answer the last ping"
		return info
	}
	ctx, cancel := context.WithTimeout(ctx, healthProbeTimeout)
	defer cancel()
	var problems []string
	if v, err := s.svc.Version(ctx); err != nil {
		problems = append(problems, err.Error())
	} else {
		info.Version = v
	}
	if jails, err := s.svc.GetJails(ctx); err != nil {
		problems = append(problems, err.Error())
	} else {
		info.Jails = jails
	}
	info.Error = strings.Join(problems, "; ")
	return info
}

func (s *Server) callbackInfo() callbackInfo {
	cb, source, err := config.ResolveCallback(s.cfg.ConfigRoot, s.cfg.EnvCallback)
	info := callbackInfo{
		Configured:   source != config.CallbackSourceNone,
		Source:       source,
		PollInterval: s.cfg.CallbackPollInterval.String(),
		Stats:        s.poller.Stats(),
	}
	if info.Configured {
		info.ServerID = cb.ServerID
		info.Fingerprint = config.CallbackFingerprint(s.cfg.Secret, cb)
	}
	if err != nil {
		info.LastError = err.Error()
	}
	if info.Configured && s.cfg.CallbackPollInterval == 0 && info.LastError == "" {
		info.LastError = "callback polling is disabled (AGENT_CALLBACK_POLL_INTERVAL=0)"
	}
	return info
}

func (s *Server) handleActionReload(w http.ResponseWriter, r *http.Request) {
	s.handleLegacyOperation(w, r, "reload")
}

func (s *Server) handleActionRestart(w http.ResponseWriter, r *http.Request) {
	s.handleLegacyOperation(w, r, "restart")
}

func (s *Server) handleActionValidate(w http.ResponseWriter, r *http.Request) {
	s.handleLegacyOperation(w, r, "validate")
}

func (s *Server) handlePutCallbackConfig(w http.ResponseWriter, r *http.Request) {
	var req config.CallbackRuntimeConfig
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := config.SaveCallbackRuntimeConfig(s.cfg.ConfigRoot, req); err != nil {
		writeError(w, err)
		return
	}
	if u, err := url.Parse(strings.TrimSpace(req.CallbackURL)); err == nil && u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		log.Printf("WARNING: callback URL %s uses plain http to a non-loopback host - the callback secret travels in cleartext", u.Redacted())
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDeleteCallbackConfig(w http.ResponseWriter, r *http.Request) {
	cleared, reason, err := config.DeleteCallbackRuntimeConfig(s.cfg.ConfigRoot, r.URL.Query().Get("serverId"))
	if err != nil {
		writeError(w, err)
		return
	}
	resp := map[string]any{"ok": true, "cleared": cleared}
	if reason != "" {
		resp["reason"] = reason
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListJails(w http.ResponseWriter, r *http.Request) {
	jails, err := s.svc.GetJailInfos(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jails": jails})
}

func (s *Server) handleCreateJail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.svc.CreateJail(req.Name, req.Content); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true})
}

func (s *Server) handleJailsAll(w http.ResponseWriter, r *http.Request) {
	jails, err := s.svc.GetAllJailsForManage(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jails": jails})
}

func (s *Server) handleJailsUpdateEnabled(w http.ResponseWriter, r *http.Request) {
	var updates map[string]bool
	if !decodeJSON(w, r, &updates) {
		return
	}
	if err := s.svc.UpdateJailEnabledStates(updates); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleJailsTestLogpath(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Logpath string `json:"logpath"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	files, err := s.svc.TestLogpath(req.Logpath)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": files})
}

func (s *Server) handleJailsTestLogpathWithResolution(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Logpath string `json:"logpath"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	orig, resolved, files, err := s.svc.TestLogpathWithResolution(req.Logpath)
	resp := map[string]any{"original_logpath": orig, "resolved_logpath": resolved, "files": files}
	if err != nil {
		status, code := errorStatus(err)
		resp["files"], resp["error"] = []string{}, err.Error()
		if code != "" {
			resp["code"] = code
		}
		writeJSON(w, status, resp)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCheckIntegrity(w http.ResponseWriter, r *http.Request) {
	exists, managed, hasLegacyUIAction, err := s.svc.CheckJailLocalState()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"exists":      exists,
		"hasUIAction": hasLegacyUIAction,
		"managed":     managed,
	})
}

func (s *Server) handleEnsureStructure(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content string `json:"content"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	reason, err := s.svc.EnsureJailLocalStructure(req.Content)
	if err != nil {
		writeError(w, err)
		return
	}
	resp := map[string]any{"ok": true, "skipped": reason != ""}
	if reason != "" {
		resp["reason"] = reason
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleJailBanned(w http.ResponseWriter, r *http.Request) {
	jail := r.PathValue("name")
	ips, total, err := s.svc.GetBannedIPs(r.Context(), jail)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jail": jail, "bannedIPs": ips, "totalBanned": total})
}

func (s *Server) handleDeleteJail(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.DeleteJail(r.PathValue("name")); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleGetJailConfig(w http.ResponseWriter, r *http.Request) {
	cfg, path, err := s.svc.GetJailConfig(r.PathValue("name"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "filePath": path})
}

func (s *Server) handlePutJailConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Config string `json:"config"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.svc.SetJailConfig(r.PathValue("name"), req.Config); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleJailIP(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IP string `json:"ip"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		if err := fail2ban.ValidateJailName(r.PathValue("name")); err != nil {
			writeError(w, err)
			return
		}
		if err := fail2ban.ValidateIP(req.IP); err != nil {
			writeError(w, err)
			return
		}
		s.handleLegacyOperation(w, r, kind, strings.TrimSpace(r.PathValue("name")), strings.TrimSpace(req.IP))
	}
}

func (s *Server) handleListFilters(w http.ResponseWriter, r *http.Request) {
	filters, err := s.svc.GetFilters()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"filters": filters})
}

func (s *Server) handleCreateFilter(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.svc.SetFilterConfig(req.Name, req.Content); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true})
}

func (s *Server) handleGetFilter(w http.ResponseWriter, r *http.Request) {
	cfg, path, err := s.svc.GetFilterConfig(r.PathValue("name"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "filePath": path})
}

func (s *Server) handlePutFilter(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Config string `json:"config"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.svc.SetFilterConfig(r.PathValue("name"), req.Config); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDeleteFilter(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.DeleteFilter(r.PathValue("name")); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleFiltersTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FilterName    string   `json:"filterName"`
		LogLines      []string `json:"logLines"`
		FilterContent string   `json:"filterContent"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	out, path, exitCode, err := s.svc.TestFilter(r.Context(), req.FilterName, req.LogLines, req.FilterContent)
	if err != nil {
		status, code := errorStatus(err)
		resp := map[string]any{"error": err.Error(), "output": out, "filterPath": path}
		if code != "" {
			resp["code"] = code
		}
		writeJSON(w, status, resp)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": out, "filterPath": path, "exitCode": exitCode})
}

// Reports whether a listen host binds only the loopback interface
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	err := json.NewDecoder(r.Body).Decode(v)
	if err == nil {
		return true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "request body too large"})
		return false
	}
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
	return false
}

// Maps service errors to an HTTP status and a stable machine-readable code ("" for internal errors).
func errorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, fail2ban.ErrInvalidName):
		return http.StatusBadRequest, "invalid_name"
	case errors.Is(err, fail2ban.ErrInvalidIP):
		return http.StatusBadRequest, "invalid_ip"
	case errors.Is(err, config.ErrCallbackInvalid):
		return http.StatusBadRequest, "callback_invalid"
	case errors.Is(err, fail2ban.ErrLogpathInvalid):
		return http.StatusBadRequest, "logpath_invalid"
	case errors.Is(err, fail2ban.ErrLogpathInaccessible):
		return http.StatusUnprocessableEntity, "logpath_inaccessible"
	case errors.Is(err, fail2ban.ErrLogpathUnresolved):
		return http.StatusUnprocessableEntity, "logpath_unresolved"
	case errors.Is(err, fail2ban.ErrConfigInvalid):
		return http.StatusUnprocessableEntity, "config_invalid"
	case errors.Is(err, fail2ban.ErrNotFound):
		return http.StatusNotFound, "not_found"
	}
	return http.StatusInternalServerError, ""
}

func writeError(w http.ResponseWriter, err error) {
	status, code := errorStatus(err)
	resp := map[string]any{"error": err.Error()}
	if code != "" {
		resp["code"] = code
	}
	writeJSON(w, status, resp)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
