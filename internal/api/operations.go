package api

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui-agent/internal/health"
	"github.com/swissmakers/fail2ban-ui-agent/internal/operations"
)

type operationRunner struct {
	svc    *fail2ban.Service
	health *health.Supervisor
}

func (r operationRunner) SetBusy(busy bool) {
	wasBusy := r.svc.Busy()
	r.svc.SetOperationPending(busy)
	if wasBusy && !busy && r.health != nil {
		r.health.Wake()
	}
}
func (r operationRunner) Quiescent(ctx context.Context) bool { return r.svc.Ping(ctx) == nil }
func (r operationRunner) Run(ctx context.Context, op operations.Operation) operations.Result {
	ctx = fail2ban.ManagedOperationContext(ctx)
	var result operations.Result
	switch op.Kind {
	case "reload":
		result.Output, result.Err = r.svc.Reload(ctx)
	case "restart":
		result.Mode, result.Err = r.svc.Restart(ctx)
	case "ban":
		result.Err = r.svc.BanIP(ctx, op.Jail, op.IP)
	case "unban":
		result.Err = r.svc.UnbanIP(ctx, op.Jail, op.IP)
	case "validate":
		result.Output, result.Err = r.svc.Validate(ctx)
		if errors.Is(result.Err, fail2ban.ErrConfigInvalid) {
			result.Code = "config_invalid"
		}
	}
	return result
}

func (s *Server) handleOperationCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"version": 1, "kinds": []string{"reload", "restart", "validate", "ban", "unban"}, "configurationSnapshots": true})
}

func (s *Server) handleBackupConfiguration(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.svc.BackupConfiguration(req.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": req.ID})
}
func (s *Server) handleRestoreConfiguration(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.RestoreConfiguration(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
func (s *Server) handleDeleteConfigurationBackup(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.DeleteConfigurationBackup(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSubmitOperation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
		Jail string `json:"jail"`
		IP   string `json:"ip"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Kind == "ban" || req.Kind == "unban" {
		if err := fail2ban.ValidateJailName(req.Jail); err != nil {
			writeError(w, err)
			return
		}
		if err := fail2ban.ValidateIP(req.IP); err != nil {
			writeError(w, err)
			return
		}
	}
	op, err := s.operations.Submit(req.ID, req.Kind, strings.TrimSpace(req.Jail), strings.TrimSpace(req.IP))
	if err != nil {
		writeOperationError(w, err)
		return
	}
	w.Header().Set("Location", "/v1/operations/"+op.ID)
	writeJSON(w, http.StatusAccepted, op)
}

func (s *Server) handleGetOperation(w http.ResponseWriter, r *http.Request) {
	op, err := s.operations.Get(r.PathValue("id"))
	if err != nil {
		writeOperationError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, op)
}

// Legacy clients may still wait for their original response, but the daemon
// command now belongs to the same persistent worker as the asynchronous API.
func (s *Server) handleLegacyOperation(w http.ResponseWriter, r *http.Request, kind string, target ...string) {
	id := r.Header.Get("Idempotency-Key")
	if id == "" {
		id = "legacy-" + rand.Text()
	}
	op, err := s.operations.Submit(id, kind, target...)
	if err != nil {
		writeOperationError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), actionTimeout)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		switch op.State {
		case "succeeded":
			body := map[string]any{"ok": true, "operationId": op.ID}
			if kind == "restart" {
				body["mode"] = op.Mode
			} else {
				body["output"] = op.Output
			}
			writeJSON(w, http.StatusOK, body)
			return
		case "failed":
			status := http.StatusInternalServerError
			if op.Code == "config_invalid" {
				status = http.StatusUnprocessableEntity
			}
			body := map[string]any{"ok": false, "error": op.Error, "operationId": op.ID}
			if kind == "restart" {
				body["mode"] = op.Mode
			} else {
				body["output"] = op.Output
			}
			if op.Code != "" {
				body["code"] = op.Code
			}
			writeJSON(w, status, body)
			return
		case "unknown":
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": op.Error, "code": "outcome_unknown", "operationId": op.ID})
			return
		}
		select {
		case <-ctx.Done():
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "command continues independently; query its operation status before retrying", "code": "operation_pending", "operationId": op.ID})
			return
		case <-ticker.C:
		}
		op, err = s.operations.Get(id)
		if err != nil {
			writeOperationError(w, err)
			return
		}
	}
}

func (s *Server) handleReconcileOperation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind string `json:"kind"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	op, err := s.operations.Reconcile(r.PathValue("id"), req.Kind)
	if err != nil {
		writeOperationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, op)
}

func writeOperationError(w http.ResponseWriter, err error) {
	status, code := http.StatusServiceUnavailable, "operation_store_unavailable"
	switch {
	case errors.Is(err, operations.ErrBusy):
		status, code = http.StatusConflict, "operation_busy"
	case errors.Is(err, operations.ErrConflict):
		status, code = http.StatusConflict, "operation_id_conflict"
	case errors.Is(err, operations.ErrInvalid):
		status, code = http.StatusBadRequest, "operation_invalid"
	case errors.Is(err, operations.ErrNotFound):
		status, code = http.StatusNotFound, "operation_not_found"
	}
	writeJSON(w, status, map[string]any{"error": err.Error(), "code": code})
}

// Only the submit endpoint can bypass the mutation gate. Read-only POST probes
// remain useful while Fail2Ban is applying a change.
func operationMutation(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return false
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	if strings.HasPrefix(path, "/v1/operations/") && strings.HasSuffix(path, "/reconcile") {
		return false
	}
	if strings.HasPrefix(path, "/v1/jails/") && (strings.HasSuffix(path, "/ban") || strings.HasSuffix(path, "/unban")) {
		return false
	}
	switch path {
	case "/v1/operations", "/v1/actions/reload", "/v1/actions/restart", "/v1/actions/validate", "/v1/jails/test-logpath", "/v1/jails/test-logpath-with-resolution", "/v1/filters/test":
		return false
	}
	return true
}
