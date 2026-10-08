package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/operations"
)

func TestOperationSurvivesRequestCancellationAndReportsStatus(t *testing.T) {
	fakeTools(t, map[string]string{"fail2ban-client": `[ "$1" = "-c" ] && shift 2
case "$1" in
reload) /bin/sleep 0.15; echo OK ;;
ping) echo pong ;;
*) exit 1 ;;
esac`})
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/v1/operations", strings.NewReader(`{"id":"survive","kind":"reload"}`)).WithContext(ctx)
	req.Header.Set("X-F2B-Token", testSecret)
	rr := httptest.NewRecorder()
	h.s.mux.ServeHTTP(rr, req)
	cancel()
	if rr.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", rr.Code, rr.Body.String())
	}
	if got := h.do(http.MethodPost, "/v1/jails/update-enabled", `{"sshd":false}`, true); got.Code != http.StatusConflict {
		t.Fatalf("overlapping mutation: %d %s", got.Code, got.Body.String())
	}
	if got := h.do(http.MethodGet, "/healthz", "", false); got.Code != http.StatusOK {
		t.Fatal("transport liveness stalled")
	}
	deadline := time.Now().Add(time.Second)
	for {
		got := h.do(http.MethodGet, "/v1/operations/survive", "", true)
		var op operations.Operation
		if err := json.Unmarshal(got.Body.Bytes(), &op); err != nil {
			t.Fatal(err)
		}
		if op.State == "succeeded" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("request cancellation killed job: %+v", op)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := h.do(http.MethodPost, "/v1/operations", `{"id":"survive","kind":"restart"}`, true); got.Code != http.StatusConflict {
		t.Fatalf("ID conflict: %d", got.Code)
	}
}

func TestOperationEndpointsRequireAuthentication(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/v1/operations/capabilities", "/v1/operations/id"} {
		if got := h.do(http.MethodGet, path, "", false); got.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s: %d", path, got.Code)
		}
	}
}

func TestBanOperationValidatesTargetAndReturnsDurableResult(t *testing.T) {
	fakeTools(t, map[string]string{"fail2ban-client": `[ "$1" = "-c" ] && shift 2
case "$1" in
set) [ "$2" = "sshd" ] && [ "$3" = "banip" ] && [ "$4" = "192.0.2.1" ] ;;
ping) echo pong ;;
*) exit 1 ;;
esac`})
	h := newHarness(t)
	for _, body := range []string{`{"id":"invalid","kind":"ban","jail":"../bad","ip":"192.0.2.1"}`, `{"id":"invalid","kind":"ban","jail":"sshd","ip":"--help"}`} {
		if got := h.do(http.MethodPost, "/v1/operations", body, true); got.Code != http.StatusBadRequest {
			t.Fatalf("invalid target admitted: %d %s", got.Code, got.Body.String())
		}
	}
	got := h.do(http.MethodPost, "/v1/operations", `{"id":"ban1","kind":"ban","jail":"sshd","ip":"192.0.2.1"}`, true)
	if got.Code != http.StatusAccepted {
		t.Fatalf("ban submit: %d %s", got.Code, got.Body.String())
	}
	deadline := time.Now().Add(time.Second)
	for {
		op, err := h.s.operations.Get("ban1")
		if err != nil {
			t.Fatal(err)
		}
		if op.State == "succeeded" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ban did not complete: %+v", op)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMissingOperationReconcileDoesNotDispatch(t *testing.T) {
	fakeTools(t, map[string]string{"fail2ban-client": `[ "$1" = "-c" ] && shift 2
[ "$1" = ping ] && echo pong`})
	h := newHarness(t)
	got := h.do(http.MethodPost, "/v1/operations/missing/reconcile", `{"kind":"reload"}`, true)
	if got.Code != http.StatusOK {
		t.Fatalf("reconcile: %d %s", got.Code, got.Body.String())
	}
	got = h.do(http.MethodPost, "/v1/operations", `{"id":"missing","kind":"reload"}`, true)
	var op operations.Operation
	_ = json.Unmarshal(got.Body.Bytes(), &op)
	if got.Code != http.StatusAccepted || op.State != "unknown" || op.Code != "not_dispatched" {
		t.Fatalf("delayed submit escaped tombstone: %d %+v", got.Code, op)
	}
}

func TestOperationGateReleaseRefreshesSupervisorImmediately(t *testing.T) {
	fakeTools(t, map[string]string{"fail2ban-client": fakeClient, "fail2ban-regex": "exit 0\n"})
	h := newHarness(t)
	h.startSupervisor(t)
	before := h.hs.State().LastCheck
	runner := operationRunner{svc: h.s.svc, health: h.hs}
	runner.SetBusy(true)
	runner.SetBusy(false)
	deadline := time.Now().Add(time.Second)
	for !h.hs.State().LastCheck.After(before) {
		if time.Now().After(deadline) {
			t.Fatal("gate release left health stale until the next hourly tick")
		}
		time.Sleep(time.Millisecond)
	}
	if st := h.hs.State(); !st.PingOK || st.RemediationAttempts != 0 {
		t.Fatalf("release refresh was not read-only and healthy: %+v", st)
	}
}
