package operations

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type fakeRunner struct {
	start  chan context.Context
	finish chan struct{}
	calls  atomic.Int32
	busy   atomic.Bool
	quiet  atomic.Bool
}

func (f *fakeRunner) SetBusy(b bool)                 { f.busy.Store(b) }
func (f *fakeRunner) Quiescent(context.Context) bool { return f.quiet.Load() }
func (f *fakeRunner) Run(ctx context.Context, op Operation) Result {
	f.calls.Add(1)
	if f.start != nil {
		f.start <- ctx
	}
	select {
	case <-f.finish:
		return Result{Output: "OK"}
	case <-ctx.Done():
		return Result{Err: ctx.Err()}
	}
}
func awaitState(t *testing.T, m *Manager, id, state string) Operation {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		op, err := m.Get(id)
		if err == nil && op.State == state {
			return op
		}
		if time.Now().After(deadline) {
			t.Fatalf("state=%+v err=%v, wanted %s", op, err, state)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSubmitDurableIdempotentAndDoesNotHoldStatus(t *testing.T) {
	f := &fakeRunner{start: make(chan context.Context, 1), finish: make(chan struct{})}
	m := New(t.TempDir(), f)
	t.Cleanup(m.Close)
	if _, err := m.Submit("op1", "reload"); err != nil {
		t.Fatal(err)
	}
	ctx := <-f.start
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) < 20*time.Minute {
		t.Fatalf("worker retained old short timeout: %v", deadline)
	}
	if _, err := m.Submit("op1", "reload"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Submit("op1", "restart"); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if _, err := m.Submit("op2", "reload"); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy: %v", err)
	}
	if _, err := m.AcquireMutation(); !errors.Is(err, ErrBusy) {
		t.Fatalf("mutation while running: %v", err)
	}
	op := awaitState(t, m, "op1", "running")
	raw, err := os.ReadFile(filepath.Join(m.dir, "op1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored Operation
	if json.Unmarshal(raw, &stored) != nil || stored.ID != op.ID || stored.State != "running" {
		t.Fatalf("dispatch was not durably recorded: %s", raw)
	}
	close(f.finish)
	awaitState(t, m, "op1", "succeeded")
	if f.calls.Load() != 1 {
		t.Fatalf("command repeated %d times", f.calls.Load())
	}
	if f.busy.Load() {
		t.Fatal("gate not released")
	}
}

func TestRestartNeverReplaysUnknownOperation(t *testing.T) {
	dir := t.TempDir()
	f := &fakeRunner{start: make(chan context.Context, 1), finish: make(chan struct{})}
	m := New(dir, f)
	if _, err := m.Submit("op1", "reload"); err != nil {
		t.Fatal(err)
	}
	<-f.start
	m.Close()
	op := awaitState(t, m, "op1", "unknown")
	if op.Quiescent {
		t.Fatal("interrupted command treated as complete")
	}
	f2 := &fakeRunner{finish: make(chan struct{})}
	f2.quiet.Store(true)
	m2 := New(dir, f2)
	t.Cleanup(m2.Close)
	deadline := time.Now().Add(time.Second)
	for {
		op, _ = m2.Get("op1")
		if op.Quiescent {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("read-only recovery did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	if op.State != "unknown" || f2.calls.Load() != 0 {
		t.Fatalf("recovery claimed success or replayed: %+v calls %d", op, f2.calls.Load())
	}
	if m2.Busy() {
		t.Fatal("quiescent daemon still reserved")
	}
	if _, err := m2.Submit("op1", "reload"); err != nil {
		t.Fatal(err)
	}
	if f2.calls.Load() != 0 {
		t.Fatal("duplicate replayed interrupted command")
	}
}

func TestCorruptStoreFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{}
	m := New(dir, f)
	defer m.Close()
	if _, err := m.Submit("new", "reload"); err == nil {
		t.Fatal("corrupt store admitted command")
	}
	if _, err := m.AcquireMutation(); err == nil {
		t.Fatal("corrupt store admitted config mutation")
	}
	if !m.Busy() || !f.busy.Load() {
		t.Fatal("supervisor must not remediate unknown persisted work")
	}
}

func TestMutationGateAlsoPreventsOperationSubmit(t *testing.T) {
	f := &fakeRunner{}
	m := New(t.TempDir(), f)
	defer m.Close()
	release, err := m.AcquireMutation()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Submit("op", "validate"); !errors.Is(err, ErrBusy) {
		t.Fatalf("job overlapped config write: %v", err)
	}
	if !f.busy.Load() {
		t.Fatal("supervisor not deferred during mutation")
	}
	release()
	if m.Busy() || f.busy.Load() {
		t.Fatal("mutation gate not released")
	}
}

func TestMissingReconcileSealsIDAgainstDelayedSubmit(t *testing.T) {
	f := &fakeRunner{}
	f.quiet.Store(true)
	m := New(t.TempDir(), f)
	defer m.Close()
	op, err := m.Reconcile("missing", "ban")
	if err != nil {
		t.Fatal(err)
	}
	if op.State != "unknown" || op.Code != "not_dispatched" {
		t.Fatalf("missing ID was not sealed: %+v", op)
	}
	op, err = m.Submit("missing", "ban", "sshd", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if op.State != "unknown" || f.calls.Load() != 0 {
		t.Fatalf("delayed submit executed after reconciliation: %+v calls=%d", op, f.calls.Load())
	}
	if _, err = m.Reconcile("missing", "reload"); !errors.Is(err, ErrConflict) {
		t.Fatalf("reconcile changed command kind: %v", err)
	}
}

func TestBanTargetCannotChangeUnderSameID(t *testing.T) {
	f := &fakeRunner{start: make(chan context.Context, 1), finish: make(chan struct{})}
	m := New(t.TempDir(), f)
	defer m.Close()
	if _, err := m.Submit("ban1", "ban", "sshd", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	<-f.start
	if _, err := m.Submit("ban1", "ban", "sshd", "192.0.2.2"); !errors.Is(err, ErrConflict) {
		t.Fatalf("same ID changed target: %v", err)
	}
	if _, err := m.Submit("ban1", "ban", "sshd", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	close(f.finish)
	op := awaitState(t, m, "ban1", "succeeded")
	if op.Jail != "sshd" || op.IP != "192.0.2.1" || f.calls.Load() != 1 {
		t.Fatalf("ban target not preserved: %+v", op)
	}
}
