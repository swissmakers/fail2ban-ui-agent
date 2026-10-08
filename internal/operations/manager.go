// Package operations persists service commands before dispatch so a lost HTTP
// response can be recovered without running the same command twice.
package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/fsutil"
)

var (
	ErrBusy     = errors.New("another service operation is active")
	ErrConflict = errors.New("operation ID already belongs to another command")
	ErrNotFound = errors.New("operation not found")
	ErrInvalid  = errors.New("invalid operation")
	validID     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,159}$`)
)

const CommandTimeout = 30 * time.Minute

type Operation struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Jail       string    `json:"jail,omitempty"`
	IP         string    `json:"ip,omitempty"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"createdAt"`
	StartedAt  time.Time `json:"startedAt,omitzero"`
	FinishedAt time.Time `json:"finishedAt,omitzero"`
	Output     string    `json:"output,omitempty"`
	Mode       string    `json:"mode,omitempty"`
	Error      string    `json:"error,omitempty"`
	Code       string    `json:"code,omitempty"`
	// Quiescent confirms that the daemon answered a fresh probe after an
	// interrupted command. It never claims the requested change succeeded.
	Quiescent bool `json:"quiescent"`
}

type Result struct {
	Output, Mode, Code string
	Err                error
}

type Runner interface {
	Run(context.Context, Operation) Result
	Quiescent(context.Context) bool
	SetBusy(bool)
}

type Manager struct {
	mu               sync.Mutex
	dir              string
	runner           Runner
	jobs             map[string]Operation
	active           map[string]bool
	mutating         bool
	storeErr         error
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	timeout          time.Duration
	recoveryInterval time.Duration
}

func New(dir string, runner Runner) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{dir: dir, runner: runner, jobs: make(map[string]Operation), active: make(map[string]bool), ctx: ctx, cancel: cancel, timeout: CommandTimeout, recoveryInterval: 5 * time.Second}
	m.storeErr = m.load()
	runner.SetBusy(m.storeErr != nil || len(m.active) > 0)
	for id := range m.active {
		m.wg.Add(1)
		go m.recover(id)
	}
	return m
}

func (m *Manager) load() error {
	if info, err := os.Lstat(m.dir); err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("unsafe operation store directory")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(m.dir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 128<<10 {
			return fmt.Errorf("invalid operation file %s", entry.Name())
		}
		raw, err := os.ReadFile(filepath.Join(m.dir, entry.Name()))
		if err != nil {
			return err
		}
		var op Operation
		if err := json.Unmarshal(raw, &op); err != nil {
			return fmt.Errorf("read operation %s: %w", entry.Name(), err)
		}
		if !validID.MatchString(op.ID) || entry.Name() != op.ID+".json" || !validKind(op.Kind) {
			return fmt.Errorf("invalid stored operation %s", entry.Name())
		}
		switch op.State {
		case "queued":
			// A queued record was never dispatched. Do not replay silently after restart.
			op.State, op.Code, op.Error = "failed", "interrupted", "agent restarted before command dispatch; no command was run"
			op.FinishedAt, op.Quiescent = time.Now().UTC(), true
		case "running":
			op.State, op.Code, op.Error = "unknown", "outcome_unknown", "agent restarted while command was running; checking daemon without repeating it"
			op.Quiescent = false
		case "unknown", "failed", "succeeded":
		default:
			return fmt.Errorf("invalid stored operation state %q", op.State)
		}
		if op.State == "unknown" && !op.Quiescent {
			m.active[op.ID] = true
		}
		if err := m.save(op); err != nil {
			return err
		}
		m.jobs[op.ID] = op
	}
	return nil
}

func validKind(kind string) bool {
	return kind == "reload" || kind == "restart" || kind == "validate" || kind == "ban" || kind == "unban"
}

func (m *Manager) save(op Operation) error {
	raw, err := json.Marshal(op)
	if err != nil {
		return err
	}
	return fsutil.ReplaceFile(filepath.Join(m.dir, op.ID+".json"), raw, 0600)
}

func (m *Manager) Submit(id, kind string, target ...string) (Operation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validID.MatchString(id) || !validKind(kind) {
		return Operation{}, ErrInvalid
	}
	var jail, ip string
	if len(target) == 2 {
		jail, ip = target[0], target[1]
	} else if len(target) != 0 {
		return Operation{}, ErrInvalid
	}
	if kind == "ban" || kind == "unban" {
		if jail == "" || ip == "" {
			return Operation{}, ErrInvalid
		}
	} else if jail != "" || ip != "" {
		return Operation{}, ErrInvalid
	}
	if op, ok := m.jobs[id]; ok {
		if op.Kind != kind || (op.Code != "not_dispatched" && (op.Jail != jail || op.IP != ip)) {
			return Operation{}, ErrConflict
		}
		return op, nil
	}
	if m.storeErr != nil {
		return Operation{}, fmt.Errorf("operation store unavailable: %w", m.storeErr)
	}
	if err := m.ctx.Err(); err != nil {
		return Operation{}, err
	}
	if m.mutating || len(m.active) > 0 {
		return Operation{}, ErrBusy
	}
	op := Operation{ID: id, Kind: kind, Jail: jail, IP: ip, State: "queued", CreatedAt: time.Now().UTC()}
	if err := m.save(op); err != nil {
		return Operation{}, err
	}
	m.jobs[id], m.active[id] = op, true
	m.runner.SetBusy(true)
	m.wg.Add(1)
	go m.run(id)
	return op, nil
}

func (m *Manager) Get(id string) (Operation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if op, ok := m.jobs[id]; ok {
		return op, nil
	}
	return Operation{}, ErrNotFound
}

// Reconcile seals an absent ID before inspecting the daemon. A delayed Submit
// can then only observe this tombstone, never dispatch work after recovery has
// already determined that the original request was missing.
func (m *Manager) Reconcile(id, kind string) (Operation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validID.MatchString(id) || !validKind(kind) {
		return Operation{}, ErrInvalid
	}
	if op, ok := m.jobs[id]; ok {
		if op.Kind != kind {
			return Operation{}, ErrConflict
		}
		return op, nil
	}
	if m.storeErr != nil {
		return Operation{}, fmt.Errorf("operation store unavailable: %w", m.storeErr)
	}
	if err := m.ctx.Err(); err != nil {
		return Operation{}, err
	}
	op := Operation{ID: id, Kind: kind, State: "unknown", Code: "not_dispatched", Error: "submission was not found; this ID is reserved so a delayed request cannot execute", CreatedAt: time.Now().UTC()}
	if err := m.save(op); err != nil {
		return Operation{}, err
	}
	m.jobs[id], m.active[id] = op, true
	m.runner.SetBusy(true)
	m.wg.Add(1)
	go m.recover(id)
	return op, nil
}

// AcquireMutation prevents legacy actions and file writes from racing a job.
// It does not wait on the daemon; clients can present a useful busy response.
func (m *Manager) AcquireMutation() (func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.storeErr != nil {
		return nil, fmt.Errorf("operation store unavailable: %w", m.storeErr)
	}
	if m.ctx.Err() != nil {
		return nil, m.ctx.Err()
	}
	if m.mutating || len(m.active) > 0 {
		return nil, ErrBusy
	}
	m.mutating = true
	m.runner.SetBusy(true)
	return func() {
		m.mu.Lock()
		m.mutating = false
		m.runner.SetBusy(m.storeErr != nil || len(m.active) > 0)
		m.mu.Unlock()
	}, nil
}

func (m *Manager) Busy() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.storeErr != nil || m.mutating || len(m.active) > 0
}

func (m *Manager) run(id string) {
	defer m.wg.Done()
	m.mu.Lock()
	op := m.jobs[id]
	op.State, op.StartedAt = "running", time.Now().UTC()
	if err := m.save(op); err != nil {
		op.State, op.Code, op.Error, op.Quiescent = "failed", "operation_store_unavailable", err.Error(), true
		op.FinishedAt = time.Now().UTC()
		m.jobs[id] = op
		delete(m.active, id)
		m.runner.SetBusy(len(m.active) > 0)
		m.mu.Unlock()
		return // Never dispatch unless the running record is durable.
	}
	m.jobs[id] = op
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(m.ctx, m.timeout)
	result := m.runner.Run(ctx, op)
	cancel()
	op.Output, op.Mode, op.Code = result.Output, result.Mode, result.Code
	if len(op.Output) > 64<<10 {
		op.Output = op.Output[:64<<10] + "\n[output truncated]"
	}
	op.FinishedAt, op.Quiescent = time.Now().UTC(), true
	op.State = "succeeded"
	if result.Err != nil {
		op.State, op.Error = "failed", result.Err.Error()
		if op.Kind != "validate" {
			op.State, op.Code, op.Quiescent = "unknown", "outcome_unknown", false
		}
	}
	m.mu.Lock()
	if err := m.save(op); err != nil {
		// Keep the in-memory result honest and the gate closed after persistence failure.
		op.State, op.Code, op.Error, op.Quiescent = "unknown", "store_unavailable", err.Error(), false
	}
	m.jobs[id] = op
	if op.Quiescent {
		delete(m.active, id)
	}
	m.runner.SetBusy(m.storeErr != nil || len(m.active) > 0)
	if !op.Quiescent {
		m.wg.Add(1)
		go m.recover(id)
	}
	m.mu.Unlock()
}

func (m *Manager) recover(id string) {
	defer m.wg.Done()
	for {
		if m.ctx.Err() != nil {
			return
		}
		ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
		quiet := m.runner.Quiescent(ctx)
		cancel()
		if quiet {
			m.mu.Lock()
			op := m.jobs[id]
			op.Quiescent = true
			op.Error = "daemon responds again; the interrupted command's result is unknown; verify the requested state before retrying"
			if err := m.save(op); err == nil {
				m.jobs[id] = op
				delete(m.active, id)
				m.runner.SetBusy(m.storeErr != nil || len(m.active) > 0)
				m.mu.Unlock()
				return
			}
			m.mu.Unlock()
		}
		timer := time.NewTimer(m.recoveryInterval)
		select {
		case <-m.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (m *Manager) Close() { m.cancel(); m.wg.Wait() }
