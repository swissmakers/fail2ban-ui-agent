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

package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/fsutil"
	"github.com/swissmakers/fail2ban-ui-agent/internal/model"
)

const (
	shortCommandTimeout = 15 * time.Second
	longCommandTimeout  = 45 * time.Second
	maxCommandOutput    = 64 << 10
	maxIncludeDepth     = 3
	// W_OK
	accessWriteOK = 0x2

	agentManagedMarker   = "managed by fail2ban-ui-agent"
	legacyUIActionMarker = "ui-custom-action"

	// The dot keeps the temp filter name out of validIncludeName's namespace, so no copied include can overwrite it.
	testFilterFile = "agent.filter-under-test.conf"
)

// Per service-manager budget; a variable so tests can shorten it.
var restartTimeout = longCommandTimeout

var restartCommands = [][]string{
	{"systemctl", "restart", "fail2ban"},
	{"service", "fail2ban", "restart"},
	{"rc-service", "fail2ban", "restart"},
}

type Service struct {
	configRoot string
	logRoot    string
	// Serializes reload/restart/validate between the API and the supervisor; a channel so waiting honours ctx.
	svcLock          chan struct{}
	operationPending atomic.Bool
	serviceRunning   atomic.Bool
}

type operationContextKey struct{}

// ManagedOperationContext permits only the durable worker to enter the service
// gate while an operation is reserved, and selects its longer command budget.
func ManagedOperationContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, operationContextKey{}, true)
}

func (s *Service) SetOperationPending(busy bool) { s.operationPending.Store(busy) }
func (s *Service) Busy() bool                    { return s.operationPending.Load() || s.serviceRunning.Load() }

var ErrOperationBusy = errors.New("service operation is running or awaiting reconciliation")

func NewService(configRoot, logRoot string) *Service {
	return &Service{
		configRoot: strings.TrimRight(configRoot, "/"),
		logRoot:    strings.TrimRight(logRoot, "/"),
		svcLock:    make(chan struct{}, 1),
	}
}

func (s *Service) lockService(ctx context.Context) error {
	managed, _ := ctx.Value(operationContextKey{}).(bool)
	if s.operationPending.Load() && !managed {
		return ErrOperationBusy
	}
	select {
	case s.svcLock <- struct{}{}:
		if s.operationPending.Load() && !managed {
			<-s.svcLock
			return ErrOperationBusy
		}
		s.serviceRunning.Store(true)
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting for another reload/restart/validate: %w", ctx.Err())
	}
}

func (s *Service) unlockService() { s.serviceRunning.Store(false); <-s.svcLock }

// Ping succeeds only when the server actually answered "pong".
func (s *Service) Ping(ctx context.Context) error {
	out, err := s.client(ctx, shortCommandTimeout, "ping")
	if err != nil {
		return err
	}
	if !strings.Contains(out, "pong") {
		return fmt.Errorf("fail2ban-client ping: unexpected reply %q", capOutput([]byte(strings.TrimSpace(out)), 256))
	}
	return nil
}

func (s *Service) Version(ctx context.Context) (string, error) {
	out, err := s.client(ctx, shortCommandTimeout, "version")
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	return capOutput([]byte(strings.TrimSpace(line)), 64), nil
}

func (s *Service) Environment() model.Environment {
	_, clientErr := exec.LookPath("fail2ban-client")
	_, regexErr := exec.LookPath("fail2ban-regex")
	return model.Environment{
		ConfigWritable: syscall.Access(s.configRoot, accessWriteOK) == nil,
		Fail2banClient: clientErr == nil,
		Fail2banRegex:  regexErr == nil,
	}
}

// Reports whether systemd knows fail2ban as deliberately stopped ("inactive", not "failed").
func (s *Service) StoppedByAdmin(ctx context.Context) bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "systemctl", "show", "fail2ban", "--property=LoadState,ActiveState").Output()
	return unitStoppedByAdmin(string(out))
}

// An unknown unit also reports "inactive", so only a loaded unit counts as stopped on purpose.
func unitStoppedByAdmin(show string) bool {
	props := map[string]string{}
	for _, line := range strings.Split(show, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	return props["LoadState"] == "loaded" && props["ActiveState"] == "inactive"
}

func (s *Service) GetJailInfos(ctx context.Context) ([]model.JailInfo, error) {
	jails, err := s.GetJails(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]model.JailInfo, 0, len(jails))
	for _, jail := range jails {
		ips, banned, err := s.getBannedInfo(ctx, jail)
		if err != nil {
			return nil, err
		}
		out = append(out, model.JailInfo{
			JailName:      jail,
			TotalBanned:   banned,
			NewInLastHour: 0,
			BannedIPs:     ips,
			Enabled:       true,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].JailName < out[j].JailName })
	return out, nil
}

func (s *Service) GetJails(ctx context.Context) ([]string, error) {
	out, err := s.client(ctx, shortCommandTimeout, "status")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "jail list:") {
			idx := strings.Index(line, ":")
			if idx < 0 {
				break
			}
			raw := strings.TrimSpace(line[idx+1:])
			if raw == "" {
				return []string{}, nil
			}
			parts := strings.Split(raw, ",")
			jails := make([]string, 0, len(parts))
			for _, p := range parts {
				name := strings.TrimSpace(p)
				if name != "" {
					jails = append(jails, name)
				}
			}
			return jails, nil
		}
	}
	return []string{}, nil
}

func (s *Service) GetBannedIPs(ctx context.Context, jail string) ([]string, int, error) {
	if err := ValidateJailName(jail); err != nil {
		return nil, 0, err
	}
	return s.getBannedInfo(ctx, strings.TrimSpace(jail))
}

func (s *Service) getBannedInfo(ctx context.Context, jail string) ([]string, int, error) {
	out, err := s.client(ctx, shortCommandTimeout, "status", jail)
	if err != nil {
		return nil, 0, err
	}
	var (
		bannedIPs []string
		total     int
	)
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case strings.Contains(strings.ToLower(l), "currently banned:"):
			total = parseIntAfterColon(l)
		case strings.Contains(strings.ToLower(l), "banned ip list:"):
			idx := strings.Index(l, ":")
			if idx >= 0 {
				raw := strings.TrimSpace(l[idx+1:])
				if raw != "" {
					bannedIPs = strings.Fields(raw)
				}
			}
		}
	}
	if total == 0 {
		total = len(bannedIPs)
	}
	return bannedIPs, total, nil
}

func (s *Service) BanIP(ctx context.Context, jail, ip string) error {
	if err := ValidateJailName(jail); err != nil {
		return err
	}
	if err := ValidateIP(ip); err != nil {
		return err
	}
	if err := s.lockService(ctx); err != nil {
		return err
	}
	defer s.unlockService()
	_, err := s.client(ctx, mutationCommandTimeout(ctx), "set", strings.TrimSpace(jail), "banip", strings.TrimSpace(ip))
	return err
}

func (s *Service) UnbanIP(ctx context.Context, jail, ip string) error {
	if err := ValidateJailName(jail); err != nil {
		return err
	}
	if err := ValidateIP(ip); err != nil {
		return err
	}
	if err := s.lockService(ctx); err != nil {
		return err
	}
	defer s.unlockService()
	_, err := s.client(ctx, mutationCommandTimeout(ctx), "set", strings.TrimSpace(jail), "unbanip", strings.TrimSpace(ip))
	return err
}

func (s *Service) Reload(ctx context.Context) (string, error) {
	if err := s.lockService(ctx); err != nil {
		return "", err
	}
	defer s.unlockService()
	return s.client(ctx, longCommandTimeout, "reload")
}

func mutationCommandTimeout(ctx context.Context) time.Duration {
	if managed, _ := ctx.Value(operationContextKey{}).(bool); managed {
		return 30 * time.Minute
	}
	return shortCommandTimeout
}

// Restart returns "restart" when a service manager restarted fail2ban, or "reload" when it fell back to a reload.
func (s *Service) Restart(ctx context.Context) (string, error) {
	if err := s.lockService(ctx); err != nil {
		return "", err
	}
	defer s.unlockService()
	var errs []error
	for _, c := range restartCommands {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		if _, err := runCommand(ctx, restartTimeout, c[0], c[1:]...); err != nil {
			// A manager that timed out may still be restarting; starting a second one would queue another restart.
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return "restart", err
			}
			errs = append(errs, err)
			continue
		}
		return "restart", nil
	}
	// fallback if service manager is unavailable or failed
	if _, err := s.client(ctx, longCommandTimeout, "reload"); err != nil {
		return "reload", errors.Join(append(errs, fmt.Errorf("fallback reload: %w", err))...)
	}
	return "reload", nil
}

// Validate runs `fail2ban-client -t`; a failed test wraps ErrConfigInvalid, anything else means it could not run.
func (s *Service) Validate(ctx context.Context) (string, error) {
	if err := s.lockService(ctx); err != nil {
		return "", err
	}
	defer s.unlockService()
	ctx, cancel := context.WithTimeout(ctx, longCommandTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "fail2ban-client", "-c", s.configRoot, "-t").CombinedOutput()
	output := capOutput(out, maxCommandOutput)
	if err == nil {
		return output, nil
	}
	var exitErr *exec.ExitError
	if ctx.Err() == nil && errors.As(err, &exitErr) && exitErr.Exited() {
		return output, fmt.Errorf("%w (exit status %d)", ErrConfigInvalid, exitErr.ExitCode())
	}
	return output, fmt.Errorf("fail2ban-client -t: %w", err)
}

func (s *Service) GetFilterConfig(name string) (string, string, error) {
	p, err := s.pickFilterPath(name)
	if err != nil {
		return "", "", err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return "", "", err
	}
	return string(raw), p, nil
}

func (s *Service) SetFilterConfig(name, content string) error {
	if err := ValidateFilterName(name); err != nil {
		return err
	}
	p := filepath.Join(s.configRoot, "filter.d", strings.TrimSpace(name)+".local")
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return err
	}
	return fsutil.WriteConfig(p, []byte(content), 0644)
}

func (s *Service) GetFilters() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.configRoot, "filter.d"))
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	return filterNamesFromEntries(entries), nil
}

// Unique, sorted filter names from .conf/.local files; names the API could not address (dotfiles included) are skipped.
func filterNamesFromEntries(entries []fs.DirEntry) []string {
	set := map[string]struct{}{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		base, ok := strings.CutSuffix(e.Name(), ".conf")
		if !ok {
			base, ok = strings.CutSuffix(e.Name(), ".local")
		}
		if ok && ValidateFilterName(base) == nil {
			set[base] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// TestFilter runs fail2ban-regex; any normal exit returns its exit code, err is set only when it could not run.
func (s *Service) TestFilter(ctx context.Context, filterName string, logLines []string, filterContent string) (string, string, int, error) {
	if err := ValidateFilterName(filterName); err != nil {
		return "", "", 0, err
	}
	filterName = strings.TrimSpace(filterName)

	// Private temp dir with fixed file names (never derived from caller input) so nothing can collide or traverse.
	tmpDir, err := os.MkdirTemp("", "f2b-agent-test-")
	if err != nil {
		return "", "", 0, err
	}
	defer os.RemoveAll(tmpDir)

	var filterPath string
	if strings.TrimSpace(filterContent) != "" {
		if !strings.HasSuffix(filterContent, "\n") {
			filterContent += "\n"
		}
		filterPath = filepath.Join(tmpDir, testFilterFile)
		if err := os.WriteFile(filterPath, []byte(filterContent), 0600); err != nil {
			return "", "", 0, err
		}
		if err := copyFilterIncludes(filepath.Join(s.configRoot, "filter.d"), tmpDir, filterName, filterContent); err != nil {
			return "", filterPath, 0, err
		}
	} else if filterPath, err = s.pickFilterPath(filterName); err != nil {
		return "", "", 0, err
	}

	logPath := filepath.Join(tmpDir, "test.log")
	if err := os.WriteFile(logPath, []byte(strings.Join(logLines, "\n")+"\n"), 0600); err != nil {
		return "", filterPath, 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, longCommandTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "fail2ban-regex", logPath, filterPath).CombinedOutput()
	if err == nil {
		return string(out), filterPath, 0, nil
	}
	var exitErr *exec.ExitError
	if ctx.Err() == nil && errors.As(err, &exitErr) && exitErr.Exited() {
		return string(out), filterPath, exitErr.ExitCode(), nil
	}
	return string(out), filterPath, 0, fmt.Errorf("fail2ban-regex: %w", err)
}

// Copies content's [INCLUDES] closure plus .local siblings from filterDir into dst, where fail2ban-regex looks for them.
func copyFilterIncludes(filterDir, dst, filterName, content string) error {
	visited := map[string]bool{filterName: true}
	var walk func(content string, depth int) error
	walk = func(content string, depth int) error {
		if depth > maxIncludeDepth {
			return nil
		}
		for _, inc := range parseFilterIncludes(content) {
			if !validIncludeName(inc) {
				continue
			}
			base := strings.TrimSuffix(strings.TrimSuffix(inc, ".conf"), ".local")
			if visited[base] {
				continue
			}
			visited[base] = true
			for _, ext := range []string{".conf", ".local"} {
				raw, err := os.ReadFile(filepath.Join(filterDir, base+ext))
				if err != nil {
					continue
				}
				if err := os.WriteFile(filepath.Join(dst, base+ext), raw, 0600); err != nil {
					return err
				}
				if err := walk(string(raw), depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(content, 1)
}

// Returns the before/after file names of the [INCLUDES] section, including continuation lines.
func parseFilterIncludes(content string) []string {
	var out []string
	inIncludes, inValue := false, false
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "["):
			inIncludes = strings.EqualFold(trimmed, "[INCLUDES]")
			inValue = false
		case !inIncludes || trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";"):
			inValue = false
		case inValue && (line[0] == ' ' || line[0] == '\t'):
			out = append(out, strings.Fields(trimmed)...)
		default:
			key, value, ok := strings.Cut(trimmed, "=")
			key = strings.ToLower(strings.TrimSpace(key))
			inValue = ok && (key == "before" || key == "after")
			if inValue {
				out = append(out, strings.Fields(value)...)
			}
		}
	}
	return out
}

func (s *Service) GetJailConfig(jail string) (string, string, error) {
	if err := ValidateJailName(jail); err != nil {
		return "", "", err
	}
	return readJailConfigWithFallback(strings.TrimSpace(jail), s.configRoot)
}

func (s *Service) SetJailConfig(jail, content string) error {
	if err := ValidateJailName(jail); err != nil {
		return err
	}
	jail = strings.TrimSpace(jail)
	if strings.TrimSpace(content) == "" {
		content = fmt.Sprintf("[%s]\n", jail)
	}
	return writeJailLocal(s.configRoot, jail, content)
}

func (s *Service) CreateJail(name, content string) error {
	if err := ValidateJailName(name); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	return writeJailLocal(s.configRoot, name, ensureSectionHeader(name, content))
}

// Prepends [name] unless the content already defines that section.
func ensureSectionHeader(name, content string) string {
	header := "[" + name + "]"
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == header {
			return content
		}
	}
	if strings.TrimSpace(content) == "" {
		return header + "\n"
	}
	return header + "\n" + content
}

func (s *Service) UpdateJailEnabledStates(updates map[string]bool) error {
	for jail := range updates {
		if err := ValidateJailName(jail); err != nil {
			return err
		}
	}
	for jail, enabled := range updates {
		jail = strings.TrimSpace(jail)
		content, _, err := readJailConfigWithFallback(jail, s.configRoot)
		if err != nil {
			return err
		}
		if err := writeJailLocal(s.configRoot, jail, applyJailEnabledInContent(content, jail, enabled)); err != nil {
			return fmt.Errorf("jail %q: %w", jail, err)
		}
	}
	return nil
}

func (s *Service) TestLogpath(pattern string) ([]string, error) {
	p, err := ValidateLogpath(pattern)
	if err != nil {
		return nil, err
	}
	if p == "" {
		return []string{}, nil
	}
	return listLogpath(p)
}

// Lists the files a validated logpath matches; permission errors map to ErrLogpathInaccessible.
func listLogpath(p string) ([]string, error) {
	if strings.ContainsAny(p, "*?[") {
		files, err := filepath.Glob(p)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid glob pattern: %v", ErrLogpathInvalid, err)
		}
		if len(files) == 0 {
			if _, err := os.ReadDir(filepath.Dir(p)); errors.Is(err, fs.ErrPermission) {
				return nil, fmt.Errorf("%w: %s", ErrLogpathInaccessible, filepath.Dir(p))
			}
			return []string{}, nil
		}
		sort.Strings(files)
		return files, nil
	}

	info, err := os.Stat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return []string{}, nil
	case errors.Is(err, fs.ErrPermission):
		return nil, fmt.Errorf("%w: %s", ErrLogpathInaccessible, p)
	case err != nil:
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}
	if !info.IsDir() {
		return []string{p}, nil
	}
	entries, err := os.ReadDir(p)
	if errors.Is(err, fs.ErrPermission) {
		return nil, fmt.Errorf("%w: %s", ErrLogpathInaccessible, p)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, filepath.Join(p, entry.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

func (s *Service) TestLogpathWithResolution(pattern string) (string, string, []string, error) {
	original := strings.TrimSpace(pattern)
	if original == "" {
		return original, "", []string{}, nil
	}
	resolved, err := ResolveLogpathVariables(original, s.configRoot)
	if err != nil {
		// linuxserver images can keep fail2ban config under /config/fail2ban.
		for _, fallbackRoot := range []string{"/etc/fail2ban", "/config/fail2ban"} {
			if filepath.Clean(fallbackRoot) == filepath.Clean(s.configRoot) {
				continue
			}
			altResolved, altErr := ResolveLogpathVariables(original, fallbackRoot)
			if altErr == nil {
				resolved = altResolved
				err = nil
				break
			}
		}
		if err != nil {
			return original, "", nil, fmt.Errorf("%w: %v", ErrLogpathUnresolved, err)
		}
	}
	if resolved == "" {
		resolved = original
	}
	checked, err := ValidateLogpath(resolved)
	if err != nil {
		return original, resolved, nil, err
	}
	resolved = remapLogRoot(checked, s.logRoot)
	files, err := listLogpath(resolved)
	if err != nil {
		return original, resolved, nil, err
	}
	return original, resolved, files, nil
}

// Moves a path under /var/log to logRoot (e.g. a container mount); /var/logfoo is left alone.
func remapLogRoot(p, logRoot string) string {
	if logRoot == "" || logRoot == "/var/log" {
		return p
	}
	if p == "/var/log" {
		return logRoot
	}
	if rest, ok := strings.CutPrefix(p, "/var/log/"); ok {
		return filepath.Join(logRoot, rest)
	}
	return p
}

// Reports whether jail.local exists, whether the agent or the UI manages it, and whether it still carries the legacy UI action.
func (s *Service) CheckJailLocalState() (exists bool, managed bool, hasLegacyUIAction bool, err error) {
	raw, err := os.ReadFile(filepath.Join(s.configRoot, "jail.local"))
	if errors.Is(err, fs.ErrNotExist) {
		return false, false, false, nil
	}
	if err != nil {
		return false, false, false, err
	}
	content := string(raw)
	return true, isManagedJailLocal(content), strings.Contains(content, legacyUIActionMarker), nil
}

// Files written by the agent or by the UI's local/SSH connectors (ui-custom-action) are ours to rewrite.
func isManagedJailLocal(content string) bool {
	return strings.Contains(content, agentManagedMarker) || strings.Contains(content, legacyUIActionMarker)
}

func stripLegacyUICustomActionLines(content string) string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trim := strings.TrimSpace(strings.ToLower(line))
		if strings.Contains(trim, legacyUIActionMarker) {
			continue
		}
		if strings.HasPrefix(trim, "action_mwlg") || trim == "action = %(action_mwlg)s" {
			continue
		}
		if trim == "# custom fail2ban action for ui callbacks" || trim == "# custom fail2ban action applied by fail2ban-ui" {
			continue
		}
		out = append(out, line)
	}
	result := strings.Join(out, "\n")
	for strings.Contains(result, "\n\n\n") {
		result = strings.ReplaceAll(result, "\n\n\n", "\n\n")
	}
	return strings.TrimRight(result, "\n") + "\n"
}

// Writes the managed jail.local; returns a skip reason instead of touching a user-owned file.
func (s *Service) EnsureJailLocalStructure(content string) (skipReason string, err error) {
	exists, managed, _, err := s.CheckJailLocalState()
	if err != nil {
		return "", err
	}
	if exists && !managed {
		return "unmanaged", nil
	}
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		trimmed = "[DEFAULT]\n# " + agentManagedMarker + "\nbanaction = iptables-multiport\n"
	}
	final := stripLegacyUICustomActionLines(trimmed)
	if !strings.Contains(final, agentManagedMarker) {
		final = strings.TrimRight(final, "\n") + "\n# " + agentManagedMarker + "\n"
	}
	return "", fsutil.WriteConfig(filepath.Join(s.configRoot, "jail.local"), []byte(final), 0644)
}

func (s *Service) DeleteJail(name string) error {
	if err := ValidateJailName(name); err != nil {
		return err
	}
	return removeLocalAndConf(jailDDir(s.configRoot), strings.TrimSpace(name), "jail")
}

func (s *Service) DeleteFilter(name string) error {
	if err := ValidateFilterName(name); err != nil {
		return err
	}
	return removeLocalAndConf(filepath.Join(s.configRoot, "filter.d"), strings.TrimSpace(name), "filter")
}

func removeLocalAndConf(dir, name, kind string) error {
	var deleted int
	for _, ext := range []string{".local", ".conf"} {
		path := filepath.Join(dir, name+ext)
		if err := os.Remove(path); err == nil {
			deleted++
			_ = os.Remove(path + fsutil.BackupSuffix)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if deleted == 0 {
		return fmt.Errorf("%w: %s file %s.local or %s.conf does not exist", ErrNotFound, kind, name, name)
	}
	return nil
}

// Every fail2ban-client call reads the config tree (and thus the socket path) from the agent's config root.
func (s *Service) client(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	return runCommand(ctx, timeout, "fail2ban-client", append([]string{"-c", s.configRoot}, args...)...)
}

func runCommand(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	if managed, _ := ctx.Value(operationContextKey{}).(bool); managed {
		// The worker owns a bounded lifetime independent of HTTP. Short read
		// probes retain their normal timeout; service changes may take minutes.
		if timeout == longCommandTimeout || timeout == restartTimeout {
			timeout = 30 * time.Minute
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if ctxErr := ctx.Err(); err != nil && ctxErr != nil {
		return "", fmt.Errorf("%s %s did not finish: %w", name, strings.Join(args, " "), ctxErr)
	}
	if err != nil {
		return "", fmt.Errorf("%s %s failed: %w (%s)", name, strings.Join(args, " "), err, capOutput([]byte(strings.TrimSpace(string(out))), 4096))
	}
	return string(out), nil
}

func capOutput(out []byte, limit int) string {
	if len(out) <= limit {
		return string(out)
	}
	return string(out[:limit]) + "\n[output truncated]"
}

func (s *Service) pickFilterPath(name string) (string, error) {
	if err := ValidateFilterName(name); err != nil {
		return "", err
	}
	name = strings.TrimSpace(name)
	for _, ext := range []string{".local", ".conf"} {
		p := filepath.Join(s.configRoot, "filter.d", name+ext)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%w: filter %s", ErrNotFound, name)
}

func parseIntAfterColon(line string) int {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return 0
	}
	v := strings.TrimSpace(line[idx+1:])
	n, _ := strconv.Atoi(v)
	return n
}
