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
	"time"

	"github.com/swissmakers/fail2ban-ui-agent/internal/model"
)

type Service struct {
	configRoot string
	runRoot    string
	logRoot    string
}

func NewService(configRoot, runRoot, logRoot string) *Service {
	return &Service{
		configRoot: strings.TrimRight(configRoot, "/"),
		runRoot:    strings.TrimRight(runRoot, "/"),
		logRoot:    strings.TrimRight(logRoot, "/"),
	}
}

func (s *Service) Ping(ctx context.Context) error {
	_, err := s.client(ctx, "ping")
	return err
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
	out, err := s.client(ctx, "status")
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
	ips, count, err := s.getBannedInfo(ctx, strings.TrimSpace(jail))
	if err != nil {
		return nil, 0, err
	}
	return ips, count, nil
}

func (s *Service) getBannedInfo(ctx context.Context, jail string) ([]string, int, error) {
	out, err := s.client(ctx, "status", jail)
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
	_, err := s.client(ctx, "set", strings.TrimSpace(jail), "banip", strings.TrimSpace(ip))
	return err
}

func (s *Service) UnbanIP(ctx context.Context, jail, ip string) error {
	if err := ValidateJailName(jail); err != nil {
		return err
	}
	if err := ValidateIP(ip); err != nil {
		return err
	}
	_, err := s.client(ctx, "set", strings.TrimSpace(jail), "unbanip", strings.TrimSpace(ip))
	return err
}

func (s *Service) Reload(ctx context.Context) error {
	_, err := s.ReloadWithOutput(ctx)
	return err
}

func (s *Service) ReloadWithOutput(ctx context.Context) (string, error) {
	return s.client(ctx, "reload")
}

func (s *Service) Restart(ctx context.Context) error {
	candidates := [][]string{
		{"systemctl", "restart", "fail2ban"},
		{"service", "fail2ban", "restart"},
		{"rc-service", "fail2ban", "restart"},
	}
	var lastErr error
	for _, c := range candidates {
		cmd := exec.CommandContext(ctx, c[0], c[1:]...)
		if out, err := cmd.CombinedOutput(); err == nil {
			_ = out
			return nil
		} else {
			lastErr = fmt.Errorf("%s: %w (%s)", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
		}
	}
	// fallback if service manager is unavailable
	if _, err := s.ReloadWithOutput(ctx); err != nil {
		if lastErr != nil {
			return fmt.Errorf("%v; fallback reload failed: %w", lastErr, err)
		}
		return err
	}
	return nil
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
	name = strings.TrimSpace(name)
	p := filepath.Join(s.configRoot, "filter.d", name+".local")
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(content), 0644)
}

func (s *Service) GetFilters() ([]string, error) {
	dir := filepath.Join(s.configRoot, "filter.d")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	set := map[string]struct{}{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".conf") || strings.HasSuffix(name, ".local") {
			base := strings.TrimSuffix(strings.TrimSuffix(name, ".conf"), ".local")
			if base != "" {
				set[base] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out, nil
}

func (s *Service) TestFilter(ctx context.Context, filterName string, logLines []string, filterContent string) (string, string, error) {
	if err := ValidateFilterName(filterName); err != nil {
		return "", "", err
	}
	filterName = strings.TrimSpace(filterName)

	var filterPath string
	if strings.TrimSpace(filterContent) != "" {
		// Ad-hoc content: write to a private temp dir with a randomised file name
		// (never derived from caller input) so it cannot collide or traverse.
		tmpDir, err := os.MkdirTemp("", "f2b-agent-test-")
		if err != nil {
			return "", "", err
		}
		defer os.RemoveAll(tmpDir)
		filterPath = filepath.Join(tmpDir, "filter.conf")
		if err := os.WriteFile(filterPath, []byte(filterContent), 0600); err != nil {
			return "", "", err
		}
		logPath := filepath.Join(tmpDir, "logs.log")
		if err := os.WriteFile(logPath, []byte(strings.Join(logLines, "\n")), 0600); err != nil {
			return "", "", err
		}
		cmd := exec.CommandContext(ctx, "fail2ban-regex", logPath, filterPath)
		out, err := cmd.CombinedOutput()
		return string(out), filterPath, err
	}

	filterPath, err := s.pickFilterPath(filterName)
	if err != nil {
		return "", "", err
	}
	tmpDir, err := os.MkdirTemp("", "f2b-agent-test-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(tmpDir)
	logPath := filepath.Join(tmpDir, "logs.log")
	if err := os.WriteFile(logPath, []byte(strings.Join(logLines, "\n")), 0600); err != nil {
		return "", "", err
	}

	cmd := exec.CommandContext(ctx, "fail2ban-regex", logPath, filterPath)
	out, err := cmd.CombinedOutput()
	return string(out), filterPath, err
}

func (s *Service) GetJailConfig(jail string) (string, string, error) {
	if err := ValidateJailName(jail); err != nil {
		return "", "", err
	}
	jail = strings.TrimSpace(jail)
	return readJailConfigWithFallback(jail, s.configRoot)
}

func (s *Service) SetJailConfig(jail, content string) error {
	if err := ValidateJailName(jail); err != nil {
		return err
	}
	jail = strings.TrimSpace(jail)
	if err := ensureJailLocalFile(jail, s.configRoot); err != nil {
		return err
	}
	p := filepath.Join(s.configRoot, "jail.d", jail+".local")
	if strings.TrimSpace(content) == "" {
		content = fmt.Sprintf("[%s]\n", jail)
	}
	return os.WriteFile(p, []byte(content), 0644)
}

func (s *Service) UpdateJailEnabledStates(updates map[string]bool) error {
	for jail, enabled := range updates {
		if err := ValidateJailName(jail); err != nil {
			return err
		}
		jail = strings.TrimSpace(jail)
		if err := ensureJailLocalFile(jail, s.configRoot); err != nil {
			return fmt.Errorf("jail %q: %w", jail, err)
		}
		content, _, err := readJailConfigWithFallback(jail, s.configRoot)
		if err != nil {
			return err
		}
		content = applyJailEnabledInContent(content, jail, enabled)
		path := filepath.Join(s.configRoot, "jail.d", jail+".local")
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) TestLogpath(pattern string) ([]string, error) {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return []string{}, nil
	}

	hasWildcard := strings.ContainsAny(p, "*?[")
	if hasWildcard {
		files, err := filepath.Glob(p)
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern: %w", err)
		}
		sort.Strings(files)
		return files, nil
	}

	info, err := os.Stat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	if info.IsDir() {
		entries, err := os.ReadDir(p)
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

	return []string{p}, nil
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
			return original, "", nil, fmt.Errorf("failed to resolve logpath variables: %w", err)
		}
	}
	if resolved == "" {
		resolved = original
	}
	if strings.HasPrefix(resolved, "/var/log") && s.logRoot != "/var/log" && s.logRoot != "" {
		resolved = filepath.Join(strings.TrimRight(s.logRoot, "/"), strings.TrimPrefix(resolved, "/var/log"))
	}
	files, err := s.TestLogpath(resolved)
	if err != nil {
		return original, resolved, nil, fmt.Errorf("failed to test logpath: %w", err)
	}
	return original, resolved, files, nil
}

func (s *Service) CheckJailLocalState() (bool, bool, bool, error) {
	return s.jailLocalState()
}

func (s *Service) jailLocalState() (exists bool, managed bool, hasLegacyUICustomAction bool, err error) {
	p := filepath.Join(s.configRoot, "jail.local")
	raw, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, false, false, nil
		}
		return false, false, false, err
	}
	content := string(raw)
	return true, strings.Contains(content, "managed by fail2ban-ui-agent"), strings.Contains(content, "ui-custom-action"), nil
}

func stripLegacyUICustomActionLines(content string) string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trim := strings.TrimSpace(strings.ToLower(line))
		if trim == "action = ui-custom-action" || trim == "banaction = ui-custom-action" || strings.Contains(trim, "ui-custom-action") {
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

func (s *Service) EnsureJailLocalStructureWithContent(content string) error {
	p := filepath.Join(s.configRoot, "jail.local")
	if exists, managed, _, err := s.jailLocalState(); err == nil && exists && !managed {
		return nil
	}
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		trimmed = "[DEFAULT]\n# managed by fail2ban-ui-agent\nbanaction = iptables-multiport\n"
	}
	final := stripLegacyUICustomActionLines(trimmed)
	if !strings.Contains(final, "managed by fail2ban-ui-agent") {
		final = strings.TrimRight(final, "\n") + "\n# managed by fail2ban-ui-agent\n"
	}
	return os.WriteFile(p, []byte(final), 0644)
}

func (s *Service) CleanupLegacyUICustomAction() error {
	p := filepath.Join(s.configRoot, "jail.local")
	raw, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	content := string(raw)
	cleaned := stripLegacyUICustomActionLines(content)
	if cleaned == strings.TrimRight(content, "\n")+"\n" || cleaned == content {
		return nil
	}
	if !strings.Contains(cleaned, "managed by fail2ban-ui-agent") {
		cleaned = strings.TrimRight(cleaned, "\n") + "\n# managed by fail2ban-ui-agent\n"
	}
	return os.WriteFile(p, []byte(cleaned), 0644)
}

func (s *Service) CreateJail(name, content string) error {
	return s.SetJailConfig(name, content)
}

func (s *Service) DeleteJail(name string) error {
	if err := ValidateJailName(name); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	jd := jailDDir(s.configRoot)
	localPath := filepath.Join(jd, name+".local")
	confPath := filepath.Join(jd, name+".conf")
	var deleted int
	if err := os.Remove(localPath); err == nil {
		deleted++
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Remove(confPath); err == nil {
		deleted++
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if deleted == 0 {
		return fmt.Errorf("jail file %s.local or %s.conf does not exist", name, name)
	}
	return nil
}

func (s *Service) CreateFilter(name, content string) error {
	return s.SetFilterConfig(name, content)
}

func (s *Service) DeleteFilter(name string) error {
	if err := ValidateFilterName(name); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	fd := filepath.Join(s.configRoot, "filter.d")
	localPath := filepath.Join(fd, name+".local")
	confPath := filepath.Join(fd, name+".conf")
	var deleted int
	if err := os.Remove(localPath); err == nil {
		deleted++
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Remove(confPath); err == nil {
		deleted++
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if deleted == 0 {
		return fmt.Errorf("filter file %s.local or %s.conf does not exist", name, name)
	}
	return nil
}

func (s *Service) client(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "fail2ban-client", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("fail2ban-client %s failed: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (s *Service) pickFilterPath(name string) (string, error) {
	if err := ValidateFilterName(name); err != nil {
		return "", err
	}
	name = strings.TrimSpace(name)
	local := filepath.Join(s.configRoot, "filter.d", name+".local")
	if _, err := os.Stat(local); err == nil {
		return local, nil
	}
	conf := filepath.Join(s.configRoot, "filter.d", name+".conf")
	if _, err := os.Stat(conf); err == nil {
		return conf, nil
	}
	return "", fmt.Errorf("filter %s not found", name)
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
