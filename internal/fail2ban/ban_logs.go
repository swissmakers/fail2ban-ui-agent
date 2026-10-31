// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
//
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
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
)

const (
	banLogMaxLines       = 200
	banLogMaxLineLen     = 2048
	banLogTailBytes      = 4 << 20
	banLogMaxJournalRead = 50000
)

func (s *Service) BanLogLines(ctx context.Context, jail string, ips []string) map[string]string {
	out := map[string]string{}
	if ValidateJailName(jail) != nil {
		return out
	}
	var wanted []string
	for _, ip := range ips {
		if ValidateIP(ip) == nil {
			wanted = append(wanted, strings.TrimSpace(ip))
		}
	}
	if len(wanted) == 0 {
		return out
	}
	var lines []string
	if res, err := s.client(ctx, shortCommandTimeout, "get", jail, "logpath"); err == nil {
		for _, path := range parseMonitoredLogpaths(res) {
			lines = append(lines, tailLinesNewestFirst(path, banLogTailBytes)...)
		}
	}
	matches := collectBanLogMatches(lines, wanted, banLogMaxLines)
	var missing []string
	for _, ip := range wanted {
		if len(matches[ip]) == 0 {
			missing = append(missing, ip)
		}
	}
	if len(missing) > 0 {
		// Best effort: a journal that cannot be read completely still contributes the lines read so far.
		journal, _ := journalLinesNewestFirst(ctx)
		for ip, found := range collectBanLogMatches(journal, missing, banLogMaxLines) {
			matches[ip] = found
		}
	}
	for ip, found := range matches {
		if len(found) > 0 {
			out[ip] = sanitizeLogText(strings.Join(found, "\n"))
		}
	}
	return out
}

func parseMonitoredLogpaths(output string) []string {
	var paths []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"|- ", "`- "} {
			if path, ok := strings.CutPrefix(line, prefix); ok && strings.HasPrefix(strings.TrimSpace(path), "/") {
				paths = append(paths, strings.TrimSpace(path))
			}
		}
	}
	return paths
}

// Reads at most maxBytes from the end of a regular file and returns its complete lines, newest first.
func tailLinesNewestFirst(path string, maxBytes int64) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return nil
	}
	offset := int64(0)
	if info.Size() > maxBytes {
		offset = info.Size() - maxBytes
	}
	buf := make([]byte, info.Size()-offset)
	if _, err := f.ReadAt(buf, offset); err != nil && err != io.EOF {
		return nil
	}
	text := string(buf)
	if offset > 0 {
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			text = text[i+1:]
		} else {
			return nil
		}
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	return lines
}

// The journal is only searched when it is available, newest entries of the last day first and bounded in size.
// Lines read before a scan error are complete and still returned with the error.
func journalLinesNewestFirst(ctx context.Context) ([]string, error) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, shortCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "journalctl", "--no-pager", "-r", "-o", "cat", "--since", "-1 day")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var lines []string
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for len(lines) < banLogMaxJournalRead && scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	scanErr := scanner.Err()
	cancel()
	_ = cmd.Wait()
	return lines, scanErr
}

// Keeps the first limit lines per IP that contain it as a whole word, like grep -wF.
func collectBanLogMatches(lines, ips []string, limit int) map[string][]string {
	matches := make(map[string][]string, len(ips))
	for _, line := range lines {
		for _, ip := range ips {
			if len(matches[ip]) < limit && containsWord(line, ip) {
				if len(line) > banLogMaxLineLen {
					line = line[:banLogMaxLineLen]
				}
				matches[ip] = append(matches[ip], line)
			}
		}
	}
	return matches
}

func containsWord(line, word string) bool {
	for start := 0; ; {
		i := strings.Index(line[start:], word)
		if i < 0 {
			return false
		}
		i += start
		end := i + len(word)
		if (i == 0 || !isWordByte(line[i-1])) && (end == len(line) || !isWordByte(line[end])) {
			return true
		}
		start = i + 1
	}
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func sanitizeLogText(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7e) {
			b.WriteByte(c)
		}
	}
	return b.String()
}
