// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU General Public License, Version 3 (GPL-3.0)
// You may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/gpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fail2ban

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func jailDDir(configRoot string) string {
	return filepath.Join(configRoot, "jail.d")
}

// ensureJailLocalFile guarantees jail.d/{name}.local exists: use existing .local, else copy from .conf, else create minimal.
func ensureJailLocalFile(jailName, configRoot string) error {
	jailName = strings.TrimSpace(jailName)
	if jailName == "" {
		return fmt.Errorf("jail name cannot be empty")
	}
	jailDPath := jailDDir(configRoot)
	localPath := filepath.Join(jailDPath, jailName+".local")
	confPath := filepath.Join(jailDPath, jailName+".conf")

	if _, err := os.Stat(localPath); err == nil {
		return nil
	}
	if _, err := os.Stat(confPath); err == nil {
		content, err := os.ReadFile(confPath)
		if err != nil {
			return fmt.Errorf("read jail .conf %s: %w", confPath, err)
		}
		if err := os.MkdirAll(jailDPath, 0755); err != nil {
			return err
		}
		if err := os.WriteFile(localPath, content, 0644); err != nil {
			return fmt.Errorf("write jail .local %s: %w", localPath, err)
		}
		return nil
	}
	if err := os.MkdirAll(jailDPath, 0755); err != nil {
		return err
	}
	minimal := fmt.Sprintf("[%s]\n", jailName)
	if err := os.WriteFile(localPath, []byte(minimal), 0644); err != nil {
		return fmt.Errorf("create jail .local %s: %w", localPath, err)
	}
	return nil
}

// readJailConfigWithFallback reads jail.d/{name}.local, else .conf, else returns a minimal section (path = intended .local).
func readJailConfigWithFallback(jailName, configRoot string) (content string, filePath string, err error) {
	jailName = strings.TrimSpace(jailName)
	if jailName == "" {
		return "", "", fmt.Errorf("jail name cannot be empty")
	}
	jailDPath := jailDDir(configRoot)
	localPath := filepath.Join(jailDPath, jailName+".local")
	confPath := filepath.Join(jailDPath, jailName+".conf")

	if raw, e := os.ReadFile(localPath); e == nil {
		return string(raw), localPath, nil
	}
	if raw, e := os.ReadFile(confPath); e == nil {
		return string(raw), confPath, nil
	}
	return fmt.Sprintf("[%s]\n", jailName), localPath, nil
}

// applyJailEnabledInContent updates or inserts enabled = for the given [jailName] section (same rules as Fail2ban-UI local connector).
func applyJailEnabledInContent(content, jailName string, enabled bool) string {
	jailName = strings.TrimSpace(jailName)
	var lines []string
	if len(content) > 0 {
		lines = strings.Split(content, "\n")
	} else {
		lines = []string{fmt.Sprintf("[%s]", jailName)}
	}
	var outputLines []string
	var foundEnabled bool
	var currentJail string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			currentJail = strings.Trim(trimmed, "[]")
			outputLines = append(outputLines, line)
		} else if strings.HasPrefix(strings.ToLower(trimmed), "enabled") {
			if currentJail == jailName {
				outputLines = append(outputLines, fmt.Sprintf("enabled = %t", enabled))
				foundEnabled = true
			} else {
				outputLines = append(outputLines, line)
			}
		} else {
			outputLines = append(outputLines, line)
		}
	}
	if !foundEnabled {
		var newLines []string
		for i, line := range outputLines {
			newLines = append(newLines, line)
			if strings.TrimSpace(line) == fmt.Sprintf("[%s]", jailName) {
				newLines = append(newLines, fmt.Sprintf("enabled = %t", enabled))
				if i+1 < len(outputLines) {
					newLines = append(newLines, outputLines[i+1:]...)
				}
				break
			}
		}
		if len(newLines) > len(outputLines) {
			outputLines = newLines
		} else {
			outputLines = append(outputLines, fmt.Sprintf("enabled = %t", enabled))
		}
	}
	newContent := strings.Join(outputLines, "\n")
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}
	return newContent
}
