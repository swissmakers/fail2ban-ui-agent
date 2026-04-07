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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var variablePattern = regexp.MustCompile(`%\(([^)]+)\)s`)

func normalizeConfigRoot(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "/etc/fail2ban"
	}
	return filepath.Clean(trimmed)
}

func extractVariablesFromString(s string) []string {
	matches := variablePattern.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return nil
	}
	var variables []string
	for _, match := range matches {
		if len(match) > 1 {
			variables = append(variables, match[1])
		}
	}
	return variables
}

func searchVariableInFile(filePath, varName string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentVar string
	var currentValue strings.Builder
	var inMultiLine bool
	var pendingLine string
	var pendingLineOriginal string

	for {
		var originalLine string
		var line string

		if pendingLine != "" {
			originalLine = pendingLineOriginal
			line = pendingLine
			pendingLine = ""
			pendingLineOriginal = ""
		} else {
			if !scanner.Scan() {
				break
			}
			originalLine = scanner.Text()
			line = strings.TrimSpace(originalLine)
		}

		if !inMultiLine && (strings.HasPrefix(line, "#") || line == "") {
			continue
		}

		if !inMultiLine {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				if strings.EqualFold(key, varName) {
					currentVar = key
					currentValue.WriteString(value)

					if scanner.Scan() {
						nextLineOriginal := scanner.Text()
						nextLineTrimmed := strings.TrimSpace(nextLineOriginal)
						isContinuation := nextLineTrimmed != "" &&
							!strings.HasPrefix(nextLineTrimmed, "#") &&
							!strings.HasPrefix(nextLineTrimmed, "[") &&
							(strings.HasPrefix(nextLineOriginal, " ") || strings.HasPrefix(nextLineOriginal, "\t") ||
								(!strings.Contains(nextLineTrimmed, "=")))

						if isContinuation {
							inMultiLine = true
							pendingLine = nextLineTrimmed
							pendingLineOriginal = nextLineOriginal
							continue
						}
						return strings.TrimSpace(currentValue.String()), nil
					}
					return strings.TrimSpace(currentValue.String()), nil
				}
			}
		} else {
			trimmedLine := strings.TrimSpace(originalLine)
			if strings.HasPrefix(trimmedLine, "[") {
				return strings.TrimSpace(currentValue.String()), nil
			}
			if strings.Contains(trimmedLine, "=") && !strings.HasPrefix(originalLine, " ") && !strings.HasPrefix(originalLine, "\t") {
				return strings.TrimSpace(currentValue.String()), nil
			}
			if currentValue.Len() > 0 {
				currentValue.WriteString(" ")
			}
			currentValue.WriteString(trimmedLine)
			if scanner.Scan() {
				nextLineOriginal := scanner.Text()
				nextLineTrimmed := strings.TrimSpace(nextLineOriginal)
				if nextLineTrimmed == "" ||
					strings.HasPrefix(nextLineTrimmed, "#") ||
					strings.HasPrefix(nextLineTrimmed, "[") ||
					(strings.Contains(nextLineTrimmed, "=") && !strings.HasPrefix(nextLineOriginal, " ") && !strings.HasPrefix(nextLineOriginal, "\t")) {
					return strings.TrimSpace(currentValue.String()), nil
				}
				pendingLine = nextLineTrimmed
				pendingLineOriginal = nextLineOriginal
				continue
			}
			return strings.TrimSpace(currentValue.String()), nil
		}
	}

	if inMultiLine && currentVar != "" {
		return strings.TrimSpace(currentValue.String()), nil
	}
	return "", nil
}

func findVariableDefinition(varName, fail2banPath string) (string, error) {
	fail2banPath = normalizeConfigRoot(fail2banPath)
	if _, err := os.Stat(fail2banPath); os.IsNotExist(err) {
		return "", fmt.Errorf("variable '%s' not found: /etc/fail2ban directory does not exist", varName)
	}

	var foundValue string
	err := filepath.Walk(fail2banPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".local") {
			return nil
		}
		value, err := searchVariableInFile(path, varName)
		if err != nil {
			return nil
		}
		if value != "" {
			foundValue = value
			return filepath.SkipAll
		}
		return nil
	})
	if foundValue != "" {
		return foundValue, nil
	}
	if err != nil && err != filepath.SkipAll {
		return "", err
	}

	err = filepath.Walk(fail2banPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".conf") {
			return nil
		}
		value, err := searchVariableInFile(path, varName)
		if err != nil {
			return nil
		}
		if value != "" {
			foundValue = value
			return filepath.SkipAll
		}
		return nil
	})
	if foundValue != "" {
		return foundValue, nil
	}
	if err != nil && err != filepath.SkipAll {
		return "", err
	}
	return "", fmt.Errorf("variable '%s' not found in Fail2Ban configuration files", varName)
}

func resolveVariableRecursive(varName string, visited map[string]bool, fail2banPath string) (string, error) {
	if visited[varName] {
		return "", fmt.Errorf("circular reference detected for variable '%s'", varName)
	}
	visited[varName] = true
	defer delete(visited, varName)

	value, err := findVariableDefinition(varName, fail2banPath)
	if err != nil {
		return "", err
	}
	resolved := value
	maxIterations := 10
	iteration := 0
	for iteration < maxIterations {
		variables := extractVariablesFromString(resolved)
		if len(variables) == 0 {
			break
		}
		for _, nestedVar := range variables {
			if visited[nestedVar] {
				return "", fmt.Errorf("circular reference detected: '%s' -> '%s'", varName, nestedVar)
			}
			nestedValue, err := resolveVariableRecursive(nestedVar, visited, fail2banPath)
			if err != nil {
				return "", fmt.Errorf("failed to resolve variable '%s' in '%s': %w", nestedVar, varName, err)
			}
			pattern := fmt.Sprintf("%%\\(%s\\)s", regexp.QuoteMeta(nestedVar))
			re := regexp.MustCompile(pattern)
			resolved = re.ReplaceAllString(resolved, nestedValue)
		}
		iteration++
	}
	if iteration >= maxIterations {
		return "", fmt.Errorf("maximum resolution iterations reached for variable '%s', possible circular reference. Last resolved value: '%s'", varName, resolved)
	}
	return resolved, nil
}

// ResolveLogpathVariables expands %(var)s patterns in logpath using Fail2ban config files.
func ResolveLogpathVariables(logpath, fail2banPath string) (string, error) {
	if logpath == "" {
		return "", nil
	}
	resolved := strings.TrimSpace(logpath)
	maxIterations := 10
	iteration := 0
	for iteration < maxIterations {
		variables := extractVariablesFromString(resolved)
		if len(variables) == 0 {
			break
		}
		visited := make(map[string]bool)
		for _, varName := range variables {
			varValue, err := resolveVariableRecursive(varName, visited, fail2banPath)
			if err != nil {
				return "", fmt.Errorf("failed to resolve variable '%s': %w", varName, err)
			}
			pattern := fmt.Sprintf("%%\\(%s\\)s", regexp.QuoteMeta(varName))
			re := regexp.MustCompile(pattern)
			resolved = re.ReplaceAllString(resolved, varValue)
		}
		iteration++
	}
	if iteration >= maxIterations {
		return "", fmt.Errorf("maximum resolution iterations reached, possible circular reference in logpath '%s'", logpath)
	}
	return resolved, nil
}
