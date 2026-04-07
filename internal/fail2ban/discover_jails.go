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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/swissmakers/fail2ban-ui-agent/internal/model"
)

func listJailFilesInDir(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read jail.d: %w", err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if strings.HasSuffix(name, ".local") || strings.HasSuffix(name, ".conf") {
			files = append(files, filepath.Join(directory, name))
		}
	}
	return files, nil
}

func parseJailSectionsFromFile(path string) ([]model.JailInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var jails []model.JailInfo
	scanner := bufio.NewScanner(file)
	var currentJail string
	ignored := map[string]bool{"DEFAULT": true, "INCLUDES": true}
	enabled := true

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if currentJail != "" && !ignored[currentJail] {
				jails = append(jails, model.JailInfo{JailName: currentJail, Enabled: enabled})
			}
			currentJail = strings.TrimSpace(strings.Trim(line, "[]"))
			if currentJail == "" {
				continue
			}
			enabled = true
		} else if strings.HasPrefix(strings.ToLower(line), "enabled") {
			if currentJail != "" {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					enabled = strings.EqualFold(strings.TrimSpace(parts[1]), "true")
				}
			}
		}
	}
	if currentJail != "" && !ignored[currentJail] {
		jails = append(jails, model.JailInfo{JailName: currentJail, Enabled: enabled})
	}
	return jails, scanner.Err()
}

// DiscoverJailsFromFiles lists jails defined under jail.d (same rules as Fail2ban-UI local connector).
func DiscoverJailsFromFiles(configRoot string) ([]model.JailInfo, error) {
	dir := jailDDir(configRoot)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}
	files, err := listJailFilesInDir(dir)
	if err != nil {
		return nil, err
	}

	var all []model.JailInfo
	processedFiles := make(map[string]bool)
	processedJails := make(map[string]bool)

	process := func(filePath string, wantSuffix string) error {
		if !strings.HasSuffix(filePath, wantSuffix) {
			return nil
		}
		filename := filepath.Base(filePath)
		var baseName string
		if wantSuffix == ".local" {
			baseName = strings.TrimSuffix(filename, ".local")
		} else {
			baseName = strings.TrimSuffix(filename, ".conf")
		}
		if baseName == "" || processedFiles[baseName] {
			return nil
		}
		processedFiles[baseName] = true
		jails, err := parseJailSectionsFromFile(filePath)
		if err != nil {
			return err
		}
		for _, j := range jails {
			if j.JailName == "" || j.JailName == "DEFAULT" || processedJails[j.JailName] {
				continue
			}
			all = append(all, j)
			processedJails[j.JailName] = true
		}
		return nil
	}

	for _, fp := range files {
		if err := process(fp, ".local"); err != nil {
			return nil, err
		}
	}
	for _, fp := range files {
		if err := process(fp, ".conf"); err != nil {
			return nil, err
		}
	}
	return all, nil
}

// GetAllJailsForManage returns jails from jail.d (enabled flags) merged with live ban counts from fail2ban-client.
func (s *Service) GetAllJailsForManage(ctx context.Context) ([]model.JailInfo, error) {
	discovered, err := DiscoverJailsFromFiles(s.configRoot)
	if err != nil {
		return nil, err
	}
	running, runErr := s.GetJailInfos(ctx)
	if runErr != nil {
		running = nil
	}
	byName := make(map[string]model.JailInfo, len(running))
	for _, j := range running {
		byName[j.JailName] = j
	}

	out := make([]model.JailInfo, 0, len(discovered)+len(byName))
	seen := make(map[string]bool)
	for _, d := range discovered {
		j := d
		if r, ok := byName[j.JailName]; ok {
			j.TotalBanned = r.TotalBanned
			j.BannedIPs = r.BannedIPs
			j.NewInLastHour = r.NewInLastHour
		}
		out = append(out, j)
		seen[j.JailName] = true
	}
	for name, r := range byName {
		if seen[name] {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].JailName < out[j].JailName })
	return out, nil
}
