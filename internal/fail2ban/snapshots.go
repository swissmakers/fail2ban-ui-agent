package fail2ban

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/swissmakers/fail2ban-ui-agent/internal/fsutil"
)

var snapshotIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,159}$`)

type snapshotFile struct {
	Path    string `json:"path"`
	Content []byte `json:"content"`
	Mode    uint32 `json:"mode"`
	UID     int    `json:"uid"`
	GID     int    `json:"gid"`
}
type configSnapshot struct {
	Version int            `json:"version"`
	ID      string         `json:"id"`
	Files   []snapshotFile `json:"files"`
}

func (s *Service) snapshotPath(id string) (string, error) {
	if !snapshotIDPattern.MatchString(id) {
		return "", fmt.Errorf("invalid snapshot ID")
	}
	dir := filepath.Join(s.configRoot, ".fail2ban-ui-snapshots")
	if info, err := os.Lstat(dir); err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return "", fmt.Errorf("unsafe configuration snapshot directory")
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return filepath.Join(dir, id+".json"), nil
}

func snapshotConfigPath(path string) bool {
	if path == "jail.conf" || path == "jail.local" || path == "fail2ban-ui-agent.id" {
		return true
	}
	dir, base := filepath.Split(path)
	if dir != "jail.d/" && dir != "filter.d/" && dir != "action.d/" {
		return false
	}
	return base != "" && !strings.HasPrefix(base, ".") && (strings.HasSuffix(base, ".conf") || strings.HasSuffix(base, ".local"))
}

func (s *Service) snapshotFiles() ([]string, error) {
	paths := []string{}
	add := func(rel string) error {
		info, err := os.Lstat(filepath.Join(s.configRoot, rel))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("cannot snapshot non-regular config file %s", rel)
		}
		paths = append(paths, rel)
		return nil
	}
	for _, rel := range []string{"jail.conf", "jail.local", "fail2ban-ui-agent.id"} {
		if err := add(rel); err != nil {
			return nil, err
		}
	}
	for _, dir := range []string{"jail.d", "filter.d", "action.d"} {
		info, err := os.Lstat(filepath.Join(s.configRoot, dir))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("cannot snapshot non-directory config path %s", dir)
		}
		entries, err := os.ReadDir(filepath.Join(s.configRoot, dir))
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			rel := dir + "/" + entry.Name()
			if snapshotConfigPath(rel) {
				if err := add(rel); err != nil {
					return nil, err
				}
			}
		}
	}
	sort.Strings(paths)
	return paths, nil
}

// BackupConfiguration is immutable for an ID: retries never overwrite the
// pre-change snapshot with files that may already contain the requested edit.
func (s *Service) BackupConfiguration(id string) error {
	path, err := s.snapshotPath(id)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		_, err = s.readSnapshot(id)
		return err
	} else if !os.IsNotExist(err) {
		return err
	}
	paths, err := s.snapshotFiles()
	if err != nil {
		return err
	}
	snap := configSnapshot{Version: 1, ID: id, Files: []snapshotFile{}}
	total := 0
	for _, rel := range paths {
		info, err := os.Lstat(filepath.Join(s.configRoot, rel))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 10<<20 {
			return fmt.Errorf("config file %s is unsafe or too large to snapshot", rel)
		}
		raw, err := os.ReadFile(filepath.Join(s.configRoot, rel))
		if err != nil {
			return err
		}
		total += len(raw)
		if total > 32<<20 {
			return fmt.Errorf("configuration snapshot exceeds 32 MiB")
		}
		file := snapshotFile{Path: rel, Content: raw, Mode: uint32(info.Mode().Perm()), UID: os.Getuid(), GID: os.Getgid()}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			file.UID, file.GID = int(stat.Uid), int(stat.Gid)
		}
		snap.Files = append(snap.Files, file)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return fsutil.ReplaceFile(path, raw, 0600)
}

func (s *Service) readSnapshot(id string) (configSnapshot, error) {
	path, err := s.snapshotPath(id)
	if err != nil {
		return configSnapshot{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return configSnapshot{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 48<<20 {
		return configSnapshot{}, fmt.Errorf("invalid snapshot file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return configSnapshot{}, err
	}
	var snap configSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return snap, err
	}
	if snap.Version != 1 || snap.ID != id {
		return snap, fmt.Errorf("invalid configuration snapshot")
	}
	seen := map[string]bool{}
	for _, file := range snap.Files {
		if !snapshotConfigPath(file.Path) || seen[file.Path] || file.Mode&^0777 != 0 || file.UID < 0 || file.GID < 0 {
			return snap, fmt.Errorf("invalid configuration snapshot entry")
		}
		seen[file.Path] = true
	}
	return snap, nil
}

func (s *Service) RestoreConfiguration(id string) error {
	snap, err := s.readSnapshot(id)
	if err != nil {
		return err
	}
	current, err := s.snapshotFiles()
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, file := range snap.Files {
		path := filepath.Join(s.configRoot, file.Path)
		want[file.Path] = true
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm() == os.FileMode(file.Mode) {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) == file.UID && int(stat.Gid) == file.GID {
				if raw, err := os.ReadFile(path); err == nil && bytes.Equal(raw, file.Content) {
					continue
				}
			}
		}
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		if err := fsutil.ReplaceFile(path, file.Content, os.FileMode(file.Mode)); err != nil {
			return err
		}
		if err := os.Chown(path, file.UID, file.GID); err != nil && !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
			return err
		}
	}
	for _, rel := range current {
		if !want[rel] {
			if err := os.Remove(filepath.Join(s.configRoot, rel)); err != nil {
				return err
			}
		}
	}
	for _, dir := range []string{s.configRoot, filepath.Join(s.configRoot, "jail.d"), filepath.Join(s.configRoot, "filter.d"), filepath.Join(s.configRoot, "action.d")} {
		f, err := os.Open(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		err = f.Sync()
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) DeleteConfigurationBackup(id string) error {
	path, err := s.snapshotPath(id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
