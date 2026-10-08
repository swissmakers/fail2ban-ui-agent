package fail2ban

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigurationSnapshotExactRestoreAndIdempotency(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"jail.d", "filter.d"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	original := map[string]string{"jail.local": "[DEFAULT]\nenabled=false\n", "jail.d/ssh.local": "[ssh]\nenabled = true\n", "filter.d/ssh.conf": "[Definition]\nfailregex = original\n"}
	for path, raw := range original {
		if err := os.WriteFile(filepath.Join(root, path), []byte(raw), 0640); err != nil {
			t.Fatal(err)
		}
	}
	s := NewService(root, root)
	if err := s.BackupConfiguration("op1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "jail.local"), []byte("bad edit"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "filter.d/ssh.conf")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "jail.d/new.local"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.BackupConfiguration("op1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.RestoreConfiguration("op1"); err != nil {
			t.Fatal(err)
		}
	}
	for path, want := range original {
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || string(raw) != want {
			t.Fatalf("restored %s: %q %v", path, raw, err)
		}
		info, err := os.Stat(filepath.Join(root, path))
		if err != nil || info.Mode().Perm() != 0640 {
			t.Fatalf("permissions changed for %s", path)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "jail.d/new.local")); !os.IsNotExist(err) {
		t.Fatal("new config file was not removed")
	}
	if err := s.DeleteConfigurationBackup("op1"); err != nil {
		t.Fatal(err)
	}
	if err := s.RestoreConfiguration("op1"); !os.IsNotExist(err) {
		t.Fatalf("snapshot not removed: %v", err)
	}
}

func TestSnapshotRejectsTraversalAndSymlinks(t *testing.T) {
	root := t.TempDir()
	s := NewService(root, root)
	for _, id := range []string{"../escape", "/absolute", "..", ""} {
		if err := s.BackupConfiguration(id); err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "jail.local")); err != nil {
		t.Fatal(err)
	}
	if err := s.BackupConfiguration("safe"); err == nil {
		t.Fatal("snapshot followed external config symlink")
	}
}
