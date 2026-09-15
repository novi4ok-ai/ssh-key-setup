package setup

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := make(map[string]string)
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		files[path] = info.Mode().String()
		if !entry.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files[path] += string(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestCheckDoesNotModifyFiles(t *testing.T) {
	srv := startTestServer(t)
	s := Service{Home: t.TempDir()}
	in := srv.input()
	installed, err := s.Run(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, remote := snapshot(t, s.Home), snapshot(t, srv.home)
	in.Check, in.Password = true, ""
	checked, err := s.Run(context.Background(), in, nil)
	if err != nil || checked.Command != installed.Command {
		t.Fatalf("check: %v", err)
	}
	if !reflect.DeepEqual(before, snapshot(t, s.Home)) || !reflect.DeepEqual(remote, snapshot(t, srv.home)) {
		t.Fatal("diagnostics modified files or permissions")
	}
	data, err := os.ReadFile(installed.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "Port "+in.Port, "Port 1", 1))
	if err := os.WriteFile(installed.ConfigPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(context.Background(), in, nil); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("missed wrong port: %v", err)
	}
}

func TestCheckMissingSetupCreatesNothing(t *testing.T) {
	home := t.TempDir()
	_, err := (Service{Home: home}).Run(context.Background(), Input{Host: "127.0.0.1", User: "tester", Check: true}, nil)
	if err == nil {
		t.Fatal("missing key accepted")
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatal("check created files")
	}
}
