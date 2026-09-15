package setup

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestConnectionCommandPreservesDollarInUser(t *testing.T) {
	s := startTestServer(t)
	in := s.input()
	in.User = "tester$"
	result, err := (Service{Home: t.TempDir()}).Run(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Parse the displayed command as a shell would, without connecting.
	script := "set -- " + strings.TrimPrefix(result.Command, "ssh ") + "; printf '%s\\n' \"$#\" \"$1\""
	output, err := exec.Command("sh", "-c", script).Output()
	if err != nil || string(output) != "1\ntester$@127.0.0.1\n" {
		t.Fatalf("shell changed the destination: %q, %v", output, err)
	}
}

func TestClientConfigOpenSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH client is required")
	}
	dir := t.TempDir()
	original := "Host *\n    Port 2200\n    ServerAliveInterval 30\n"
	filename := filepath.Join(dir, "config")
	if err := os.WriteFile(filename, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{Host: "192.0.2.1", User: "alice", Port: 2222},
		{Host: "192.0.2.1", User: "bob", Port: 2223},
	} {
		keyPath := filepath.Join(dir, "name with spaces\\and\"quotes\"", c.User)
		if _, err := configureClient(dir, c, keyPath); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		user string
		port int
	}{
		{"alice", 2222}, {"bob", 2223}, {"carol", 2200},
	} {
		t.Run(tc.user, func(t *testing.T) {
			output, err := exec.Command("ssh", "-G", "-F", filename, tc.user+"@192.0.2.1").Output()
			if err != nil {
				t.Fatal(err)
			}
			text := "\n" + string(output)
			for _, line := range []string{"port " + strconv.Itoa(tc.port), "serveraliveinterval 30"} {
				if !strings.Contains(text, "\n"+line+"\n") {
					t.Errorf("missing effective setting %q", line)
				}
			}
			if tc.user != "carol" {
				keyPath := filepath.Join(dir, "name with spaces\\and\"quotes\"", tc.user)
				if !strings.Contains(text, "\nidentityfile "+keyPath+"\n") {
					t.Error("OpenSSH did not preserve the literal identity path")
				}
			}
		})
	}
}
