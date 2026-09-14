package setup

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Opt-in: scripts/test-openssh.py provides an isolated real OpenSSH server.
func TestOpenSSH(t *testing.T) {
	port := os.Getenv("SSH_SETUP_TEST_PORT")
	if port == "" {
		t.Skip("run python3 scripts/test-openssh.py to test real OpenSSH")
	}
	password, err := os.ReadFile(os.Getenv("SSH_SETUP_TEST_PASSWORD_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	in := Input{Host: "127.0.0.1", Port: port, User: os.Getenv("SSH_SETUP_TEST_USER"), Password: string(password)}
	home := t.TempDir()
	s := Service{Home: home}
	first, err := s.Run(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.BackupPath == "" {
		t.Fatal("expected backup of seeded authorized_keys")
	}
	again, err := s.Run(context.Background(), in, nil)
	if err != nil || !again.AlreadyInstalled {
		t.Fatalf("repeat: %v", err)
	}
	// Also verify that the generated format works with the system OpenSSH client.
	cmd := exec.Command("ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile="+filepath.Join(home, ".ssh", "known_hosts"), "-i", first.KeyPath, "-p", port, in.User+"@127.0.0.1", "true")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("OpenSSH client rejected generated key: %v: %s", err, output)
	}
	if binary := os.Getenv("SSH_SETUP_TEST_CLI"); binary != "" {
		for _, stdin := range []bool{false, true} {
			args := []string{"-ip", in.Host, "-u", in.User, "-port", port}
			if stdin {
				args = append(args, "-password-stdin")
			} else {
				args = append(args, "-p", in.Password)
			}
			cli := exec.Command(binary, args...)
			cli.Env = append(os.Environ(), "HOME="+home, "DISPLAY=:invalid")
			cli.Stdin = strings.NewReader(in.Password + "\n")
			output, err := cli.Output()
			if err != nil || strings.TrimSpace(string(output)) != first.Command {
				t.Fatalf("CLI (stdin=%v) failed: %v", stdin, err)
			}
		}
		cli := exec.Command(binary, "-ip", in.Host, "-u", in.User, "-port", port, "-p", "wrong password")
		cli.Env = append(os.Environ(), "HOME="+home)
		output, err := cli.Output()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || len(output) != 0 {
			t.Fatalf("CLI wrong password: expected exit 1 and no command, got %v", err)
		}
	}
	in.Password = "wrong password"
	if _, err = s.Run(context.Background(), in, nil); err == nil {
		t.Fatal("wrong password accepted")
	}
}
