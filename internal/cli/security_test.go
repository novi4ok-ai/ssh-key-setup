package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssh-key-setup/internal/setup"
)

func TestSecurityFlagsAndSecretFile(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "phrase")
	if err := os.WriteFile(filename, []byte("fixture phrase\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a, out, log := testApp(t, "")
	a.Run = func(_ context.Context, in setup.Input, _ func(setup.Event)) (setup.Result, error) {
		if !in.EncryptKey || !in.UseAgent || string(in.Passphrase) != "fixture phrase" {
			t.Fatal("security options lost")
		}
		return setup.Result{Command: "ssh work"}, nil
	}
	if code := a.Execute(context.Background(), []string{"-host", "example.com", "-u", "tester", "-protect-key", "-agent", "-passphrase-file", filename}); code != 0 {
		t.Fatalf("security flags: %d", code)
	}
	if strings.Contains(out.String()+log.String(), "fixture phrase") {
		t.Fatal("passphrase leaked")
	}
	for _, flags := range [][]string{{"-confirm-host-key"}, {"-check", "-protect-key"}, {"-gui", "-agent"}} {
		a, _, _ := testApp(t, "")
		if code := a.Execute(context.Background(), flags); code != 2 {
			t.Fatalf("invalid security mode: %d", code)
		}
	}
}
