package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ssh-key-setup/internal/setup"
)

func testApp(t *testing.T, input string) (App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(filename, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	out, log := new(bytes.Buffer), new(bytes.Buffer)
	return App{In: f, Out: out, Err: log}, out, log
}

func TestParametersAndPasswordStdin(t *testing.T) {
	for _, tc := range []struct {
		name, stdin  string
		passwordArgs []string
	}{
		{"argument", "", []string{"-p", " exact password "}},
		{"stdin LF", " exact password \nignored\n", []string{"-password-stdin"}},
		{"stdin CRLF", " exact password \r\n", []string{"-password-stdin"}},
		{"stdin EOF", " exact password ", []string{"-password-stdin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, out, log := testApp(t, tc.stdin)
			a.Graphical = true
			a.LaunchGUI = func() error { t.Fatal("flags launched GUI"); return nil }
			called := false
			a.Run = func(ctx context.Context, in setup.Input, report func(setup.Event)) (setup.Result, error) {
				called = true
				c, err := setup.Normalize(in)
				if err != nil || c.Host != "::1" || c.User != "root" || c.Port != 2222 || c.Password != " exact password " {
					t.Fatal("arguments or password were corrupted")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 2*time.Second {
					t.Fatal("timeout not applied")
				}
				report(setup.Event{Step: 4, Done: true, Message: "verified"})
				return setup.Result{Command: "ssh verified", KeyPath: "/tmp/key", BackupPath: "/remote/backup", AlreadyInstalled: true}, nil
			}
			args := append([]string{"-ip", " ::1 ", "-u", " root ", "-port", "2222", "-timeout", "2s"}, tc.passwordArgs...)
			if code := a.Execute(context.Background(), args); code != 0 || !called {
				t.Fatalf("exit %d: %s", code, log)
			}
			if out.String() != "ssh verified\n" || strings.Contains(log.String(), "exact password") || !strings.Contains(log.String(), "/remote/backup") {
				t.Fatal("incorrect command, missing recovery information, or leaked password")
			}
		})
	}
}

func TestInvalidInputNeverConnects(t *testing.T) {
	for _, args := range [][]string{
		{"-unknown"}, {"positional"}, {"-ip", "example.com", "-u", "root", "-p", "secret"},
		{"-ip", "127.0.0.1", "-u", "root"},
		{"-ip", "127.0.0.1", "-u", "root", "-p", ""},
		{"-ip", "127.0.0.1", "-u", "root", "-p", "secret", "-port", "65536"},
		{"-p", "secret", "-password-stdin"}, {"-timeout", "0s"}, {"-timeout", "bad"},
		{"-gui", "-cli"}, {"-gui", "-ip", "127.0.0.1"}, {"-gui"},
		{"-ip", "127.0.0.1", "-u", "root", "-password-stdin"},
	} {
		a, out, log := testApp(t, "")
		a.Run = func(context.Context, setup.Input, func(setup.Event)) (setup.Result, error) {
			t.Fatal("invalid input started network operation")
			return setup.Result{}, nil
		}
		if code := a.Execute(context.Background(), args); code != 2 || out.Len() != 0 {
			t.Fatalf("args %v: exit %d, stdout %q, stderr %s", args, code, out.String(), log)
		}
		if strings.Contains(log.String(), "secret") {
			t.Fatal("password leaked")
		}
	}
}

func TestModeSelection(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		args                        []string
		graphical, failGUI, wantGUI bool
		code                        int
		wantHelp                    bool
	}{
		{"desktop help", nil, true, false, false, 0, true},
		{"headless help", nil, false, false, false, 0, true},
		{"forced failure", []string{"-gui"}, true, true, true, 1, false},
		{"forced console", []string{"-cli"}, true, false, false, 2, false},
		{"long help", []string{"--help"}, true, false, false, 0, true},
		{"short help", []string{"-h"}, true, false, false, 0, true},
		{"version", []string{"--version"}, true, false, false, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, out, log := testApp(t, "")
			a.Graphical = tc.graphical
			launched := false
			a.LaunchGUI = func() error {
				launched = true
				if tc.failGUI {
					return errors.New("unavailable")
				}
				return nil
			}
			if code := a.Execute(context.Background(), tc.args); code != tc.code || launched != tc.wantGUI {
				t.Fatalf("exit %d, launched %v: %s", code, launched, log)
			}
			if gotHelp := strings.Contains(out.String(), "ИСПОЛЬЗОВАНИЕ"); gotHelp != tc.wantHelp {
				t.Fatalf("help=%v, stdout=%q", gotHelp, out.String())
			}
			if tc.wantHelp {
				for _, expected := range []string{"-ip <адрес>", "-password-stdin", "ПРИМЕРЫ", "БЕЗОПАСНОСТЬ", "КОДЫ ЗАВЕРШЕНИЯ"} {
					if !strings.Contains(out.String(), expected) {
						t.Fatalf("help lacks %q", expected)
					}
				}
				if log.Len() != 0 {
					t.Fatalf("successful help wrote stderr: %s", log)
				}
			}
		})
	}
}

func TestFailureAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{
		{errors.New("verification failed"), 1}, {context.Canceled, 130}, {context.DeadlineExceeded, 1},
	} {
		a, out, log := testApp(t, "")
		a.Run = func(ctx context.Context, in setup.Input, report func(setup.Event)) (setup.Result, error) {
			if in.Port != "22" {
				t.Fatal("wrong default port")
			}
			return setup.Result{KeyPath: "/tmp/preserved-key", BackupPath: "/remote/backup"}, tc.err
		}
		code := a.Execute(context.Background(), []string{"-ip", "127.0.0.1", "-u", "root", "-p", "secret"})
		if code != tc.code || out.Len() != 0 || strings.Contains(log.String(), "Готово!") || !strings.Contains(log.String(), "/tmp/preserved-key") {
			t.Fatalf("exit %d: %s", code, log)
		}
	}
}

func TestCancelWaitingForStdin(t *testing.T) {
	a, _, _ := testApp(t, "")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	a.In = r
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if code := a.Execute(ctx, []string{"-ip", "127.0.0.1", "-u", "root", "-password-stdin"}); code != 130 {
		t.Fatalf("exit %d", code)
	}
	if time.Since(start) > time.Second {
		t.Fatal("input cancellation stalled")
	}
}

func TestRejectOversizedPasswordStdin(t *testing.T) {
	a, _, _ := testApp(t, strings.Repeat("x", 4097)+"\n")
	if code := a.Execute(context.Background(), []string{"-ip", "127.0.0.1", "-u", "root", "-password-stdin"}); code != 2 {
		t.Fatalf("exit %d", code)
	}
}
