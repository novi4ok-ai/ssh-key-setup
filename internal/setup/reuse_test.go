package setup

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestReuseKeyRepairsConfigWithoutPassword(t *testing.T) {
	srv := startTestServer(t)
	s := Service{Home: t.TempDir()}
	in := srv.input()
	first, err := s.Run(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, srv.home)
	passwordCalls := srv.passwordCalls.Load()
	if err := os.Remove(first.ConfigPath); err != nil {
		t.Fatal(err)
	}
	in.Password = ""
	in.RequestPassword = func(context.Context) (string, error) { t.Fatal("working key prompted for password"); return "", nil }
	again, err := s.Run(context.Background(), in, nil)
	if err != nil || !again.AlreadyInstalled || again.Command != first.Command {
		t.Fatalf("reuse: %v", err)
	}
	if passwordCalls != srv.passwordCalls.Load() || !reflect.DeepEqual(before, snapshot(t, srv.home)) {
		t.Fatal("reuse changed remote state or used password")
	}
	in.Check = true
	if _, err := s.Run(context.Background(), in, nil); err != nil {
		t.Fatal(err)
	}
	in.Check = false
	srv.mu.Lock()
	srv.key = newSigner(t)
	srv.mu.Unlock()
	if _, err := s.Run(context.Background(), in, nil); err == nil {
		t.Fatal("changed host key accepted")
	}
}

func TestPasswordFallbackOnlyWhenNeeded(t *testing.T) {
	srv := startTestServer(t)
	s := Service{Home: t.TempDir()}
	in := srv.input()
	password := in.Password
	in.Password = ""
	if _, err := s.Run(context.Background(), in, nil); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("missing password: %v", err)
	}
	calls := 0
	in.RequestPassword = func(context.Context) (string, error) { calls++; return password, nil }
	if _, err := s.Run(context.Background(), in, nil); err != nil || calls != 1 {
		t.Fatalf("fallback: %v", err)
	}
}
