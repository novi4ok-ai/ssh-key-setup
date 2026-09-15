package setup

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestPreviewIsLocalAndReadOnly(t *testing.T) {
	s := Service{Home: t.TempDir()}
	before := snapshot(t, s.Home)
	in := Input{Host: "unreachable.invalid", User: "tester", Alias: "work", DryRun: true}
	result, err := s.Run(context.Background(), in, nil)
	if err != nil || !strings.Contains(result.Preview, "Host work") || result.Command != "" {
		t.Fatalf("preview: %v", err)
	}
	if !reflect.DeepEqual(before, snapshot(t, s.Home)) {
		t.Fatal("preview created files")
	}
	srv := startTestServer(t)
	installed, err := s.Run(context.Background(), srv.input(), nil)
	if err != nil {
		t.Fatal(err)
	}
	before = snapshot(t, s.Home)
	remote := snapshot(t, srv.home)
	passwordCalls, publicCalls := srv.passwordCalls.Load(), srv.publicCalls.Load()
	in = srv.input()
	in.DryRun, in.Password = true, ""
	result, err = s.Run(context.Background(), in, nil)
	if err != nil || !strings.Contains(result.Preview, installed.KeyPath) || !strings.Contains(result.Preview, "уже соответствует") {
		t.Fatalf("existing preview: %v", err)
	}
	if !reflect.DeepEqual(before, snapshot(t, s.Home)) || !reflect.DeepEqual(remote, snapshot(t, srv.home)) || passwordCalls != srv.passwordCalls.Load() || publicCalls != srv.publicCalls.Load() {
		t.Fatal("preview changed files or authenticated")
	}
}
