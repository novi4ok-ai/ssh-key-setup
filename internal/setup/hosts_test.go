package setup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDNSAndAliasValidation(t *testing.T) {
	for _, host := range []string{"localhost", "Server.Example.COM.", "xn--e1afmkfd.xn--p1ai"} {
		c, err := Normalize(Input{Host: host, User: "tester", Alias: "Work", Check: true})
		if err != nil || c.Host != strings.ToLower(strings.TrimSuffix(host, ".")) || c.Alias != "work" {
			t.Fatalf("normalization of %q: %+v, %v", host, c, err)
		}
	}
	for _, host := range []string{"-host", "host-", "bad_host", "host/name", "host\nother", strings.Repeat("a", 64) + ".com"} {
		if ValidateHost(host) == nil {
			t.Fatalf("accepted %q", host)
		}
	}
	for _, alias := range []string{"*", "-oProxyCommand=x", "two names", "work\nHost *", "127.0.0.1"} {
		if ValidateAlias(alias) == nil {
			t.Fatalf("accepted alias %q", alias)
		}
	}
}

func TestNamedConnectionsUseIndependentPorts(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []Config{
		{Host: "server.example.com", User: "tester", Port: 22, Alias: "work"},
		{Host: "server.example.com", User: "tester", Port: 2222, Alias: "backup"},
	} {
		path := keyFilename(dir, c)
		config, err := configureClient(dir, c, path)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkClientConfig(context.Background(), config, c, path); err != nil {
			t.Fatal(err)
		}
	}
	c := Config{Host: "server.example.com", User: "tester", Port: 22, Alias: "work"}
	if err := checkClientConfig(context.Background(), filepath.Join(dir, "config"), c, keyFilename(dir, c)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "config"))
	if _, err := configureClient(dir, c, keyFilename(dir, c)); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "config"))
	if strings.Count(string(before), "# >>>") != 2 || strings.Count(string(after), "# >>>") != 2 {
		t.Fatal("duplicate alias block")
	}
}

func TestDNSSetupAndCheck(t *testing.T) {
	srv := startTestServer(t)
	in := srv.input()
	in.Host, in.Alias = "localhost", "localtest"
	s := Service{Home: t.TempDir()}
	result, err := s.Run(context.Background(), in, nil)
	if err != nil || result.Command != "ssh localtest" {
		t.Fatalf("DNS setup: %v", err)
	}
	in.Check, in.Password = true, ""
	if _, err := s.Run(context.Background(), in, nil); err != nil {
		t.Fatal(err)
	}
}
