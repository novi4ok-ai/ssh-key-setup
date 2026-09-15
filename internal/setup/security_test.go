package setup

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestHostTrustBeforePassword(t *testing.T) {
	srv := startTestServer(t)
	for _, reject := range []string{"pin", "confirmation"} {
		t.Run(reject, func(t *testing.T) {
			s := Service{Home: t.TempDir()}
			in := srv.input()
			calls := srv.passwordCalls.Load()
			if reject == "pin" {
				in.ExpectedFingerprint = ssh.FingerprintSHA256(newSigner(t).PublicKey())
			}
			confirmed := false
			if reject == "confirmation" {
				in.ConfirmHostKey = func(_ context.Context, host, fingerprint string) error {
					confirmed = true
					if fingerprint != ssh.FingerprintSHA256(srv.key.PublicKey()) {
						t.Error("wrong fingerprint displayed")
					}
					return errors.New("rejected")
				}
			}
			if _, err := s.Run(context.Background(), in, nil); err == nil {
				t.Fatal("untrusted server accepted")
			}
			if calls != srv.passwordCalls.Load() {
				t.Fatal("password sent before host approval")
			}
			data, err := os.ReadFile(filepath.Join(s.Home, ".ssh", "known_hosts"))
			if err != nil || len(data) != 0 {
				t.Fatal("rejected key was saved")
			}
			if reject == "confirmation" && !confirmed {
				t.Fatal("no confirmation requested")
			}
		})
	}
	in := srv.input()
	in.ExpectedFingerprint = ssh.FingerprintSHA256(srv.key.PublicKey())
	if _, err := (Service{Home: t.TempDir()}).Run(context.Background(), in, nil); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptedKeyAndPassphraseReuse(t *testing.T) {
	srv := startTestServer(t)
	s := Service{Home: t.TempDir()}
	in := srv.input()
	in.EncryptKey, in.Passphrase = true, []byte("fixture-key-passphrase")
	first, err := s.Run(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(first.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	var missing *ssh.PassphraseMissingError
	if _, err := ssh.ParsePrivateKey(data); !errors.As(err, &missing) {
		t.Fatal("private key was not encrypted")
	}
	if _, err := ssh.ParsePrivateKeyWithPassphrase(data, []byte("wrong")); err == nil {
		t.Fatal("wrong phrase accepted")
	}
	// This passphrase belongs only to a disposable test key.
	if out, err := exec.Command("ssh-keygen", "-y", "-P", "fixture-key-passphrase", "-f", first.KeyPath).Output(); err != nil || !bytes.HasPrefix(out, []byte("ssh-ed25519 ")) {
		t.Fatalf("OpenSSH cannot decrypt generated key: %v", err)
	}
	in.Password, in.Passphrase = "", nil
	requests := 0
	in.RequestPassphrase = func(_ context.Context, newKey bool) ([]byte, error) {
		requests++
		if newKey {
			t.Error("existing key requested a new passphrase")
		}
		return []byte("fixture-key-passphrase"), nil
	}
	if _, err := s.Run(context.Background(), in, nil); err != nil || requests != 1 {
		t.Fatalf("encrypted reuse: %v; requests %d", err, requests)
	}
	in.Check, in.EncryptKey = true, false
	if _, err := s.Run(context.Background(), in, nil); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(first.KeyPath)
	if !bytes.Equal(data, after) {
		t.Fatal("existing encrypted key overwritten")
	}
}

func TestAgentAvoidsRepeatedPassphrase(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); defer conn.Close(); _ = agent.ServeAgent(keyring, conn) }()
		}
	}()
	t.Cleanup(func() { l.Close(); wg.Wait() })
	t.Setenv("SSH_AUTH_SOCK", socket)
	srv := startTestServer(t)
	s := Service{Home: t.TempDir()}
	in := srv.input()
	in.UseAgent, in.EncryptKey, in.Passphrase = true, true, []byte("agent-fixture")
	if _, err := s.Run(context.Background(), in, nil); err != nil {
		t.Fatal(err)
	}
	keys, err := keyring.List()
	if err != nil || len(keys) != 1 {
		t.Fatal("generated key was not added to agent")
	}
	in.Password, in.Passphrase = "", nil
	in.RequestPassphrase = func(context.Context, bool) ([]byte, error) { t.Fatal("agent key prompted for phrase"); return nil, nil }
	if _, err := s.Run(context.Background(), in, nil); err != nil {
		t.Fatal(err)
	}
	in.Check, in.EncryptKey = true, false
	if _, err := s.Run(context.Background(), in, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPassphraseFileProtection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phrase")
	if err := os.WriteFile(path, []byte(" secret \r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	phrase, err := ReadPassphraseFile(path)
	if err != nil || string(phrase) != " secret " {
		t.Fatalf("phrase file: %v", err)
	}
	clear(phrase)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPassphraseFile(path); err == nil {
		t.Fatal("world-readable phrase accepted")
	}
}
