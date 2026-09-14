package setup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestNormalize(t *testing.T) {
	in := Input{Host: " \t::ffff:192.0.2.1\n", Port: " 2222 ", User: " ubuntu ", Password: " password with spaces "}
	c, err := Normalize(in)
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "192.0.2.1" || c.Port != 2222 || c.User != "ubuntu" || c.Password != in.Password {
		t.Fatalf("normalization corrupted fields")
	}
	for _, host := range []string{"", "192. 0.2.1", "192.0.2.999", "example.com", "0.0.0.0", "::", "ff02::1", "255.255.255.255", "127.0.0.1;id", "fe80::1%eth0"} {
		if ValidateHost(host) == nil {
			t.Errorf("accepted bad host %q", host)
		}
	}
	for _, port := range []string{"0", "65536", "-22", "+22", "2 2", "22\n80", "abc"} {
		if ValidatePort(port) == nil {
			t.Errorf("accepted bad port %q", port)
		}
	}
	for _, user := range []string{"", "a b", "-oProxyCommand=id", "root;id", "root\nHost *", "$(id)"} {
		if ValidateUser(user) == nil {
			t.Errorf("accepted bad user %q", user)
		}
	}
	if ValidatePassword("  ") != nil {
		t.Fatal("spaces in a password must remain valid")
	}
	if ValidatePassword("a\nb") == nil || ValidatePassword("") == nil {
		t.Fatal("accepted invalid password")
	}
	in.Host = "2001:db8::1"
	in.Port = ""
	c, err = Normalize(in)
	if err != nil || c.Address() != "[2001:db8::1]:22" {
		t.Fatalf("IPv6/default port: %v, %s", err, c.Address())
	}
}

func TestLocalProtection(t *testing.T) {
	home := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareLocal(home); err == nil {
		t.Fatal("accepted symlink .ssh")
	}
	home = t.TempDir()
	dir, unlock, err := prepareLocal(home)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, _, err = prepareLocal(home); err == nil {
		t.Fatal("second lock succeeded")
	}
	c := Config{Host: "127.0.0.1", User: "tester", Port: 22}
	signer, keyPath, err := keyFor(dir, c)
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := keyFor(dir, c)
	if err != nil || !bytes.Equal(signer.PublicKey().Marshal(), again.PublicKey().Marshal()) {
		t.Fatal("did not reuse key")
	}
	for _, file := range []string{keyPath, keyPath + ".pub"} {
		info, err := os.Stat(file)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("unsafe permissions on %s", file)
		}
	}
	original, _ := os.ReadFile(keyPath)
	if err = os.WriteFile(keyPath+".pub", []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = keyFor(dir, c); err == nil {
		t.Fatal("accepted mismatched public key")
	}
	after, _ := os.ReadFile(keyPath)
	if !bytes.Equal(original, after) {
		t.Fatal("overwrote private key")
	}
	link := filepath.Join(dir, "unsafe")
	if err = os.Symlink(keyPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err = readPrivate(link); err == nil {
		t.Fatal("followed symlink")
	}
	if err = os.Symlink(keyPath, filepath.Join(dir, "config")); err != nil {
		t.Fatal(err)
	}
	if _, err = configureClient(dir, c, keyPath); err == nil {
		t.Fatal("followed symlink config")
	}
}

func TestClientConfigFormattingAndDamage(t *testing.T) {
	quoted, err := sshConfigQuote("/home/name with \"quotes\"/key")
	if err != nil || quoted != "\"/home/name with \\\"quotes\\\"/key\"" {
		t.Fatalf("quoted path: %q, %v", quoted, err)
	}
	if _, err = sshConfigQuote("/home/name\nHost */key"); err == nil {
		t.Fatal("accepted newline in key path")
	}
	begin, end := "# >>> ssh-key-setup key", "# <<< ssh-key-setup key"
	original := []byte("Host old\n    Port 2200\n")
	if got, err := removeManagedBlock(original, begin, end); err != nil || !bytes.Equal(got, original) {
		t.Fatalf("changed unmanaged config: %q, %v", got, err)
	}
	damaged := []byte(begin + "\nHost example\n")
	if _, err := removeManagedBlock(damaged, begin, end); err == nil {
		t.Fatal("accepted damaged managed block")
	}
	duplicate := []byte(begin + "\n" + end + "\n" + begin + "\n" + end + "\n")
	if _, err := removeManagedBlock(duplicate, begin, end); err == nil {
		t.Fatal("accepted duplicate managed blocks")
	}
}

type testServer struct {
	home          string
	listener      net.Listener
	mu            sync.Mutex
	key           ssh.Signer
	connections   map[net.Conn]bool
	closing       bool
	wg            sync.WaitGroup
	passwordCalls atomic.Int32
	publicCalls   atomic.Int32
	denyPublic    atomic.Bool
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func startTestServer(t *testing.T) *testServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{home: t.TempDir(), listener: l, key: newSigner(t), connections: make(map[net.Conn]bool)}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			if s.closing {
				s.mu.Unlock()
				conn.Close()
				return
			}
			s.connections[conn] = true
			key := s.key
			s.wg.Add(1)
			s.mu.Unlock()
			go func() {
				defer s.wg.Done()
				defer func() { conn.Close(); s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
				s.serve(conn, key)
			}()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		s.mu.Lock()
		s.closing = true
		for c := range s.connections {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

func (s *testServer) serve(conn net.Conn, key ssh.Signer) {
	config := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			s.passwordCalls.Add(1)
			if meta.User() != "tester" || string(password) != " secret with spaces " {
				return nil, fmt.Errorf("authentication rejected")
			}
			return nil, nil
		},
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.publicCalls.Add(1)
			if s.denyPublic.Load() || meta.User() != "tester" {
				return nil, fmt.Errorf("public key rejected")
			}
			data, _ := os.ReadFile(filepath.Join(s.home, ".ssh", "authorized_keys"))
			for _, line := range bytes.Split(data, []byte{'\n'}) {
				candidate, _, _, _, err := ssh.ParseAuthorizedKey(line)
				if err == nil && bytes.Equal(candidate.Marshal(), key.Marshal()) {
					return nil, nil
				}
			}
			return nil, fmt.Errorf("public key rejected")
		},
	}
	config.AddHostKey(key)
	server, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer server.Close()
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		if channel.ChannelType() != "session" {
			channel.Reject(ssh.UnknownChannelType, "sessions only")
			continue
		}
		ch, requests, err := channel.Accept()
		if err != nil {
			return
		}
		for req := range requests {
			var subsystem struct{ Name string }
			if req.Type == "subsystem" && ssh.Unmarshal(req.Payload, &subsystem) == nil && subsystem.Name == "sftp" {
				req.Reply(true, nil)
				server, err := sftp.NewServer(ch, sftp.WithServerWorkingDirectory(s.home))
				if err == nil {
					_ = server.Serve()
					_ = server.Close()
				}
				break
			}
			req.Reply(false, nil)
		}
		ch.Close()
	}
}

func (s *testServer) input() Input {
	host, port, _ := net.SplitHostPort(s.listener.Addr().String())
	return Input{Host: host, Port: port, User: "tester", Password: " secret with spaces "}
}

func TestSSHSetupEndToEnd(t *testing.T) {
	s := startTestServer(t)
	home := t.TempDir()
	service := Service{Home: home}
	localDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(localDir, 0700); err != nil {
		t.Fatal(err)
	}
	originalConfig := []byte("# Existing SSH settings must remain byte-for-byte\nHost *\n    ServerAliveInterval 30\n")
	if err := os.WriteFile(filepath.Join(localDir, "config"), originalConfig, 0644); err != nil {
		t.Fatal(err)
	}
	remoteDir := filepath.Join(s.home, ".ssh")
	if err := os.Mkdir(remoteDir, 0700); err != nil {
		t.Fatal(err)
	}
	otherKey := newSigner(t)
	original := append([]byte("# Existing key; preserve comments and no final newline\n"), bytes.TrimSpace(ssh.MarshalAuthorizedKey(otherKey.PublicKey()))...)
	authorized := filepath.Join(remoteDir, "authorized_keys")
	if err := os.WriteFile(authorized, original, 0644); err != nil {
		t.Fatal(err)
	}
	result, err := service.Run(context.Background(), s.input(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Command != "ssh tester@127.0.0.1" || result.ConfigPath != filepath.Join(localDir, "config") || result.BackupPath == "" || s.publicCalls.Load() == 0 {
		t.Fatal("missing verification or backup")
	}
	clientConfig, err := os.ReadFile(result.ConfigPath)
	if err != nil || !bytes.HasSuffix(clientConfig, originalConfig) ||
		!bytes.Contains(clientConfig, []byte("IdentityFile \""+result.KeyPath+"\"")) ||
		!bytes.Contains(clientConfig, []byte("Match originalhost 127.0.0.1 user tester")) {
		t.Fatalf("client config is invalid or existing settings changed: %v\n%s", err, clientConfig)
	}
	configInfo, err := os.Stat(result.ConfigPath)
	if err != nil || configInfo.Mode().Perm() != 0600 {
		t.Fatalf("unsafe client config permissions: %v", err)
	}
	backup, err := os.ReadFile(result.BackupPath)
	if err != nil || !bytes.Equal(backup, original) {
		t.Fatal("backup does not preserve exact original")
	}
	installed, _ := os.ReadFile(authorized)
	if !bytes.HasPrefix(installed, original) {
		t.Fatal("existing records changed")
	}
	info, _ := os.Stat(authorized)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe authorized_keys mode")
	}
	knownPath := filepath.Join(home, ".ssh", "known_hosts")
	knownBefore, _ := os.ReadFile(knownPath)
	if !bytes.HasPrefix(knownBefore, []byte("|1|")) {
		t.Fatal("server key not saved with a hashed address")
	}
	again, err := service.Run(context.Background(), s.input(), nil)
	if err != nil || !again.AlreadyInstalled || again.KeyPath != result.KeyPath {
		t.Fatalf("repeat failed: %v", err)
	}
	after, _ := os.ReadFile(authorized)
	knownAfter, _ := os.ReadFile(knownPath)
	configAfter, _ := os.ReadFile(result.ConfigPath)
	if !bytes.Equal(installed, after) || !bytes.Equal(knownBefore, knownAfter) || !bytes.Equal(clientConfig, configAfter) ||
		bytes.Count(configAfter, []byte("# >>> ssh-key-setup ")) != 1 {
		t.Fatal("repeat added duplicates")
	}
	passwordCalls := s.passwordCalls.Load()
	s.mu.Lock()
	s.key = newSigner(t)
	s.mu.Unlock()
	_, err = service.Run(context.Background(), s.input(), nil)
	if err == nil || !strings.Contains(err.Error(), "ключ сервера изменился") {
		t.Fatalf("host key change accepted: %v", err)
	}
	if s.passwordCalls.Load() != passwordCalls {
		t.Fatal("sent password to changed server")
	}
}

func TestWrongPasswordAndVerificationFailure(t *testing.T) {
	s := startTestServer(t)
	home := t.TempDir()
	service := Service{Home: home}
	in := s.input()
	in.Password = "wrong"
	_, err := service.Run(context.Background(), in, nil)
	if err == nil || !strings.Contains(err.Error(), "отклонил вход") {
		t.Fatalf("wrong password: %v", err)
	}
	keys, _ := filepath.Glob(filepath.Join(home, ".ssh", "*ed25519"))
	if len(keys) != 0 {
		t.Fatal("generated key before authenticating")
	}
	s.denyPublic.Store(true)
	result, err := service.Run(context.Background(), s.input(), nil)
	if err == nil || result.Command != "" || !strings.Contains(err.Error(), "вход по нему не подтверждён") {
		t.Fatal("reported success without key authentication")
	}
	if _, err = os.Stat(result.KeyPath); err != nil {
		t.Fatal("private key lost after verification failure")
	}
}

func TestLocalAndRemoteSameHome(t *testing.T) {
	s := startTestServer(t)
	// Connecting to one's own local account must not confuse the local flock
	// file with the remote SFTP lock directory.
	result, err := (Service{Home: s.home}).Run(context.Background(), s.input(), nil)
	if err != nil || result.Command == "" {
		t.Fatalf("setup with a shared home failed: %v", err)
	}
}

func TestRemoteSymlinkAndRestrictions(t *testing.T) {
	s := startTestServer(t)
	service := Service{Home: t.TempDir()}
	if err := os.Symlink(t.TempDir(), filepath.Join(s.home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Run(context.Background(), s.input(), nil); err == nil {
		t.Fatal("accepted remote symlink .ssh")
	}
	if err := os.Remove(filepath.Join(s.home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	result, err := service.Run(context.Background(), s.input(), nil)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(result.PublicKeyPath)
	authorized := filepath.Join(s.home, ".ssh", "authorized_keys")
	restricted := append([]byte("restrict "), pub...)
	if err := os.WriteFile(authorized, restricted, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Run(context.Background(), s.input(), nil); err == nil || !strings.Contains(err.Error(), "ограничениями") {
		t.Fatalf("bypassed restrictions: %v", err)
	}
	after, _ := os.ReadFile(authorized)
	if !bytes.Equal(after, restricted) {
		t.Fatal("modified restricted key")
	}
}

func TestCancellationAndTimeout(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	host, port, _ := net.SplitHostPort(l.Addr().String())
	in := Input{Host: host, Port: port, User: "tester", Password: "secret"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := (Service{Home: t.TempDir()}).Run(ctx, in, nil); done <- err }()
	conn := <-accepted
	defer conn.Close()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("wrong cancellation error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not interrupt handshake")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = (Service{Home: t.TempDir()}).Run(ctx, in, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wrong timeout error: %v", err)
	}
}
