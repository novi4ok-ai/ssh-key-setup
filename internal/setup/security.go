package setup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/unix"
)

type keyAccess struct {
	ctx        context.Context
	in         Input
	passphrase []byte
	agent      agent.ExtendedAgent
	closeAgent func()
}

func newKeyAccess(ctx context.Context, in Input) (*keyAccess, error) {
	a := &keyAccess{ctx: ctx, in: in, passphrase: bytes.Clone(in.Passphrase)}
	if in.UseAgent {
		socket := os.Getenv("SSH_AUTH_SOCK")
		if socket == "" {
			a.close()
			return nil, fmt.Errorf("ssh-agent недоступен: SSH_AUTH_SOCK не задан")
		}
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
		if err != nil {
			a.close()
			return nil, fmt.Errorf("ssh-agent: %w", err)
		}
		deadline := time.Now().Add(90 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			a.close()
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		a.closeAgent = func() { stop(); conn.Close() }
		a.agent = agent.NewClient(conn)
	}
	return a, nil
}

func (a *keyAccess) close() {
	clear(a.passphrase)
	if a.closeAgent != nil {
		a.closeAgent()
	}
}

func (a *keyAccess) phrase(newKey bool) ([]byte, error) {
	if len(a.passphrase) == 0 && a.in.RequestPassphrase != nil {
		var err error
		a.passphrase, err = a.in.RequestPassphrase(a.ctx, newKey)
		if err != nil {
			return nil, err
		}
	}
	if err := ValidatePassword(string(a.passphrase)); err != nil {
		return nil, fmt.Errorf("нужна непустая парольная фраза ключа (до 4096 байт); используйте скрытый ввод, -passphrase-file или -agent")
	}
	return a.passphrase, nil
}

func (a *keyAccess) parse(data []byte) (ssh.Signer, error) {
	key, err := ssh.ParseRawPrivateKey(data)
	var encrypted *ssh.PassphraseMissingError
	if errors.As(err, &encrypted) {
		if a.agent != nil && encrypted.PublicKey != nil {
			signers, err := a.agent.Signers()
			if err != nil {
				return nil, fmt.Errorf("ssh-agent: %w", err)
			}
			for _, signer := range signers {
				if signer.PublicKey().Type() == ssh.KeyAlgoED25519 && bytes.Equal(signer.PublicKey().Marshal(), encrypted.PublicKey.Marshal()) {
					return signer, nil
				}
			}
		}
		phrase, e := a.phrase(false)
		if e != nil {
			return nil, e
		}
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(data, phrase)
	} else if err == nil && a.in.EncryptKey {
		return nil, fmt.Errorf("существующий ключ не зашифрован; -protect-key защищает только новый ключ, существующие ключи не перезаписываются")
	}
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть ключ: проверьте формат и парольную фразу")
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("существующий ключ не Ed25519")
	}
	if err := a.add(key); err != nil {
		return nil, err
	}
	return signer, nil
}

func (a *keyAccess) marshal(key ed25519.PrivateKey) (*pem.Block, error) {
	if a.in.EncryptKey {
		phrase, err := a.phrase(true)
		if err != nil {
			return nil, err
		}
		return ssh.MarshalPrivateKeyWithPassphrase(key, "ssh-key-setup", phrase)
	}
	return ssh.MarshalPrivateKey(key, "ssh-key-setup")
}

func (a *keyAccess) add(key any) error {
	if a.agent == nil || a.in.Check {
		return nil
	}
	if pointer, ok := key.(*ed25519.PrivateKey); ok {
		key = *pointer
	}
	if err := a.agent.Add(agent.AddedKey{PrivateKey: key, Comment: "ssh-key-setup", LifetimeSecs: 3600}); err != nil {
		return fmt.Errorf("не удалось добавить ключ в ssh-agent: %w", err)
	}
	return nil
}

// ReadPassphraseFile accepts a private, owned regular file and one LF/CRLF line.
func ReadPassphraseFile(filename string) ([]byte, error) {
	f, err := openLocal(filename, unix.O_RDONLY, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("файл парольной фразы должен иметь права 600 или 400")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4099))
	if err != nil {
		clear(data)
		return nil, err
	}
	phrase := bytes.TrimSuffix(data, []byte{'\n'})
	if len(phrase) != len(data) {
		phrase = bytes.TrimSuffix(phrase, []byte{'\r'})
	}
	if err := ValidatePassword(string(phrase)); err != nil {
		clear(data)
		return nil, fmt.Errorf("неверный формат файла парольной фразы")
	}
	return phrase, nil
}
