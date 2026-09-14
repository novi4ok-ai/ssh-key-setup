package setup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sys/unix"
)

type Event struct {
	Step    int
	Done    bool
	Message string
}

type Result struct {
	KeyPath, PublicKeyPath, ConfigPath, Fingerprint, Command, BackupPath string
	AlreadyInstalled                                                     bool
}

type Service struct {
	Home string
	// Defaults to 25 seconds per connection (including handshake and SFTP).
	ConnectionTimeout time.Duration
}

func (s Service) Run(ctx context.Context, in Input, report func(Event)) (result Result, retErr error) {
	if report == nil {
		report = func(Event) {}
	}
	emit := func(step int, done bool, message string) { report(Event{Step: step, Done: done, Message: message}) }
	defer func() {
		if retErr != nil && ctx.Err() != nil {
			retErr = errors.Join(ctx.Err(), retErr)
		} else if deadline, ok := ctx.Deadline(); retErr != nil && ok && !time.Now().Before(deadline) {
			// A socket deadline can fire just before the context timer does.
			retErr = errors.Join(context.DeadlineExceeded, retErr)
		}
	}()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	emit(0, false, "Проверяем параметры и локальные файлы…")
	c, err := Normalize(in)
	if err != nil {
		return result, err
	}
	home := s.Home
	if home == "" {
		home, err = os.UserHomeDir()
		if err != nil {
			return result, err
		}
	}
	dir, unlock, err := prepareLocal(home)
	if err != nil {
		return result, fmt.Errorf("локальный каталог SSH: %w", err)
	}
	defer unlock()
	knownPath := filepath.Join(dir, "known_hosts")
	f, err := openPrivate(knownPath, unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return result, fmt.Errorf("known_hosts: %w", err)
	}
	f.Close()
	if _, err = knownhosts.New(knownPath); err != nil {
		return result, fmt.Errorf("не удалось прочитать known_hosts: %w", err)
	}
	emit(0, true, "Параметры проверены")
	var trustedKey ssh.PublicKey
	trust := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		trustedKey = key
		check, err := knownhosts.New(knownPath)
		if err != nil {
			return err
		}
		result.Fingerprint = ssh.FingerprintSHA256(key)
		err = check(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return fmt.Errorf("ключ сервера отклонён: %w", err)
		}
		if len(keyErr.Want) > 0 {
			return fmt.Errorf("ключ сервера изменился! Сохранён: %s; получен: %s. Пароль не отправлен. Проверьте сервер и запись в %s", ssh.FingerprintSHA256(keyErr.Want[0].Key), result.Fingerprint, knownPath)
		}
		// Trust on first use, as explicitly requested. Hash the address on disk.
		out, err := openPrivate(knownPath, unix.O_RDWR|unix.O_APPEND)
		if err != nil {
			return err
		}
		defer out.Close()
		info, err := out.Stat()
		if err != nil {
			return err
		}
		prefix := ""
		if info.Size() > 0 {
			var last [1]byte
			if _, err = out.ReadAt(last[:], info.Size()-1); err != nil {
				return err
			}
			if last[0] != '\n' {
				prefix = "\n"
			}
		}
		line := knownhosts.Line([]string{knownhosts.HashHostname(knownhosts.Normalize(hostname))}, key)
		if _, err = out.WriteString(prefix + line + "\n"); err != nil {
			return err
		}
		if err = out.Sync(); err != nil {
			return err
		}
		emit(1, false, "Новый ключ сервера принят и сохранён автоматически")
		return nil
	}
	emit(1, false, "Подключаемся к серверу…")
	client, closeClient, err := s.connect(ctx, c, []ssh.AuthMethod{ssh.Password(c.Password)}, trust)
	if err != nil {
		return result, connectionError(err)
	}
	defer closeClient()
	emit(1, true, "Сервер проверен, вход по паролю выполнен")
	if err = ctx.Err(); err != nil {
		return result, err
	}
	emit(2, false, "Подготавливаем ключ Ed25519…")
	signer, keyPath, err := keyFor(dir, c)
	result.KeyPath = keyPath
	if err != nil {
		return result, err
	}
	result.PublicKeyPath = keyPath + ".pub"
	emit(2, true, "Ключ готов и сохранён на этом компьютере")
	if err = ctx.Err(); err != nil {
		return result, err
	}
	emit(3, false, "Устанавливаем открытый ключ через SFTP…")
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return result, fmt.Errorf("не удалось открыть SFTP; проверьте, что он разрешён на сервере: %w", err)
	}
	result.AlreadyInstalled, result.BackupPath, err = installKey(sftpClient, signer.PublicKey())
	_ = sftpClient.Close()
	if err != nil {
		return result, fmt.Errorf("установка открытого ключа: %w", err)
	}
	emit(3, true, "Открытый ключ установлен; прежние записи сохранены")
	closeClient()
	emit(4, false, "Проверяем новое подключение только по ключу…")
	_, closeVerified, err := s.connect(ctx, c, []ssh.AuthMethod{ssh.PublicKeys(signer)}, ssh.FixedHostKey(trustedKey))
	if err != nil {
		return result, fmt.Errorf("ключ установлен, но вход по нему не подтверждён: %w. Проверьте PubkeyAuthentication, AuthorizedKeysFile и правила доступа на сервере. Локальный ключ сохранён: %s", err, keyPath)
	}
	closeVerified()
	result.ConfigPath, err = configureClient(dir, c, keyPath)
	if err != nil {
		return result, fmt.Errorf("ключ установлен и проверен, но не удалось настроить обычную команду ssh: %w. Подключиться можно так: %s", err, explicitConnectCommand(c, keyPath))
	}
	result.Command = "ssh " + c.User + "@" + c.Host
	emit(4, true, "Готово! Вход по ключу и обычная команда ssh настроены")
	return result, nil
}

func (s Service) connect(ctx context.Context, c Config, auth []ssh.AuthMethod, hostKey ssh.HostKeyCallback) (*ssh.Client, func(), error) {
	timeout := s.ConnectionTimeout
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", c.Address())
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	cleanup := func() { stop(); _ = conn.Close() }
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err = conn.SetDeadline(deadline); err != nil {
		cleanup()
		return nil, nil, err
	}
	sshConn, channels, requests, err := ssh.NewClientConn(conn, c.Address(), &ssh.ClientConfig{
		User: c.User, Auth: auth, HostKeyCallback: hostKey, ClientVersion: "SSH-2.0-ssh-key-setup",
	})
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	client := ssh.NewClient(sshConn, channels, requests)
	return client, func() { _ = client.Close(); cleanup() }, nil
}

func connectionError(err error) error {
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return fmt.Errorf("сервер не ответил вовремя; проверьте IP, порт, сеть и firewall")
	}
	if strings.Contains(err.Error(), "unable to authenticate") {
		return fmt.Errorf("сервер отклонил вход: проверьте логин и пароль; вход по паролю должен быть разрешён (MFA в этой версии не поддерживается)")
	}
	return fmt.Errorf("SSH-подключение: %w", err)
}

func explicitConnectCommand(c Config, keyPath string) string {
	return fmt.Sprintf("ssh -o IdentitiesOnly=yes -i %s -p %d %s", shellQuote(keyPath), c.Port, shellQuote(c.User+"@"+c.Host))
}
