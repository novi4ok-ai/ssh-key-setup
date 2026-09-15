package setup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// inspectDir never creates files or repairs permissions.
func (s Service) inspectDir() (string, error) {
	home := s.Home
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", err
		}
	}
	if !filepath.IsAbs(home) {
		return "", fmt.Errorf("домашний каталог должен иметь абсолютный путь")
	}
	dir := filepath.Join(home, ".ssh")
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return dir, nil
	}
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || int(st.Uid) != os.Geteuid() || info.Mode().Perm() != 0700 {
		return "", fmt.Errorf("%s: нужен каталог текущего пользователя без ссылок с правами 700", dir)
	}
	return dir, nil
}

func (s Service) Check(ctx context.Context, in Input, report func(Event)) (result Result, err error) {
	if report == nil {
		report = func(Event) {}
	}
	defer func() {
		if err != nil && ctx.Err() != nil {
			err = errors.Join(ctx.Err(), err)
		}
	}()
	in.Check = true
	c, err := Normalize(in)
	if err != nil {
		return result, err
	}
	dir, err := s.inspectDir()
	if err != nil {
		return result, err
	}
	result.KeyPath = keyFilename(dir, c)
	data, err := readLocal(result.KeyPath, false)
	if err != nil {
		return result, fmt.Errorf("локальный ключ недоступен; сначала выполните настройку: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	clear(data)
	if err != nil {
		return result, fmt.Errorf("не удалось открыть ключ: %w", err)
	}
	report(Event{Step: 0, Done: true, Message: "Локальный ключ прочитан; файлы не изменяются"})
	knownPath := filepath.Join(dir, "known_hosts")
	if _, err = readLocal(knownPath, false); err != nil {
		return result, fmt.Errorf("нет доступного known_hosts; сначала выполните настройку: %w", err)
	}
	trusted, err := knownhosts.New(knownPath)
	if err != nil {
		return result, err
	}
	_, closeClient, err := s.connect(ctx, c, []ssh.AuthMethod{ssh.PublicKeys(signer)}, func(host string, addr net.Addr, key ssh.PublicKey) error {
		result.Fingerprint = ssh.FingerprintSHA256(key)
		return trusted(host, addr, key)
	})
	if err != nil {
		return result, fmt.Errorf("вход по ключу не подтверждён; проверьте адрес, порт, known_hosts и authorized_keys: %w", err)
	}
	closeClient()
	report(Event{Step: 2, Done: true, Message: "Сервер доступен, его ключ проверен, вход по вашему ключу выполнен"})
	result.ConfigPath = filepath.Join(dir, "config")
	if err = checkClientConfig(ctx, result.ConfigPath, c, result.KeyPath); err != nil {
		return result, fmt.Errorf("вход по ключу работает, но обычная команда ssh настроена неверно: %w", err)
	}
	result.Command = connectCommand(c)
	report(Event{Step: 4, Done: true, Message: "Диагностика завершена: параметры обычной команды ssh соответствуют подключению"})
	return result, nil
}

func connectCommand(c Config) string {
	if c.Alias != "" {
		return "ssh " + c.Alias
	}
	return "ssh " + strings.ReplaceAll(c.User, "$", "\\$") + "@" + c.Host
}

func checkClientConfig(ctx context.Context, filename string, c Config, keyPath string) error {
	if _, err := readLocal(filename, false); err != nil {
		return fmt.Errorf("SSH config: %w", err)
	}
	target := c.User + "@" + c.Host
	if c.Alias != "" {
		target = c.Alias
	}
	cmd := exec.CommandContext(ctx, "ssh", "-G", "-F", filename, target)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("не удалось проверить конфигурацию системным ssh -G: %w", err)
	}
	settings := map[string]string{"hostname": c.Host, "user": c.User, "port": strconv.Itoa(c.Port), "identitiesonly": "yes"}
	identity := false
	for _, line := range strings.Split(string(output), "\n") {
		name, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		if expected, ok := settings[name]; ok {
			if value != expected {
				return fmt.Errorf("%s: выбрано %q, ожидалось %q", name, value, expected)
			}
			delete(settings, name)
		}
		if name == "identityfile" && value == strings.ReplaceAll(keyPath, "%", "%%") {
			identity = true
		}
	}
	if len(settings) != 0 || !identity {
		return fmt.Errorf("в SSH config отсутствуют параметры подключения или нужный IdentityFile")
	}
	return nil
}
