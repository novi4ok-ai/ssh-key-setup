package setup

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type Input struct {
	EncryptKey, UseAgent              bool
	Passphrase                        []byte
	ExpectedFingerprint               string
	ConfirmHostKey                    func(context.Context, string, string) error
	RequestPassphrase                 func(context.Context, bool) ([]byte, error)
	DryRun                            bool
	RequestPassword                   func(context.Context) (string, error)
	Host, Port, User, Password, Alias string
	Check                             bool
}

type Config struct {
	Host, User, Password, Alias string
	Port                        int
}

var loginPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?$`)
var aliasPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`)
var dnsLabelPattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

func ValidateAlias(value string) error {
	if value != "" && !aliasPattern.MatchString(value) {
		return fmt.Errorf("Имя подключения: до 64 латинских букв, цифр, _ и -; первая — буква")
	}
	return nil
}

func ValidateHost(value string) error {
	value = strings.TrimSpace(value)
	addr, err := netip.ParseAddr(value)
	if err != nil {
		name := strings.TrimSuffix(value, ".")
		valid := len(name) > 0 && len(name) <= 253 && strings.ContainsAny(strings.ToLower(name), "abcdefghijklmnopqrstuvwxyz")
		for _, label := range strings.Split(name, ".") {
			valid = valid && dnsLabelPattern.MatchString(label)
		}
		if valid {
			return nil
		}
		return fmt.Errorf("Введите IPv4, IPv6 или DNS-имя без пробелов внутри, например server.example.com")
	}
	if addr.Zone() != "" {
		return fmt.Errorf("IPv6 zone ID в этой версии не поддерживается")
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsMulticast() {
		return fmt.Errorf("Нужен адрес конкретного сервера, не широковещательный или неопределённый адрес")
	}
	if addr.String() == "255.255.255.255" {
		return fmt.Errorf("Широковещательный адрес не подходит для SSH")
	}
	return nil
}

func ValidatePort(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return fmt.Errorf("Порт — целое число от 1 до 65535")
		}
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("Порт — целое число от 1 до 65535")
	}
	return nil
}

func ValidateUser(value string) error {
	if !loginPattern.MatchString(strings.TrimSpace(value)) {
		return fmt.Errorf("Логин: латинские буквы, цифры, _, . и -; первый символ — буква или _")
	}
	return nil
}

func ValidatePassword(value string) error {
	if len(value) == 0 {
		return fmt.Errorf("Введите пароль пользователя на сервере")
	}
	if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("Пароль не должен содержать переносы строк или NUL; максимум 4096 байт")
	}
	return nil
}

func Normalize(in Input) (Config, error) {
	if in.ExpectedFingerprint != "" {
		data, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(in.ExpectedFingerprint, "SHA256:"))
		if !strings.HasPrefix(in.ExpectedFingerprint, "SHA256:") || err != nil || len(data) != 32 {
			return Config{}, fmt.Errorf("отпечаток должен иметь формат SHA256:…")
		}
	}
	for _, check := range []struct {
		value    string
		validate func(string) error
	}{
		{in.Host, ValidateHost}, {in.Port, ValidatePort}, {in.User, ValidateUser}, {in.Alias, ValidateAlias},
	} {
		if err := check.validate(check.value); err != nil {
			return Config{}, err
		}
	}
	if !in.Check && !in.DryRun && in.Password != "" {
		if err := ValidatePassword(in.Password); err != nil {
			return Config{}, err
		}
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Host), "."))
	if addr, err := netip.ParseAddr(strings.TrimSpace(in.Host)); err == nil {
		host = addr.Unmap().String()
	}
	port := 22
	if p := strings.TrimSpace(in.Port); p != "" {
		port, _ = strconv.Atoi(p)
	}
	return Config{Host: host, Port: port, User: strings.TrimSpace(in.User), Password: in.Password, Alias: strings.ToLower(in.Alias)}, nil
}

func (c Config) Address() string { return net.JoinHostPort(c.Host, strconv.Itoa(c.Port)) }

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
