package setup

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type Input struct {
	Host, Port, User, Password string
	Check                      bool
}

type Config struct {
	Host, User, Password string
	Port                 int
}

var loginPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?$`)

func ValidateHost(value string) error {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || addr.Zone() != "" {
		return fmt.Errorf("Введите IPv4 или IPv6 без пробелов внутри, например 192.168.1.10")
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
	for _, check := range []struct {
		value    string
		validate func(string) error
	}{
		{in.Host, ValidateHost}, {in.Port, ValidatePort}, {in.User, ValidateUser},
	} {
		if err := check.validate(check.value); err != nil {
			return Config{}, err
		}
	}
	if !in.Check {
		if err := ValidatePassword(in.Password); err != nil {
			return Config{}, err
		}
	}
	addr, _ := netip.ParseAddr(strings.TrimSpace(in.Host))
	port := 22
	if p := strings.TrimSpace(in.Port); p != "" {
		port, _ = strconv.Atoi(p)
	}
	return Config{Host: addr.Unmap().String(), Port: port, User: strings.TrimSpace(in.User), Password: in.Password}, nil
}

func (c Config) Address() string { return net.JoinHostPort(c.Host, strconv.Itoa(c.Port)) }

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
