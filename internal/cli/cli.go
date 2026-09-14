package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
	"ssh-key-setup/internal/setup"
)

type Runner func(context.Context, setup.Input, func(setup.Event)) (setup.Result, error)

type App struct {
	In        *os.File
	Out, Err  io.Writer
	Run       Runner
	Graphical bool
	LaunchGUI func() error
}

func (a App) Execute(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("ssh-key-setup", flag.ContinueOnError)
	flags.SetOutput(a.Err)
	var in setup.Input
	flags.StringVar(&in.Host, "ip", "", "IP-адрес сервера (IPv4 или IPv6)")
	flags.StringVar(&in.User, "u", "", "Пользователь на сервере")
	flags.StringVar(&in.Password, "p", "", "Пароль сервера")
	flags.StringVar(&in.Port, "port", "22", "Порт SSH")
	console := flags.Bool("cli", false, "Принудительно использовать консоль")
	gui := flags.Bool("gui", false, "Принудительно открыть графический интерфейс")
	passwordStdin := flags.Bool("password-stdin", false, "Прочитать пароль из первой строки stdin")
	timeout := flags.Duration("timeout", 90*time.Second, "Тайм-аут настройки, например 90s или 2m")
	version := flags.Bool("version", false, "Показать версию")
	flags.Usage = func() {
		fmt.Fprintln(a.Err, "SSH Key Setup — настройка входа на Linux-сервер по ключу Ed25519.")
		fmt.Fprintln(a.Err, "Использование: ssh-key-setup [-cli] [-ip IP] [-u USER] [-p PASSWORD] [-port PORT]")
		fmt.Fprintln(a.Err, "Без параметров: GUI при наличии графики и ssh-key-setup-gui, иначе консольный мастер.")
		fmt.Fprintln(a.Err, "Недостающие параметры запрашиваются в терминале; пароль вводится без отображения.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	failInput := func(message string) int { fmt.Fprintln(a.Err, message); return 2 }
	if flags.NArg() != 0 {
		return failInput("Позиционные аргументы не поддерживаются; используйте -ip, -u, -p и -port. См. -help.")
	}
	if *version {
		fmt.Fprintln(a.Out, "SSH Key Setup 1.1.0")
		return 0
	}
	provided := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	if *timeout <= 0 {
		return failInput("Тайм-аут должен быть больше нуля.")
	}
	if *passwordStdin && provided["p"] {
		return failInput("Используйте только один источник пароля: -p или -password-stdin.")
	}
	if *gui {
		if *console || provided["ip"] || provided["u"] || provided["p"] || provided["port"] || provided["timeout"] || *passwordStdin {
			return failInput("-gui нельзя совмещать с параметрами консольного режима.")
		}
		if !a.Graphical {
			return failInput("Нет графической сессии. Используйте консольный режим.")
		}
	}
	if *gui || (len(args) == 0 && a.Graphical) {
		if a.LaunchGUI == nil {
			fmt.Fprintln(a.Err, "Графический модуль ssh-key-setup-gui не установлен рядом с программой.")
		} else if err := a.LaunchGUI(); err == nil {
			return 0
		} else {
			fmt.Fprintf(a.Err, "Не удалось запустить графический интерфейс: %v\n", err)
		}
		if ctx.Err() != nil {
			return 130
		}
		if *gui {
			return 1
		}
		fmt.Fprintln(a.Err, "Переходим в консольный режим.")
	}
	if err := a.collectInput(ctx, &in, provided, *passwordStdin); err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(a.Err, "Ввод отменён.")
			return 130
		}
		return failInput(err.Error())
	}
	if _, err := setup.Normalize(in); err != nil {
		return failInput(err.Error())
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	result, err := a.Run(ctx, in, func(event setup.Event) {
		if event.Step >= 0 && event.Step < 5 {
			fmt.Fprintf(a.Err, "[%d/5] %s\n", event.Step+1, event.Message)
		}
	})
	in.Password = ""
	if result.KeyPath != "" {
		fmt.Fprintln(a.Err, "Закрытый ключ:", result.KeyPath)
	}
	if result.BackupPath != "" {
		fmt.Fprintln(a.Err, "Резервная копия на сервере:", result.BackupPath)
	}
	if result.Fingerprint != "" {
		fmt.Fprintln(a.Err, "Отпечаток сервера:", result.Fingerprint)
	}
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			fmt.Fprintln(a.Err, "Настройка отменена. Уже созданные ключи сохранены.")
		case errors.Is(err, context.DeadlineExceeded):
			fmt.Fprintln(a.Err, "Истекло время настройки. Уже созданные ключи сохранены.")
		}
		fmt.Fprintln(a.Err, "Ошибка:", err)
		if errors.Is(err, context.Canceled) {
			return 130
		}
		return 1
	}
	if result.AlreadyInstalled {
		fmt.Fprintln(a.Err, "Ключ уже установлен; дубликат не добавлен.")
	}
	fmt.Fprintln(a.Err, "Готово! Вход по ключу проверен отдельным подключением.")
	fmt.Fprintln(a.Out, result.Command)
	return 0
}

func (a App) collectInput(ctx context.Context, in *setup.Input, provided map[string]bool, passwordStdin bool) error {
	terminal := term.IsTerminal(int(a.In.Fd()))
	promptPort := terminal && !provided["ip"] && !provided["u"] && !provided["p"] && !passwordStdin
	if !terminal {
		var missing []string
		for _, name := range []string{"ip", "u", "p"} {
			if !provided[name] && !(name == "p" && passwordStdin) {
				missing = append(missing, "-"+name)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("нет терминала; укажите %s (для пароля также доступен -password-stdin)", strings.Join(missing, ", "))
		}
	}
	for _, field := range []struct {
		name, prompt string
		value        *string
		validate     func(string) error
	}{
		{"ip", "IP-адрес сервера: ", &in.Host, setup.ValidateHost},
		{"port", "Порт SSH [22]: ", &in.Port, setup.ValidatePort},
		{"u", "Пользователь: ", &in.User, setup.ValidateUser},
		{"p", "Пароль сервера: ", &in.Password, setup.ValidatePassword},
	} {
		if provided[field.name] || (field.name == "port" && !promptPort) {
			if err := field.validate(*field.value); err != nil {
				return err
			}
			continue
		}
		for {
			var value string
			var err error
			if terminal && field.name == "p" {
				value, err = a.readPassword(ctx, field.prompt)
			} else {
				if terminal {
					fmt.Fprint(a.Err, field.prompt)
				}
				value, err = readLine(ctx, a.In)
			}
			if err != nil {
				return fmt.Errorf("не удалось прочитать %s: %w", field.name, err)
			}
			if err = field.validate(value); err != nil {
				if !terminal || (field.name == "p" && passwordStdin) {
					return err
				}
				fmt.Fprintln(a.Err, err)
				continue
			}
			*field.value = value
			break
		}
	}
	return nil
}
