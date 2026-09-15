package cli

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

const version = "1.1.0"

func (a App) printHelp() {
	color := false
	if out, ok := a.Out.(*os.File); ok {
		color = term.IsTerminal(int(out.Fd())) && os.Getenv("NO_COLOR") == ""
	}
	style := func(code, value string) string {
		if !color {
			return value
		}
		return "\x1b[" + code + "m" + value + "\x1b[0m"
	}
	heading := func(value string) string { return style("1;36", value) }
	command := func(value string) string { return style("1;32", value) }

	fmt.Fprintf(a.Out, `%s %s
Настраивает вход на Linux-сервер по ключу Ed25519 и проверяет результат.
Закрытый ключ остаётся на этом компьютере; затем работает обычная команда ssh.

%s
  %s
  %s
  %s

%s
  %-22s %s
  %-22s %s
  %-22s %s
  %-22s %s
  %-22s %s
  %-22s %s
  %-22s %s
  %-22s %s
  %-22s %s
  %-22s %s

%s
  %s
  %s
  %s

%s
  Если не указывать -p, пароль будет запрошен без отображения на экране.
  Значение -p видно в истории оболочки и списке процессов. Для сценариев
  автоматизации передавайте одну строку пароля через -password-stdin.
  Первый ключ сервера принимается автоматически; его отпечаток сохраняется
  в ~/.ssh/known_hosts. Изменившийся сохранённый ключ будет отклонён.

%s
  0 — успех, справка или версия
  1 — ошибка подключения, настройки или запуска GUI
  2 — неверные параметры или ввод
  130 — отмена через Ctrl+C или SIGTERM

Дополнительная документация: README.md
`,
		heading("SSH Key Setup"), version,
		heading("ИСПОЛЬЗОВАНИЕ"),
		command("ssh-key-setup -ip <IP> -u <USER> [-p <PASSWORD>] [-port <PORT>]"),
		command("ssh-key-setup -cli"),
		command("ssh-key-setup -gui"),
		heading("ПАРАМЕТРЫ"),
		"-ip <адрес>", "IPv4 или IPv6 сервера",
		"-u <пользователь>", "имя пользователя на сервере",
		"-p <пароль>", "пароль сервера; безопаснее скрытый ввод",
		"-port <порт>", "порт SSH (по умолчанию 22)",
		"-password-stdin", "прочитать пароль из первой строки stdin",
		"-timeout <время>", "общий тайм-аут: 90s, 2m и т. п. (по умолчанию 90s)",
		"-cli", "запустить интерактивный консольный мастер",
		"-gui", "открыть дополнительный графический интерфейс",
		"-version", "показать версию",
		"-help, -h", "показать эту справку",
		heading("ПРИМЕРЫ"),
		command("ssh-key-setup -ip '192.0.2.10' -u 'root' -p '12345'"),
		command("ssh-key-setup -ip '2001:db8::10' -u 'admin' -port 2222"),
		command("ssh-key-setup -ip '192.0.2.10' -u 'root' -password-stdin < /run/secrets/server-password"),
		heading("БЕЗОПАСНОСТЬ"), heading("КОДЫ ЗАВЕРШЕНИЯ"),
	)
	fmt.Fprintln(a.Out, "\nДИАГНОСТИКА\n  -check  проверить существующий ключ и SSH config без изменения файлов; пароль не нужен")
	fmt.Fprintln(a.Out, "\nАДРЕСА И ИМЕНА\n  -host <адрес>  IP или DNS-имя (вместо -ip)\n  -alias <имя>   подключаться командой ssh <имя>")
}
