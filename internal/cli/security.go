package cli

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/term"
	"ssh-key-setup/internal/setup"
)

func (a App) configureSecurity(in *setup.Input, confirm bool, filename string) error {
	if in.DryRun {
		return nil
	}
	terminal := term.IsTerminal(int(a.In.Fd()))
	if confirm && !terminal {
		return fmt.Errorf("-confirm-host-key требует терминала; для автоматизации задайте -fingerprint")
	}
	if filename != "" {
		phrase, err := setup.ReadPassphraseFile(filename)
		if err != nil {
			return fmt.Errorf("файл парольной фразы: %w", err)
		}
		in.Passphrase = phrase
	}
	if terminal {
		in.RequestPassphrase = func(ctx context.Context, newKey bool) ([]byte, error) {
			phrase, err := a.readPassword(ctx, "Парольная фраза ключа: ")
			if err != nil {
				return nil, err
			}
			if setup.ValidatePassword(phrase) != nil {
				return nil, fmt.Errorf("нужна непустая парольная фраза до 4096 байт")
			}
			if newKey {
				again, err := a.readPassword(ctx, "Повторите парольную фразу: ")
				if err != nil {
					return nil, err
				}
				if again != phrase {
					return nil, fmt.Errorf("парольные фразы не совпали")
				}
			}
			return []byte(phrase), nil
		}
	}
	if confirm {
		in.ConfirmHostKey = func(ctx context.Context, host, fingerprint string) error {
			fmt.Fprintf(a.Err, "Новый сервер %s\nОтпечаток: %s\nСверьте его через доверенный канал. Подтвердить [yes/нет]: ", host, fingerprint)
			answer, err := readLine(ctx, a.In)
			if err != nil {
				return err
			}
			if strings.TrimSpace(answer) != "yes" {
				return fmt.Errorf("ключ сервера не подтверждён; пароль не отправлен")
			}
			return nil
		}
	}
	return nil
}
