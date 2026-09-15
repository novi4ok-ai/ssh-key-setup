package ui

import (
	"context"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"ssh-key-setup/internal/setup"
)

func (v *View) confirmHostKey(ctx context.Context, host, fingerprint string) error {
	done := make(chan bool, 1)
	var prompt *dialog.ConfirmDialog
	fyne.Do(func() {
		if ctx.Err() != nil {
			return
		}
		prompt = dialog.NewConfirm("Проверка сервера", fmt.Sprintf("Сервер: %s\nОтпечаток: %s\n\nСверьте отпечаток через доверенный канал. Доверять этому ключу?", host, fingerprint), func(ok bool) {
			select {
			case done <- ok:
			default:
			}
		}, v.Window)
		prompt.SetConfirmText("Доверять")
		prompt.SetDismissText("Отмена")
		prompt.Show()
	})
	select {
	case ok := <-done:
		if !ok {
			return context.Canceled
		}
		return nil
	case <-ctx.Done():
		fyne.Do(func() {
			if prompt != nil {
				prompt.Hide()
			}
		})
		return ctx.Err()
	}
}

func (v *View) askSecret(ctx context.Context, title string, repeat bool) (string, error) {
	type answer struct {
		value string
		ok    bool
	}
	done := make(chan answer, 1)
	var prompt *dialog.FormDialog
	var entry, again *widget.Entry
	fyne.Do(func() {
		if ctx.Err() != nil {
			return
		}
		entry = widget.NewPasswordEntry()
		entry.Validator = setup.ValidatePassword
		items := []*widget.FormItem{widget.NewFormItem(title, entry)}
		if repeat {
			again = widget.NewPasswordEntry()
			again.Validator = func(value string) error {
				if value != entry.Text {
					return fmt.Errorf("парольные фразы не совпадают")
				}
				return setup.ValidatePassword(value)
			}
			entry.OnChanged = func(string) { _ = again.Validate() }
			items = append(items, widget.NewFormItem("Повторите фразу", again))
		}
		prompt = dialog.NewForm(title, "Продолжить", "Отмена", items, func(ok bool) {
			value := ""
			if ok {
				value = entry.Text
			}
			entry.SetText("")
			if again != nil {
				again.SetText("")
			}
			select {
			case done <- answer{value, ok}:
			default:
			}
		}, v.Window)
		prompt.Show()
	})
	select {
	case result := <-done:
		if !result.ok {
			return "", context.Canceled
		}
		return result.value, nil
	case <-ctx.Done():
		fyne.Do(func() {
			if entry != nil {
				entry.SetText("")
			}
			if again != nil {
				again.SetText("")
			}
			if prompt != nil {
				prompt.Hide()
			}
		})
		return "", ctx.Err()
	}
}
