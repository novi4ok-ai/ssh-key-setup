//go:build gui

package main

import (
	"fmt"
	"os"

	"fyne.io/fyne/v2/app"
	"ssh-key-setup/internal/setup"
	"ssh-key-setup/internal/ui"
)

func main() {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		fmt.Fprintln(os.Stderr, "Нет графической сессии. Запустите ssh-key-setup для работы в консоли.")
		os.Exit(1)
	}
	a := app.NewWithID("io.ssh-key-setup.desktop")
	v := ui.New(a, setup.Service{}.Run)
	v.Window.ShowAndRun()
}
