//go:build gui

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"ssh-key-setup/internal/setup"
	"ssh-key-setup/internal/ui"
)

func main() {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		fmt.Fprintln(os.Stderr, "Нет графической сессии. Запустите ssh-key-setup -cli для работы в консоли.")
		os.Exit(1)
	}
	a := app.NewWithID("io.ssh-key-setup.desktop")
	v := ui.New(a, setup.Service{}.Run)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-signals:
			fyne.Do(v.RequestClose)
		case <-done:
		}
	}()
	v.Window.ShowAndRun()
}
