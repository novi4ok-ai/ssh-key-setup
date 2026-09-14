package main

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"ssh-key-setup/internal/cli"
	"ssh-key-setup/internal/setup"
)

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := cli.App{
		In: os.Stdin, Out: os.Stdout, Err: os.Stderr, Run: setup.Service{}.Run,
		Graphical: os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "",
		LaunchGUI: func() error {
			executable, err := os.Executable()
			if err != nil {
				return err
			}
			cmd := exec.CommandContext(ctx, filepath.Join(filepath.Dir(executable), "ssh-key-setup-gui"))
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
			return cmd.Run()
		},
	}
	return a.Execute(ctx, os.Args[1:])
}
