package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestGUIHelperProcess(t *testing.T) {
	if os.Getenv("SSH_SETUP_GUI_HELPER") != "1" {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	fmt.Println("ready")
	<-ctx.Done()
	fmt.Println("cleanup complete")
	os.Exit(0)
}

func TestGUIReceivesGracefulCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := guiCommand(ctx, os.Args[0])
	cmd.Args = append(cmd.Args, "-test.run=^TestGUIHelperProcess$")
	cmd.Env = append(os.Environ(), "SSH_SETUP_GUI_HELPER=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	reader := bufio.NewReader(stdout)
	if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("helper startup: %v", err)
	}
	cancel()
	if line, err := reader.ReadString('\n'); err != nil || line != "cleanup complete\n" {
		t.Fatalf("GUI was killed before cleanup: %v", err)
	}
	_ = cmd.Wait()
}
