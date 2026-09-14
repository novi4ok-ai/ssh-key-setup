package ui

import (
	"context"
	"image/png"
	"os"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"ssh-key-setup/internal/setup"
)

// The test driver normally executes Do immediately. Queue callbacks to model
// the real single-threaded GUI and make the race detector meaningful.
type queuedDriver struct {
	fyne.Driver
	queue chan func()
}

func (d *queuedDriver) DoFromGoroutine(fn func(), wait bool) {
	if !wait {
		d.queue <- fn
		return
	}
	done := make(chan struct{})
	d.queue <- func() { fn(); close(done) }
	<-done
}

type queuedApp struct {
	fyne.App
	driver *queuedDriver
}

func (a *queuedApp) Driver() fyne.Driver { return a.driver }

func newTestApp(t *testing.T) *queuedApp {
	base := test.NewTempApp(t)
	a := &queuedApp{App: base, driver: &queuedDriver{Driver: base.Driver(), queue: make(chan func(), 32)}}
	fyne.SetCurrentApp(a)
	return a
}

func drainUntilDone(t *testing.T, a *queuedApp, v *View) {
	t.Helper()
	timeout := time.After(3 * time.Second)
	for v.busy {
		select {
		case fn := <-a.driver.queue:
			fn()
		case <-timeout:
			t.Fatal("GUI did not finish")
		}
	}
}

func TestFormValidationAndScreenshot(t *testing.T) {
	a := newTestApp(t)
	called := false
	v := New(a, func(context.Context, setup.Input, func(setup.Event)) (setup.Result, error) {
		called = true
		return setup.Result{}, nil
	})
	v.Window.Show()
	test.Tap(v.Start)
	if called || v.busy || !strings.Contains(v.Status.Text, "IPv4") {
		t.Fatal("invalid form started a connection")
	}
	if !v.Password.Password || !v.Copy.Disabled() {
		t.Fatal("password or initial copy state is incorrect")
	}
	v.Status.SetText("Введите данные сервера и нажмите «Настроить доступ».")
	if filename := os.Getenv("SSH_SETUP_SCREENSHOT"); filename != "" {
		f, err := os.Create(filename)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err = png.Encode(f, v.Window.Canvas().Capture()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFormAsyncSuccessAndCopy(t *testing.T) {
	a := newTestApp(t)
	input := make(chan setup.Input, 1)
	release := make(chan struct{})
	v := New(a, func(ctx context.Context, in setup.Input, report func(setup.Event)) (setup.Result, error) {
		input <- in
		<-release
		report(setup.Event{Step: 4, Done: true, Message: "verified"})
		return setup.Result{Command: "ssh verified-server", KeyPath: "/tmp/test-key"}, nil
	})
	v.Host.SetText(" 127.0.0.1 ")
	v.User.SetText(" tester ")
	v.Password.SetText(" exact password ")
	test.Tap(v.Start)
	in := <-input
	if in.Password != " exact password " || v.Password.Text != "" || !v.Start.Disabled() || !v.Host.Disabled() {
		t.Fatal("password handling or busy state is incorrect")
	}
	if v.Host.Text != "127.0.0.1" || v.User.Text != "tester" {
		t.Fatal("normalized fields not displayed")
	}
	close(release)
	drainUntilDone(t, a, v)
	if v.Copy.Disabled() || !v.result.Visible() || v.Start.Disabled() || !v.Cancel.Disabled() {
		t.Fatal("wrong success state")
	}
	test.Tap(v.Copy)
	if a.Clipboard().Content() != "ssh verified-server" {
		t.Fatal("wrong copied command")
	}
	if strings.Contains(v.Details.Text, "exact password") {
		t.Fatal("password in GUI details")
	}
}

func TestFormCancel(t *testing.T) {
	a := newTestApp(t)
	v := New(a, func(ctx context.Context, in setup.Input, report func(setup.Event)) (setup.Result, error) {
		<-ctx.Done()
		return setup.Result{}, ctx.Err()
	})
	v.Host.SetText("127.0.0.1")
	v.User.SetText("tester")
	v.Password.SetText("secret")
	test.Tap(v.Start)
	test.Tap(v.Cancel)
	drainUntilDone(t, a, v)
	if v.result.Visible() || !v.Copy.Disabled() || !strings.Contains(v.Status.Text, "отменена") {
		t.Fatal("cancelled operation shown as success")
	}
}
