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
	"fyne.io/fyne/v2/widget"
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

func TestCheckAndPreviewModes(t *testing.T) {
	for _, preview := range []bool{false, true} {
		a := newTestApp(t)
		v := New(a, func(_ context.Context, in setup.Input, _ func(setup.Event)) (setup.Result, error) {
			if in.DryRun != preview || in.Check == preview || in.Password != "" || in.Alias != "work" || !in.UseAgent {
				t.Error("incorrect diagnostic/preview options")
			}
			return setup.Result{Command: "ssh work", Preview: "Planned changes"}, nil
		})
		v.Host.SetText("server.example.com")
		v.User.SetText("tester")
		v.Alias.SetText("work")
		v.Password.SetText("not needed")
		v.Agent.SetChecked(true)
		if preview {
			test.Tap(v.Preview)
		} else {
			test.Tap(v.Check)
		}
		drainUntilDone(t, a, v)
		if preview {
			if v.result.Visible() || !v.Copy.Disabled() || !strings.Contains(v.Details.Text, "Planned changes") {
				t.Fatal("preview shown as successful setup")
			}
		} else if v.resultTitle.Text != "Доступ проверен" || v.Copy.Disabled() {
			t.Fatal("wrong diagnostic success")
		}
	}
}

func findDialogButton(object fyne.CanvasObject, label string) *widget.Button {
	if button, ok := object.(*widget.Button); ok && button.Text == label {
		return button
	}
	if popup, ok := object.(*widget.PopUp); ok {
		return findDialogButton(popup.Content, label)
	}
	if box, ok := object.(*fyne.Container); ok {
		for _, child := range box.Objects {
			if found := findDialogButton(child, label); found != nil {
				return found
			}
		}
	}
	if item, ok := object.(fyne.Widget); ok {
		for _, child := range test.WidgetRenderer(item).Objects() {
			if found := findDialogButton(child, label); found != nil {
				return found
			}
		}
	}
	return nil
}

func dialogEntries(object fyne.CanvasObject) []*widget.Entry {
	if entry, ok := object.(*widget.Entry); ok {
		return []*widget.Entry{entry}
	}
	var children []fyne.CanvasObject
	switch item := object.(type) {
	case *fyne.Container:
		children = item.Objects
	case fyne.Widget:
		children = test.WidgetRenderer(item).Objects()
	}
	var result []*widget.Entry
	for _, child := range children {
		result = append(result, dialogEntries(child)...)
	}
	return result
}

func waitForDialog(t *testing.T, a *queuedApp, v *View) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for v.Window.Canvas().Overlays().Top() == nil {
		select {
		case fn := <-a.driver.queue:
			fn()
		case <-deadline:
			t.Fatal("dialog not shown")
		}
	}
}

func TestHostConfirmationDialog(t *testing.T) {
	for _, accept := range []bool{false, true} {
		a := newTestApp(t)
		v := New(a, func(ctx context.Context, in setup.Input, _ func(setup.Event)) (setup.Result, error) {
			err := in.ConfirmHostKey(ctx, "server.example.com", "SHA256:fixture")
			return setup.Result{Command: "ssh work"}, err
		})
		v.Host.SetText("server.example.com")
		v.User.SetText("tester")
		v.ConfirmHost.SetChecked(true)
		v.Window.Show()
		test.Tap(v.Start)
		waitForDialog(t, a, v)
		label := "Отмена"
		if accept {
			label = "Доверять"
		}
		button := findDialogButton(v.Window.Canvas().Overlays().Top(), label)
		if button == nil {
			t.Fatalf("confirmation button missing from %T", v.Window.Canvas().Overlays().Top())
		}
		test.Tap(button)
		drainUntilDone(t, a, v)
		if v.result.Visible() != accept {
			t.Fatal("confirmation result ignored")
		}
	}
}

func TestCancelWhileWaitingForSecret(t *testing.T) {
	a := newTestApp(t)
	v := New(a, func(ctx context.Context, in setup.Input, _ func(setup.Event)) (setup.Result, error) {
		_, err := in.RequestPassphrase(ctx, true)
		return setup.Result{}, err
	})
	v.Host.SetText("127.0.0.1")
	v.User.SetText("tester")
	v.Window.Show()
	test.Tap(v.Start)
	waitForDialog(t, a, v)
	v.RequestClose()
	drainUntilDone(t, a, v)
	if !v.closing || v.result.Visible() || !strings.Contains(v.Status.Text, "отменена") {
		t.Fatal("secret prompt did not cancel")
	}
}

func TestNewPassphraseDialogValidation(t *testing.T) {
	a := newTestApp(t)
	v := New(a, func(ctx context.Context, in setup.Input, _ func(setup.Event)) (setup.Result, error) {
		phrase, err := in.RequestPassphrase(ctx, true)
		defer clear(phrase)
		if err == nil && string(phrase) != "fixture phrase" {
			t.Error("passphrase changed")
		}
		return setup.Result{Command: "ssh work"}, err
	})
	v.Host.SetText("127.0.0.1")
	v.User.SetText("tester")
	v.Window.Show()
	test.Tap(v.Start)
	waitForDialog(t, a, v)
	popup := v.Window.Canvas().Overlays().Top()
	entries := dialogEntries(popup)
	if len(entries) != 2 || !entries[0].Password || !entries[1].Password {
		t.Fatal("expected two hidden phrase fields")
	}
	button := findDialogButton(popup, "Продолжить")
	if button == nil {
		t.Fatal("secret confirmation button missing")
	}
	entries[0].SetText("fixture phrase")
	entries[1].SetText("mismatch")
	if !button.Disabled() {
		t.Fatal("mismatched phrases accepted")
	}
	entries[1].SetText("fixture phrase")
	if button.Disabled() {
		t.Fatal("matching phrases rejected")
	}
	test.Tap(button)
	drainUntilDone(t, a, v)
	if !v.result.Visible() || strings.Contains(v.Details.Text, "fixture phrase") {
		t.Fatal("wrong secret result or leaked phrase")
	}
}
