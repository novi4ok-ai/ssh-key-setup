package ui

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"image/color"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"ssh-key-setup/internal/setup"
)

type Runner func(context.Context, setup.Input, func(setup.Event)) (setup.Result, error)

type View struct {
	Alias, Fingerprint             *widget.Entry
	ProtectKey, Agent, ConfirmHost *widget.Check
	Check, Preview                 *widget.Button
	details                        *widget.Accordion
	resultTitle                    *canvas.Text
	checking, previewing           bool
	Window                         fyne.Window
	Host, Port, User, Password     *widget.Entry
	Start, Cancel, Copy            *widget.Button
	Status                         *widget.Label
	Progress                       *widget.ProgressBar
	Command                        *widget.Entry
	Details                        *widget.Label
	steps                          []*widget.Label
	icons                          []*widget.Icon
	logs                           []string
	busy, closing                  bool
	cancel                         context.CancelFunc
	run                            Runner
	result                         *fyne.Container
	clipboard                      fyne.Clipboard
}

//go:embed icon.svg
var iconSVG []byte

var stepNames = []string{"Проверка параметров", "Подключение к серверу", "Подготовка ключа", "Установка на сервер", "Проверка входа по ключу"}

func text(value string, size float32, c color.Color, bold bool) *canvas.Text {
	t := canvas.NewText(value, c)
	t.TextSize = size
	t.TextStyle.Bold = bold
	return t
}

func inset(object fyne.CanvasObject, padding float32) *fyne.Container {
	return container.New(layout.NewCustomPaddedLayout(padding, padding, padding, padding), object)
}

func card(object fyne.CanvasObject) *fyne.Container {
	bg := canvas.NewRectangle(panel)
	bg.CornerRadius = 16
	return container.NewStack(bg, inset(object, 22))
}

func paragraph(value string) *widget.Label {
	l := widget.NewLabel(value)
	l.Wrapping = fyne.TextWrapWord
	return l
}

func field(title string, entry *widget.Entry) *fyne.Container {
	return container.NewVBox(widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), entry)
}

func New(a fyne.App, run Runner) *View {
	a.Settings().SetTheme(appTheme{theme.DefaultTheme()})
	a.SetIcon(fyne.NewStaticResource("ssh-key-setup.svg", iconSVG))
	v := &View{Window: a.NewWindow("SSH Key Setup"), run: run, clipboard: a.Clipboard()}
	v.Host = widget.NewEntry()
	v.Host.SetPlaceHolder("server.example.com или 192.168.1.10")
	v.Host.Validator = setup.ValidateHost
	v.Port = widget.NewEntry()
	v.Port.SetText("22")
	v.Port.Validator = setup.ValidatePort
	v.User = widget.NewEntry()
	v.User.SetPlaceHolder("Например, ubuntu")
	v.User.Validator = setup.ValidateUser
	v.Password = widget.NewPasswordEntry()
	v.Password.SetPlaceHolder("Не нужен, если сохранённый ключ уже работает")
	v.Password.Validator = func(value string) error {
		if value == "" {
			return nil
		}
		return setup.ValidatePassword(value)
	}
	v.Alias = widget.NewEntry()
	v.Alias.SetPlaceHolder("Например, work → ssh work")
	v.Alias.Validator = setup.ValidateAlias
	v.Fingerprint = widget.NewEntry()
	v.Fingerprint.SetPlaceHolder("SHA256:… (необязательно)")
	v.ProtectKey = widget.NewCheck("Защитить новый ключ парольной фразой", nil)
	v.Agent = widget.NewCheck("Использовать ssh-agent (ключ на один час)", nil)
	v.ConfirmHost = widget.NewCheck("Подтверждать новый ключ сервера", nil)
	v.Status = paragraph("Введите данные сервера и нажмите «Настроить доступ».")
	v.Progress = widget.NewProgressBar()
	v.Progress.Hide()
	v.Start = widget.NewButtonWithIcon("Настроить доступ", theme.LoginIcon(), v.start)
	v.Start.Importance = widget.HighImportance
	v.Check = widget.NewButton("Проверить доступ", func() { v.begin(true, false) })
	v.Preview = widget.NewButton("Предпросмотр", func() { v.begin(false, true) })
	v.Cancel = widget.NewButton("Отменить", func() {
		if v.cancel != nil {
			v.cancel()
			v.Cancel.Disable()
			v.Status.SetText("Останавливаем подключение…")
		}
	})
	v.Cancel.Disable()
	v.Command = widget.NewEntry()
	v.Command.TextStyle = fyne.TextStyle{Monospace: true}
	v.Command.Disable()
	v.Copy = widget.NewButtonWithIcon("Копировать команду", theme.ContentCopyIcon(), nil)
	v.Copy.Disable()
	v.Details = paragraph("")
	v.resultTitle = text("Доступ настроен", 23, accent, true)
	v.result = card(container.NewVBox(v.resultTitle, paragraph("Подключайтесь из терминала этой командой:"), v.Command, v.Copy))
	v.result.Hide()

	white := color.NRGBA{R: 235, G: 242, B: 251, A: 255}
	header := container.NewVBox(
		text("SSH  /  KEY SETUP", 13, accent, true),
		text("Ваш сервер. Вход по ключу.", 30, white, true),
		paragraph("Настройте доступ один раз — подключайтесь без пароля сервера."),
	)
	form := card(container.NewVBox(
		text("Подключение", 22, white, true),
		container.NewGridWithColumns(2, field("Адрес сервера", v.Host), field("Порт SSH", v.Port)),
		field("Пользователь", v.User),
		field("Имя подключения (необязательно)", v.Alias),
		field("Пароль сервера", v.Password),
		paragraph("Пробелы по краям IP и логина убираются автоматически. Пароль остаётся без изменений."),
	))
	stepBox := container.NewVBox(text("Как проходит настройка", 22, white, true))
	for i, name := range stepNames {
		icon := widget.NewIcon(theme.NewDisabledResource(theme.RadioButtonIcon()))
		label := widget.NewLabel(fmt.Sprintf("%02d   %s", i+1, name))
		label.Wrapping = fyne.TextWrapWord
		v.steps = append(v.steps, label)
		v.icons = append(v.icons, icon)
		stepBox.Add(container.NewBorder(nil, nil, icon, nil, label))
	}
	stepBox.Add(widget.NewSeparator())
	stepBox.Add(paragraph("Ed25519 · парольная фраза по желанию\nЗакрытый ключ остаётся на компьютере."))
	stepBox.Add(paragraph("Новый ключ сервера принимается автоматически. При изменении сохранённого ключа подключение останавливается."))
	columns := container.NewGridWithColumns(2, form, card(stepBox))
	security := widget.NewAccordion(widget.NewAccordionItem("Дополнительная защита", container.NewVBox(
		field("Ожидаемый отпечаток сервера", v.Fingerprint), v.ConfirmHost, v.ProtectKey, v.Agent,
		paragraph("Отпечаток сверьте через доверенный канал. Парольная фраза запрашивается отдельно; существующие ключи не перезаписываются."),
	)))
	actions := container.NewVBox(paragraph("Проверка и предпросмотр не требуют пароля сервера."), container.NewHBox(v.Preview, v.Check, layout.NewSpacer(), v.Cancel, v.Start))
	footer := card(container.NewVBox(v.Status, v.Progress, actions))
	v.details = widget.NewAccordion(widget.NewAccordionItem("Подробности настройки", v.Details))
	content := container.NewVBox(header, columns, security, footer, v.result, v.details)
	v.Window.SetContent(container.NewVScroll(inset(content, 24)))
	v.Window.Resize(fyne.NewSize(1100, 860))
	v.Window.CenterOnScreen()
	v.Window.SetCloseIntercept(v.RequestClose)
	v.Password.OnSubmitted = func(string) {
		if !v.busy {
			v.start()
		}
	}
	return v
}

func (v *View) setBusy(busy bool) {
	v.busy = busy
	for _, entry := range []*widget.Entry{v.Host, v.Port, v.User, v.Password, v.Alias, v.Fingerprint} {
		if busy {
			entry.Disable()
		} else {
			entry.Enable()
		}
	}
	for _, check := range []*widget.Check{v.ProtectKey, v.Agent, v.ConfirmHost} {
		if busy {
			check.Disable()
		} else {
			check.Enable()
		}
	}
	for _, button := range []*widget.Button{v.Check, v.Preview} {
		if busy {
			button.Disable()
		} else {
			button.Enable()
		}
	}
	if busy {
		v.Start.Disable()
		v.Cancel.Enable()
	} else {
		v.Start.Enable()
		v.Cancel.Disable()
	}
}

func (v *View) start() {
	v.begin(false, false)
}

// RequestClose runs on the UI thread, both for window-close and process signals.
func (v *View) RequestClose() {
	if v.busy {
		v.closing = true
		v.cancel()
		v.Status.SetText("Завершаем операцию и закрываем окно…")
	} else {
		v.Window.SetCloseIntercept(nil)
		v.Window.Close()
	}
}

func (v *View) begin(check, preview bool) {
	if v.busy {
		return
	}
	in := setup.Input{Host: v.Host.Text, Port: v.Port.Text, User: v.User.Text, Password: v.Password.Text,
		Alias: v.Alias.Text, Check: check, DryRun: preview, EncryptKey: v.ProtectKey.Checked && !check,
		UseAgent: v.Agent.Checked, ExpectedFingerprint: strings.TrimSpace(v.Fingerprint.Text),
		RequestPassword: func(ctx context.Context) (string, error) {
			return v.askSecret(ctx, "Пароль сервера", false)
		},
		RequestPassphrase: func(ctx context.Context, newKey bool) ([]byte, error) {
			phrase, err := v.askSecret(ctx, "Парольная фраза ключа", newKey)
			return []byte(phrase), err
		},
	}
	if check || preview {
		in.Password = ""
	}
	if v.ConfirmHost.Checked && !check {
		in.ConfirmHostKey = v.confirmHostKey
	}
	c, err := setup.Normalize(in)
	if err != nil {
		v.Status.SetText(err.Error())
		return
	}
	v.Host.SetText(c.Host)
	v.Port.SetText(fmt.Sprint(c.Port))
	v.User.SetText(c.User)
	v.Alias.SetText(c.Alias)
	v.checking, v.previewing = check, preview
	v.Password.SetText("")
	v.result.Hide()
	v.Copy.Disable()
	v.Command.SetText("")
	v.logs = nil
	v.Details.SetText("")
	for i := range v.icons {
		v.icons[i].SetResource(theme.NewDisabledResource(theme.RadioButtonIcon()))
	}
	v.Progress.SetValue(0)
	v.Progress.Show()
	v.setBusy(true)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	v.cancel = cancel
	go func() {
		result, err := v.run(ctx, in, func(event setup.Event) {
			fyne.Do(func() { v.onEvent(event) })
		})
		in.Password = ""
		cancel()
		fyne.Do(func() { v.finish(result, err) })
	}()
}

func (v *View) onEvent(event setup.Event) {
	if event.Step < 0 || event.Step >= len(v.steps) {
		return
	}
	v.Status.SetText(event.Message)
	v.logs = append(v.logs, event.Message)
	v.Details.SetText(strings.Join(v.logs, "\n"))
	if event.Done {
		v.icons[event.Step].SetResource(theme.NewSuccessThemedResource(theme.ConfirmIcon()))
		v.Progress.SetValue(float64(event.Step+1) / float64(len(v.steps)))
	} else {
		v.icons[event.Step].SetResource(theme.NewPrimaryThemedResource(theme.MediaPlayIcon()))
	}
}

func (v *View) finish(result setup.Result, err error) {
	v.setBusy(false)
	v.cancel = nil
	v.Progress.Hide()
	if err != nil {
		message := err.Error()
		if errors.Is(err, context.Canceled) {
			message = "Настройка отменена. Уже созданные ключи сохранены. При обрыве связи проверьте подробности перед повторным запуском.\n" + err.Error()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			message = "Истекло время настройки (90 секунд). Проверьте доступность сервера.\n" + err.Error()
		}
		v.Status.SetText(message)
		v.logs = append(v.logs, message)
	} else if v.previewing {
		v.Status.SetText("Предпросмотр готов. Подключений и изменений файлов не было.")
		v.logs = append(v.logs, result.Preview)
		v.details.OpenAll()
	} else {
		v.Status.SetText("Готово! Вход по ключу проверен отдельным подключением.")
		v.resultTitle.Text = "Доступ настроен"
		if v.checking {
			v.Status.SetText("Доступ проверен. SSH-файлы не изменялись.")
			v.resultTitle.Text = "Доступ проверен"
		}
		v.resultTitle.Refresh()
		v.Command.SetText(result.Command)
		v.Copy.OnTapped = func() { v.clipboard.SetContent(result.Command) }
		v.Copy.Enable()
		v.result.Show()
	}
	if result.KeyPath != "" {
		v.logs = append(v.logs, "Закрытый ключ: "+result.KeyPath)
	}
	if result.ConfigPath != "" {
		v.logs = append(v.logs, "Конфигурация SSH: "+result.ConfigPath)
	}
	if result.Fingerprint != "" {
		v.logs = append(v.logs, "Отпечаток сервера: "+result.Fingerprint)
	}
	if result.BackupPath != "" {
		v.logs = append(v.logs, "Резервная копия на сервере: "+result.BackupPath)
	}
	if result.AlreadyInstalled {
		v.logs = append(v.logs, "Ключ уже был установлен; дубликат не добавлен.")
	}
	v.Details.SetText(strings.Join(v.logs, "\n"))
	if v.closing {
		v.Window.SetCloseIntercept(nil)
		v.Window.Close()
	}
}
