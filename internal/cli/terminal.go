package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func (a App) readPassword(ctx context.Context, prompt string) (string, error) {
	fd := int(a.In.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", err
	}
	hidden := *old
	hidden.Lflag &^= unix.ECHO | unix.ECHONL
	if err = unix.IoctlSetTermios(fd, unix.TCSETS, &hidden); err != nil {
		return "", err
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, old)
	defer fmt.Fprintln(a.Err)
	fmt.Fprint(a.Err, prompt)
	return readLine(ctx, a.In)
}

// Poll allows cancellation during terminal/pipe input without a blocked
// goroutine. Read one byte at a time so later password input is not buffered.
func readLine(ctx context.Context, file *os.File) (string, error) {
	var data []byte
	defer func() { clear(data) }()
	var b [1]byte
	fds := []unix.PollFd{{Fd: int32(file.Fd()), Events: unix.POLLIN}}
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := unix.Poll(fds, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}
		n, err = file.Read(b[:])
		if n > 0 {
			if b[0] == '\n' {
				return strings.TrimSuffix(string(data), "\r"), nil
			}
			data = append(data, b[0])
			if len(data) > 4096 {
				return "", fmt.Errorf("строка превышает 4096 байт")
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(data) > 0 {
				return string(data), nil
			}
			return "", err
		}
	}
}
