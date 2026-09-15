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
	fd := int(file.Fd())
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return "", err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return "", err
	}
	defer unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags)
	var data []byte
	defer func() { clear(data) }()
	var b [1]byte
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
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
		// A signal can flush canonical terminal input after Poll reports it.
		// A nonblocking syscall keeps that race cancellable.
		n, err = unix.Read(fd, b[:])
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if n == 0 && err == nil {
			err = io.EOF
		}
		if n > 0 {
			if b[0] == '\n' {
				return strings.TrimSuffix(string(data), "\r"), nil
			}
			data = append(data, b[0])
			// A CR after 4096 bytes may belong to a CRLF line ending.
			if len(data) > 4096 && !(len(data) == 4097 && b[0] == '\r') {
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
