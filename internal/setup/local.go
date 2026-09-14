package setup

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

const maxFileSize = 4 << 20

// Files are opened without following symlinks. Never chmod somebody else's file.
func openPrivate(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || !ok || int(st.Uid) != os.Geteuid() || st.Nlink != 1 {
			err = fmt.Errorf("небезопасный файл: %s (нужен обычный файл текущего пользователя без жёстких ссылок)", path)
		}
	}
	if err == nil {
		err = f.Chmod(0600)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func prepareLocal(home string) (string, func(), error) {
	if !filepath.IsAbs(home) {
		return "", nil, fmt.Errorf("домашний каталог должен иметь абсолютный путь")
	}
	dir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || int(st.Uid) != os.Geteuid() {
		return "", nil, fmt.Errorf("%s должен быть каталогом текущего пользователя, а не символической ссылкой", dir)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return "", nil, err
	}
	lock, err := openPrivate(filepath.Join(dir, ".ssh-key-setup.lock"), unix.O_CREAT|unix.O_RDWR)
	if err != nil {
		return "", nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return "", nil, fmt.Errorf("уже выполняется другая настройка SSH; дождитесь её завершения")
	}
	return dir, func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN); _ = lock.Close() }, nil
}

func readPrivate(path string) ([]byte, error) {
	f, err := openPrivate(path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err == nil && len(data) > maxFileSize {
		err = fmt.Errorf("файл слишком большой: %s", path)
	}
	return data, err
}

func writeNewPrivate(path string, data []byte) error {
	f, err := openPrivate(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func keyFor(dir string, c Config) (ssh.Signer, string, error) {
	id := sha256.Sum256([]byte(c.User + "@" + c.Address()))
	keyPath := filepath.Join(dir, fmt.Sprintf("ssh-key-setup_%x_ed25519", id[:16]))
	data, err := readPrivate(keyPath)
	var signer ssh.Signer
	if errors.Is(err, os.ErrNotExist) {
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, keyPath, e
		}
		block, e := ssh.MarshalPrivateKey(key, "ssh-key-setup")
		if e != nil {
			return nil, keyPath, e
		}
		if e = writeNewPrivate(keyPath, pem.EncodeToMemory(block)); e != nil {
			return nil, keyPath, e
		}
		signer, err = ssh.NewSignerFromKey(key)
	} else if err == nil {
		signer, err = ssh.ParsePrivateKey(data)
		clear(data)
		if err == nil && signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
			err = fmt.Errorf("существующий ключ не Ed25519")
		}
	}
	if err != nil {
		return nil, keyPath, fmt.Errorf("ключ %s: %w; существующие ключи не перезаписываются", keyPath, err)
	}
	public := ssh.MarshalAuthorizedKey(signer.PublicKey())
	existing, err := readPrivate(keyPath + ".pub")
	if errors.Is(err, os.ErrNotExist) {
		err = writeNewPrivate(keyPath+".pub", public)
	} else if err == nil {
		key, _, _, rest, parseErr := ssh.ParseAuthorizedKey(existing)
		if parseErr != nil || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(key.Marshal(), signer.PublicKey().Marshal()) {
			err = fmt.Errorf("открытый ключ %s.pub не соответствует закрытому", keyPath)
		}
	}
	if err != nil {
		return nil, keyPath, err
	}
	return signer, keyPath, nil
}

func configureClient(dir string, c Config, keyPath string) (string, error) {
	quotedKey, err := sshConfigQuote(keyPath)
	if err != nil {
		return "", err
	}
	id := filepath.Base(keyPath)
	begin := "# >>> ssh-key-setup " + id
	end := "# <<< ssh-key-setup " + id
	block := []byte(begin + "\n" +
		"Host " + c.Host + "\n" +
		"    User " + c.User + "\n" +
		"    Port " + strconv.Itoa(c.Port) + "\n\n" +
		"Match originalhost " + c.Host + " user " + c.User + "\n" +
		"    IdentityFile " + quotedKey + "\n" +
		"    IdentitiesOnly yes\n\n" +
		"Host *\n" + end + "\n\n")

	filename := filepath.Join(dir, "config")
	original, err := readPrivate(filename)
	exists := err == nil
	if errors.Is(err, os.ErrNotExist) {
		original = nil
	} else if err != nil {
		return "", fmt.Errorf("не удалось прочитать %s: %w", filename, err)
	}
	remaining, err := removeManagedBlock(original, begin, end)
	if err != nil {
		return "", fmt.Errorf("не удалось обновить %s: %w", filename, err)
	}
	updated := append(bytes.Clone(block), remaining...)
	if len(updated) > maxFileSize {
		return "", fmt.Errorf("%s после обновления превысит 4 МиБ", filename)
	}
	if bytes.Equal(updated, original) {
		return filename, nil
	}

	var random [12]byte
	if _, err = rand.Read(random[:]); err != nil {
		return "", err
	}
	temp := filename + ".ssh-key-setup-" + hex.EncodeToString(random[:])
	if err = writeNewPrivate(temp, updated); err != nil {
		return "", fmt.Errorf("не удалось записать временный SSH config: %w", err)
	}
	defer os.Remove(temp)

	current, currentErr := readPrivate(filename)
	currentExists := currentErr == nil
	if errors.Is(currentErr, os.ErrNotExist) {
		current = nil
	} else if currentErr != nil {
		return "", currentErr
	}
	if currentExists != exists || !bytes.Equal(current, original) {
		return "", fmt.Errorf("%s изменён другой программой; повторите настройку", filename)
	}
	if err = os.Rename(temp, filename); err != nil {
		return "", err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return "", err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	return filename, nil
}

func sshConfigQuote(value string) (string, error) {
	if strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("путь к ключу содержит символ, недопустимый в SSH config")
	}
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return "\"" + value + "\"", nil
}

func removeManagedBlock(data []byte, begin, end string) ([]byte, error) {
	start, _ := findConfigLine(data, begin, 0)
	if start < 0 {
		return bytes.Clone(data), nil
	}
	if another, _ := findConfigLine(data, begin, start+len(begin)); another >= 0 {
		return nil, fmt.Errorf("найдено несколько управляемых блоков %s", begin)
	}
	_, finish := findConfigLine(data, end, start+len(begin))
	if finish < 0 {
		return nil, fmt.Errorf("управляемый блок повреждён: отсутствует строка %q", end)
	}
	if finish < len(data) {
		if data[finish] == '\n' {
			finish++
		} else if finish+1 < len(data) && data[finish] == '\r' && data[finish+1] == '\n' {
			finish += 2
		}
	}
	// The generated block owns one blank separator line.
	if finish < len(data) {
		if data[finish] == '\n' {
			finish++
		} else if finish+1 < len(data) && data[finish] == '\r' && data[finish+1] == '\n' {
			finish += 2
		}
	}
	result := make([]byte, 0, len(data)-(finish-start))
	result = append(result, data[:start]...)
	result = append(result, data[finish:]...)
	return result, nil
}

// Return the start and first byte after a complete line, excluding its newline.
func findConfigLine(data []byte, expected string, offset int) (int, int) {
	for offset <= len(data) {
		lineEnd := bytes.IndexByte(data[offset:], '\n')
		if lineEnd < 0 {
			lineEnd = len(data)
		} else {
			lineEnd += offset
		}
		contentEnd := lineEnd
		if contentEnd > offset && data[contentEnd-1] == '\r' {
			contentEnd--
		}
		if string(data[offset:contentEnd]) == expected {
			return offset, lineEnd
		}
		if lineEnd == len(data) {
			break
		}
		offset = lineEnd + 1
	}
	return -1, -1
}
