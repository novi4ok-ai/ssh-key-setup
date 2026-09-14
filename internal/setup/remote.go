package setup

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func remoteRead(client *sftp.Client, filename string, uid uint32) ([]byte, bool, error) {
	info, err := client.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	st, ok := info.Sys().(*sftp.FileStat)
	if !info.Mode().IsRegular() || !ok || st.UID != uid {
		return nil, false, fmt.Errorf("%s должен быть обычным файлом владельца домашнего каталога, без символических ссылок", filename)
	}
	if info.Size() > maxFileSize {
		return nil, false, fmt.Errorf("%s превышает 4 МиБ", filename)
	}
	f, err := client.Open(filename)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err == nil && len(data) > maxFileSize {
		err = fmt.Errorf("%s превышает 4 МиБ", filename)
	}
	return data, true, err
}

func remoteWriteNew(client *sftp.Client, filename string, data []byte) error {
	f, err := client.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = client.Remove(filename)
		}
	}()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if _, supported := client.HasExtension("fsync@openssh.com"); supported {
		if err = f.Sync(); err != nil {
			return err
		}
	}
	if err = f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

// Update through SFTP, never interpolate user input into remote shell commands.
// A cooperative lock and a last-minute comparison protect existing content.
func installKey(client *sftp.Client, public ssh.PublicKey) (already bool, backup string, retErr error) {
	home, err := client.RealPath(".")
	if err != nil || !path.IsAbs(home) {
		return false, "", fmt.Errorf("не удалось определить домашний каталог через SFTP")
	}
	homeInfo, err := client.Stat(home)
	if err != nil {
		return false, "", err
	}
	homeStat, ok := homeInfo.Sys().(*sftp.FileStat)
	if !ok || !homeInfo.IsDir() {
		return false, "", fmt.Errorf("сервер не сообщает владельца домашнего каталога")
	}
	dir := path.Join(home, ".ssh")
	info, err := client.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err = client.Mkdir(dir); err != nil {
			return false, "", err
		}
		info, err = client.Lstat(dir)
	}
	if err != nil {
		return false, "", err
	}
	st, ok := info.Sys().(*sftp.FileStat)
	if !info.IsDir() || !ok || st.UID != homeStat.UID {
		return false, "", fmt.Errorf("%s должен быть каталогом владельца home, без символических ссылок", dir)
	}
	if err = client.Chmod(dir, 0700); err != nil {
		return false, "", err
	}
	lock := path.Join(dir, ".ssh-key-setup.install.lock")
	if err = client.Mkdir(lock); err != nil {
		return false, "", fmt.Errorf("не удалось заблокировать %s: возможно, идёт другая настройка или осталась блокировка после обрыва связи", lock)
	}
	defer func() {
		if err := client.RemoveDirectory(lock); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("не удалось убрать блокировку %s; после проверки отсутствия другой настройки удалите этот пустой каталог на сервере", lock))
		}
	}()
	filename := path.Join(dir, "authorized_keys")
	original, exists, err := remoteRead(client, filename, homeStat.UID)
	if err != nil {
		return false, "", err
	}
	for _, line := range bytes.Split(original, []byte{'\n'}) {
		key, _, options, _, parseErr := ssh.ParseAuthorizedKey(line)
		if parseErr == nil && bytes.Equal(key.Marshal(), public.Marshal()) {
			if len(options) > 0 {
				return false, "", fmt.Errorf("этот ключ уже установлен с ограничениями; программа не будет обходить или изменять их")
			}
			return true, "", client.Chmod(filename, 0600)
		}
	}
	_, atomicReplace := client.HasExtension("posix-rename@openssh.com")
	if exists && !atomicReplace {
		return false, "", fmt.Errorf("SFTP-сервер не поддерживает безопасную атомарную замену authorized_keys (posix-rename)")
	}
	var random [12]byte
	if _, err = rand.Read(random[:]); err != nil {
		return false, "", err
	}
	suffix := hex.EncodeToString(random[:])
	temp := path.Join(dir, ".authorized_keys.ssh-key-setup-"+suffix)
	updated := bytes.Clone(original)
	if len(updated) > 0 && updated[len(updated)-1] != '\n' {
		updated = append(updated, '\n')
	}
	updated = append(updated, []byte(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))+" ssh-key-setup\n")...)
	if len(updated) > maxFileSize {
		return false, "", fmt.Errorf("authorized_keys после добавления превысит 4 МиБ")
	}
	if err = remoteWriteNew(client, temp, updated); err != nil {
		return false, "", err
	}
	defer client.Remove(temp)
	if exists {
		backup = filename + ".backup-" + suffix
		if err = remoteWriteNew(client, backup, original); err != nil {
			return false, "", fmt.Errorf("резервная копия: %w", err)
		}
	}
	current, currentExists, err := remoteRead(client, filename, homeStat.UID)
	if err != nil {
		return false, backup, err
	}
	if currentExists != exists || !bytes.Equal(current, original) {
		return false, backup, fmt.Errorf("authorized_keys изменён другой программой; повторите настройку")
	}
	if atomicReplace {
		err = client.PosixRename(temp, filename)
	} else {
		err = client.Rename(temp, filename)
	}
	if err != nil {
		return false, backup, err
	}
	return false, backup, nil
}
