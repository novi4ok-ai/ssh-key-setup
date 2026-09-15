package setup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Preview only inspects local files. Remote state is deliberately not assumed.
func (s Service) Preview(ctx context.Context, in Input) (result Result, err error) {
	if err := ctx.Err(); err != nil {
		return result, err
	}
	in.DryRun = true
	c, err := Normalize(in)
	if err != nil {
		return result, err
	}
	dir, err := s.inspectDir()
	if err != nil {
		return result, err
	}
	keyPath := keyFilename(dir, c)
	keyAction := "создать новый ключ Ed25519"
	data, err := readLocal(keyPath, false)
	clear(data)
	if err == nil {
		keyAction = "использовать существующий ключ (его работоспособность ещё не проверена)"
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	begin, end, block, err := clientBlock(c, keyPath)
	if err != nil {
		return result, err
	}
	filename := filepath.Join(dir, "config")
	original, err := readLocal(filename, false)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	remaining, err := removeManagedBlock(original, begin, end)
	if err != nil {
		return result, err
	}
	updated := append(bytes.Clone(block), remaining...)
	if len(updated) > maxFileSize {
		return result, fmt.Errorf("SSH config после обновления превысит 4 МиБ")
	}
	configAction := "добавить или обновить управляемый блок после проверки входа"
	if bytes.Equal(original, updated) {
		configAction = "блок уже соответствует выбранным параметрам"
	}
	result.Preview = fmt.Sprintf("ПРЕДПРОСМОТР — файлы не изменялись, подключения не выполнялись\n"+
		"Сервер: %s, пользователь: %s\nКлюч: %s\nДействие: %s\n"+
		"Открытая часть: %s.pub\nSSH config: %s\nДействие: %s\n\n%s\n"+
		"При настройке новый ключ сервера может быть добавлен в %s.\n"+
		"Если вход существующим ключом не работает, после входа по паролю будет проверен серверный ~/.ssh/authorized_keys.\n"+
		"При необходимости добавления ключа существующий authorized_keys сначала получит резервную копию.\n"+
		"Планируемая команда после успешной проверки: %s\n", c.Address(), c.User, keyPath, keyAction,
		keyPath, filename, configAction, block, filepath.Join(dir, "known_hosts"), connectCommand(c))
	return result, nil
}
