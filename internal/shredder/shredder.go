package shredder

import (
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ndavd/agevault/internal/utils"
)

func ShredFile(path string, iterations int) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	bufferSize := int64(1024 * 1024)
	if info.Size() < bufferSize {
		bufferSize = info.Size()
	}
	random := make([]byte, bufferSize)
	for i := 0; i < iterations; i++ {
		for offset := int64(0); offset < info.Size(); offset += int64(len(random)) {
			if _, err = rand.Read(random); err != nil {
				_ = file.Close()
				return err
			}
			length := int64(len(random))
			if remaining := info.Size() - offset; remaining < length {
				length = remaining
			}
			if _, err = file.WriteAt(random[:int(length)], offset); err != nil {
				_ = file.Close()
				return err
			}
		}
		if err = file.Sync(); err != nil {
			return err
		}
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}

func ShredDir(path string, iterations int) error {
	exists, isDir := utils.Exists(path)
	if !exists || !isDir {
		return errors.New("is not a directory or does not exist")
	}
	err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Type().IsRegular() {
			if err := ShredFile(path, iterations); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return os.RemoveAll(path)
}
