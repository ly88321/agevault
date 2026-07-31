package crypt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"filippo.io/age"
	"golang.org/x/term"
)

func EncryptToFile(destinationFilename string, data []byte, recipient age.Recipient) error {
	return EncryptToFileFromReader(destinationFilename, bytes.NewReader(data), recipient)
}

// EncryptToFileFromReader writes an encrypted file atomically. The destination is
// replaced only after encryption, flushing, and closing have all succeeded.
func EncryptToFileFromReader(destinationFilename string, source io.Reader, recipient age.Recipient) (err error) {
	directory := filepath.Dir(destinationFilename)
	file, err := os.CreateTemp(directory, ".agevault-*")
	if err != nil {
		return err
	}
	temporaryFilename := file.Name()
	defer func() {
		file.Close()
		if err != nil {
			_ = os.Remove(temporaryFilename)
		}
	}()
	if err = file.Chmod(0o600); err != nil {
		return err
	}
	writeCloser, err := age.Encrypt(file, recipient)
	if err != nil {
		return err
	}
	if _, err = io.Copy(writeCloser, source); err != nil {
		return err
	}
	if err = writeCloser.Close(); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryFilename, destinationFilename)
}

func DecryptToWriter(destinationWriter io.Writer, encryptedDataReader io.Reader, identity age.Identity) error {
	reader, err := age.Decrypt(encryptedDataReader, identity)
	if err != nil {
		return err
	}
	_, err = io.Copy(destinationWriter, reader)
	return err
}

func ReadSecret(label string, confirm bool) (string, error) {
	prefix := ""
	if confirm {
		prefix = "create "
	}
	fmt.Printf("%s%s: ", prefix, label)
	secretBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	if len(secretBytes) == 0 {
		return "", errors.New("passphrase cannot be empty")
	}
	if confirm {
		fmt.Printf("confirm %s: ", label)
		confirmSecretBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return "", err
		}
		if string(secretBytes) != string(confirmSecretBytes) {
			return "", fmt.Errorf("%s not matching", label)
		}
	}
	return string(secretBytes), nil
}
