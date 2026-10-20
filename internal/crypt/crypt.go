package crypt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"filippo.io/age"
	"github.com/ndavd/agevault/internal/utils"
	"golang.org/x/term"
)

func EncryptToFile(destinationFilename string, data []byte, recipients ...age.Recipient) error {
	return EncryptToFileFromReader(destinationFilename, bytes.NewReader(data), recipients...)
}

// EncryptToFileFromReader writes an encrypted file atomically. The destination is
// published without replacing an existing file, after flushing and closing succeed.
func EncryptToFileFromReader(destinationFilename string, source io.Reader, recipients ...age.Recipient) (err error) {
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
	writeCloser, err := age.Encrypt(file, recipients...)
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
	// Link publishes a complete file without replacing a concurrently created destination.
	if err = os.Link(temporaryFilename, destinationFilename); err != nil {
		return err
	}
	_ = os.Remove(temporaryFilename)
	return utils.SyncDir(directory)
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

func Fingerprint(recipient fmt.Stringer) string {
	sum := sha256.Sum256([]byte(recipient.String()))
	return hex.EncodeToString(sum[:16])
}
