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
	"github.com/ndavd/agevault/internal/storage"
	"golang.org/x/term"
)

func EncryptToFile(destinationFilename string, data []byte, recipients ...age.Recipient) error {
	return EncryptToFileFromReader(destinationFilename, bytes.NewReader(data), recipients...)
}

// EncryptToFileFromReader writes an encrypted file atomically. The destination is
// published without replacing an existing file, after flushing and closing succeed.
func EncryptToFileFromReader(destinationFilename string, source io.Reader, recipients ...age.Recipient) error {
	return EncryptToFileFromReaderWithOperations(destinationFilename, source, storage.OS(), recipients...)
}

func EncryptToFileFromReaderWithOperations(destinationFilename string, source io.Reader, ops storage.Operations, recipients ...age.Recipient) (err error) {
	directory := filepath.Dir(destinationFilename)
	file, err := ops.CreateTemp(directory, ".agevault-*")
	if err != nil {
		return err
	}
	temporaryFilename := file.Name()
	defer func() {
		file.Close()
		if err != nil {
			if cleanupErr := ops.Remove(temporaryFilename); cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("could not remove temporary ciphertext %q: %w", temporaryFilename, cleanupErr))
			}
		}
	}()
	if err = file.Chmod(0o600); err != nil {
		return err
	}
	writeCloser, err := age.Encrypt(checkedWriter{file}, recipients...)
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
	if err = ops.Reach(storage.CipherFileSynced); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	// Link publishes a complete file without replacing a concurrently created destination.
	if err = ops.Link(temporaryFilename, destinationFilename); err != nil {
		return err
	}
	if err = ops.Reach(storage.CipherPublished); err != nil {
		return err
	}
	if err = ops.Remove(temporaryFilename); err != nil {
		return err
	}
	if err = ops.SyncDir(directory); err != nil {
		return err
	}
	return ops.Reach(storage.CipherDirectorySynced)
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

// Convert a short successful write into a failure even for writer users which
// only inspect the returned error (for example age header/final-chunk writes).
type checkedWriter struct{ io.Writer }

func (w checkedWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}
