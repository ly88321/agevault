package archive

import (
	"archive/zip"
	"bytes"
	"fmt"
	"github.com/ndavd/agevault/internal/storage"
	"io"
	"os"
)

func UnZip(inputReader bytes.Reader, outputDestination string, vaultName string) error {
	return UnZipWithOperations(inputReader, outputDestination, vaultName, storage.OS())
}
func UnZipWithOperations(inputReader bytes.Reader, outputDestination, vaultName string, ops storage.Operations) error {
	reader, err := zip.NewReader(&inputReader, inputReader.Size())
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(outputDestination)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, f := range reader.File {
		name, e := safeName(f.Name, vaultName)
		if e != nil {
			return e
		}
		if f.FileInfo().IsDir() {
			if e = ops.MkdirAll(root, name, 0700); e != nil {
				return e
			}
			continue
		}
		if !f.Mode().IsRegular() {
			return fmt.Errorf("unsupported archive type for %s", f.Name)
		}
		r, e := f.Open()
		if e != nil {
			return e
		}
		e = extractFile(root, name, r, -1, ops)
		closeErr := r.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func IsZip(r io.Reader) bool {
	h := make([]byte, 4)
	if _, err := io.ReadFull(r, h); err != nil {
		return false
	}
	const zipMagicNumber = "PK\x03\x04"
	return bytes.Equal(h, []byte(zipMagicNumber))
}
