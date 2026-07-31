package archive

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func UnZip(inputReader bytes.Reader, outputDestination string) error {
	reader, err := zip.NewReader(&inputReader, inputReader.Size())
	if err != nil {
		return err
	}
	destination, err := filepath.Abs(outputDestination)
	if err != nil {
		return err
	}
	for _, f := range reader.File {
		err := unzipFile(f, destination)
		if err != nil {
			return err
		}
	}
	return nil
}

func unzipFile(f *zip.File, destination string) error {
	if filepath.IsAbs(f.Name) {
		return fmt.Errorf("absolute archive path: %s", f.Name)
	}
	path := filepath.Join(destination, f.Name)
	relativePath, err := filepath.Rel(destination, path)
	if err != nil || relativePath == ".." || len(relativePath) > 2 && relativePath[:3] == ".."+string(os.PathSeparator) {
		return fmt.Errorf("invalid archive path: %s", f.Name)
	}
	if f.FileInfo().IsDir() {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
		return nil
	}
	if !f.Mode().IsRegular() {
		return fmt.Errorf("unsupported archive entry type for %s", f.Name)
	}
	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return err
	}
	destinationFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.Mode().Perm())
	if err != nil {
		return err
	}
	defer destinationFile.Close()
	zippedFile, err := f.Open()
	if err != nil {
		return err
	}
	defer zippedFile.Close()
	_, err = io.Copy(destinationFile, zippedFile)
	return err
}

func IsZip(r io.Reader) bool {
	h := make([]byte, 4)
	if _, err := io.ReadFull(r, h); err != nil {
		return false
	}
	const zipMagicNumber = "PK\x03\x04"
	return bytes.Equal(h, []byte(zipMagicNumber))
}
