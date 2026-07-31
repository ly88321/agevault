package archive

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ndavd/agevault/internal/utils"
)

func TarDirectory(inputSource string, destinationWriter io.Writer) error {
	exists, isDir := utils.Exists(inputSource)
	if !exists || !isDir {
		return errors.New("source does not exist or is not a directory")
	}
	source := filepath.Clean(inputSource)
	parent := filepath.Dir(source)
	writer := tar.NewWriter(destinationWriter)
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links are not supported: %s", path)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported file type: %s", path)
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		relativePath, err := filepath.Rel(parent, path)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(relativePath)
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if closeErr := writer.Close(); err == nil {
		err = closeErr
	}
	return err
}

func UnTar(input io.Reader, outputDestination string) error {
	reader := tar.NewReader(input)
	destination, err := filepath.Abs(outputDestination)
	if err != nil {
		return err
	}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		err = untarFile(reader, header, destination)
		if err != nil {
			return err
		}
	}
	return nil
}

func untarFile(r *tar.Reader, h *tar.Header, destination string) error {
	if filepath.IsAbs(h.Name) {
		return fmt.Errorf("absolute archive path: %s", h.Name)
	}
	path := filepath.Join(destination, h.Name)
	relativePath, err := filepath.Rel(destination, path)
	if err != nil || relativePath == ".." || len(relativePath) > 2 && relativePath[:3] == ".."+string(os.PathSeparator) {
		return fmt.Errorf("invalid archive path: %s", h.Name)
	}
	switch h.Typeflag {
	case tar.TypeDir:
		return os.MkdirAll(path, 0o700)
	case tar.TypeReg, tar.TypeRegA:
		// handled below
	default:
		return fmt.Errorf("unsupported archive entry type for %s", h.Name)
	}
	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return err
	}
	destinationFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, h.FileInfo().Mode().Perm())
	if err != nil {
		return err
	}
	defer destinationFile.Close()
	_, err = io.CopyN(destinationFile, r, h.Size)
	return err
}
