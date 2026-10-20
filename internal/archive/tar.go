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
		if linked, e := utils.HasHardLinks(info, path); e != nil {
			return e
		} else if linked {
			return fmt.Errorf("hard linked file: %s", path)
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

func UnTar(input io.Reader, outputDestination string, vaultName string) error {
	root, err := os.OpenRoot(outputDestination)
	if err != nil {
		return err
	}
	defer root.Close()
	reader := tar.NewReader(input)
	for {
		h, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name, err := safeName(h.Name, vaultName)
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err = root.MkdirAll(name, 0700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err = extractFile(root, name, reader, h.Size); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported archive type for %s", h.Name)
		}
	}
}
