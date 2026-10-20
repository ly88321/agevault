package archive

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

func safeName(name, vault string) (string, error) {
	clean := path.Clean(name)
	if strings.ContainsRune(name, 0) || strings.HasPrefix(name, "/") || clean == ".." || strings.HasPrefix(clean, "../") || (clean != vault && !strings.HasPrefix(clean, vault+"/")) {
		return "", fmt.Errorf("invalid archive path: %s", name)
	}
	// POSIX names containing ':' or backslashes are ordinary filenames. Preserve
	// them on POSIX for legacy compatibility; Windows must reject device/ADS aliases.
	if runtime.GOOS != "windows" {
		return clean, nil
	}
	if strings.ContainsAny(name, `\\:<>"|?*`) || !filepath.IsLocal(filepath.FromSlash(clean)) {
		return "", fmt.Errorf("unsafe Windows archive path: %s", name)
	}
	for _, part := range strings.Split(clean, "/") {
		base := strings.ToUpper(strings.Split(part, ".")[0])
		if strings.TrimRight(part, ". ") != part || base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9') {
			return "", fmt.Errorf("unsafe archive path: %s", name)
		}
	}
	return clean, nil
}
func extractFile(root *os.Root, name string, r io.Reader, size int64) error {
	if err := root.MkdirAll(path.Dir(name), 0700); err != nil {
		return err
	}
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if size < 0 {
		_, err = io.Copy(f, r)
	} else {
		_, err = io.CopyN(f, r, size)
	}
	if err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return f.Close()
}
