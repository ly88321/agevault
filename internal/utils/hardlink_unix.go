//go:build unix

package utils

import (
	"io/fs"
	"syscall"
)

func HasHardLinks(info fs.FileInfo, _ string) (bool, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && st.Nlink > 1, nil
}
