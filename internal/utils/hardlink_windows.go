//go:build windows

package utils

import (
	"golang.org/x/sys/windows"
	"io/fs"
)

func HasHardLinks(info fs.FileInfo, path string) (bool, error) {
	if !info.Mode().IsRegular() {
		return false, nil
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	var data windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &data); err != nil {
		return false, err
	}
	return data.NumberOfLinks > 1, nil
}
