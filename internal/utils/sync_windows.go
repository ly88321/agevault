//go:build windows

package utils

// Windows does not expose POSIX directory fsync through os.File.Sync.
func SyncDir(string) error { return nil }
