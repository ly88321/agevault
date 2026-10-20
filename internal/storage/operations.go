// Package storage isolates filesystem operations at vault commit boundaries.
// Production uses OS operations. Tests pass scoped replacements; no environment
// variable or command-line flag enables fault injection in the application.
package storage

import (
	"io"
	"os"

	"github.com/ndavd/agevault/internal/utils"
)

type File interface {
	io.Writer
	Name() string
	Chmod(os.FileMode) error
	Sync() error
	Close() error
}
type ReadFile interface {
	io.Reader
	Close() error
}

type Operations struct {
	CreateTemp func(string, string) (File, error)
	MkdirTemp  func(string, string) (string, error)
	OpenRead   func(string) (ReadFile, error)
	OpenSync   func(string) (File, error)
	OpenFile   func(*os.Root, string, int, os.FileMode) (File, error)
	MkdirAll   func(*os.Root, string, os.FileMode) error
	Link       func(string, string) error
	Rename     func(string, string) error
	Remove     func(string) error
	RemoveAll  func(string) error
	SyncDir    func(string) error
	Checkpoint func(string) error
}

func OS() Operations {
	return Operations{
		CreateTemp: func(dir, pattern string) (File, error) { return os.CreateTemp(dir, pattern) },
		MkdirTemp:  os.MkdirTemp,
		OpenRead:   func(name string) (ReadFile, error) { return os.Open(name) },
		OpenSync:   func(name string) (File, error) { return os.OpenFile(name, os.O_RDWR, 0) },
		OpenFile: func(root *os.Root, name string, flags int, mode os.FileMode) (File, error) {
			return root.OpenFile(name, flags, mode)
		},
		MkdirAll:  func(root *os.Root, name string, mode os.FileMode) error { return root.MkdirAll(name, mode) },
		Link:      os.Link,
		Rename:    os.Rename,
		Remove:    os.Remove,
		RemoveAll: os.RemoveAll,
		SyncDir:   utils.SyncDir,
	}
}
func (ops Operations) Reach(point string) error {
	if ops.Checkpoint != nil {
		return ops.Checkpoint(point)
	}
	return nil
}

const (
	CipherFileSynced          = "cipher-file-synced"
	CipherPublished           = "cipher-published"
	CipherDirectorySynced     = "cipher-directory-synced"
	LockBeforeShred           = "lock-before-shred"
	LockAfterShred            = "lock-after-shred"
	ExtractFileSynced         = "extract-file-synced"
	UnlockAuthenticated       = "unlock-authenticated"
	UnlockBeforePublish       = "unlock-before-publish"
	UnlockPublished           = "unlock-published"
	UnlockDirectorySynced     = "unlock-directory-synced"
	UnlockBeforeCipherRemoval = "unlock-before-cipher-removal"
	UnlockComplete            = "unlock-complete"
)
