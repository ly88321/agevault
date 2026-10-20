package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"filippo.io/age"
	"github.com/ndavd/agevault/internal/archive"
	"github.com/ndavd/agevault/internal/crypt"
	"github.com/ndavd/agevault/internal/recipients"
	"github.com/ndavd/agevault/internal/shredder"
	"github.com/ndavd/agevault/internal/storage"
)

type faultFixture struct {
	identity age.Identity
	key      string
}

func faultPayloads() map[string][]byte {
	return map[string][]byte{"one.bin": bytes.Repeat([]byte("first sensitive payload\n"), 6000), "two.bin": bytes.Repeat([]byte("second payload\n"), 3000)}
}
func faultMakeFixture(t *testing.T, locked, pq bool) faultFixture {
	t.Helper()
	securityMkdir(t, "vault")
	identity, recipient, err := generateIdentity(pq)
	if err != nil {
		t.Fatal(err)
	}
	sr, err := age.NewScryptRecipient(testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	// Test fixture only: keep subprocess/fault matrices fast; production uses age defaults.
	sr.SetWorkFactor(10)
	if err = crypt.EncryptToFile(".vault.age", []byte(identity.String()), sr); err != nil {
		t.Fatal(err)
	}
	if err = recipients.Append("vault", "vault", recipient); err != nil {
		t.Fatal(err)
	}
	for name, data := range faultPayloads() {
		securityWrite(t, filepath.Join("vault", name), data)
	}
	if locked {
		if _, err = Lock("vault", "vault"); err != nil {
			t.Fatal(err)
		}
	}
	return faultFixture{identity: identity.(age.Identity), key: ".vault.age"}
}
func faultAssertPlain(t *testing.T, root string) {
	t.Helper()
	for name, want := range faultPayloads() {
		got := securityRead(t, filepath.Join(root, name))
		if !bytes.Equal(got, want) {
			t.Fatalf("payload %s changed", name)
		}
	}
}
func faultAssertCipher(t *testing.T, data []byte, id age.Identity) {
	t.Helper()
	r, err := age.Decrypt(bytes.NewReader(data), id)
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err = archive.UnTar(r, dest, "vault"); err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(io.Discard, r); err != nil {
		t.Fatal(err)
	}
	faultAssertPlain(t, filepath.Join(dest, "vault"))
}
func faultAssertNoStaging(t *testing.T) {
	t.Helper()
	paths, err := filepath.Glob(".agevault-unlock-*")
	if err != nil || len(paths) != 0 {
		t.Fatalf("staging leftovers: %v, %v", paths, err)
	}
}

type diskFaultFile struct {
	storage.File
	remaining int
	writeErr  error
	short     bool
	syncErr   error
	closeErr  error
}

func (f *diskFaultFile) Write(p []byte) (int, error) {
	if f.short {
		return f.File.Write(p[:len(p)/2])
	}
	if f.writeErr == nil {
		return f.File.Write(p)
	}
	if f.remaining <= 0 {
		return 0, f.writeErr
	}
	nmax := len(p)
	if nmax > f.remaining {
		nmax = f.remaining
	}
	n, err := f.File.Write(p[:nmax])
	f.remaining -= n
	if err != nil {
		return n, err
	}
	if nmax < len(p) || f.remaining == 0 {
		return n, f.writeErr
	}
	return n, nil
}
func (f *diskFaultFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.File.Sync()
}
func (f *diskFaultFile) Close() error {
	err := f.File.Close()
	if f.closeErr != nil {
		return f.closeErr
	}
	return err
}
func wrapCipherFile(ops *storage.Operations, wrap func(storage.File) storage.File) {
	create := ops.CreateTemp
	ops.CreateTemp = func(dir, pattern string) (storage.File, error) {
		f, err := create(dir, pattern)
		if err != nil {
			return nil, err
		}
		return wrap(f), nil
	}
}
func wrapExtractFile(ops *storage.Operations, wrap func(storage.File) storage.File) {
	open := ops.OpenFile
	ops.OpenFile = func(root *os.Root, name string, flags int, mode os.FileMode) (storage.File, error) {
		f, err := open(root, name, flags, mode)
		if err != nil {
			return nil, err
		}
		return wrap(f), nil
	}
}

type diskFaultRead struct {
	storage.ReadFile
	remaining int
	closeErr  error
}

func (f *diskFaultRead) Read(p []byte) (int, error) {
	if f.remaining <= 0 {
		return 0, syscall.EIO
	}
	if len(p) > f.remaining {
		p = p[:f.remaining]
	}
	n, err := f.ReadFile.Read(p)
	f.remaining -= n
	return n, err
}
func (f *diskFaultRead) Close() error {
	err := f.ReadFile.Close()
	if f.closeErr != nil {
		return f.closeErr
	}
	return err
}

func TestKeepCiphertext(t *testing.T) {
	for _, pq := range []bool{false, true} {
		t.Run(map[bool]string{false: "classical", true: "hybrid"}[pq], func(t *testing.T) {
			runInIsolatedDir(t)
			fixture := faultMakeFixture(t, true, pq)
			before := securityRead(t, "vault.age")
			options := defaultVaultOptions()
			options.keepCiphertext = true
			options.shredFile = func(string, int) error { t.Fatal("retention must never call ciphertext shredding"); return syscall.EIO }
			if err := unlockWithOptions("vault", "vault", constPassphrase, options, fixture.key); err != nil {
				t.Fatal(err)
			}
			faultAssertPlain(t, "vault")
			if !bytes.Equal(before, securityRead(t, "vault.age")) {
				t.Fatal("retained ciphertext modified")
			}
			if _, err := Lock("vault", "vault"); err == nil {
				t.Fatal("retained ciphertext overwritten")
			}
			faultAssertPlain(t, "vault")
			faultAssertNoStaging(t)
		})
	}
}
func TestKeepCiphertextLegacyZip(t *testing.T) {
	runInIsolatedDir(t)
	fixture := faultMakeFixture(t, false, false)
	rs, err := recipients.Read("vault")
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, data := range faultPayloads() {
		f, e := w.Create("vault/" + name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(data); e != nil {
			t.Fatal(e)
		}
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = crypt.EncryptToFile("vault.age", b.Bytes(), rs...); err != nil {
		t.Fatal(err)
	}
	if err = os.RemoveAll("vault"); err != nil {
		t.Fatal(err)
	}
	before := securityRead(t, "vault.age")
	options := defaultVaultOptions()
	options.keepCiphertext = true
	if err = unlockWithOptions("vault", "vault", constPassphrase, options, fixture.key); err != nil {
		t.Fatal(err)
	}
	faultAssertPlain(t, "vault")
	if !bytes.Equal(before, securityRead(t, "vault.age")) {
		t.Fatal("legacy ciphertext modified")
	}
}
func TestKeepCiphertextOptionParsing(t *testing.T) {
	for _, args := range [][]string{{"--keep-ciphertext"}, {"--key", "key.age", "--keep-ciphertext"}, {"--keep-ciphertext", "--key", "key.age"}} {
		opts, err := parseOptions("unlock", args)
		if err != nil || !opts.keepCiphertext {
			t.Fatalf("%v: %+v %v", args, opts, err)
		}
	}
	for _, action := range []string{"lock", "keygen"} {
		if _, err := parseOptions(action, []string{"--keep-ciphertext"}); err == nil {
			t.Fatalf("retention accepted for %s", action)
		}
	}
	for _, args := range [][]string{{"--key"}, {"--key", "--keep-ciphertext"}} {
		if _, err := parseOptions("unlock", args); err == nil {
			t.Fatalf("missing key path accepted: %v", args)
		}
	}
	opts, err := parseOptions("unlock", nil)
	if err != nil || opts.keepCiphertext {
		t.Fatal("retention changed default behavior")
	}
}

func TestLockDiskFaultsPreservePlaintext(t *testing.T) {
	cases := []string{"create-ENOSPC", "write-ENOSPC", "short-write", "sync-EIO", "close-EIO", "link-EIO", "temp-remove-EIO", "directory-sync-EIO"}
	for _, point := range cases {
		t.Run(point, func(t *testing.T) {
			runInIsolatedDir(t)
			fixture := faultMakeFixture(t, false, false)
			options := defaultVaultOptions()
			shredded := false
			options.shredDir = func(string, int) error { shredded = true; return errors.New("must not shred") }
			switch point {
			case "create-ENOSPC":
				options.disk.CreateTemp = func(string, string) (storage.File, error) { return nil, syscall.ENOSPC }
			case "write-ENOSPC":
				wrapCipherFile(&options.disk, func(f storage.File) storage.File {
					return &diskFaultFile{File: f, remaining: 4096, writeErr: syscall.ENOSPC}
				})
			case "short-write":
				wrapCipherFile(&options.disk, func(f storage.File) storage.File { return &diskFaultFile{File: f, short: true} })
			case "sync-EIO":
				wrapCipherFile(&options.disk, func(f storage.File) storage.File { return &diskFaultFile{File: f, syncErr: syscall.EIO} })
			case "close-EIO":
				wrapCipherFile(&options.disk, func(f storage.File) storage.File { return &diskFaultFile{File: f, closeErr: syscall.EIO} })
			case "link-EIO":
				options.disk.Link = func(string, string) error { return syscall.EIO }
			case "temp-remove-EIO":
				options.disk.Remove = func(string) error { return syscall.EIO }
			case "directory-sync-EIO":
				options.disk.SyncDir = func(string) error { return syscall.EIO }
			}
			if _, err := lockWithOptions("vault", "vault", constPassphrase, options); err == nil {
				t.Fatal("injected disk fault ignored")
			}
			if shredded {
				t.Fatal("erased source after incomplete commit")
			}
			faultAssertPlain(t, "vault")
			if data, err := os.ReadFile("vault.age"); err == nil {
				faultAssertCipher(t, data, fixture.identity)
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
		})
	}
}

func TestUnlockDiskFaultsPreserveRecovery(t *testing.T) {
	cases := []string{"staging-ENOSPC", "input-open-EIO", "read-EIO", "input-close-EIO", "open-EACCES", "mkdir-ENOSPC", "write-ENOSPC", "short-write", "sync-EIO", "close-EIO", "tree-file-sync-EIO", "tree-file-close-EIO", "tree-directory-sync-EIO", "rename-EIO", "parent-sync-EIO"}
	for _, point := range cases {
		t.Run(point, func(t *testing.T) {
			runInIsolatedDir(t)
			fixture := faultMakeFixture(t, true, false)
			before := securityRead(t, "vault.age")
			options := defaultVaultOptions()
			removed := false
			options.shredFile = func(string, int) error { removed = true; return errors.New("must not remove source ciphertext") }
			switch point {
			case "input-open-EIO":
				options.disk.OpenRead = func(string) (storage.ReadFile, error) { return nil, syscall.EIO }
			case "staging-ENOSPC":
				options.disk.MkdirTemp = func(string, string) (string, error) { return "", syscall.ENOSPC }
			case "read-EIO", "input-close-EIO":
				open := options.disk.OpenRead
				options.disk.OpenRead = func(name string) (storage.ReadFile, error) {
					f, err := open(name)
					if err != nil {
						return nil, err
					}
					remaining := 70000
					var closeErr error
					if point == "input-close-EIO" {
						remaining = 1 << 30
						closeErr = syscall.EIO
					}
					return &diskFaultRead{ReadFile: f, remaining: remaining, closeErr: closeErr}, nil
				}
			case "open-EACCES":
				options.disk.OpenFile = func(*os.Root, string, int, os.FileMode) (storage.File, error) { return nil, syscall.EACCES }
			case "mkdir-ENOSPC":
				options.disk.MkdirAll = func(*os.Root, string, os.FileMode) error { return syscall.ENOSPC }
			case "write-ENOSPC":
				wrapExtractFile(&options.disk, func(f storage.File) storage.File {
					return &diskFaultFile{File: f, remaining: 4096, writeErr: syscall.ENOSPC}
				})
			case "short-write":
				wrapExtractFile(&options.disk, func(f storage.File) storage.File { return &diskFaultFile{File: f, short: true} })
			case "sync-EIO":
				wrapExtractFile(&options.disk, func(f storage.File) storage.File { return &diskFaultFile{File: f, syncErr: syscall.EIO} })
			case "close-EIO":
				wrapExtractFile(&options.disk, func(f storage.File) storage.File { return &diskFaultFile{File: f, closeErr: syscall.EIO} })
			case "tree-file-sync-EIO", "tree-file-close-EIO":
				open := options.disk.OpenSync
				options.disk.OpenSync = func(name string) (storage.File, error) {
					f, err := open(name)
					if err != nil {
						return nil, err
					}
					if point == "tree-file-close-EIO" {
						return &diskFaultFile{File: f, closeErr: syscall.EIO}, nil
					}
					return &diskFaultFile{File: f, syncErr: syscall.EIO}, nil
				}
			case "tree-directory-sync-EIO":
				options.disk.SyncDir = func(string) error { return syscall.EIO }
			case "rename-EIO":
				options.disk.Rename = func(string, string) error { return syscall.EIO }
			case "parent-sync-EIO":
				normal := options.disk.SyncDir
				options.disk.SyncDir = func(name string) error {
					if name == "." {
						return syscall.EIO
					}
					return normal(name)
				}
			}
			if err := unlockWithOptions("vault", "vault", constPassphrase, options, fixture.key); err == nil {
				t.Fatal("disk fault ignored")
			}
			if removed {
				t.Fatal("removed ciphertext before successful restore commit")
			}
			if !bytes.Equal(before, securityRead(t, "vault.age")) {
				t.Fatal("source ciphertext changed")
			}
			faultAssertNoStaging(t)
			if point == "parent-sync-EIO" {
				faultAssertPlain(t, "vault")
			} else {
				if _, err := os.Lstat("vault"); !os.IsNotExist(err) {
					t.Fatal("partial restore published")
				}
				recovery := defaultVaultOptions()
				recovery.keepCiphertext = true
				if err := unlockWithOptions("vault", "vault", constPassphrase, recovery, fixture.key); err != nil {
					t.Fatal(err)
				}
				faultAssertPlain(t, "vault")
			}
		})
	}
}

func TestFailedPrivateStagingCleanupIsReported(t *testing.T) {
	runInIsolatedDir(t)
	fixture := faultMakeFixture(t, true, false)
	before := securityRead(t, "vault.age")
	options := defaultVaultOptions()
	wrapExtractFile(&options.disk, func(f storage.File) storage.File {
		return &diskFaultFile{File: f, remaining: 4096, writeErr: syscall.ENOSPC}
	})
	options.disk.RemoveAll = func(string) error { return syscall.EIO }
	err := unlockWithOptions("vault", "vault", constPassphrase, options, fixture.key)
	if !errors.Is(err, syscall.ENOSPC) || !errors.Is(err, syscall.EIO) || !strings.Contains(err.Error(), "private staging directory") {
		t.Fatalf("cleanup failure hidden: %v", err)
	}
	if !bytes.Equal(before, securityRead(t, "vault.age")) {
		t.Fatal("ciphertext changed")
	}
	leftovers, e := filepath.Glob(".agevault-unlock-*")
	if e != nil || len(leftovers) != 1 {
		t.Fatalf("expected reported private staging: %v %v", leftovers, e)
	}
}
func TestPartialShredFailuresRemainRecoverable(t *testing.T) {
	t.Run("lock", func(t *testing.T) {
		runInIsolatedDir(t)
		fixture := faultMakeFixture(t, false, false)
		options := defaultVaultOptions()
		options.shredDir = func(string, int) error {
			if err := shredder.ShredFile("vault/one.bin", 1); err != nil {
				return err
			}
			return syscall.EIO
		}
		if _, err := lockWithOptions("vault", "vault", constPassphrase, options); !errors.Is(err, syscall.EIO) {
			t.Fatalf("shred error lost: %v", err)
		}
		faultAssertCipher(t, securityRead(t, "vault.age"), fixture.identity)
		if err := os.Rename("vault", "partial-source"); err != nil {
			t.Fatal(err)
		}
		recovery := defaultVaultOptions()
		recovery.keepCiphertext = true
		if err := unlockWithOptions("vault", "vault", constPassphrase, recovery, fixture.key); err != nil {
			t.Fatal(err)
		}
		faultAssertPlain(t, "vault")
	})
	t.Run("unlock", func(t *testing.T) {
		runInIsolatedDir(t)
		fixture := faultMakeFixture(t, true, false)
		options := defaultVaultOptions()
		options.shredFile = func(name string, _ int) error {
			f, err := os.OpenFile(name, os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			defer f.Close()
			if _, err = f.WriteAt([]byte("damaged"), 0); err != nil {
				return err
			}
			return syscall.EIO
		}
		err := unlockWithOptions("vault", "vault", constPassphrase, options, fixture.key)
		if !errors.Is(err, syscall.EIO) || !strings.Contains(err.Error(), "vault restored") {
			t.Fatalf("ambiguous cleanup failure: %v", err)
		}
		faultAssertPlain(t, "vault")
	})
}
func TestCipherRemovalFollowsDurableRestore(t *testing.T) {
	runInIsolatedDir(t)
	fixture := faultMakeFixture(t, true, false)
	options := defaultVaultOptions()
	published, parentSynced, removed := false, false, false
	rename := options.disk.Rename
	options.disk.Rename = func(from, to string) error {
		if err := rename(from, to); err != nil {
			return err
		}
		published = true
		return nil
	}
	sync := options.disk.SyncDir
	options.disk.SyncDir = func(name string) error {
		if err := sync(name); err != nil {
			return err
		}
		if name == "." && published {
			parentSynced = true
		}
		return nil
	}
	options.shredFile = func(name string, iterations int) error {
		if !published || !parentSynced {
			t.Fatal("ciphertext removed before restore commit")
		}
		faultAssertPlain(t, "vault")
		removed = true
		return shredder.ShredFile(name, iterations)
	}
	if err := unlockWithOptions("vault", "vault", constPassphrase, options, fixture.key); err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("default behavior no longer removes ciphertext")
	}
}
