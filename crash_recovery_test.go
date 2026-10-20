package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ndavd/agevault/internal/shredder"
	"github.com/ndavd/agevault/internal/storage"
)

const abruptExit = 86

// All environment handling and immediate exits live in _test.go. The application
// has no environment-controlled fault injection or crash flags.
func TestCrashHelperProcess(t *testing.T) {
	if os.Getenv("AGEVAULT_CRASH_TEST_CHILD") != "1" {
		return
	}
	point, action := os.Getenv("AGEVAULT_CRASH_TEST_POINT"), os.Getenv("AGEVAULT_CRASH_TEST_ACTION")
	options := defaultVaultOptions()
	options.disk.Checkpoint = func(actual string) error {
		if actual == point {
			os.Exit(abruptExit)
		}
		return nil
	}
	if point == "cipher-mid-write" {
		wrapCipherFile(&options.disk, func(f storage.File) storage.File { return crashWriteFile{f} })
	}
	if point == "restore-mid-write" {
		open := options.disk.OpenFile
		options.disk.OpenFile = func(root *os.Root, name string, flags int, mode os.FileMode) (storage.File, error) {
			f, err := open(root, name, flags, mode)
			if err != nil {
				return nil, err
			}
			if name == "vault/one.bin" {
				return crashWriteFile{f}, nil
			}
			return f, nil
		}
	}
	if point == "lock-partial-shred" {
		options.shredDir = func(string, int) error {
			if err := shredder.ShredFile("vault/one.bin", 1); err != nil {
				return err
			}
			os.Exit(abruptExit)
			return nil
		}
	}
	var err error
	if action == "lock" {
		_, err = lockWithOptions("vault", "vault", constPassphrase, options)
	} else {
		err = unlockWithOptions("vault", "vault", constPassphrase, options, ".vault.age")
	}
	if err != nil {
		t.Logf("checkpoint not reached: %v", err)
	}
	os.Exit(87)
}

type crashWriteFile struct{ storage.File }

func (f crashWriteFile) Write(p []byte) (int, error) {
	limit := len(p)
	if limit > 64 {
		limit = 64
	}
	n, err := f.File.Write(p[:limit])
	if err != nil {
		return n, err
	}
	os.Exit(abruptExit)
	return n, nil
}
func runCrashChild(t *testing.T, action, point string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashHelperProcess$", "-test.v")
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "AGEVAULT_CRASH_TEST_CHILD=1", "AGEVAULT_CRASH_TEST_ACTION="+action, "AGEVAULT_CRASH_TEST_POINT="+point)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("crash subprocess timed out: %s", output)
	}
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != abruptExit {
		t.Fatalf("did not terminate at %s: %v, %s", point, err, output)
	}
}
func TestAbruptLockRecovery(t *testing.T) {
	points := []string{"cipher-mid-write", storage.CipherFileSynced, storage.CipherPublished, storage.CipherDirectorySynced, storage.LockBeforeShred, "lock-partial-shred", storage.LockAfterShred}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			runInIsolatedDir(t)
			fixture := faultMakeFixture(t, false, false)
			runCrashChild(t, "lock", point)
			data, err := os.ReadFile("vault.age")
			if os.IsNotExist(err) {
				faultAssertPlain(t, "vault")
				// An uncommitted encrypted temporary file must not block a safe retry.
				if _, err = Lock("vault", "vault"); err != nil {
					t.Fatal(err)
				}
				data = securityRead(t, "vault.age")
			} else if err != nil {
				t.Fatal(err)
			} else {
				faultAssertCipher(t, data, fixture.identity)
				if point != storage.LockAfterShred {
					if point != "lock-partial-shred" {
						faultAssertPlain(t, "vault")
					}
					if _, err = Lock("vault", "vault"); err == nil {
						t.Fatal("retry overwrote committed ciphertext")
					}
					// Preserve any original/partially erased source for inspection before recovery.
					if err = os.Rename("vault", "source-before-crash"); err != nil {
						t.Fatal(err)
					}
				}
			}
			recovery := defaultVaultOptions()
			recovery.keepCiphertext = true
			if err = unlockWithOptions("vault", "vault", constPassphrase, recovery, fixture.key); err != nil {
				t.Fatal(err)
			}
			faultAssertPlain(t, "vault")
			if !bytes.Equal(data, securityRead(t, "vault.age")) {
				t.Fatal("recovery modified the retained ciphertext")
			}
		})
	}
}
func TestAbruptUnlockRecovery(t *testing.T) {
	points := []string{"restore-mid-write", storage.ExtractFileSynced, storage.UnlockAuthenticated, storage.UnlockBeforePublish, storage.UnlockPublished, storage.UnlockDirectorySynced, storage.UnlockBeforeCipherRemoval, storage.UnlockComplete}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			runInIsolatedDir(t)
			fixture := faultMakeFixture(t, true, false)
			before := securityRead(t, "vault.age")
			runCrashChild(t, "unlock", point)
			if point == storage.UnlockComplete {
				if _, err := os.Lstat("vault.age"); !os.IsNotExist(err) {
					t.Fatal("default successful unlock retained ciphertext unexpectedly")
				}
				faultAssertPlain(t, "vault")
				return
			}
			if !bytes.Equal(before, securityRead(t, "vault.age")) {
				t.Fatal("crash modified ciphertext before completed restoration")
			}
			published := point == storage.UnlockPublished || point == storage.UnlockDirectorySynced || point == storage.UnlockBeforeCipherRemoval
			if published {
				faultAssertPlain(t, "vault")
				if err := Unlock("vault", "vault", constPassphrase, fixture.key); err == nil {
					t.Fatal("retry overwrote an already restored destination")
				}
				faultAssertPlain(t, "vault")
			} else {
				if _, err := os.Lstat("vault"); !os.IsNotExist(err) {
					t.Fatal("partial plaintext published")
				}
				// Crash leftovers are intentionally not auto-trusted or silently deleted.
				leftovers, err := filepath.Glob(".agevault-unlock-*")
				if err != nil || len(leftovers) == 0 {
					t.Fatalf("expected private crash staging: %v %v", leftovers, err)
				}
				recovery := defaultVaultOptions()
				recovery.keepCiphertext = true
				if err = unlockWithOptions("vault", "vault", constPassphrase, recovery, fixture.key); err != nil {
					t.Fatal(err)
				}
				faultAssertPlain(t, "vault")
			}
			if !bytes.Equal(before, securityRead(t, "vault.age")) {
				t.Fatal("crash recovery changed source ciphertext")
			}
		})
	}
}
