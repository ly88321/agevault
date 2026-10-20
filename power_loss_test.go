package main

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/ndavd/agevault/internal/shredder"
	"github.com/ndavd/agevault/internal/storage"
)

// This model drops every unsynced byte and directory entry on simulated power
// loss. It checks the application's durability protocol, not hardware guarantees.
type volatileFile struct {
	name    string
	pending bytes.Buffer
	durable []byte
}

func (f *volatileFile) Write(p []byte) (int, error) { return f.pending.Write(p) }
func (f *volatileFile) Name() string                { return f.name }
func (f *volatileFile) Chmod(os.FileMode) error     { return nil }
func (f *volatileFile) Sync() error {
	f.durable = append([]byte(nil), f.pending.Bytes()...)
	return nil
}
func (f *volatileFile) Close() error { return nil }

type powerLossDisk struct {
	pending map[string]*volatileFile
	durable map[string][]byte
}

func newPowerLossDisk() *powerLossDisk {
	return &powerLossDisk{pending: map[string]*volatileFile{}, durable: map[string][]byte{}}
}
func (d *powerLossDisk) operations() storage.Operations {
	ops := storage.OS()
	ops.CreateTemp = func(string, string) (storage.File, error) {
		f := &volatileFile{name: ".agevault-power-test-temp"}
		d.pending[f.name] = f
		return f, nil
	}
	ops.Link = func(from, to string) error {
		if _, ok := d.pending[to]; ok {
			return os.ErrExist
		}
		f, ok := d.pending[from]
		if !ok {
			return os.ErrNotExist
		}
		d.pending[to] = f
		return nil
	}
	ops.Remove = func(name string) error {
		if _, ok := d.pending[name]; !ok {
			return os.ErrNotExist
		}
		delete(d.pending, name)
		return nil
	}
	ops.SyncDir = func(string) error {
		d.durable = map[string][]byte{}
		for name, f := range d.pending {
			d.durable[name] = append([]byte(nil), f.durable...)
		}
		return nil
	}
	return ops
}
func (d *powerLossDisk) crashSnapshot() map[string][]byte {
	snapshot := map[string][]byte{}
	for name, data := range d.durable {
		snapshot[name] = append([]byte(nil), data...)
	}
	return snapshot
}
func TestPowerLossCommitOrdering(t *testing.T) {
	lostPower := errors.New("simulated loss of volatile filesystem state")
	for _, point := range []string{storage.CipherFileSynced, storage.CipherPublished, storage.CipherDirectorySynced, storage.LockBeforeShred, storage.LockAfterShred} {
		t.Run(point, func(t *testing.T) {
			runInIsolatedDir(t)
			fixture := faultMakeFixture(t, false, false)
			disk := newPowerLossDisk()
			options := defaultVaultOptions()
			options.disk = disk.operations()
			var snapshot map[string][]byte
			options.disk.Checkpoint = func(actual string) error {
				if actual == point {
					snapshot = disk.crashSnapshot()
					return lostPower
				}
				return nil
			}
			options.shredDir = func(name string, iterations int) error {
				// If file Sync or directory Sync is omitted/moved after shredding, this
				// assertion fails even though ordinary real-filesystem round trips may pass.
				committed, ok := disk.crashSnapshot()["vault.age"]
				if !ok {
					t.Fatal("plaintext erased before durable ciphertext name exists")
				}
				faultAssertCipher(t, committed, fixture.identity)
				return shredder.ShredDir(name, iterations)
			}
			if _, err := lockWithOptions("vault", "vault", constPassphrase, options); !errors.Is(err, lostPower) {
				t.Fatalf("expected simulated power loss: %v", err)
			}
			if snapshot == nil {
				t.Fatal("power-loss boundary not reached")
			}
			durable, hasCipher := snapshot["vault.age"]
			wantDurable := point == storage.CipherDirectorySynced || point == storage.LockBeforeShred || point == storage.LockAfterShred
			if hasCipher != wantDurable {
				t.Fatalf("durability at %s: %v, want %v", point, hasCipher, wantDurable)
			}
			if hasCipher {
				faultAssertCipher(t, durable, fixture.identity)
			}
			if point == storage.LockAfterShred {
				if _, err := os.Lstat("vault"); !os.IsNotExist(err) {
					t.Fatal("expected shredded source")
				}
			} else {
				faultAssertPlain(t, "vault")
			}
		})
	}
}
