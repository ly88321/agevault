package main

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"
	"github.com/ndavd/agevault/internal/crypt"
	"github.com/ndavd/agevault/internal/recipients"
)

func securityWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func securityRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func securityMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
}
func securityIdentity(t *testing.T, filename string) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := age.NewScryptRecipient(testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err = crypt.EncryptToFile(filename, []byte(id.String()), recipient); err != nil {
		t.Fatal(err)
	}
	return id
}
func securityMetadata(t *testing.T, key, recipient string) {
	t.Helper()
	data, err := json.Marshal(struct {
		Version   int
		KeyFile   string
		Recipient string
	}{1, key, recipient})
	if err != nil {
		t.Fatal(err)
	}
	securityWrite(t, ".vault.av", data)
}
func securityEnvelope(t *testing.T, filename string, recipient string) {
	t.Helper()
	encrypted := securityRead(t, filename)
	data, err := json.Marshal(struct {
		Version           int
		Recipient         string
		EncryptedIdentity string
	}{1, recipient, base64.StdEncoding.EncodeToString(encrypted)})
	if err != nil {
		t.Fatal(err)
	}
	securityWrite(t, filename, data)
}
func securityAssertNoCipher(t *testing.T) {
	t.Helper()
	if _, err := os.Lstat("vault.age"); !os.IsNotExist(err) {
		t.Fatalf("ciphertext unexpectedly created: %v", err)
	}
}
func securityAssertPayload(t *testing.T) {
	t.Helper()
	if got := securityRead(t, "vault/payload"); string(got) != "keep this data" {
		t.Fatalf("payload changed: %q", got)
	}
}

func TestLockRejectsIdentityInsideVault(t *testing.T) {
	for _, mode := range []string{"explicit-with-recipients", "legacy-metadata", "default-symlink", "legacy-symlink-with-recipients"} {
		t.Run(mode, func(t *testing.T) {
			runInIsolatedDir(t)
			securityMkdir(t, "vault")
			securityWrite(t, "vault/payload", []byte("keep this data"))
			inside := filepath.Join("vault", "only-key.age")
			id := securityIdentity(t, inside)
			before := securityRead(t, inside)
			var explicit []string
			switch mode {
			case "explicit-with-recipients":
				if err := recipients.Append("vault", "vault", id.Recipient()); err != nil {
					t.Fatal(err)
				}
				explicit = []string{inside}
			case "legacy-metadata":
				securityMetadata(t, inside, id.Recipient().String())
			case "default-symlink":
				if err := os.Symlink(inside, ".vault.age"); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			case "legacy-symlink-with-recipients":
				if err := recipients.Append("vault", "vault", id.Recipient()); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(inside, ".old.vault.key.age"); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			prompted := false
			if _, err := lockWithPassphrase("vault", "vault", func(string) (string, error) { prompted = true; return testPassphrase, nil }, explicit...); err == nil {
				t.Fatal("unsafe identity accepted")
			}
			if prompted {
				t.Fatal("should reject unsafe identity before prompting")
			}
			securityAssertNoCipher(t)
			securityAssertPayload(t)
			if !bytes.Equal(securityRead(t, inside), before) {
				t.Fatal("identity changed")
			}
		})
	}
}

func TestLegacyMigrationUsesActualIdentity(t *testing.T) {
	for _, mode := range []string{"explicit-stale-metadata", "metadata-public-mismatch", "envelope-public-mismatch", "external-recipient-filename", "standalone-custom"} {
		t.Run(mode, func(t *testing.T) {
			runInIsolatedDir(t)
			securityMkdir(t, "vault")
			securityMkdir(t, "keys")
			securityWrite(t, "vault/payload", []byte("keep this data"))
			old, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join("keys", "custom.age")
			selected := securityIdentity(t, filename)
			var explicit []string
			switch mode {
			case "explicit-stale-metadata":
				securityMetadata(t, "missing-old.age", old.Recipient().String())
				explicit = []string{filename}
			case "metadata-public-mismatch":
				securityMetadata(t, filename, old.Recipient().String())
			case "envelope-public-mismatch":
				if err = os.Rename(filename, ".vault.age"); err != nil {
					t.Fatal(err)
				}
				filename = ".vault.age"
				securityEnvelope(t, filename, old.Recipient().String())
			case "external-recipient-filename":
				legacy := filepath.Join("keys", "."+selected.Recipient().String()+".vault.key.age")
				if err = os.Rename(filename, legacy); err != nil {
					t.Fatal(err)
				}
				filename = legacy
				explicit = []string{filename}
			case "standalone-custom":
				explicit = []string{filename}
			}
			rs, err := lockWithPassphrase("vault", "vault", constPassphrase, explicit...)
			if err != nil {
				t.Fatal(err)
			}
			if len(rs) != 1 || rs[0].(recipients.Recipient).String() != selected.Recipient().String() {
				t.Fatal("encrypted to stale recipient")
			}
			if err = Unlock("vault", "vault", constPassphrase, filename); err != nil {
				t.Fatal(err)
			}
			securityAssertPayload(t)
		})
	}
}

func TestExplicitIdentityMustBelongToSharedVault(t *testing.T) {
	runInIsolatedDir(t)
	securityMkdir(t, "vault")
	securityWrite(t, "vault/payload", []byte("keep this data"))
	allowed := securityIdentity(t, "allowed.age")
	securityIdentity(t, "other.age")
	if err := recipients.Append("vault", "vault", allowed.Recipient()); err != nil {
		t.Fatal(err)
	}
	before := securityRead(t, filepath.Join("vault", recipients.FileName))
	if _, err := lockWithPassphrase("vault", "vault", constPassphrase, "other.age"); err == nil {
		t.Fatal("unlisted identity accepted")
	}
	securityAssertNoCipher(t)
	securityAssertPayload(t)
	if !bytes.Equal(before, securityRead(t, filepath.Join("vault", recipients.FileName))) {
		t.Fatal("shared recipient list modified")
	}
	if _, err := lockWithPassphrase("vault", "vault", constPassphrase, "allowed.age"); err != nil {
		t.Fatal(err)
	}
	if err := Unlock("vault", "vault", constPassphrase, "allowed.age"); err != nil {
		t.Fatal(err)
	}
	securityAssertPayload(t)
}

func TestLegacyMigrationFailureLeavesSourceIntact(t *testing.T) {
	for _, mode := range []string{"wrong-passphrase", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			runInIsolatedDir(t)
			securityMkdir(t, "vault")
			securityWrite(t, "vault/payload", []byte("keep this data"))
			securityIdentity(t, "custom.age")
			password := func(string) (string, error) {
				if mode == "cancelled" {
					return "", errors.New("cancelled")
				}
				return "wrong", nil
			}
			if _, err := lockWithPassphrase("vault", "vault", password, "custom.age"); err == nil {
				t.Fatal("invalid passphrase accepted")
			}
			securityAssertNoCipher(t)
			securityAssertPayload(t)
			if _, err := os.Lstat(filepath.Join("vault", recipients.FileName)); !os.IsNotExist(err) {
				t.Fatal("unauthenticated recipient list created")
			}
		})
	}
}

func TestKeygenPreservesVerifiedLegacyRecipient(t *testing.T) {
	runInIsolatedDir(t)
	securityMkdir(t, "vault")
	securityWrite(t, "vault/payload", []byte("keep this data"))
	old := securityIdentity(t, ".vault.age")
	securityEnvelope(t, ".vault.age", "invalid-public-hint")
	newKey, _, err := keygenWithPassphrase("vault", "vault", testPassphrase, false, constPassphrase, "new.age")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := recipients.Read("vault")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 || rs[0].(recipients.Recipient).String() != old.Recipient().String() {
		t.Fatal("lost legacy recipient")
	}
	for _, key := range []string{".vault.age", newKey} {
		if _, err = Lock("vault", "vault"); err != nil {
			t.Fatal(err)
		}
		if err = Unlock("vault", "vault", constPassphrase, key); err != nil {
			t.Fatal(err)
		}
		securityAssertPayload(t)
	}
}

func TestKeygenRejectsMalformedLegacyMetadata(t *testing.T) {
	runInIsolatedDir(t)
	securityMkdir(t, "vault")
	securityWrite(t, "vault/payload", []byte("keep this data"))
	securityWrite(t, ".vault.av", []byte("not JSON"))
	if _, _, err := keygenWithPassphrase("vault", "vault", testPassphrase, false, constPassphrase, "new.age"); err == nil {
		t.Fatal("invalid legacy metadata ignored")
	}
	securityAssertPayload(t)
	if _, err := os.Lstat("new.age"); !os.IsNotExist(err) {
		t.Fatal("created new identity despite invalid metadata")
	}
}

func TestPOSIXNamesLockUnlock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-specific filenames; Windows rejection is tested in archive package")
	}
	runInIsolatedDir(t)
	key, _, err := Keygen("vault", "vault", testPassphrase, false, "key.age")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"aux.txt", "file:note", "name.", "name ", `back\slash`}
	for _, name := range names {
		securityWrite(t, filepath.Join("vault", name), []byte(name))
	}
	if _, err = Lock("vault", "vault"); err != nil {
		t.Fatal(err)
	}
	if err = Unlock("vault", "vault", constPassphrase, key); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if string(securityRead(t, filepath.Join("vault", name))) != name {
			t.Fatalf("changed POSIX filename %q", name)
		}
	}
}

func TestAuthenticatedInvalidArchivesPreserveRecovery(t *testing.T) {
	for _, mode := range []string{"escape", "symlink", "root-is-file"} {
		t.Run(mode, func(t *testing.T) {
			runInIsolatedDir(t)
			key, _, err := Keygen("vault", "vault", testPassphrase, false, "key.age")
			if err != nil {
				t.Fatal(err)
			}
			rs, err := recipients.Read("vault")
			if err != nil {
				t.Fatal(err)
			}
			if err = os.RemoveAll("vault"); err != nil {
				t.Fatal(err)
			}
			var b bytes.Buffer
			w := tar.NewWriter(&b)
			h := &tar.Header{Name: "vault", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}
			if mode == "escape" {
				h.Name = "../outside"
			}
			if mode == "symlink" {
				h.Name = "vault/link"
				h.Typeflag = tar.TypeSymlink
				h.Linkname = "../../outside"
				h.Size = 0
			}
			if err = w.WriteHeader(h); err != nil {
				t.Fatal(err)
			}
			if h.Size > 0 {
				if _, err = w.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
			}
			if err = w.Close(); err != nil {
				t.Fatal(err)
			}
			if err = crypt.EncryptToFile("vault.age", b.Bytes(), rs...); err != nil {
				t.Fatal(err)
			}
			before := securityRead(t, "vault.age")
			if err = Unlock("vault", "vault", constPassphrase, key); err == nil {
				t.Fatal("invalid archive accepted")
			}
			if !bytes.Equal(before, securityRead(t, "vault.age")) {
				t.Fatal("ciphertext changed on failed restoration")
			}
			if _, err = os.Lstat("vault"); !os.IsNotExist(err) {
				t.Fatal("invalid vault published")
			}
			leftovers, err := filepath.Glob(".agevault-unlock-*")
			if err != nil || len(leftovers) > 0 {
				t.Fatalf("staging cleanup failed: %v %v", leftovers, err)
			}
		})
	}
}
