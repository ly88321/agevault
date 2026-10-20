package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"filippo.io/age"
	"github.com/ndavd/agevault/internal/crypt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSharingAndExplicitKeys(t *testing.T) {
	for _, pq := range []bool{false, true} {
		t.Run(map[bool]string{false: "x25519", true: "hybrid"}[pq], func(t *testing.T) {
			runInIsolatedDir(t)
			for _, key := range []string{"alice.age", "bob.age"} {
				if _, _, err := Keygen("vault", "vault", testPassphrase, pq, key); err != nil {
					t.Fatal(err)
				}
			}
			os.WriteFile("vault/foo.txt", []byte(testFooContent), 0600)
			for _, key := range []string{"alice.age", "bob.age"} {
				if _, err := Lock("vault", "vault"); err != nil {
					t.Fatal(err)
				}
				if err := Unlock("vault", "vault", constPassphrase, key); err != nil {
					t.Fatal(err)
				}
				assertVaultUnlocked(t)
			}
			if _, err := getIdentityFilename("missing"); err == nil {
				t.Fatal("unexpected identity")
			}
		})
	}
}
func TestForkIdentityCompatibility(t *testing.T) {
	for _, envelope := range []bool{false, true} {
		t.Run(map[bool]string{false: "metadata", true: "json-envelope"}[envelope], func(t *testing.T) {
			runInIsolatedDir(t)
			os.Mkdir("vault", 0700)
			os.WriteFile("vault/foo.txt", []byte(testFooContent), 0600)
			id, _ := age.GenerateX25519Identity()
			r, _ := age.NewScryptRecipient(testPassphrase)
			if err := crypt.EncryptToFile("custom.age", []byte(id.String()), r); err != nil {
				t.Fatal(err)
			}
			if envelope {
				data, _ := os.ReadFile("custom.age")
				data, _ = json.Marshal(struct {
					Version           int
					Recipient         string
					EncryptedIdentity string
				}{1, id.Recipient().String(), base64.StdEncoding.EncodeToString(data)})
				os.WriteFile(".vault.age", data, 0600)
			} else {
				data, _ := json.Marshal(struct {
					Version   int
					KeyFile   string
					Recipient string
				}{1, "custom.age", id.Recipient().String()})
				os.WriteFile(".vault.av", data, 0600)
			}
			if _, err := Lock("vault", "vault"); err != nil {
				t.Fatal(err)
			}
			if err := Unlock("vault", "vault", constPassphrase); err != nil {
				t.Fatal(err)
			}
			assertVaultUnlocked(t)
		})
	}
}
func TestFailedUnlockRetainsCiphertext(t *testing.T) {
	runInIsolatedDir(t)
	key, _, err := Keygen("vault", "vault", testPassphrase, true)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile("vault/foo.txt", bytes.Repeat([]byte("x"), 100000), 0600)
	if _, err = Lock("vault", "vault"); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile("vault.age")
	for _, mode := range []string{"wrong-password", "truncated", "tampered"} {
		t.Run(mode, func(t *testing.T) {
			data := append([]byte(nil), original...)
			pw := constPassphrase
			switch mode {
			case "wrong-password":
				pw = func(string) (string, error) { return "wrong", nil }
			case "truncated":
				data = data[:len(data)-1]
			case "tampered":
				data[len(data)-1] ^= 1
			}
			os.WriteFile("vault.age", data, 0600)
			if err := Unlock("vault", "vault", pw, key); err == nil {
				t.Fatal("invalid decryption succeeded")
			}
			got, _ := os.ReadFile("vault.age")
			if !bytes.Equal(got, data) {
				t.Fatal("ciphertext altered on failure")
			}
			if _, err := os.Stat("vault"); !os.IsNotExist(err) {
				t.Fatal("partial vault published")
			}
			paths, _ := filepath.Glob(".agevault-*")
			if len(paths) != 0 {
				t.Fatalf("plaintext leftovers: %v", paths)
			}
		})
	}
	os.WriteFile("vault.age", original, 0600)
	if err := Unlock("vault", "vault", constPassphrase, key); err != nil {
		t.Fatal(err)
	}
}
func TestLargeFileStreamingRoundtrip(t *testing.T) {
	if testing.Short() {
		t.Skip("large file")
	}
	runInIsolatedDir(t)
	key, _, err := Keygen("vault", "vault", testPassphrase, true)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create("vault/large")
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	chunk := bytes.Repeat([]byte("0123456789abcdef"), 65536)
	for i := 0; i < 64; i++ {
		if _, err = io.Copy(io.MultiWriter(f, h), bytes.NewReader(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	want := h.Sum(nil)
	if _, err = Lock("vault", "vault"); err != nil {
		t.Fatal(err)
	}
	if err = Unlock("vault", "vault", constPassphrase, key); err != nil {
		t.Fatal(err)
	}
	f, err = os.Open("vault/large")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h.Reset()
	io.Copy(h, f)
	if !bytes.Equal(h.Sum(nil), want) {
		t.Fatal("large file changed")
	}
}
func TestIdentitySafety(t *testing.T) {
	runInIsolatedDir(t)
	if _, _, err := Keygen("vault", "vault", testPassphrase, false, "vault/identity.age"); err == nil {
		t.Fatal("identity inside vault accepted")
	}
	os.WriteFile("existing.age", []byte("keep"), 0600)
	if _, _, err := Keygen("vault", "vault", testPassphrase, false, "existing.age"); err == nil {
		t.Fatal("existing key replaced")
	}
	got, _ := os.ReadFile("existing.age")
	if string(got) != "keep" {
		t.Fatal("existing key changed")
	}
	os.WriteFile(".a.vault.key.age", nil, 0600)
	os.WriteFile(".b.vault.key.age", nil, 0600)
	if _, err := getIdentityFilename("vault"); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatal("ambiguous identity accepted")
	}
}

func TestMalformedLegacyRecipient(t *testing.T) {
	runInIsolatedDir(t)
	os.Mkdir("vault", 0700)
	os.WriteFile(".vault.age", []byte(`{"Version":1,"Recipient":"   ","EncryptedIdentity":""}`), 0600)
	if _, err := Lock("vault", "vault"); err == nil {
		t.Fatal("empty legacy recipient accepted")
	}
}
func TestKeygenRejectsSymlinkIntoVault(t *testing.T) {
	runInIsolatedDir(t)
	os.Mkdir("vault", 0700)
	if err := os.Symlink("vault", "alias"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, _, err := Keygen("vault", "vault", testPassphrase, false, "alias/key.age"); err == nil {
		t.Fatal("identity inside symlinked vault accepted")
	}
}
