package crypt

import (
	"errors"
	"filippo.io/age"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("source failed") }
func TestAtomicEncryptionFailure(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "vault.age")
	id, _ := age.GenerateX25519Identity()
	if err := EncryptToFileFromReader(dest, brokenReader{}, id.Recipient()); err == nil {
		t.Fatal("source error ignored")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("partial output retained")
	}
	os.WriteFile(dest, []byte("existing"), 0600)
	if err := EncryptToFileFromReader(dest, strings.NewReader("new"), id.Recipient()); err == nil {
		t.Fatal("existing output replaced")
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "existing" {
		t.Fatal("existing output changed")
	}
	entries, _ = os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("temporary output leaked")
	}
}
