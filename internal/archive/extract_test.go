package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRejectUnsafeArchives(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "other/file", "vault/../../escape", `vault\..\escape`, "vault/file:ads", "vault/CON", "vault/trailing.", "vault/trailing "} {
		t.Run(name, func(t *testing.T) {
			var b bytes.Buffer
			w := tar.NewWriter(&b)
			w.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: 1})
			w.Write([]byte("x"))
			w.Close()
			if err := UnTar(&b, t.TempDir(), "vault"); err == nil {
				t.Fatal("unsafe tar accepted")
			}
			b.Reset()
			z := zip.NewWriter(&b)
			f, _ := z.Create(name)
			f.Write([]byte("x"))
			z.Close()
			if err := UnZip(*bytes.NewReader(b.Bytes()), t.TempDir(), "vault"); err == nil {
				t.Fatal("unsafe zip accepted")
			}
		})
	}
}
func TestRejectLinksAndDuplicates(t *testing.T) {
	for _, kind := range []byte{tar.TypeSymlink, tar.TypeLink, tar.TypeFifo} {
		var b bytes.Buffer
		w := tar.NewWriter(&b)
		w.WriteHeader(&tar.Header{Name: "vault/link", Linkname: "outside", Typeflag: kind})
		w.Close()
		if err := UnTar(&b, t.TempDir(), "vault"); err == nil {
			t.Fatal("special entry accepted")
		}
	}
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for i := 0; i < 2; i++ {
		w.WriteHeader(&tar.Header{Name: "vault/file", Mode: 0600, Size: 1})
		w.Write([]byte("x"))
	}
	w.Close()
	if err := UnTar(&b, t.TempDir(), "vault"); err == nil {
		t.Fatal("duplicate accepted")
	}
}
func TestExtractionCannotFollowOutsideSymlink(t *testing.T) {
	dest := t.TempDir()
	outside := t.TempDir()
	os.Mkdir(filepath.Join(dest, "vault"), 0700)
	if err := os.Symlink(outside, filepath.Join(dest, "vault", "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	w.WriteHeader(&tar.Header{Name: "vault/link/file", Mode: 0600, Size: 1})
	w.Write([]byte("x"))
	w.Close()
	if err := UnTar(&b, dest, "vault"); err == nil {
		t.Fatal("symlink escape accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "file")); !os.IsNotExist(err) {
		t.Fatal("outside file created")
	}
}
