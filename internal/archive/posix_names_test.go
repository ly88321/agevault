package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLegacyPOSIXArchiveNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX path semantics")
	}
	for _, format := range []string{"tar", "zip"} {
		t.Run(format, func(t *testing.T) {
			names := []string{"vault/aux.txt", "vault/file:note", "vault/name.", "vault/name ", `vault/back\slash`}
			var b bytes.Buffer
			if format == "tar" {
				w := tar.NewWriter(&b)
				for _, name := range names {
					if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: 1}); err != nil {
						t.Fatal(err)
					}
					if _, err := w.Write([]byte("x")); err != nil {
						t.Fatal(err)
					}
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				w := zip.NewWriter(&b)
				for _, name := range names {
					f, err := w.Create(name)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = f.Write([]byte("x")); err != nil {
						t.Fatal(err)
					}
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
			}
			dest := t.TempDir()
			var err error
			if format == "tar" {
				err = UnTar(&b, dest, "vault")
			} else {
				err = UnZip(*bytes.NewReader(b.Bytes()), dest, "vault")
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range names {
				data, err := os.ReadFile(filepath.Join(dest, name))
				if err != nil || string(data) != "x" {
					t.Fatalf("legacy name %q: %s %v", name, data, err)
				}
			}
		})
	}
}
func TestWriterReaderPathPolicyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "vault")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	// safeName is shared by writing and both archive readers. Verify its Windows rules directly.
	if runtime.GOOS == "windows" {
		for _, name := range []string{"vault/file:ads", "vault/CON", "vault/trailing.", "vault/trailing ", "vault/file?"} {
			if _, err := safeName(name, "vault"); err == nil {
				t.Fatalf("unsafe Windows name %q", name)
			}
		}
	}
	var b bytes.Buffer
	if err := TarDirectory(source, &b); err != nil {
		t.Fatal(err)
	}
	if err := UnTar(&b, t.TempDir(), "vault"); err != nil {
		t.Fatal(err)
	}
}
