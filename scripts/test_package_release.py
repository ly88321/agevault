from pathlib import Path
import tempfile
import unittest
import zipfile

from package_release import TARGETS, archive_binary, digest, manifest, manifest_text, package_name


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        for os_name, arch in TARGETS:
            binary = self.directory / "binary"
            binary.write_bytes({"linux": b"\x7fELF", "darwin": b"\xcf\xfa\xed\xfe", "windows": b"MZ"}[os_name] + arch.encode())
            archive_binary(binary, self.directory / package_name(os_name, arch), os_name)
            binary.unlink()

    def test_complete_manifest_checksums_and_canonical_order(self):
        checksums = manifest(self.directory)
        self.assertEqual(6, len(checksums))
        text = manifest_text(checksums)
        self.assertEqual(sorted(checksums), [line.split("  ")[1] for line in text.splitlines()])
        for name, checksum in checksums.items():
            self.assertEqual(digest(self.directory / name), checksum)
        (self.directory / "SHA256SUMS").write_bytes(text.encode("ascii"))
        self.assertEqual(checksums, manifest(self.directory))

    def test_missing_or_extra_package_is_rejected(self):
        extra = self.directory / "unrelated.txt"
        extra.write_text("extra", encoding="ascii")
        with self.assertRaises(ValueError):
            manifest(self.directory)
        extra.unlink()
        (self.directory / package_name("linux", "arm64")).unlink()
        with self.assertRaises(ValueError):
            manifest(self.directory)

    def test_corrupt_archive_rejected(self):
        (self.directory / package_name("windows", "arm64")).write_bytes(b"corrupt")
        with self.assertRaises(zipfile.BadZipFile):
            manifest(self.directory)

    def test_unexpected_archive_member_rejected(self):
        target = self.directory / package_name("windows", "amd64")
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("../agevault.exe", b"MZpayload")
        with self.assertRaises(ValueError):
            manifest(self.directory)

    def test_wrong_binary_format_rejected(self):
        target = self.directory / package_name("windows", "amd64")
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("agevault.exe", b"not a Windows binary")
        with self.assertRaises(ValueError):
            manifest(self.directory)

    def test_archive_metadata_is_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "binary"
            binary.write_bytes(b"unchanged payload")
            for os_name in ("linux", "darwin", "windows"):
                first, second = Path(temporary) / "first", Path(temporary) / "second"
                archive_binary(binary, first, os_name)
                archive_binary(binary, second, os_name)
                self.assertEqual(first.read_bytes(), second.read_bytes())


if __name__ == "__main__":
    unittest.main()
