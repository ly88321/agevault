"""Build deterministic single-binary archives and verify the complete release set."""

import gzip
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import zipfile

TARGETS = [(os_name, arch) for os_name in ("linux", "darwin", "windows")
           for arch in ("amd64", "arm64")]


def package_name(os_name, arch):
    extension = "zip" if os_name == "windows" else "tar.gz"
    return f"agevault-{os_name}-{arch}.{extension}"


def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def archive_binary(binary, output, os_name):
    name = "agevault.exe" if os_name == "windows" else "agevault"
    data = binary.read_bytes()
    if os_name == "windows":
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100755 << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data)
    else:
        with output.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as archive:
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                entry.mode = 0o755
                entry.mtime = 0
                archive.addfile(entry, io.BytesIO(data))


def build(os_name, arch, directory):
    if (os_name, arch) not in TARGETS:
        raise ValueError("Unsupported release target")
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        binary = Path(temporary) / "agevault"
        environment = dict(os.environ, GOOS=os_name, GOARCH=arch, CGO_ENABLED="0")
        subprocess.run(["go", "build", "-trimpath", "-ldflags=-s -w", "-o", str(binary), "."],
                       env=environment, check=True)
        archive_binary(binary, directory / package_name(os_name, arch), os_name)


def manifest(directory):
    expected = {package_name(*target) for target in TARGETS}
    actual = {p.name for p in directory.iterdir()}
    if actual - {"SHA256SUMS"} != expected:
        raise ValueError(f"Expected exactly six packages; found {sorted(actual)}")
    checksums = {}
    for os_name, arch in TARGETS:
        name = package_name(os_name, arch)
        path = directory / name
        binary_name = "agevault.exe" if os_name == "windows" else "agevault"
        if os_name == "windows":
            with zipfile.ZipFile(path) as archive:
                entries = archive.infolist()
                if len(entries) != 1 or entries[0].filename != binary_name or entries[0].file_size == 0:
                    raise ValueError(f"Invalid package: {name}")
                data = archive.read(binary_name)
        else:
            with tarfile.open(path, "r:gz") as archive:
                entries = archive.getmembers()
                if (len(entries) != 1 or entries[0].name != binary_name or not entries[0].isfile()
                        or entries[0].size == 0 or entries[0].mode & 0o111 != 0o111):
                    raise ValueError(f"Invalid package: {name}")
                data = archive.extractfile(entries[0]).read()
        magic = {"windows": b"MZ", "linux": b"\x7fELF", "darwin": b"\xcf\xfa\xed\xfe"}[os_name]
        if not data.startswith(magic):
            raise ValueError(f"Incorrect binary format: {name}")
        checksums[name] = digest(path)
    return checksums


def manifest_text(checksums):
    return "".join(f"{checksums[name]}  {name}\n" for name in sorted(checksums))


if __name__ == "__main__":
    if sys.argv[1] == "build" and len(sys.argv) == 5:
        build(sys.argv[2], sys.argv[3], Path(sys.argv[4]))
    elif sys.argv[1] == "checksums" and len(sys.argv) == 3:
        destination = Path(sys.argv[2])
        (destination / "SHA256SUMS").write_bytes(manifest_text(manifest(destination)).encode("ascii"))
    else:
        raise SystemExit("Usage: package_release.py build OS ARCH DIR | checksums DIR")
