import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from draft_release import GitHub, VERSION, WORKFLOWS, sync_draft, wait_for_ci
from package_release import TARGETS, archive_binary, manifest, manifest_text, package_name

SHA = "a" * 40
NOTES = "# Release notes\n\n\u540e\u91cf\u5b50\u52a0\u5bc6\n"


class FakeAPI(GitHub):
    def __init__(self):
        self.sha = SHA
        self.refs = []
        self.release = None
        self.assets = []
        self.mutations = []
        self.duplicate = False
        self.second_page = False
        self.bad_upload = False
        self.runs = [{"id": index, "path": path, "head_sha": SHA, "head_branch": "main",
                      "event": "push", "status": "completed", "conclusion": "success"}
                     for index, path in enumerate(sorted(WORKFLOWS), 1)]

    def request(self, path, method="GET", payload=None, file=None):
        if method != "GET":
            self.mutations.append((method, path, payload))
            if payload is not None and payload.get("draft") is not True:
                raise AssertionError("Every release write must explicitly retain draft=true")
            if "/git/" in path:
                raise AssertionError("Ref mutation is forbidden")
        if path == "/commits/main":
            return {"sha": self.sha}
        if path.startswith("/git/matching-refs/"):
            return self.refs
        if path.startswith("/actions/runs?"):
            return {"workflow_runs": copy.deepcopy(self.runs)}
        if path.startswith("/releases?per_page="):
            if self.second_page and parse_qs(urlsplit(path).query).get("page") == ["1"]:
                return [{"tag_name": f"v0.{i}"} for i in range(100)]
            return ([self.release] * (2 if self.duplicate else 1)) if self.release else []
        if path == "/releases" and method == "POST":
            self.release = dict(payload, id=1, published_at=None,
                                upload_url="https://uploads.github.com/repos/test/v/releases/1/assets{?name,label}",
                                html_url="https://example.invalid/draft")
            return copy.deepcopy(self.release)
        if path == "/releases/1":
            if method == "PATCH":
                self.release.update(payload)
            return copy.deepcopy(self.release)
        if path.startswith("/releases/1/assets?"):
            return copy.deepcopy(self.assets)
        if path.startswith("/releases/assets/") and method == "DELETE":
            self.assets = [a for a in self.assets if a["id"] != int(path.rsplit("/", 1)[1])]
            return None
        if path.startswith("https://uploads.github.com/") and method == "POST":
            name = parse_qs(urlsplit(path).query)["name"][0]
            if name in {a["name"] for a in self.assets}:
                raise AssertionError("Duplicate asset")
            checksum = hashlib.sha256(file.read_bytes()).hexdigest()
            asset = {"id": max([a["id"] for a in self.assets] + [0]) + 1, "name": name,
                     "state": "uploaded", "digest": "sha256:" + ("0" * 64 if self.bad_upload else checksum)}
            self.assets.append(asset)
            return copy.deepcopy(asset)
        raise AssertionError((method, path))


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        for os_name, arch in TARGETS:
            binary = self.directory / "binary"
            binary.write_bytes({"linux": b"\x7fELF", "darwin": b"\xcf\xfa\xed\xfe", "windows": b"MZ"}[os_name] + arch.encode())
            archive_binary(binary, self.directory / package_name(os_name, arch), os_name)
            binary.unlink()
        self.write_checksums()
        self.api = FakeAPI()

    def write_checksums(self):
        (self.directory / "SHA256SUMS").write_bytes(manifest_text(manifest(self.directory)).encode("ascii"))

    def sync(self):
        sync_draft(self.api, SHA, self.directory, NOTES)

    def test_create_and_rerun_no_duplicate_draft_assets_or_tag(self):
        self.sync()
        first_assets = copy.deepcopy(self.api.assets)
        self.api.mutations.clear()
        self.sync()
        self.assertEqual(first_assets, self.api.assets)
        self.assertEqual(["PATCH"], [m[0] for m in self.api.mutations])
        self.assertEqual([], self.api.refs)
        self.assertTrue(self.api.release["draft"])
        self.assertEqual(NOTES, self.api.release["body"])

    def test_existing_draft_on_second_page_is_reused_and_target_updated(self):
        self.sync()
        self.api.second_page = True
        self.api.release["target_commitish"] = "b" * 40
        self.api.mutations.clear()
        self.sync()
        self.assertEqual(SHA, self.api.release["target_commitish"])
        self.assertEqual(["PATCH"], [m[0] for m in self.api.mutations])

    def test_published_release_or_changed_notes_or_duplicates_block_writes(self):
        self.sync()
        original = copy.deepcopy(self.api.release)
        for case in ("published", "notes", "duplicates"):
            with self.subTest(case=case):
                self.api.release = copy.deepcopy(original)
                self.api.duplicate = case == "duplicates"
                if case == "published":
                    self.api.release.update(draft=False, published_at="now")
                if case == "notes":
                    self.api.release["body"] += "edited"
                self.api.mutations.clear()
                with self.assertRaises(ValueError):
                    self.sync()
                self.assertEqual([], self.api.mutations)

    def test_stale_main_or_existing_tag_blocks_writes(self):
        for case in ("main", "tag"):
            with self.subTest(case=case):
                self.api = FakeAPI()
                if case == "main":
                    self.api.sha = "b" * 40
                else:
                    self.api.refs = [{"ref": f"refs/tags/{VERSION}"}]
                with self.assertRaises(ValueError):
                    self.sync()
                self.assertEqual([], self.api.mutations)

    def test_invalid_checksum_blocks_writes(self):
        (self.directory / "SHA256SUMS").write_text("wrong", encoding="ascii")
        with self.assertRaises(ValueError):
            self.sync()
        self.assertEqual([], self.api.mutations)

    def test_upload_digest_failure_then_rerun_recovers(self):
        self.api.bad_upload = True
        with self.assertRaisesRegex(ValueError, "verification failed"):
            self.sync()
        self.assertTrue(self.api.release["draft"])
        self.api.bad_upload = False
        self.sync()
        self.assertEqual(7, len(self.api.assets))
        self.assertEqual(1, sum(m[0] == "POST" and m[1] == "/releases" for m in self.api.mutations))

    def test_failed_pending_or_wrong_sha_ci_blocks(self):
        wait_for_ci(self.api, SHA, attempts=1, pause=0)
        for case in ("failure", "pending", "wrong-sha", "missing"):
            with self.subTest(case=case), patch("draft_release.time.sleep"):
                self.api = FakeAPI()
                if case == "failure":
                    self.api.runs[0]["conclusion"] = "failure"
                elif case == "pending":
                    self.api.runs[0]["status"] = "in_progress"
                elif case == "wrong-sha":
                    self.api.runs[0]["head_sha"] = "b" * 40
                else:
                    self.api.runs.pop()
                with self.assertRaises(ValueError):
                    wait_for_ci(self.api, SHA, attempts=1, pause=0)
                self.assertEqual([], self.api.mutations)

    def test_missing_extra_or_corrupt_package_rejected(self):
        extra = self.directory / "extra.txt"
        extra.write_text("extra", encoding="ascii")
        with self.assertRaises(ValueError):
            manifest(self.directory)
        extra.unlink()
        package = self.directory / package_name("windows", "arm64")
        original = package.read_bytes()
        package.unlink()
        with self.assertRaises(ValueError):
            manifest(self.directory)
        package.write_bytes(b"invalid")
        with self.assertRaises(Exception):
            manifest(self.directory)
        package.write_bytes(original)
        self.assertEqual(6, len(manifest(self.directory)))


if __name__ == "__main__":
    unittest.main()
