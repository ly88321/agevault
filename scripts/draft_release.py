"""Prepare v1.2.0 without creating refs or publishing releases. No third-party deps."""

import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from package_release import digest, manifest, manifest_text

VERSION = "v1.2.0"
WORKFLOWS = {".github/workflows/CI.yaml", ".github/workflows/go-test.yaml"}


class GitHub:
    def __init__(self, repository, token):
        self.root = f"https://api.github.com/repos/{repository}"
        self.token = token

    def request(self, path, method="GET", payload=None, file=None):
        url = path if path.startswith("https://") else self.root + path
        if urlsplit(url).hostname not in {"api.github.com", "uploads.github.com"}:
            raise ValueError("Unexpected GitHub API host")
        data = file.read_bytes() if file else (json.dumps(payload).encode("utf-8") if payload is not None else None)
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "agevault-draft-release"}
        if data is not None:
            headers["Content-Type"] = "application/octet-stream" if file else "application/json"
        with urlopen(Request(url, data=data, headers=headers, method=method), timeout=120) as response:
            content = response.read()
            return json.loads(content.decode("utf-8")) if content else None

    def items(self, path):
        page = 1
        while True:
            separator = "&" if "?" in path else "?"
            result = self.request(f"{path}{separator}per_page=100&page={page}")
            yield from result
            if len(result) < 100:
                return
            page += 1


def assert_unpublished(release, allow_placeholder=False):
    if release.get("draft") is not True or release.get("published_at") is not None:
        raise ValueError("Release is not an unpublished draft; refusing changes")
    if release["tag_name"] != VERSION and not (allow_placeholder and release["tag_name"].startswith("untagged-")):
        raise ValueError("Unexpected release version")


def assert_main_without_tag(api, sha):
    if api.request("/commits/main")["sha"] != sha:
        raise ValueError("main advanced; refusing stale draft artifacts")
    refs = api.request(f"/git/matching-refs/tags/{VERSION}")
    if any(ref["ref"] == f"refs/tags/{VERSION}" for ref in refs):
        raise ValueError("Version tag exists; refusing changes")


def wait_for_ci(api, sha, attempts=60, pause=15):
    for _ in range(attempts):
        assert_main_without_tag(api, sha)
        runs = api.request(f"/actions/runs?head_sha={sha}&per_page=100")["workflow_runs"]
        latest = {}
        for run in runs:
            if (run.get("head_sha") == sha and run.get("head_branch") == "main"
                    and run.get("event") == "push" and run.get("path") in WORKFLOWS):
                key = run["path"]
                if key not in latest or run["id"] > latest[key]["id"]:
                    latest[key] = run
        if any(run["status"] == "completed" and run["conclusion"] != "success" for run in latest.values()):
            raise ValueError("main CI failed; draft left unchanged")
        if set(latest) == WORKFLOWS and all(run["status"] == "completed" for run in latest.values()):
            return
        print("Waiting for both main CI workflows...", flush=True)
        time.sleep(pause)
    raise ValueError("main CI did not finish; draft left unchanged")


def sync_draft(api, sha, directory, notes):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Expected an exact commit SHA")
    checksums = manifest(directory)
    if (directory / "SHA256SUMS").read_bytes() != manifest_text(checksums).encode("ascii"):
        raise ValueError("SHA256SUMS does not match all six packages")
    expected = dict(checksums, SHA256SUMS=digest(directory / "SHA256SUMS"))
    assert_main_without_tag(api, sha)
    # GitHub can return a temporary tag_name for drafts that have no Git tag.
    # Recognize that same named draft so a retry cannot create a second release.
    matches = [release for release in api.items("/releases")
               if release["tag_name"] == VERSION or
               (release.get("name") == VERSION and release["tag_name"].startswith("untagged-"))]
    if len(matches) > 1:
        raise ValueError("Multiple matching releases; refusing changes")
    if matches:
        release = api.request(f"/releases/{matches[0]['id']}")
        assert_unpublished(release, allow_placeholder=True)
        if release["body"] != notes or release["name"] != VERSION:
            raise ValueError("Existing release notes/title differ; refusing changes")
        release = api.request(f"/releases/{release['id']}", "PATCH",
                              {"draft": True, "tag_name": VERSION, "target_commitish": sha})
    else:
        release = api.request("/releases", "POST", {"tag_name": VERSION, "name": VERSION,
                              "body": notes, "draft": True, "prerelease": False, "target_commitish": sha})
    assert_unpublished(release)
    release_id = release["id"]
    existing = list(api.items(f"/releases/{release_id}/assets"))
    if len({asset["name"] for asset in existing}) != len(existing) or any(a["name"] not in expected for a in existing):
        raise ValueError("Unexpected or duplicate draft assets; refusing replacement")
    by_name = {asset["name"]: asset for asset in existing}
    for name, checksum in expected.items():
        assert_main_without_tag(api, sha)
        assert_unpublished(api.request(f"/releases/{release_id}"))
        old = by_name.get(name)
        if old and old.get("state") == "uploaded" and old.get("digest") == "sha256:" + checksum:
            continue
        if old:
            api.request(f"/releases/assets/{old['id']}", "DELETE")
        upload_url = release["upload_url"].split("{", 1)[0] + "?name=" + quote(name, safe="")
        asset = api.request(upload_url, "POST", file=directory / name)
        if asset.get("digest") != "sha256:" + checksum or asset.get("state") != "uploaded":
            raise ValueError(f"Uploaded asset verification failed: {name}")
    final = api.request(f"/releases/{release_id}")
    assert_unpublished(final)
    assert_main_without_tag(api, sha)
    if final["body"] != notes or final["target_commitish"] != sha or final["name"] != VERSION:
        raise ValueError("Final draft metadata mismatch")
    assets = list(api.items(f"/releases/{release_id}/assets"))
    if len(assets) != 7 or {a["name"]: a.get("digest") for a in assets} != {n: "sha256:" + h for n, h in expected.items()}:
        raise ValueError("Final asset set mismatch")
    print(f"Verified unpublished {VERSION}: {sha}, six packages + SHA256SUMS, no tag. {final['html_url']}")


if __name__ == "__main__":
    client = GitHub(os.environ["GH_REPO"], os.environ["GH_TOKEN"])
    commit = os.environ["RELEASE_SHA"]
    wait_for_ci(client, commit)
    sync_draft(client, commit, Path(sys.argv[1]), Path(sys.argv[2]).read_text(encoding="utf-8"))
