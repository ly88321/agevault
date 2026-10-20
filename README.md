# agevault

Encrypt and restore a directory using [age](https://age-encryption.org/). This fork ports upstream [v1.2.0](https://github.com/ndavd/agevault/releases/tag/v1.2.0), while retaining streaming encryption, bounded-memory shredding, atomic ciphertext publication, custom identity paths and older identity formats. Build with Go 1.26.9 or newer.

## Usage

```text
agevault documents keygen -pq --key alice.age
agevault documents lock
agevault documents unlock --key alice.age --keep-ciphertext
```

Use a single directory name in the current working directory. Omit `-pq` for classical X25519 keys. `-pq` generates age hybrid X25519+ML-KEM-768 keys. It only affects key generation; existing vaults are not automatically upgraded. Passphrases are read from the terminal, never command-line arguments.

Key generation creates the vault directory if needed, writes a passphrase-encrypted identity outside it and adds the public recipient to `documents/.agevault-recipients`. Default identity names are `.<fingerprint>.documents.key.age`. Keep the identity and passphrase backed up separately. Without both, recovery is impossible. A custom key path must point outside the vault; use that path with `--key` on unlock.

## Sharing

While the vault is unlocked, run key generation again with a different identity path, or add a trusted public age recipient on its own line to `.agevault-recipients`. Each recipient can decrypt independently using their own identity and passphrase. Keep private identities outside the vault. Multiple discoverable keys require `--key` on unlock. Classical and hybrid recipients cannot be mixed in one vault. Removing a recipient affects subsequent encryption only; it cannot revoke copies of previous ciphertext.

`lock` normally reads an existing public recipient list without prompting, streams tar into age, flushes ciphertext and publishes it without overwriting an existing file, then overwrites plaintext files in bounded chunks. When `--key` is supplied, it asks for that identity's passphrase and verifies that its actual public recipient is listed; it does not silently replace a shared recipient list. Existing or migrated identities must resolve outside the vault, including through symlinks. Symlinks, hard links and special files are refused. Check recipients against a trusted source before locking: anyone able to edit the recipient list or legacy public metadata can redirect encryption.

## Compatibility

Unlock supports upstream v1.0 ZIP vaults, v1.1 tar vaults, v1.2 recipient lists, this fork's version-1 JSON identity envelope, `.av` metadata, `.vault.age` identities and recipient-bearing legacy filenames. When a recipient list is missing, migration decrypts the selected legacy identity once to derive its actual public recipient. It prompts for the old passphrase before locking or adding keys. An explicit `--key` takes priority over stale `.av` metadata, and raw custom identity files work even without public metadata or recipient-bearing filenames. Legacy public fields are treated as hints and cannot override the decrypted identity. New keys use upstream passphrase-encrypted age identities. Older programs cannot read hybrid keys; compatibility here means the upgraded program can read older vaults.

## Recovery and security limits

Unlock streams decrypted tar into a private `.agevault-unlock-*` staging directory. It checks archive paths and types, authenticates the complete age stream (including data after the tar end marker), syncs restored files, then renames the restored vault into place. By default, ciphertext is removed only after restoration succeeds. Add `--keep-ciphertext` to `unlock` to preserve the original ciphertext bytes, including for legacy ZIP and hybrid vaults. This option is rejected for `lock` and `keygen`. If ciphertext was retained, a later `lock` refuses to overwrite it: verify the restored data and move the old encrypted archive to a backup location before encrypting again. Failed extraction or authentication leaves ciphertext unchanged and cleans staging during normal error handling. Cleanup failure explicitly reports the private staging path; inspect it on encrypted storage. A ciphertext-cleanup failure after restoration reports that the vault was restored; the ciphertext may already be partially overwritten, so verify the restored plaintext rather than relying on that damaged archive. Retention mode never calls ciphertext shredding. The expected archive root must be a directory. Writing and extraction share the same path validation: POSIX keeps native names such as `aux.txt`, colons, backslashes and trailing dots; Windows rejects device names, alternate data streams and ambiguous aliases. Archives with Windows-incompatible filenames can be restored on POSIX; a Windows refusal retains the ciphertext. No temporary plaintext archive is written. Legacy ZIP requires random access and is held in memory, so old ZIP vaults require memory proportional to archive size. New tar vaults stream regardless of file size. Restored directories/files use private 0700/0600 permissions; original executable bits and timestamps are not restored.

If interrupted during unlock, ciphertext remains available until publication completes. A process crash can leave plaintext in `.agevault-unlock-*`; inspect and remove leftover staging directories on encrypted storage. If locking fails during shredding, the complete encrypted vault remains alongside partially erased plaintext: move the remaining plaintext directory aside, then unlock the ciphertext into its original name. If both plaintext and ciphertext exist after unlock, verify restored data before removing either copy. Do not lock or unlock concurrently or modify the source during either operation; hostile concurrent filesystem mutation is outside the supported threat model.

File overwriting cannot guarantee secure deletion on SSDs, copy-on-write filesystems, snapshots, backups, synced folders or network storage. Use full-disk encryption. On Unix directory entries are synced before source removal; Windows flushes file contents but does not provide POSIX directory fsync through Go, so sudden-power-loss durability depends on the filesystem. Windows private permissions follow the parent directory's ACL; use a private account directory.

## Build and validation

```text
go build .
go vet ./...
go test -count=1 ./...
```

Tests cover original upstream compatibility fixtures; verified fork envelope/metadata migration; stale metadata and standalone external legacy identities; identities moved or symlinked into the vault; classical/hybrid sharing and explicit-key membership; POSIX filename round trips in new and legacy tar/ZIP archives; Windows path rejection; malicious authenticated archives; wrong/cancelled passphrases; corrupted/truncated ciphertext; atomic-write failure; and a 64 MiB streaming round trip. CI runs tests on Linux, macOS and Windows with Go 1.26.9 and 1.27.2. Release publishing remains tag-triggered; this upgrade does not create a release.

Go 1.26.9 is the minimum because earlier runtimes have a Windows Root directory-creation vulnerability ([GO-2026-6604](https://pkg.go.dev/vuln/GO-2026-6604)).

## Fault injection and crash recovery tests

These tests run as part of normal `go test ./...` on Linux, Windows and macOS:

- Scoped filesystem replacements inject `ENOSPC`, `EIO`, access failures, short writes, close/flush failures, failed links/renames, failed staging cleanup and partial shredding. Tests verify that errors preserve the complete source before commit, retain a recoverable encrypted copy during partial source erasure, and keep restored plaintext after a later ciphertext-cleanup failure.
- Subprocesses exit immediately without Go cleanup at 15 points: mid-write, after ciphertext file/directory sync, before/after source shredding, during partial shredding, mid-extraction, after authentication, around restoration publication and before/after ciphertext removal. Restart tests inspect leftover private staging and recover from the original ciphertext without overwriting an existing destination.
- A deterministic power-loss model discards unsynced bytes and directory entries. It verifies that source shredding cannot start before the ciphertext name and contents are durable, and that the durable archive still restores the original files after source removal. A separate ordering test checks that ciphertext cleanup follows the restored directory's publication and parent sync.

Injection callbacks are passed explicitly to internal operations. The production CLI has no fault-injection flags or environment switches. Only `_test.go` code uses subprocess control variables and abrupt exits; the fixture-only low scrypt work factor does not affect generated user identities.

These are software crash/persistence simulations, not physical power cuts or a failing drive experiment. They cannot validate a device's cache, controller firmware, filesystem guarantees or Windows directory persistence. Full-disk encryption and backups remain necessary. A process crash can leave `.agevault-*` encrypted temporary files or `.agevault-unlock-*` plaintext staging. Do not treat a leftover temporary file as a complete backup. Verify a committed `vault.age` with the correct identity; if locking stopped partway through shredding, preserve the remaining directory under another name and restore using `--keep-ciphertext`. Old temporary hardlinks can cause default ciphertext cleanup to be refused; retention mode avoids destructive cleanup during recovery. Never remove the only verified copy or automatically discard crash leftovers.

To run only these tests:

```text
go test -count=1 -run 'TestKeepCiphertext|TestLockDiskFaults|TestUnlockDiskFaults|TestFailedPrivateStaging|TestPartialShred|TestCipherRemoval|TestAbrupt|TestPowerLoss' .
```
