# agevault

Encrypt and restore a directory using [age](https://age-encryption.org/). This fork ports upstream [v1.2.0](https://github.com/ndavd/agevault/releases/tag/v1.2.0), while retaining streaming encryption, bounded-memory shredding, atomic ciphertext publication, custom identity paths and older identity formats. Build with Go 1.26.9 or newer.

## Usage

```text
agevault documents keygen -pq --key alice.age
agevault documents lock
agevault documents unlock --key alice.age
```

Use a single directory name in the current working directory. Omit `-pq` for classical X25519 keys. `-pq` generates age hybrid X25519+ML-KEM-768 keys. It only affects key generation; existing vaults are not automatically upgraded. Passphrases are read from the terminal, never command-line arguments.

Key generation creates the vault directory if needed, writes a passphrase-encrypted identity outside it and adds the public recipient to `documents/.agevault-recipients`. Default identity names are `.<fingerprint>.documents.key.age`. Keep the identity and passphrase backed up separately. Without both, recovery is impossible. A custom key path must point outside the vault; use that path with `--key` on unlock.

## Sharing

While the vault is unlocked, run key generation again with a different identity path, or add a trusted public age recipient on its own line to `.agevault-recipients`. Each recipient can decrypt independently using their own identity and passphrase. Keep private identities outside the vault. Multiple discoverable keys require `--key` on unlock. Classical and hybrid recipients cannot be mixed in one vault. Removing a recipient affects subsequent encryption only; it cannot revoke copies of previous ciphertext.

`lock` normally reads an existing public recipient list without prompting, streams tar into age, flushes ciphertext and publishes it without overwriting an existing file, then overwrites plaintext files in bounded chunks. When `--key` is supplied, it asks for that identity's passphrase and verifies that its actual public recipient is listed; it does not silently replace a shared recipient list. Existing or migrated identities must resolve outside the vault, including through symlinks. Symlinks, hard links and special files are refused. Check recipients against a trusted source before locking: anyone able to edit the recipient list or legacy public metadata can redirect encryption.

## Compatibility

Unlock supports upstream v1.0 ZIP vaults, v1.1 tar vaults, v1.2 recipient lists, this fork's version-1 JSON identity envelope, `.av` metadata, `.vault.age` identities and recipient-bearing legacy filenames. When a recipient list is missing, migration decrypts the selected legacy identity once to derive its actual public recipient. It prompts for the old passphrase before locking or adding keys. An explicit `--key` takes priority over stale `.av` metadata, and raw custom identity files work even without public metadata or recipient-bearing filenames. Legacy public fields are treated as hints and cannot override the decrypted identity. New keys use upstream passphrase-encrypted age identities. Older programs cannot read hybrid keys; compatibility here means the upgraded program can read older vaults.

## Recovery and security limits

Unlock streams decrypted tar into a private `.agevault-unlock-*` staging directory. It checks archive paths and types, authenticates the complete age stream (including data after the tar end marker), syncs restored files, then renames the restored vault into place. Only after restoration succeeds is ciphertext removed. Failed extraction or authentication leaves ciphertext unchanged and cleans staging during normal error handling. The expected archive root must be a directory. Writing and extraction share the same path validation: POSIX keeps native names such as `aux.txt`, colons, backslashes and trailing dots; Windows rejects device names, alternate data streams and ambiguous aliases. Archives with Windows-incompatible filenames can be restored on POSIX; a Windows refusal retains the ciphertext. No temporary plaintext archive is written. Legacy ZIP requires random access and is held in memory, so old ZIP vaults require memory proportional to archive size. New tar vaults stream regardless of file size. Restored directories/files use private 0700/0600 permissions; original executable bits and timestamps are not restored.

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
