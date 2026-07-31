# agevault

`agevault` encrypts and restores one directory at a time using [age](https://age-encryption.org/).
It creates `vault.age` for encrypted data and, by default, `.vault.age` for the passphrase-protected identity.

## Important security notes

- Keep the hidden identity file and its passphrase in separate, secure backups. Without both, a vault cannot be recovered.
- The identity file contains a public recipient and an encrypted private identity. The public part lets `lock` run without prompting; `unlock` requires the passphrase.
- File overwriting is not a guaranteed secure-delete mechanism, particularly on SSDs, networked storage, synced folders, or filesystems with snapshots. Use full-disk encryption and appropriate backup policies for sensitive data.

## Install

Download a release binary, or build locally:

```text
go build -trimpath -ldflags="-s -w" -o agevault .
```

## Usage

```text
agevault [directory-name] lock|unlock|keygen [--key identity-file]
```

### Create an identity

```text
agevault documents keygen
```

This creates `.documents.age`. Use `--key` to choose a different identity-file path:

```text
agevault documents keygen --key .vault-key.age
```

### Lock and unlock

```text
agevault documents lock
agevault documents unlock
```

`lock` reads the public recipient from the identity file and does not prompt. `unlock` prompts for the identity-file passphrase.

If the default identity file is unavailable, pass its path explicitly:

```text
agevault documents unlock --key D:\secure-backup\vault-key.age
```

## Compatibility

Existing legacy identity-file and `.av` metadata pairs remain readable. New identities use the single-file format above.
