package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/ndavd/agevault/internal/archive"
	"github.com/ndavd/agevault/internal/crypt"
	"github.com/ndavd/agevault/internal/recipients"
	"github.com/ndavd/agevault/internal/shredder"
	"github.com/ndavd/agevault/internal/utils"
)

func Version() string {
	return "v1.2.0-fork.1"
}

func Usage() {
	fmt.Printf("agevault %s", Version())
	fmt.Println()
	fmt.Println("lock/unlock directory with passphrase-protected identity file")
	fmt.Println("usage: agevault [directory-name] lock|unlock|keygen [-pq] [--key identity-file]")
	fmt.Println()
	fmt.Println("-pq generates hybrid post-quantum keys; --key selects an identity file")
	os.Exit(0)
}

func errMsg(err error) {
	fmt.Printf("error: %s\n", err.Error())
	os.Exit(1)
}

var errMissingIdentity = errors.New("missing identity file")

func getIdentityFilename(trimmedVaultName string, explicit ...string) (string, error) {
	if len(explicit) > 0 && explicit[0] != "" {
		return explicit[0], nil
	}
	if _, err := os.Lstat("." + trimmedVaultName + ".age"); err == nil {
		return "." + trimmedVaultName + ".age", nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var metadata struct {
		Version int
		KeyFile string
	}
	if data, err := os.ReadFile("." + trimmedVaultName + ".av"); err == nil {
		if json.Unmarshal(data, &metadata) != nil || metadata.Version != 1 || metadata.KeyFile == "" {
			return "", errors.New("invalid vault metadata; specify --key")
		}
		return metadata.KeyFile, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	identityFilename, err := utils.FileMatchInCwd(func(filename string) bool {
		return strings.HasSuffix(filename, fmt.Sprintf(".%s.key.age", trimmedVaultName))
	})
	if err != nil {
		return "", err
	}
	if identityFilename == "" {
		return "", errMissingIdentity
	}
	return identityFilename, nil
}

func generateIdentity(postQuantum bool) (fmt.Stringer, recipients.Recipient, error) {
	if postQuantum {
		identity, err := age.GenerateHybridIdentity()
		if err != nil {
			return nil, nil, err
		}
		return identity, identity.Recipient(), nil
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, nil, err
	}
	return identity, identity.Recipient(), nil
}

func Keygen(vaultName string, trimmedVaultName string, passphrase string, postQuantum bool, explicit ...string) (string, string, error) {
	return keygenWithPassphrase(vaultName, trimmedVaultName, passphrase, postQuantum, identityPassphrase, explicit...)
}

func keygenWithPassphrase(vaultName, trimmedVaultName, passphrase string, postQuantum bool, password func(string) (string, error), explicit ...string) (string, string, error) {
	encryptedExists, encryptedIsDir := utils.Exists(fmt.Sprintf("%s.age", vaultName))
	if encryptedExists && !encryptedIsDir {
		return "", "", errors.New("vault is locked, unlock it first")
	}
	if info, e := os.Lstat(vaultName); e == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return "", "", errors.New("vault must be a real directory")
	}
	if err := os.MkdirAll(vaultName, 0o700); err != nil {
		return "", "", fmt.Errorf("could not create %s: %s", vaultName, err.Error())
	}
	// Preserve the original recipient when adding a key to an unlocked legacy vault.
	if _, e := os.Stat(filepath.Join(vaultName, recipients.FileName)); errors.Is(e, os.ErrNotExist) {
		if _, e = getIdentityFilename(trimmedVaultName); e == nil {
			if e = migrateRecipient(vaultName, trimmedVaultName, password); e != nil {
				return "", "", e
			}
		} else if !errors.Is(e, errMissingIdentity) {
			return "", "", e
		}
	}
	// NOTE: age refuses to mix post-quantum and X25519 recipients
	if existing, err := recipients.Read(vaultName); err == nil {
		if len(existing) == 0 {
			return "", "", errors.New("empty recipients file")
		}
		if _, isPostQuantum := existing[0].(*age.HybridRecipient); isPostQuantum != postQuantum {
			return "", "", errors.New("can't mix post-quantum and X25519 recipients in the same vault")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", fmt.Errorf("could not read recipients: %s", err.Error())
	}
	identity, recipient, err := generateIdentity(postQuantum)
	if err != nil {
		return "", "", err
	}
	fingerprint := crypt.Fingerprint(recipient)
	identityFilename := fmt.Sprintf(".%s.%s.key.age", fingerprint, trimmedVaultName)
	if len(explicit) > 0 && explicit[0] != "" {
		identityFilename = explicit[0]
	}
	if err = keyOutsideVault(identityFilename, vaultName); err != nil {
		return "", "", err
	}
	if _, e := os.Lstat(identityFilename); !errors.Is(e, os.ErrNotExist) {
		return "", "", errors.New("identity destination exists or is inaccessible")
	}
	scryptRecipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return "", "", err
	}
	if err = crypt.EncryptToFile(identityFilename, []byte(identity.String()), scryptRecipient); err != nil {
		return "", "", err
	}
	if err = recipients.Append(vaultName, trimmedVaultName, recipient); err != nil {
		return "", "", fmt.Errorf("could not add recipient: %s", err.Error())
	}
	return identityFilename, fingerprint, nil
}

func identityPassphrase(filename string) (string, error) {
	return crypt.ReadSecret(fmt.Sprintf("enter passphrase for identity file %q", filename), false)
}

func Lock(vaultName string, trimmedVaultName string, explicit ...string) ([]age.Recipient, error) {
	return lockWithPassphrase(vaultName, trimmedVaultName, identityPassphrase, explicit...)
}

func lockWithPassphrase(vaultName, trimmedVaultName string, password func(string) (string, error), explicit ...string) ([]age.Recipient, error) {
	encryptedFilename := fmt.Sprintf("%s.age", vaultName)
	encryptedExists, encryptedIsDir := utils.Exists(encryptedFilename)
	if encryptedExists && !encryptedIsDir {
		return nil, errors.New("already locked")
	}
	vaultExists, vaultIsDir := utils.Exists(vaultName)
	if !vaultExists || !vaultIsDir {
		return nil, fmt.Errorf("missing %s", vaultName)
	}
	// Validate the selected identity even when public recipients already exist.
	// Old forks allowed identities in the vault, so keygen's check is insufficient.
	identityFilename, err := lockIdentityFilename(trimmedVaultName, explicit...)
	if err != nil {
		return nil, err
	}
	if identityFilename != "" {
		if err = keyOutsideVault(identityFilename, vaultName); err != nil {
			return nil, err
		}
	}
	// Discovery may be ambiguous in a shared vault. Check every discoverable
	// legacy identity rather than ignoring symlinks just because no single key is selected.
	if len(explicit) == 0 || explicit[0] == "" {
		entries, e := os.ReadDir(".")
		if e != nil {
			return nil, e
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), "."+trimmedVaultName+".key.age") {
				if e = keyOutsideVault(entry.Name(), vaultName); e != nil {
					return nil, e
				}
			}
		}
	}
	var selected recipients.Recipient
	if len(explicit) > 0 && explicit[0] != "" {
		selected, err = recipientFromIdentity(identityFilename, password)
		if err != nil {
			return nil, err
		}
	}
	recipientList, err := recipients.Read(vaultName)
	if errors.Is(err, os.ErrNotExist) {
		if selected != nil {
			err = recipients.Append(vaultName, trimmedVaultName, selected)
		} else {
			err = migrateRecipient(vaultName, trimmedVaultName, password, explicit...)
		}
		if err != nil {
			return nil, err
		}
		recipientList, err = recipients.Read(vaultName)
	}
	if err != nil {
		return nil, fmt.Errorf("could not read recipients: %w", err)
	}
	if selected != nil {
		found := false
		for _, r := range recipientList {
			if public, ok := r.(fmt.Stringer); ok && public.String() == selected.String() {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("selected identity is not in vault recipients; add its public recipient before locking")
		}
	}
	archiveReader, archiveWriter := io.Pipe()
	defer archiveReader.Close()
	archiveErr := make(chan error, 1)
	go func() {
		e := archive.TarDirectory(vaultName, archiveWriter)
		archiveWriter.CloseWithError(e)
		archiveErr <- e
	}()
	if err = crypt.EncryptToFileFromReader(encryptedFilename, archiveReader, recipientList...); err != nil {
		archiveReader.CloseWithError(err)
		<-archiveErr
		return nil, fmt.Errorf("could not encrypt: %w", err)
	}
	if err = <-archiveErr; err != nil {
		return nil, err
	}
	if err = shredder.ShredDir(vaultName, 3); err != nil {
		return nil, fmt.Errorf("could not shred %s: %s", vaultName, err.Error())
	}
	return recipientList, nil
}

func Unlock(vaultName string, trimmedVaultName string, getPassphrase func(identityFilename string) (string, error), explicit ...string) error {
	identityFilename, err := getIdentityFilename(trimmedVaultName, explicit...)
	if err != nil {
		return err
	}
	_, destinationErr := os.Lstat(vaultName)
	if !errors.Is(destinationErr, os.ErrNotExist) {
		return errors.New("already unlocked")
	}
	encryptedVaultFilename := fmt.Sprintf("%s.age", vaultName)
	encryptedVault, err := os.Open(encryptedVaultFilename)
	if err != nil {
		return fmt.Errorf("missing encrypted %s: %s", vaultName, err.Error())
	}
	defer encryptedVault.Close()
	identity, err := readIdentity(identityFilename, getPassphrase)
	if err != nil {
		return err
	}
	plaintext, err := age.Decrypt(encryptedVault, identity)
	if err != nil {
		return err
	}
	staging, err := os.MkdirTemp(".", ".agevault-unlock-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	reader := bufio.NewReader(plaintext)
	header, err := reader.Peek(4)
	if err != nil {
		return err
	}
	if bytes.Equal(header, []byte("PK\x03\x04")) {
		// ZIP requires random access. Keep legacy data in memory, never a plaintext archive on disk.
		data, e := io.ReadAll(reader)
		if e != nil {
			return e
		}
		if err = archive.UnZip(*bytes.NewReader(data), staging, vaultName); err != nil {
			return err
		}
	} else {
		if err = archive.UnTar(reader, staging, vaultName); err != nil {
			return err
		}
		// tar stops at its end marker; drain age to authenticate the final chunk.
		if _, err = io.Copy(io.Discard, reader); err != nil {
			return err
		}
	}
	if err = encryptedVault.Close(); err != nil {
		return err
	}
	if _, e := os.Lstat(vaultName); !errors.Is(e, os.ErrNotExist) {
		return errors.New("vault destination exists or is inaccessible")
	}
	stagedInfo, e := os.Lstat(filepath.Join(staging, vaultName))
	if e != nil {
		return e
	}
	if !stagedInfo.IsDir() || stagedInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("archive must contain the expected vault directory")
	}
	if err = syncTree(staging); err != nil {
		return err
	}
	if err = os.Rename(filepath.Join(staging, vaultName), vaultName); err != nil {
		return err
	}
	if err = utils.SyncDir("."); err != nil {
		return err
	}
	if err = shredder.ShredFile(encryptedVaultFilename, 1); err != nil {
		return fmt.Errorf("could not shred %s: %s", encryptedVaultFilename, err.Error())
	}
	return nil
}

func main() {
	args := os.Args[1:]

	if len(args) == 1 && args[0] == "--version" {
		fmt.Println(Version())
		os.Exit(0)
	}

	if len(args) < 2 {
		Usage()
	}

	action := args[1]
	vaultName := filepath.Clean(args[0])

	// NOTE: Useful for supporting dot-directories
	trimmedVaultName := strings.Trim(vaultName, ". ")

	badArgsError := errors.New("bad args")

	postQuantum := false
	explicitKey := ""
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "-pq":
			if action != "keygen" {
				errMsg(badArgsError)
			}
			postQuantum = true
		case "--key":
			i++
			if i >= len(args) {
				errMsg(badArgsError)
			}
			explicitKey = args[i]
		default:
			errMsg(badArgsError)
		}
	}
	if strings.ContainsAny(args[0], `/\\`) || !filepath.IsLocal(args[0]) || vaultName == "." {
		errMsg(errors.New("directory name must not contain a path"))
	}
	if trimmedVaultName == "" {
		errMsg(badArgsError)
	}

	if action == "keygen" {
		pw, err := crypt.ReadSecret("identity passphrase", true)
		if err != nil {
			errMsg(err)
		}
		identityFilename, fingerprint, err := Keygen(vaultName, trimmedVaultName, pw, postQuantum, explicitKey)
		if err != nil {
			errMsg(err)
		}
		fmt.Printf("%s CREATED\n", identityFilename)
		fmt.Printf("%s ADDED to %s\n", fingerprint, filepath.Join(vaultName, recipients.FileName))
		return
	}

	if action == "lock" {
		recipientList, err := Lock(vaultName, trimmedVaultName, explicitKey)
		if err != nil {
			errMsg(err)
		}
		fmt.Printf("%s LOCKED with:\n", vaultName)
		for _, recipient := range recipientList {
			fmt.Printf("  %s\n", crypt.Fingerprint(recipient.(fmt.Stringer)))
		}
		return
	}

	if action == "unlock" {
		err := Unlock(vaultName, trimmedVaultName, func(identityFilename string) (string, error) {
			return crypt.ReadSecret(
				fmt.Sprintf("enter passphrase for identity file \"%s\"", identityFilename),
				false,
			)
		}, explicitKey)
		if err != nil {
			errMsg(err)
		}
		fmt.Printf("%s UNLOCKED\n", vaultName)
		return
	}

	errMsg(badArgsError)
}

// readIdentity accepts both the fork JSON envelope and original age identity files.
func readIdentity(filename string, password func(string) (string, error)) (age.Identity, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Version           int
		EncryptedIdentity string
	}
	if json.Unmarshal(data, &envelope) == nil && envelope.Version == 1 {
		data, err = base64.StdEncoding.DecodeString(envelope.EncryptedIdentity)
		if err != nil {
			return nil, err
		}
	}
	pw, err := password(filename)
	if err != nil {
		return nil, err
	}
	id, err := age.NewScryptIdentity(pw)
	if err != nil {
		return nil, err
	}
	var plain bytes.Buffer
	if err = crypt.DecryptToWriter(&plain, bytes.NewReader(data), id); err != nil {
		return nil, err
	}
	ids, err := age.ParseIdentities(&plain)
	if err != nil {
		return nil, err
	}
	if len(ids) != 1 {
		return nil, errors.New("expected one identity")
	}
	return ids[0], nil
}

// Public legacy metadata is a hint, never proof of which private identity is usable.
func migrateRecipient(vault, trimmed string, password func(string) (string, error), explicit ...string) error {
	filename, err := getIdentityFilename(trimmed, explicit...)
	if err != nil {
		return err
	}
	if err = keyOutsideVault(filename, vault); err != nil {
		return err
	}
	recipient, err := recipientFromIdentity(filename, password)
	if err != nil {
		return err
	}
	return recipients.Append(vault, trimmed, recipient)
}

func recipientFromIdentity(filename string, password func(string) (string, error)) (recipients.Recipient, error) {
	identity, err := readIdentity(filename, password)
	if err != nil {
		return nil, err
	}
	switch id := identity.(type) {
	case *age.X25519Identity:
		return id.Recipient(), nil
	case *age.HybridIdentity:
		return id.Recipient(), nil
	default:
		return nil, errors.New("unsupported vault identity type")
	}
}

// Public-only shared vaults need no local private identity. Explicit keys and
// known legacy locations must still be checked before destructive locking.
func lockIdentityFilename(trimmed string, explicit ...string) (string, error) {
	if len(explicit) > 0 && explicit[0] != "" {
		return explicit[0], nil
	}
	filename := "." + trimmed + ".age"
	if _, err := os.Lstat(filename); err == nil {
		return filename, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	data, err := os.ReadFile("." + trimmed + ".av")
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var metadata struct {
		Version int
		KeyFile string
	}
	if json.Unmarshal(data, &metadata) != nil || metadata.Version != 1 || metadata.KeyFile == "" {
		return "", errors.New("invalid legacy metadata; specify --key")
	}
	return metadata.KeyFile, nil
}

func syncTree(directory string) error {
	return filepath.WalkDir(directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return utils.SyncDir(path)
		}
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		return f.Sync()
	})
}

func keyOutsideVault(key, vault string) error {
	parent, err := filepath.EvalSymlinks(filepath.Dir(key))
	if err != nil {
		return err
	}
	realKey, err := filepath.Abs(filepath.Join(parent, filepath.Base(key)))
	if err != nil {
		return err
	}
	if _, e := os.Lstat(key); e == nil {
		realKey, err = filepath.EvalSymlinks(key)
		if err != nil {
			return err
		}
		realKey, err = filepath.Abs(realKey)
		if err != nil {
			return err
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	realVault, err := filepath.EvalSymlinks(vault)
	if err != nil {
		return err
	}
	realVault, err = filepath.Abs(realVault)
	if err != nil {
		return err
	}
	if rel, e := filepath.Rel(realVault, realKey); e == nil && (rel == "." || filepath.IsLocal(rel)) {
		return errors.New("identity must be outside vault")
	}
	cipher, _ := filepath.Abs(vault + ".age")
	if strings.EqualFold(realKey, cipher) {
		return errors.New("identity path conflicts with ciphertext")
	}
	return nil
}
