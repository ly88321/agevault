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

func getIdentityFilename(trimmedVaultName string, explicit ...string) (string, error) {
	if len(explicit) > 0 && explicit[0] != "" {
		return explicit[0], nil
	}
	if _, err := os.Stat("." + trimmedVaultName + ".age"); err == nil {
		return "." + trimmedVaultName + ".age", nil
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
	}
	identityFilename, err := utils.FileMatchInCwd(func(filename string) bool {
		return strings.HasSuffix(filename, fmt.Sprintf(".%s.key.age", trimmedVaultName))
	})
	if err != nil {
		return "", err
	}
	if identityFilename == "" {
		return "", errors.New("missing identity file")
	}
	return identityFilename, nil
}

// NOTE: Ensure backwards compatibility with versions before v1.2.0, where the recipient was in the identity filename
func migrateLegacyRecipient(vaultName string, trimmedVaultName string) error {
	missingErr := fmt.Errorf("missing %s, run keygen first", filepath.Join(vaultName, recipients.FileName))
	identityFilename, err := getIdentityFilename(trimmedVaultName)
	if err != nil {
		return missingErr
	}
	parts := strings.Split(filepath.Base(identityFilename), ".")
	if len(parts) < 4 {
		return missingErr
	}
	recipient, err := age.ParseX25519Recipient(parts[1])
	if err != nil {
		return missingErr
	}
	if err = recipients.Append(vaultName, trimmedVaultName, recipient); err != nil {
		return fmt.Errorf("could not add recipient: %s", err.Error())
	}
	fmt.Printf("found deprecated recipient format, migrated to %s...\n", filepath.Join(vaultName, recipients.FileName))
	return nil
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
			if e = migrateRecipient(vaultName, trimmedVaultName); e != nil {
				return "", "", e
			}
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

func Lock(vaultName string, trimmedVaultName string, explicit ...string) ([]age.Recipient, error) {
	encryptedFilename := fmt.Sprintf("%s.age", vaultName)
	encryptedExists, encryptedIsDir := utils.Exists(encryptedFilename)
	if encryptedExists && !encryptedIsDir {
		return nil, errors.New("already locked")
	}
	vaultExists, vaultIsDir := utils.Exists(vaultName)
	if !vaultExists || !vaultIsDir {
		return nil, fmt.Errorf("missing %s", vaultName)
	}
	recipientList, err := recipients.Read(vaultName)
	if errors.Is(err, os.ErrNotExist) {
		if err = migrateRecipient(vaultName, trimmedVaultName, explicit...); err != nil {
			return nil, err
		}
		recipientList, err = recipients.Read(vaultName)
	}
	if err != nil {
		return nil, fmt.Errorf("could not read recipients: %s", err.Error())
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
func migrateRecipient(vault, trimmed string, explicit ...string) error {
	filename, err := getIdentityFilename(trimmed, explicit...)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var envelope struct {
		Version   int
		Recipient string
	}
	if json.Unmarshal(data, &envelope) == nil && envelope.Version == 1 && envelope.Recipient != "" {
		list, e := parsePublicRecipient(envelope.Recipient)
		if e != nil {
			return e
		}
		return recipients.Append(vault, trimmed, list[0].(recipients.Recipient))
	}
	// Metadata from the fork stored the public recipient separately.
	var metadata struct {
		Version   int
		Recipient string
	}
	if data, e := os.ReadFile("." + trimmed + ".av"); e == nil && json.Unmarshal(data, &metadata) == nil && metadata.Version == 1 && metadata.Recipient != "" {
		list, e := parsePublicRecipient(metadata.Recipient)
		if e != nil {
			return e
		}
		return recipients.Append(vault, trimmed, list[0].(recipients.Recipient))
	}
	return migrateLegacyRecipient(vault, trimmed)
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

func parsePublicRecipient(text string) ([]age.Recipient, error) {
	list, err := age.ParseRecipients(strings.NewReader(text))
	if err != nil {
		return nil, err
	}
	if len(list) != 1 {
		return nil, errors.New("expected one legacy recipient")
	}
	return list, nil
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
