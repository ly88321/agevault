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
	"github.com/ndavd/agevault/internal/shredder"
	"github.com/ndavd/agevault/internal/utils"
)

func Version() string {
	return "v1.1.1"
}

func Usage() {
	fmt.Printf("agevault %s", Version())
	fmt.Println()
	fmt.Println("lock/unlock directory with passphrase-protected identity file")
	fmt.Println("usage: agevault [directory-name] lock|unlock|keygen [--key identity-file]")
	os.Exit(0)
}

func errMsg(err error) {
	fmt.Printf("error: %s\n", err.Error())
	os.Exit(1)
}

type keyMetadata struct {
	Version   int
	KeyFile   string
	Recipient string
}
type identityEnvelope struct {
	Version int
	Recipient string
	EncryptedIdentity string
}

func metadataFilename(vaultName string) string { return fmt.Sprintf(".%s.av", vaultName) }

func getIdentityFilename(trimmedVaultName, explicitFilename string) (string, error) {
	if explicitFilename != "" {
		exists, isDir := utils.Exists(explicitFilename)
		if !exists || isDir { return "", errors.New("specified identity file is missing") }
		return explicitFilename, nil
	}
	if name := fmt.Sprintf(".%s.age", trimmedVaultName); func() bool { e, d := utils.Exists(name); return e && !d }() {
		return name, nil
	}
	metadataBytes, err := os.ReadFile(metadataFilename(trimmedVaultName))
	if err == nil {
		var metadata keyMetadata
		if err = json.Unmarshal(metadataBytes, &metadata); err != nil || metadata.Version != 1 || metadata.KeyFile == "" {
			return "", errors.New("invalid vault metadata; use --key to specify the identity file")
		}
		exists, isDir := utils.Exists(metadata.KeyFile)
		if !exists || isDir { return "", errors.New("identity file referenced by vault metadata is missing") }
		return metadata.KeyFile, nil
	}
	if !errors.Is(err, os.ErrNotExist) { return "", err }
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

func Keygen(trimmedVaultName, explicitFilename string) (string, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", err
	}
	identityFilename := explicitFilename
	if identityFilename == "" { identityFilename = fmt.Sprintf(".%s.age", trimmedVaultName) }
	if exists, _ := utils.Exists(identityFilename); exists { return "", errors.New("identity file already exists") }
	pw, err := crypt.ReadSecret("identity passphrase", true)
	if err != nil {
		return "", err
	}
	scryptRecipient, err := age.NewScryptRecipient(pw)
	if err != nil {
		return "", err
	}
	temp, err := os.CreateTemp(".", ".agevault-key-*")
	if err != nil { return "", err }
	tempName := temp.Name(); _ = temp.Close(); defer os.Remove(tempName)
	if err = crypt.EncryptToFile(tempName, []byte(identity.String()), scryptRecipient); err != nil {
		return "", err
	}
	encrypted, err := os.ReadFile(tempName)
	if err != nil { return "", err }
	envelope, err := json.Marshal(identityEnvelope{Version: 1, Recipient: identity.Recipient().String(), EncryptedIdentity: base64.StdEncoding.EncodeToString(encrypted)})
	if err != nil { return "", err }
	if err = os.WriteFile(identityFilename, envelope, 0o600); err != nil { return "", err }
	return identityFilename, nil
}

func Lock(vaultName string, trimmedVaultName, explicitIdentityFilename string) (string, error) {
	encryptedFilename := fmt.Sprintf("%s.age", vaultName)
	if encryptedExists, _ := utils.Exists(encryptedFilename); encryptedExists {
		return "", errors.New("encrypted vault already exists")
	}
	identityFilename, err := getIdentityFilename(trimmedVaultName, explicitIdentityFilename)
	if err != nil {
		return "", err
	}
	var recipient *age.X25519Recipient
	if explicitIdentityFilename == "" {
		metadataBytes, metadataErr := os.ReadFile(identityFilename)
		if metadataErr == nil {
			var metadata identityEnvelope
			if json.Unmarshal(metadataBytes, &metadata) == nil && metadata.Recipient != "" {
				recipient, err = age.ParseX25519Recipient(metadata.Recipient)
				if err != nil {
					return "", fmt.Errorf("invalid recipient in vault metadata: %s", err.Error())
				}
			}
		}
	}
	if recipient == nil {
		identity, identityErr := decryptIdentity(identityFilename)
		if identityErr != nil {
			return "", identityErr
		}
		recipient = identity.Recipient()
		metadata, metadataErr := json.Marshal(keyMetadata{Version: 1, KeyFile: identityFilename, Recipient: recipient.String()})
		if metadataErr == nil {
			_ = os.WriteFile(metadataFilename(trimmedVaultName), metadata, 0o600)
		}
	}
	vaultExists, vaultIsDir := utils.Exists(vaultName)
	if !vaultExists || !vaultIsDir {
		return "", fmt.Errorf("missing %s", vaultName)
	}
	archiveReader, archiveWriter := io.Pipe()
	defer archiveReader.Close()
	archiveErr := make(chan error, 1)
	go func() {
		archiveErrValue := archive.TarDirectory(vaultName, archiveWriter)
		_ = archiveWriter.CloseWithError(archiveErrValue)
		archiveErr <- archiveErrValue
	}()
	if err = crypt.EncryptToFileFromReader(encryptedFilename, archiveReader, recipient); err != nil {
		return "", fmt.Errorf("could not encrypt: %s", err.Error())
	}
	if err = <-archiveErr; err != nil {
		return "", fmt.Errorf("could not archive: %s", err.Error())
	}
	if err = shredder.ShredDir(vaultName, 3); err != nil {
		return "", fmt.Errorf("could not shred %s: %s", vaultName, err.Error())
	}
	return recipient.String(), nil
}

func decryptIdentity(identityFilename string) (*age.X25519Identity, error) {
	data, err := os.ReadFile(identityFilename)
	if err != nil { return nil, fmt.Errorf("could not read identity file: %s", err.Error()) }
	var envelope identityEnvelope
	if json.Unmarshal(data, &envelope) == nil && envelope.Version == 1 {
		data, err = base64.StdEncoding.DecodeString(envelope.EncryptedIdentity)
		if err != nil { return nil, errors.New("invalid identity file") }
	}
	encryptedIdentity := bytes.NewReader(data)
	pw, err := crypt.ReadSecret(fmt.Sprintf("enter passphrase for identity file %q", identityFilename), false)
	if err != nil { return nil, err }
	scryptIdentity, err := age.NewScryptIdentity(pw)
	if err != nil { return nil, err }
	var identityBuffer bytes.Buffer
	if err = crypt.DecryptToWriter(&identityBuffer, encryptedIdentity, scryptIdentity); err != nil {
		return nil, fmt.Errorf("bad passphrase: %s", err.Error())
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(identityBuffer.String()))
	if err != nil { return nil, fmt.Errorf("could not parse decrypted identity: %s", err.Error()) }
	return identity, nil
}

func Unlock(vaultName string, trimmedVaultName, explicitIdentityFilename string) error {
	identityFilename, err := getIdentityFilename(trimmedVaultName, explicitIdentityFilename)
	if err != nil {
		return err
	}
	vaultExists, vaultIsDir := utils.Exists(vaultName)
	if vaultExists && vaultIsDir {
		return errors.New("already unlocked")
	}
	encryptedVaultFilename := fmt.Sprintf("%s.age", vaultName)
	encryptedVault, err := os.Open(encryptedVaultFilename)
	if err != nil {
		return fmt.Errorf("missing encrypted %s: %s", vaultName, err.Error())
	}
	defer encryptedVault.Close()
	identity, err := decryptIdentity(identityFilename)
	if err != nil { return err }
	temporaryArchive, err := os.CreateTemp(".", ".agevault-archive-*")
	if err != nil {
		return err
	}
	temporaryArchiveName := temporaryArchive.Name()
	defer os.Remove(temporaryArchiveName)
	if err = temporaryArchive.Chmod(0o600); err != nil {
		return err
	}
	err = crypt.DecryptToWriter(temporaryArchive, encryptedVault, identity)
	if err != nil {
		return fmt.Errorf("could not decrypt %s: %s", vaultName, err.Error())
	}
	// Windows does not permit deleting an open file. Release the encrypted
	// vault before restoration completes so it can be securely removed below.
	if err = encryptedVault.Close(); err != nil {
		return fmt.Errorf("could not close encrypted %s: %s", vaultName, err.Error())
	}
	if err = temporaryArchive.Close(); err != nil {
		return err
	}
	temporaryArchive, err = os.Open(temporaryArchiveName)
	if err != nil {
		return err
	}
	defer temporaryArchive.Close()
	stagingDirectory, err := os.MkdirTemp(".", ".agevault-unlock-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stagingDirectory)
	archiveReader := bufio.NewReader(temporaryArchive)
	archiveHeader, err := archiveReader.Peek(4)
	if err != nil {
		return fmt.Errorf("could not inspect decrypted archive: %s", err.Error())
	}
	if bytes.Equal(archiveHeader, []byte("PK\x03\x04")) {
		// NOTE: Ensure backwards compatibility with v1.0.0
		fmt.Println("found deprecated archiving format...")
		zipData, readErr := io.ReadAll(archiveReader)
		if readErr != nil {
			return readErr
		}
		zipReader := bytes.NewReader(zipData)
		if err = archive.UnZip(*zipReader, stagingDirectory); err != nil {
			return fmt.Errorf("could not unzip zipped %s: %s", vaultName, err.Error())
		}
	} else {
		if err = archive.UnTar(archiveReader, stagingDirectory); err != nil {
			return fmt.Errorf("could not untar tarred %s: %s", vaultName, err.Error())
		}
	}
	stagedVault := filepath.Join(stagingDirectory, vaultName)
	stagedExists, stagedIsDir := utils.Exists(stagedVault)
	if !stagedExists || !stagedIsDir {
		return errors.New("decrypted archive does not contain the expected vault directory")
	}
	if err = os.Rename(stagedVault, vaultName); err != nil {
		return fmt.Errorf("could not restore vault: %s", err.Error())
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

	if len(args) != 2 && (len(args) != 4 || args[2] != "--key") {
		Usage()
	}

	action := args[1]
	vaultName := args[0]
	explicitIdentityFilename := ""
	if len(args) == 4 { explicitIdentityFilename = args[3] }

	// Only vault directories in the current working directory are supported.
	// This keeps archive restoration and key discovery unambiguous.
	if strings.ContainsAny(vaultName, `/\\`) || vaultName == "." || vaultName == ".." {
		errMsg(errors.New("directory name must not contain a path"))
	}
	trimmedVaultName := strings.Trim(vaultName, ". ")

	if trimmedVaultName != "" && action == "keygen" {
		identityFilename, err := Keygen(trimmedVaultName, explicitIdentityFilename)
		if err != nil {
			errMsg(err)
		}
		fmt.Printf("%s CREATED (do not change the filename)\n", identityFilename)
		return
	}

	if trimmedVaultName != "" && action == "lock" {
		recipientString, err := Lock(vaultName, trimmedVaultName, explicitIdentityFilename)
		if err != nil {
			errMsg(err)
		}
		fmt.Printf("%s LOCKED with %s\n", vaultName, recipientString)
		return
	}

	if trimmedVaultName != "" && action == "unlock" {
		err := Unlock(vaultName, trimmedVaultName, explicitIdentityFilename)
		if err != nil {
			errMsg(err)
		}
		fmt.Printf("%s UNLOCKED\n", vaultName)
		return
	}

	errMsg(errors.New("bad args"))
}
