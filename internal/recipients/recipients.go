package recipients

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/ndavd/agevault/internal/crypt"
	"github.com/ndavd/agevault/internal/utils"
)

const FileName = ".agevault-recipients"

// NOTE: Both *age.X25519Recipient and *age.HybridRecipient satisfy this
type Recipient interface {
	age.Recipient
	fmt.Stringer
}

func Append(vaultName string, trimmedVaultName string, recipient Recipient) error {
	path := filepath.Join(vaultName, FileName)
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(data) == 0 {
		data = []byte(fmt.Sprintf("# agevault recipients for %s\n# lines starting with # are ignored\n", trimmedVaultName))
	}
	data = append(data, []byte(fmt.Sprintf("\n# fingerprint: %s\n%s\n", crypt.Fingerprint(recipient), recipient.String()))...)
	file, err := os.CreateTemp(vaultName, ".agevault-recipients-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(temp, path); err != nil {
		return err
	}
	return utils.SyncDir(vaultName)
}

func Read(vaultName string) ([]age.Recipient, error) {
	file, err := os.Open(filepath.Join(vaultName, FileName))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	list, err := age.ParseRecipients(file)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("empty recipients file")
	}
	_, hybrid := list[0].(*age.HybridRecipient)
	for _, r := range list {
		_, pq := r.(*age.HybridRecipient)
		if pq != hybrid {
			return nil, fmt.Errorf("cannot mix classical and hybrid recipients")
		}
	}
	return list, nil
}
