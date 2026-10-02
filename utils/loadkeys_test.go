package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

func TestLoadKeysMissingDirectoryDoesNotPanic(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	viper.Set("authentication-keys-directory", missing)
	viper.Set("debug", false)

	holderLock.Lock()
	certHolder = nil
	holderLock.Unlock()

	// Must not panic when WalkDir reports a nil DirEntry for a missing root.
	loadKeys()

	holderLock.Lock()
	n := len(certHolder)
	holderLock.Unlock()
	if n != 0 {
		t.Fatalf("expected empty certHolder after missing directory, got %d keys", n)
	}
}

func TestLoadKeysReadsAuthorizedKey(t *testing.T) {
	dir := t.TempDir()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_rsa.pub"), ssh.MarshalAuthorizedKey(pub), 0o600); err != nil {
		t.Fatal(err)
	}

	viper.Set("authentication-keys-directory", dir)
	viper.Set("debug", false)

	holderLock.Lock()
	certHolder = nil
	holderLock.Unlock()

	loadKeys()

	holderLock.Lock()
	n := len(certHolder)
	holderLock.Unlock()
	if n != 1 {
		t.Fatalf("expected 1 loaded key, got %d", n)
	}
}
