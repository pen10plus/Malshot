package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDPAPIProtectRoundTrip(t *testing.T) {
	plaintext := []byte("malshot-dpapi-round-trip")
	protected, err := protectData(plaintext)
	if err != nil {
		if os.PathSeparator != '\\' {
			t.Skipf("DPAPI unavailable on this platform: %v", err)
		}
		t.Fatal(err)
	}
	if bytes.Equal(plaintext, protected) {
		t.Fatal("protected data is identical to plaintext")
	}
	recovered, err := unprotectData(protected)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("round trip mismatch: got %q, want %q", recovered, plaintext)
	}
	zeroBytes(recovered)
}

func TestLoadQuarantineKeyGeneratesEncryptedVaultKey(t *testing.T) {
	root := t.TempDir()
	key, err := loadQuarantineKey(root)
	if err != nil {
		if os.PathSeparator != '\\' {
			t.Skipf("DPAPI unavailable on this platform: %v", err)
		}
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
	zeroBytes(key)
	path := filepath.Join(root, quarantineKeyFile)
	protected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(protected) == 32 {
		t.Fatal("vault.key appears to contain a raw 32-byte key")
	}
	reloaded, err := loadQuarantineKey(root)
	if err != nil {
		t.Fatal(err)
	}
	zeroBytes(reloaded)
}

func TestLoadQuarantineKeyMigratesLegacyKey(t *testing.T) {
	root := t.TempDir()
	legacy := bytes.Repeat([]byte{0x42}, 32)
	legacyPath := filepath.Join(root, legacyQuarantineKeyFile)
	if err := os.WriteFile(legacyPath, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	key, err := loadQuarantineKey(root)
	if err != nil {
		if os.PathSeparator != '\\' {
			t.Skipf("DPAPI unavailable on this platform: %v", err)
		}
		t.Fatal(err)
	}
	if !bytes.Equal(key, legacy) {
		t.Fatal("migrated key does not match legacy key")
	}
	zeroBytes(key)
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("legacy key still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, quarantineKeyFile)); err != nil {
		t.Fatalf("protected key missing: %v", err)
	}
}
