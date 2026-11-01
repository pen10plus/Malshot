package scanner

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const quarantineDir = "quarantine_vault"

const (
	quarantineKeyFile       = "vault.key"
	legacyQuarantineKeyFile = ".quarantine.key"
	quarantineChunk         = 1024 * 1024
	quarantineMagic         = "MSQ2"
)

var quarantineKeyMu sync.Mutex

// QuarantineFile encrypts, audits, and removes the original file.
func QuarantineFile(originalPath string, detectionSource string, db *sql.DB) error {
	if db == nil {
		return errors.New("quarantine database is nil")
	}
	cleanPath := filepath.Clean(originalPath)
	if cleanPath == "." || cleanPath == string(filepath.Separator) {
		return errors.New("invalid quarantine source path")
	}
	file, err := os.OpenFile(cleanPath, os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open file to revoke execution permissions: %w", err)
	}
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("revoke execution permissions: %w", err)
	}
	root, err := quarantineRoot()
	if err != nil {
		return fmt.Errorf("resolve quarantine vault: %w", err)
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return fmt.Errorf("create quarantine vault: %w", err)
	}
	if err := restrictVaultPermissions(root); err != nil {
		return fmt.Errorf("restrict quarantine vault permissions: %w", err)
	}
	key, err := loadQuarantineKey(root)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	defer zeroBytes(key)
	if err != nil {
		return fmt.Errorf("create AES-256 cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create AES-GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate quarantine nonce: %w", err)
	}
	vaultPath := filepath.Join(root, fmt.Sprintf("%d-%s.malshot",
		time.Now().UnixNano(), hex.EncodeToString(nonce)))
	if filepath.Dir(vaultPath) != root {
		return errors.New("quarantine destination escaped vault")
	}
	temp, err := os.CreateTemp(root, ".quarantine-*.tmp")
	if err != nil {
		return fmt.Errorf("create quarantine temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("protect quarantine temporary file: %w", err)
	}
	if _, err := temp.Write([]byte(quarantineMagic)); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write quarantine header: %w", err)
	}
	buffer := make([]byte, quarantineChunk)
	for {
		n, readErr := file.Read(buffer)
		if n > 0 {
			chunkNonce := make([]byte, gcm.NonceSize())
			if _, err := io.ReadFull(rand.Reader, chunkNonce); err != nil {
				_ = temp.Close()
				return fmt.Errorf("generate quarantine chunk nonce: %w", err)
			}
			sealed := gcm.Seal(nil, chunkNonce, buffer[:n], nil)
			var length [4]byte
			binary.BigEndian.PutUint32(length[:], uint32(len(sealed)))
			if _, err := temp.Write(length[:]); err != nil {
				_ = temp.Close()
				return fmt.Errorf("write quarantine chunk length: %w", err)
			}
			if _, err := temp.Write(chunkNonce); err != nil {
				_ = temp.Close()
				return fmt.Errorf("write quarantine nonce: %w", err)
			}

			if _, err := temp.Write(sealed); err != nil {
				_ = temp.Close()
				return fmt.Errorf("write encrypted quarantine chunk: %w", err)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = temp.Close()
			return fmt.Errorf("read file for quarantine: %w", readErr)
		}
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync encrypted quarantine payload: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close encrypted quarantine payload: %w", err)
	}
	if err := os.Rename(tempPath, vaultPath); err != nil {
		return fmt.Errorf("publish encrypted quarantine payload: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close source file after quarantine: %w", err)
	}
	_, err = db.Exec(
		`INSERT INTO quarantine_vault
			(original_path, vault_path, detection_source, timestamp)
		 VALUES (?, ?, ?, ?)`,
		cleanPath, vaultPath, detectionSource, time.Now().Unix(),
	)
	if err != nil {
		_ = os.Remove(vaultPath)
		return fmt.Errorf("write quarantine audit record: %w", err)
	}
	if err := os.Remove(cleanPath); err != nil {
		return fmt.Errorf("remove quarantined file: %w", err)
	}
	fmt.Printf("[QUARANTINE] %s -> %s (%s)\n", cleanPath, vaultPath, detectionSource)
	return nil
}

func quarantineRoot() (string, error) {
	if override := os.Getenv("MALSHOT_QUARANTINE_ROOT"); override != "" {
		return filepath.Abs(filepath.Clean(override))
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user configuration directory: %w", err)
	}
	root := filepath.Join(configDir, "MalShot", quarantineDir)
	return filepath.Abs(root)
}

// RestoreFile decrypts one audited payload into a new target atomically.
func RestoreFile(incidentID int, targetPath string, db *sql.DB) error {
	if db == nil {
		return errors.New("restore database is nil")
	}
	if incidentID <= 0 || targetPath == "" {
		return errors.New("invalid restore request")
	}
	var vaultPath string
	var originalPath string
	if err := db.QueryRow(`SELECT vault_path, original_path FROM quarantine_vault WHERE incident_id = ?`, incidentID).
		Scan(&vaultPath, &originalPath); err != nil {
		return fmt.Errorf("load quarantine incident: %w", err)
	}
	vaultPath, err := filepath.Abs(filepath.Clean(vaultPath))
	if err != nil {
		return fmt.Errorf("resolve quarantine payload: %w", err)
	}
	if _, err := os.Stat(vaultPath); err != nil {
		return fmt.Errorf("stat quarantine payload: %w", err)
	}
	root, err := quarantineRoot()
	if err != nil {
		return err
	}
	contained, err := filepath.Rel(root, vaultPath)
	if err != nil || contained == ".." || len(contained) >= 3 && contained[:3] == ".."+string(filepath.Separator) {
		return errors.New("quarantine payload escaped vault")
	}
	targetAbs, err := filepath.Abs(filepath.Clean(targetPath))
	if err != nil {
		return fmt.Errorf("resolve restore target: %w", err)
	}
	targetRel, err := filepath.Rel(root, targetAbs)
	insideVault := err == nil && targetRel != ".." &&
		(targetRel == "." || !strings.HasPrefix(targetRel, ".."+string(filepath.Separator)))
	if insideVault {
		return errors.New("restore target must not be inside the quarantine vault")
	}
	key, err := loadQuarantineKey(root)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	defer zeroBytes(key)
	if err != nil {
		return fmt.Errorf("create restore cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create restore AES-GCM: %w", err)
	}
	source, err := os.Open(vaultPath)
	if err != nil {
		return fmt.Errorf("open quarantine payload: %w", err)
	}
	defer source.Close()
	var magic [4]byte
	if _, err := io.ReadFull(source, magic[:]); err != nil || string(magic[:]) != quarantineMagic {
		return errors.New("unsupported or corrupt quarantine payload")
	}
	target := filepath.Clean(targetPath)
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return fmt.Errorf("create restore directory: %w", err)
	}
	temp, err := os.CreateTemp(parent, ".restore-*.tmp")
	if err != nil {
		return fmt.Errorf("create restore temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	defer temp.Close()
	if err := temp.Chmod(0600); err != nil {
		return fmt.Errorf("protect restore temporary file: %w", err)
	}
	for {
		var length [4]byte
		_, readErr := io.ReadFull(source, length[:])
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read quarantine chunk length: %w", readErr)
		}
		size := binary.BigEndian.Uint32(length[:])
		if size < uint32(gcm.Overhead()) || size > uint32(quarantineChunk+gcm.Overhead()) {
			return errors.New("invalid quarantine chunk length")
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(source, nonce); err != nil {
			return fmt.Errorf("read quarantine nonce: %w", err)
		}
		sealed := make([]byte, size)
		if _, err := io.ReadFull(source, sealed); err != nil {
			return fmt.Errorf("read encrypted quarantine chunk: %w", err)
		}
		plain, err := gcm.Open(nil, nonce, sealed, nil)
		if err != nil {
			return fmt.Errorf("authenticate quarantine chunk: %w", err)
		}
		if _, err := temp.Write(plain); err != nil {
			zeroBytes(plain)
			return fmt.Errorf("write restored file: %w", err)
		}
		zeroBytes(plain)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync restored file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close restored file: %w", err)
	}
	if err := source.Close(); err != nil {
		return fmt.Errorf("close quarantine payload: %w", err)
	}
	if err := os.Rename(tempPath, target); err != nil {
		return fmt.Errorf("publish restored file: %w", err)
	}
	if err := os.Remove(vaultPath); err != nil {
		return fmt.Errorf("remove restored quarantine payload: %w", err)
	}
	if _, err := db.Exec(`DELETE FROM quarantine_vault WHERE incident_id = ?`, incidentID); err != nil {
		return fmt.Errorf("delete restored quarantine audit: %w", err)
	}
	_ = originalPath
	return nil
}

func loadQuarantineKey(root string) ([]byte, error) {
	quarantineKeyMu.Lock()
	defer quarantineKeyMu.Unlock()
	path := filepath.Join(root, quarantineKeyFile)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := migrateLegacyQuarantineKey(root); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("inspect quarantine key: %w", err)
	}
	protected, err := os.ReadFile(path)
	if err == nil {
		key, err := unprotectData(protected)
		if err != nil {
			return nil, fmt.Errorf("unprotect quarantine key: %w", err)
		}
		if len(key) != 32 {
			zeroBytes(key)
			return nil, errors.New("unprotected quarantine key has invalid length")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read quarantine key: %w", err)
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("generate quarantine key: %w", err)
	}
	protected, err = protectData(key)
	zeroBytes(key)
	if err != nil {
		return nil, fmt.Errorf("protect quarantine key: %w", err)
	}
	if err := writeProtectedKey(path, protected); err != nil {
		return nil, err
	}
	return unprotectData(protected)
}

func writeProtectedKey(path string, protected []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".vault-key-*.tmp")
	if err != nil {
		return fmt.Errorf("create protected quarantine key: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("protect protected quarantine key: %w", err)
	}
	if _, err := temp.Write(protected); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write protected quarantine key: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync protected quarantine key: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close protected quarantine key: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("publish protected quarantine key: %w", err)
	}
	return nil
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func migrateLegacyQuarantineKey(root string) error {
	legacyPath := filepath.Join(root, legacyQuarantineKeyFile)
	legacy, err := os.ReadFile(legacyPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read legacy quarantine key: %w", err)
	}
	if len(legacy) != 32 {
		zeroBytes(legacy)
		return errors.New("legacy quarantine key has invalid length")
	}
	protected, err := protectData(legacy)
	zeroBytes(legacy)
	if err != nil {
		return fmt.Errorf("protect legacy quarantine key: %w", err)
	}
	if err := writeProtectedKey(filepath.Join(root, quarantineKeyFile), protected); err != nil {
		return err
	}
	if err := os.Remove(legacyPath); err != nil {
		return fmt.Errorf("remove legacy quarantine key: %w", err)
	}
	return nil
}
