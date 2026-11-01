//go:build deepinspection

package scanner

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDeepInspectionPipeline(t *testing.T) {
	root := t.TempDir()
	rulesPath := os.Getenv("MALSHOT_YARA_RULES")
	modelPath := os.Getenv("MALSHOT_ONNX_MODEL")
	onnxLibPath := os.Getenv("MALSHOT_ONNX_RUNTIME")

	if rulesPath == "" {
		rulePath := filepath.Join(root, "e2e.yar")
		if err := os.WriteFile(rulePath, []byte(`rule E2E_Rule { strings: $s = "MALSHOT-E2E-SAMPLE" condition: $s }`), 0600); err == nil {
			rulesPath = root
		}
	}
	if modelPath == "" {
		candidate := filepath.Join("..", "..", "lstm_malware.onnx")
		if _, err := os.Stat(candidate); err == nil {
			modelPath = candidate
		}
	}
	if onnxLibPath == "" {
		candidate := filepath.Join("..", "..", "onnxruntime.dll")
		if _, err := os.Stat(candidate); err == nil {
			onnxLibPath = candidate
		}
	}

	if rulesPath == "" || modelPath == "" || onnxLibPath == "" {
		t.Skip("skipping e2e test: set MALSHOT_YARA_RULES, MALSHOT_ONNX_MODEL, and MALSHOT_ONNX_RUNTIME")
	}
	target := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(target, []byte("MALSHOT-E2E-SAMPLE"), 0600); err != nil {
		t.Fatal(err)
	}
	localDB := filepath.Join(root, "local_state.db")
	signaturesDB := filepath.Join(root, "signatures.db")
	seedDatabases(t, localDB, signaturesDB)
	db, err := OpenDatabase(localDB, signaturesDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := db.CheckCache(target, info.ModTime().UnixNano(), info.Size())
	if err != nil || cached {
		t.Fatalf("initial cache check: cached=%v err=%v", cached, err)
	}
	hash := sha256File(t, target)
	if err := db.UpdateCache(target, info.ModTime().UnixNano(), info.Size(), hash, "clean"); err != nil {
		t.Fatal(err)
	}
	cached, err = db.CheckCache(target, info.ModTime().UnixNano(), info.Size())
	if err != nil || !cached {
		t.Fatalf("cache check after update: cached=%v err=%v", cached, err)
	}

	threat, _, err := db.CheckHash(hash)
	if err != nil || !threat {
		t.Fatalf("hash lookup: threat=%v err=%v", threat, err)
	}

	compiler, rules, err := InitYara(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	matched, err := ScanWithYara(target, rules)
	if err != nil {
		t.Fatal(err)
	}
	rules.Destroy()
	compiler.Destroy()
	if !matched {
		t.Fatal("YARA did not match the E2E sample")
	}

	session, err := InitONNX(onnxLibPath, modelPath)
	if err != nil {
		t.Fatal(err)
	}
	score, err := ScanWithLSTM(target, session)
	if err != nil {
		t.Fatal(err)
	}
	if score < 0 || score > 1 {
		t.Fatalf("LSTM score %v is outside [0,1]", score)
	}
	if err := DestroyONNX(session); err != nil {
		t.Fatal(err)
	}

	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MALSHOT_QUARANTINE_ROOT", filepath.Join(root, quarantineDir))
	defer os.Chdir(oldDir)
	if err := QuarantineFile(target, "E2E", db.local); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("original file still exists: %v", err)
	}
	vaultFiles, err := filepath.Glob(filepath.Join(root, "quarantine_vault", "*.malshot"))
	if err != nil || len(vaultFiles) != 1 {
		t.Fatalf("encrypted quarantine payload: files=%v err=%v", vaultFiles, err)
	}
	payload, err := os.ReadFile(vaultFiles[0])
	if err != nil || len(payload) <= 12 {
		t.Fatalf("encrypted payload is missing or too small: bytes=%d err=%v", len(payload), err)
	}
	incidents, err := db.QuarantineIncidents()
	if err != nil || len(incidents) != 1 || incidents[0].DetectionSource != "E2E" {
		t.Fatalf("quarantine audit: incidents=%+v err=%v", incidents, err)
	}

	runtime.GC()
	if goroutines := runtime.NumGoroutine(); goroutines > 16 {
		t.Fatalf("possible goroutine leak after pipeline: %d goroutines", goroutines)
	}
}

func seedDatabases(t *testing.T, localPath, signaturesPath string) {
	t.Helper()
	local, err := sql.Open("sqlite3", localPath)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	_, err = local.Exec(`CREATE TABLE scan_cache
		(file_path TEXT PRIMARY KEY, mtime INTEGER, size_bytes INTEGER,
		 file_hash TEXT, status TEXT, last_scanned INTEGER);
		CREATE TABLE quarantine_vault
		(incident_id INTEGER PRIMARY KEY, original_path TEXT, vault_path TEXT,
		 detection_source TEXT, timestamp INTEGER);`)
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := sql.Open("sqlite3", signaturesPath)
	if err != nil {
		t.Fatal(err)
	}
	defer signatures.Close()
	_, err = signatures.Exec(`CREATE TABLE known_threats
		(sha256_hash TEXT PRIMARY KEY, threat_name TEXT, severity INTEGER, date_added INTEGER)`)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256File(t, filepath.Join(filepath.Dir(localPath), "sample.bin"))
	if _, err := signatures.Exec(`INSERT INTO known_threats
		(sha256_hash, threat_name, severity, date_added) VALUES (?, 'E2E', 10, ?)`,
		hash, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sum.Sum(nil))
}
