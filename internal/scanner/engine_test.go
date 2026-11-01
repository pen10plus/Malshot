package scanner

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func setupTestDBs(t *testing.T, dir string) (string, string) {
	t.Helper()
	localPath := filepath.Join(dir, "local_state.db")
	signaturesPath := filepath.Join(dir, "signatures.db")

	local, err := sql.Open("sqlite3", localPath)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()

	_, err = local.Exec(`
		CREATE TABLE IF NOT EXISTS scan_cache (
			file_path TEXT PRIMARY KEY,
			mtime INTEGER,
			size_bytes INTEGER,
			file_hash TEXT,
			status TEXT,
			last_scanned INTEGER
		);
		CREATE TABLE IF NOT EXISTS quarantine_vault (
			incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
			original_path TEXT,
			vault_path TEXT,
			detection_source TEXT,
			timestamp INTEGER
		);
	`)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := sql.Open("sqlite3", signaturesPath)
	if err != nil {
		t.Fatal(err)
	}
	defer sig.Close()

	_, err = sig.Exec(`
		CREATE TABLE IF NOT EXISTS known_threats (
			sha256_hash TEXT PRIMARY KEY,
			threat_name TEXT,
			severity INTEGER,
			date_added INTEGER
		);
	`)
	if err != nil {
		t.Fatal(err)
	}

	return localPath, signaturesPath
}

func TestEngineScanCompletesAndFindsThreat(t *testing.T) {
	root := t.TempDir()
	scanTarget := filepath.Join(root, "target")
	if err := os.MkdirAll(scanTarget, 0755); err != nil {
		t.Fatal(err)
	}

	// Create clean file
	cleanFile := filepath.Join(scanTarget, "clean.txt")
	if err := os.WriteFile(cleanFile, []byte("benign file content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create threat file
	threatContent := []byte("known malicious payload 12345")
	threatFile := filepath.Join(scanTarget, "malware.exe")
	if err := os.WriteFile(threatFile, threatContent, 0644); err != nil {
		t.Fatal(err)
	}

	h := sha256.Sum256(threatContent)
	threatHash := hex.EncodeToString(h[:])

	localDB, sigDB := setupTestDBs(t, root)

	// Inject threat signature
	sigConn, err := sql.Open("sqlite3", sigDB)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sigConn.Exec(
		"INSERT INTO known_threats (sha256_hash, threat_name, severity, date_added) VALUES (?, ?, ?, ?)",
		threatHash, "Test.Malware.EICAR", 10, time.Now().Unix(),
	)
	sigConn.Close()
	if err != nil {
		t.Fatal(err)
	}

	engine, err := NewEngine(scanTarget, localDB, sigDB, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	events, err := engine.StartPath(ctx, scanTarget, ModeQuick)
	if err != nil {
		t.Fatalf("StartPath failed: %v", err)
	}

	eventCount := 0
	var finalProgress float64
	for ev := range events {
		eventCount++
		finalProgress = ev.Progress
	}

	if eventCount == 0 {
		t.Fatal("expected at least 1 scan event, got 0 (possible deadlock or walk failure)")
	}

	stats := engine.Stats()
	if stats.AnalyzedCount < 2 {
		t.Errorf("expected at least 2 analyzed files, got %d", stats.AnalyzedCount)
	}
	if stats.ThreatsCount < 1 {
		t.Errorf("expected at least 1 threat detected, got %d", stats.ThreatsCount)
	}
	if finalProgress <= 0 {
		t.Errorf("expected final progress > 0, got %f", finalProgress)
	}
}

func TestEnginePauseAndResume(t *testing.T) {
	root := t.TempDir()
	scanTarget := filepath.Join(root, "target")
	if err := os.MkdirAll(scanTarget, 0755); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 20; i++ {
		path := filepath.Join(scanTarget, "file_"+string(rune('a'+i))+".txt")
		if err := os.WriteFile(path, []byte("data payload for pause testing"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	localDB, sigDB := setupTestDBs(t, root)
	engine, err := NewEngine(scanTarget, localDB, sigDB, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	events, err := engine.StartPath(ctx, scanTarget, ModeQuick)
	if err != nil {
		t.Fatal(err)
	}

	// Read one event, then pause
	<-events
	engine.Pause()
	if !engine.IsPaused() {
		t.Error("expected engine to report paused")
	}

	time.Sleep(50 * time.Millisecond)
	engine.Resume()
	if engine.IsPaused() {
		t.Error("expected engine to not be paused after resume")
	}

	count := 1
	for range events {
		count++
	}

	if count < 20 {
		t.Errorf("expected all 20 files to complete after resume, got %d", count)
	}
}

