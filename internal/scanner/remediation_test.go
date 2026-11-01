package scanner

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func remediationDB(t *testing.T, root string) *Database {
	t.Helper()
	localPath := filepath.Join(root, "local.db")
	signaturesPath := filepath.Join(root, "signatures.db")
	local, err := sql.Open("sqlite3", localPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = local.Exec(`CREATE TABLE scan_cache (
		file_path TEXT PRIMARY KEY, mtime INTEGER, size_bytes INTEGER,
		file_hash TEXT, status TEXT, last_scanned INTEGER);
		CREATE TABLE quarantine_vault (
		incident_id INTEGER PRIMARY KEY AUTOINCREMENT, original_path TEXT,
		vault_path TEXT, detection_source TEXT, timestamp INTEGER);`)
	if err != nil {
		local.Close()
		t.Fatal(err)
	}
	local.Close()
	signatures, err := sql.Open("sqlite3", signaturesPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = signatures.Exec(`CREATE TABLE known_threats (
		sha256_hash TEXT PRIMARY KEY, threat_name TEXT, severity INTEGER, date_added INTEGER);`)
	if err != nil {
		signatures.Close()
		t.Fatal(err)
	}
	signatures.Close()
	db, err := OpenDatabase(localPath, signaturesPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestCacheRejectsSameMetadataReplacement(t *testing.T) {
	root := t.TempDir()
	db := remediationDB(t, root)
	path := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(path, []byte("benign"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateCache(path, info.ModTime().UnixNano(), info.Size(), hash, "clean"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("unsafe"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	cached, err := db.CheckCache(path, info.ModTime().UnixNano(), info.Size())
	if err != nil {
		t.Fatal(err)
	}
	if cached {
		t.Fatal("cache accepted replacement content with matching metadata")
	}
}

func TestQuarantineGeneratesDistinctPayloadsAndRejectsInvalidSource(t *testing.T) {
	root := t.TempDir()
	db := remediationDB(t, root)
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MALSHOT_QUARANTINE_ROOT", filepath.Join(root, quarantineDir))
	t.Cleanup(func() { _ = os.Chdir(oldDir) })

	first := filepath.Join(root, "first.bin")
	second := filepath.Join(root, "second.bin")
	if err := os.WriteFile(first, []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("two"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := QuarantineFile(first, "../source", db.local); err != nil {
		t.Fatal(err)
	}
	if err := QuarantineFile(second, "source", db.local); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(root, quarantineDir, "*.malshot"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d quarantine payloads, want 2", len(files))
	}
	if _, err := os.Stat(filepath.Join(root, quarantineDir, "..", "source.malshot")); !os.IsNotExist(err) {
		t.Fatal("path traversal created a file outside the quarantine vault")
	}
}

func TestLocalDatabaseSerializesConcurrentCacheWrites(t *testing.T) {
	root := t.TempDir()
	db := remediationDB(t, root)
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			path := filepath.Join(root, "file-"+time.Now().Format("150405.000000000")+"-"+string(rune('a'+i)))
			if err := db.UpdateCache(path, int64(i), int64(i), "hash", "clean"); err != nil {
				errs <- err
			}

		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestRestoreFileAuthenticatesAndPublishesOriginal(t *testing.T) {
	root := t.TempDir()
	db := remediationDB(t, root)
	t.Setenv("MALSHOT_QUARANTINE_ROOT", filepath.Join(root, quarantineDir))
	source := filepath.Join(root, "restore-source.bin")
	want := []byte("restore-me")
	if err := os.WriteFile(source, want, 0600); err != nil {
		t.Fatal(err)
	}
	if err := QuarantineFile(source, "test", db.local); err != nil {
		t.Fatal(err)
	}
	var id int
	if err := db.local.QueryRow(`SELECT incident_id FROM quarantine_vault LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "restored.bin")
	if err := RestoreFile(id, target, db.local); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("restored bytes = %q, want %q", got, want)
	}
	var count int
	if err := db.local.QueryRow(`SELECT COUNT(*) FROM quarantine_vault`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("quarantine audit rows = %d, want 0", count)
	}
}
