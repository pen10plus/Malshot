package scanner

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// Database owns the two SQLite connections used by the scanner. sql.DB is
// safe for concurrent use, so workers can share one Database.
type Database struct {
	local      *sql.DB
	signatures *sql.DB
}

// OpenDatabase opens both databases, enables WAL mode, and verifies schemas.
func OpenDatabase(localPath, signaturesPath string) (*Database, error) {
	local, err := openWALDatabase(localPath)
	if err != nil {
		return nil, fmt.Errorf("open local state database: %w", err)
	}
	if err := initLocalSchema(local); err != nil {
		_ = local.Close()
		return nil, fmt.Errorf("initialize local state schema: %w", err)
	}

	signatures, err := openWALDatabase(signaturesPath)
	if err != nil {
		_ = local.Close()
		return nil, fmt.Errorf("open signatures database: %w", err)
	}
	if err := initSignaturesSchema(signatures); err != nil {
		_ = local.Close()
		_ = signatures.Close()
		return nil, fmt.Errorf("initialize signatures schema: %w", err)
	}

	return &Database{local: local, signatures: signatures}, nil
}

func initLocalSchema(db *sql.DB) error {
	schema := `
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
	CREATE INDEX IF NOT EXISTS idx_scan_cache_lookup
		ON scan_cache (file_path, mtime, size_bytes, status);
	`
	_, err := db.Exec(schema)
	return err
}

func initSignaturesSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS known_threats (
		sha256_hash TEXT PRIMARY KEY,
		threat_name TEXT,
		severity INTEGER,
		date_added INTEGER
	);
	CREATE INDEX IF NOT EXISTS idx_known_threats_sha256_hash
		ON known_threats (sha256_hash);
	`
	_, err := db.Exec(schema)
	return err
}

func openWALDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	if _, err = db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable WAL: %w", err)
	}
	if _, err = db.Exec("PRAGMA busy_timeout=30000"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}
	// SQLite has one writer. A bounded pool prevents a worker burst from
	// creating avoidable writer contention while preserving concurrent reads.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

// Close releases both database connections.
func (d *Database) Close() error {
	if d == nil {
		return nil
	}
	var errs []error
	if d.local != nil {
		if err := d.local.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if d.signatures != nil {
		if err := d.signatures.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// CheckHash performs an indexed primary-key lookup in known_threats.
func (d *Database) CheckHash(sha256Hash string) (bool, string, error) {
	var threatName string
	err := d.signatures.QueryRow(
		"SELECT threat_name FROM known_threats WHERE sha256_hash = ? LIMIT 1",
		strings.ToLower(strings.TrimSpace(sha256Hash)),
	).Scan(&threatName)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("check signature: %w", err)
	}
	return true, threatName, nil
}

// CheckCache reports whether a previously clean scan matches the file's
// current path, modification time, and size.
func (d *Database) CheckCache(path string, mtime, size int64) (bool, error) {
	var cachedHash string
	err := d.local.QueryRow(
		`SELECT file_hash FROM scan_cache
		 WHERE file_path = ? AND mtime = ? AND size_bytes = ?
		   AND status = 'clean' LIMIT 1`,
		path, mtime, size,
	).Scan(&cachedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check scan cache: %w", err)
	}
	actualHash, err := hashFile(path)
	if err != nil {
		return false, fmt.Errorf("validate cached file %q: %w", path, err)
	}
	return strings.EqualFold(actualHash, cachedHash), nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func (d *Database) UpdateCache(path string, mtime, size int64, hash, status string) error {
	_, err := d.local.Exec(
		`INSERT INTO scan_cache
			(file_path, mtime, size_bytes, file_hash, status, last_scanned)
		 VALUES (?, ?, ?, ?, ?, strftime('%s','now'))
		 ON CONFLICT(file_path) DO UPDATE SET
		   mtime = excluded.mtime, size_bytes = excluded.size_bytes,
		   file_hash = excluded.file_hash, status = excluded.status,
		   last_scanned = excluded.last_scanned`,
		path, mtime, size, hash, status,
	)
	if err != nil {
		return fmt.Errorf("update scan cache for %q: %w", path, err)
	}
	return nil
}

func (d *Database) QuarantineIncidents() ([]QuarantineIncident, error) {
	rows, err := d.local.Query(`SELECT incident_id, original_path, vault_path, detection_source, timestamp
		FROM quarantine_vault ORDER BY timestamp DESC`)
	if err != nil {
		return nil, fmt.Errorf("query quarantine incidents: %w", err)
	}
	defer rows.Close()
	var incidents []QuarantineIncident
	for rows.Next() {
		var incident QuarantineIncident
		if err := rows.Scan(&incident.IncidentID, &incident.OriginalPath, &incident.VaultPath, &incident.DetectionSource, &incident.Timestamp); err != nil {
			return nil, fmt.Errorf("scan quarantine incident: %w", err)
		}
		incidents = append(incidents, incident)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate quarantine incidents: %w", err)
	}
	return incidents, nil
}
