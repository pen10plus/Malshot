package main

import (
	"context"
	"path/filepath"
	"testing"

	"malshot/internal/scanner"
)

func TestVerifyReleaseManifest(t *testing.T) {
	baseDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyReleaseManifest(baseDir); err != nil {
		t.Fatalf("verifyReleaseManifest failed: %v", err)
	}
}

func TestEngineScanTargetE2E(t *testing.T) {
	baseDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(baseDir, "test_scan_target")
	engine, err := scanner.NewEngine(
		target,
		filepath.Join(baseDir, "local_state.db"),
		filepath.Join(baseDir, "signatures.db"),
		2,
	)
	if err != nil {
		t.Fatalf("initialize scanner: %v", err)
	}
	defer engine.Close()

	if err := verifyReleaseManifest(baseDir); err != nil {
		t.Fatalf("manifest verification failed: %v", err)
	}

	events, err := engine.StartPath(context.Background(), target, scanner.ModeQuick)
	if err != nil {
		t.Fatalf("StartPath failed: %v", err)
	}

	for range events {
	}

	stats := engine.Stats()
	if stats.AnalyzedCount < 1 {
		t.Errorf("expected at least 1 analyzed file, got %d", stats.AnalyzedCount)
	}
	if stats.ThreatsCount < 1 {
		t.Errorf("expected at least 1 detected threat in test_scan_target, got %d", stats.ThreatsCount)
	}
}
