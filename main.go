// MalShot - offline-first malware defender.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"malshot/internal/scanner"
	"malshot/internal/ui"
	"os"
	"path/filepath"
	"strings"
)

type releaseManifest struct {
	Algorithm string            `json:"algorithm"`
	Assets    map[string]string `json:"assets"`
}

func verifyReleaseManifest(baseDir string) error {
	file, err := os.Open(filepath.Join(baseDir, "release_manifest.json"))
	if err != nil {
		return fmt.Errorf("open release manifest: %w", err)
	}
	defer file.Close()
	var manifest releaseManifest
	if err := json.NewDecoder(file).Decode(&manifest); err != nil {
		return fmt.Errorf("decode release manifest: %w", err)
	}
	if manifest.Algorithm != "SHA-256" || len(manifest.Assets) == 0 {
		return fmt.Errorf("invalid release manifest")
	}
	for relative, expected := range manifest.Assets {
		clean := filepath.Clean(relative)
		if clean == "." || filepath.IsAbs(clean) || clean == ".." ||
			len(clean) >= 3 && clean[:3] == ".."+string(filepath.Separator) {
			return fmt.Errorf("invalid manifest path %q", relative)
		}
		path := filepath.Join(baseDir, clean)
		actualFile, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open manifest asset %q: %w", relative, err)
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, actualFile)
		closeErr := actualFile.Close()
		if copyErr != nil || closeErr != nil {
			return fmt.Errorf("hash manifest asset %q: %w", relative, errors.Join(copyErr, closeErr))
		}
		if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expected) {
			return fmt.Errorf("manifest hash mismatch for %q", relative)
		}
	}
	return nil
}

func main() {
	target := "."
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	baseDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("resolve application directory: %v", err)
	}
	if executable, executableErr := os.Executable(); executableErr == nil {
		baseDir = filepath.Dir(executable)
	}

	engine, err := scanner.NewEngine(
		target,
		filepath.Join(baseDir, "local_state.db"),
		filepath.Join(baseDir, "signatures.db"),
		0,
	)
	if err != nil {
		log.Fatalf("initialize scanner: %v", err)
	}
	if err := verifyReleaseManifest(baseDir); err != nil {
		engine.SetDeepInspectionError(err)
		log.Printf("[WARN] deep inspection disabled: %v", err)
	} else {
		rulesPath := filepath.Join(baseDir, "rules")
		modelPath := filepath.Join(baseDir, "lstm_malware.onnx")
		runtimePath := filepath.Join(baseDir, "onnxruntime.dll")
		if err := engine.ConfigureDeepInspection(rulesPath, modelPath, runtimePath, 0.80); err != nil {
			log.Printf("[WARN] deep inspection disabled: %v", err)
		}
	}
	defer func() {
		if err := engine.Close(); err != nil {
			log.Printf("close scanner databases: %v", err)
		}
	}()

	ui.Run(engine)
}
