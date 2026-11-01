//go:build deepinspection

package scanner

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestDeepInspectionMemoryAndLoad is an opt-in native stress harness.
//
// Windows Application Verifier:
//   appverif.exe /verify MalShotStress.exe
//   set GODEBUG=cgocheck=1
//   MalShotStress.exe -test.run TestDeepInspectionMemoryAndLoad
//
// Dr. Memory:
//   drmemory.exe -leaks_only -- MalShotStress.exe -test.run TestDeepInspectionMemoryAndLoad
//
// The 500 MiB workload is intentionally opt-in because it is unsuitable for
// ordinary CI workers. Run with MALSHOT_STRESS_500MB=1 and ensure sufficient
// disk/RAM capacity before executing it.
func TestDeepInspectionMemoryAndLoad(t *testing.T) {
	if os.Getenv("MALSHOT_STRESS_500MB") != "1" {
		t.Skip("set MALSHOT_STRESS_500MB=1 to run the 1000-iteration native stress harness")
	}
	rulesPath := os.Getenv("MALSHOT_YARA_RULES")
	modelPath := os.Getenv("MALSHOT_ONNX_MODEL")
	runtimePath := os.Getenv("MALSHOT_ONNX_RUNTIME")
	if rulesPath == "" || modelPath == "" || runtimePath == "" {
		t.Fatal("MALSHOT_YARA_RULES, MALSHOT_ONNX_MODEL, and MALSHOT_ONNX_RUNTIME are required")
	}
	root := t.TempDir()
	target := filepath.Join(root, "stress.bin")
	if err := os.WriteFile(target, []byte("MALSHOT_DEEP_INSPECTION_TEST"), 0600); err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 1000; iteration++ {
		compiler, rules, err := InitYara(rulesPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ScanWithYara(target, rules); err != nil {
			rules.Destroy()
			compiler.Destroy()
			t.Fatal(err)
		}
		rules.Destroy()
		compiler.Destroy()

		session, err := InitONNX(runtimePath, modelPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ScanWithLSTM(target, session); err != nil {
			_ = DestroyONNX(session)
			t.Fatal(err)
		}
		if err := DestroyONNX(session); err != nil {
			t.Fatal(err)
		}

		payload := make([]byte, 500*1024*1024)
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			t.Fatal(err)
		}
		block, err := aes.NewCipher(key)
		zeroBytes(key)
		if err != nil {
			t.Fatal(err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		for offset := 0; offset < len(payload); offset += quarantineChunk {
			end := offset + quarantineChunk
			if end > len(payload) {
				end = len(payload)
			}
			nonce := make([]byte, gcm.NonceSize())
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				t.Fatal(err)
			}
			_ = gcm.Seal(nil, nonce, payload[offset:end], nil)
		}
		zeroBytes(payload)
	}
}
