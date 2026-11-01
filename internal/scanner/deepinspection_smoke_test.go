//go:build deepinspection

package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestYaraMarkerSmoke(t *testing.T) {
	root := t.TempDir()
	rulePath := filepath.Join(root, "marker.yar")
	filePath := filepath.Join(root, "sample.bin")
	rule := `rule Test_Signature { strings: $s = "MALSHOT_DEEP_INSPECTION_TEST" condition: $s }`
	if err := os.WriteFile(rulePath, []byte(rule), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, []byte("MALSHOT_DEEP_INSPECTION_TEST"), 0600); err != nil {
		t.Fatal(err)
	}
	compiler, rules, err := InitYara(rulePath)
	if err != nil {
		t.Fatal(err)
	}
	defer compiler.Destroy()
	defer rules.Destroy()
	matched, err := ScanWithYara(filePath, rules)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("expected Test_Signature to match")
	}
}
