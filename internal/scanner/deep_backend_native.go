//go:build deepinspection

package scanner

import (
	"fmt"
	"os"

	yara "github.com/hillu/go-yara/v4"
	ort "github.com/yalue/onnxruntime_go"
)

type deepBackend struct {
	compiler *yara.Compiler
	rules    *yara.Rules
	session  *ort.AdvancedSession
}

func newDeepBackend(rulesPath, modelPath, runtimePath string) (*deepBackend, error) {
	compiler, rules, err := InitYara(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("initialize YARA: %w", err)
	}
	session, err := InitONNX(runtimePath, modelPath)
	if err != nil {
		rules.Destroy()
		compiler.Destroy()
		return nil, fmt.Errorf("initialize ONNX: %w", err)
	}
	return &deepBackend{compiler: compiler, rules: rules, session: session}, nil
}

func (b *deepBackend) close() error {
	if b == nil {
		return nil
	}
	var first error
	if b.session != nil {
		first = DestroyONNX(b.session)
		b.session = nil
	}
	if b.rules != nil {
		b.rules.Destroy()
		b.rules = nil
	}
	if b.compiler != nil {
		b.compiler.Destroy()
		b.compiler = nil
	}
	return first
}

func (b *deepBackend) scan(path string) (bool, float32, error) {
	yaraThreat, err := ScanWithYara(path, b.rules)
	if err != nil {
		return false, 0, err
	}
	if colabURL := os.Getenv("MALSHOT_COLAB_URL"); colabURL != "" {
		if score, colabErr := ScanWithColab(path, colabURL); colabErr == nil {
			return yaraThreat, score, nil
		}
	}
	score, err := ScanWithLSTM(path, b.session)
	if err != nil {
		return false, 0, err
	}
	return yaraThreat, score, nil
}
