//go:build deepinspection

package scanner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	yara "github.com/hillu/go-yara/v4"
	ort "github.com/yalue/onnxruntime_go"
)

type yaraMatchCallback struct {
	matched *bool
}

func (c yaraMatchCallback) RuleMatching(_ *yara.ScanContext, rule *yara.Rule) (bool, error) {
	if rule != nil {
		*c.matched = true
	}
	return false, nil
}

// InitYara compiles every .yar and .yara file below rulesPath.
func InitYara(rulesPath string) (*yara.Compiler, *yara.Rules, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, nil, fmt.Errorf("create YARA compiler: %w", err)
	}
	files, err := collectYaraFiles(rulesPath)
	if err != nil {
		compiler.Destroy()
		return nil, nil, err
	}
	for _, path := range files {
		file, err := os.Open(path)
		if err != nil {
			compiler.Destroy()
			return nil, nil, fmt.Errorf("open YARA rule %q: %w", path, err)
		}
		addErr := compiler.AddFile(file, "")
		closeErr := file.Close()
		if addErr != nil {
			compiler.Destroy()
			return nil, nil, fmt.Errorf("compile YARA rule %q: %w", path, addErr)
		}
		if closeErr != nil {
			compiler.Destroy()
			return nil, nil, fmt.Errorf("close YARA rule %q: %w", path, closeErr)
		}
	}
	rules, err := compiler.GetRules()
	if err != nil {
		compiler.Destroy()
		return nil, nil, fmt.Errorf("finalize YARA rules: %w", err)
	}
	return compiler, rules, nil
}

func collectYaraFiles(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat YARA rules path: %w", err)
	}
	if !info.IsDir() {
		return []string{root}, nil
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && (filepath.Ext(path) == ".yar" || filepath.Ext(path) == ".yara") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk YARA rules: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no YARA rule files found in %q", root)
	}
	return files, nil
}

// ScanWithYara scans a file with the already compiled ruleset.
func ScanWithYara(filePath string, rules *yara.Rules) (bool, error) {
	if rules == nil {
		return false, errors.New("YARA rules are nil")
	}
	matched := false
	err := rules.ScanFile(filePath, 0, 0, yaraMatchCallback{matched: &matched})
	if err != nil {
		return false, fmt.Errorf("scan with YARA: %w", err)
	}
	if matched {
		fmt.Printf("[YARA] Threat detected in %s\n", filePath)
	}
	return matched, nil
}

const lstmSequenceLength = 4096

type lstmState struct {
	input  *ort.Tensor[float32]
	output *ort.Tensor[float32]
	mu     sync.Mutex
	closed bool
}

var (
	ortInitMu  sync.Mutex
	lstmStates sync.Map
)

// InitONNX initializes ONNX Runtime and creates the model session.
func InitONNX(onnxLibPath string, modelPath string) (*ort.AdvancedSession, error) {
	ortInitMu.Lock()
	defer ortInitMu.Unlock()
	if !ort.IsInitialized() {
		ort.SetSharedLibraryPath(onnxLibPath)
		if err := ort.InitializeEnvironment(); err != nil {
			return nil, fmt.Errorf("initialize ONNX Runtime: %w", err)
		}
	}
	input, err := ort.NewTensor(ort.NewShape(1, lstmSequenceLength), make([]float32, lstmSequenceLength))
	if err != nil {
		return nil, fmt.Errorf("create ONNX input tensor: %w", err)
	}
	output, err := ort.NewTensor(ort.NewShape(1, 1), make([]float32, 1))
	if err != nil {
		_ = input.Destroy()
		return nil, fmt.Errorf("create ONNX output tensor: %w", err)
	}
	session, err := ort.NewAdvancedSession(modelPath, []string{"input"}, []string{"output"},
		[]ort.Value{input}, []ort.Value{output}, nil)
	if err != nil {
		_ = input.Destroy()
		_ = output.Destroy()
		return nil, fmt.Errorf("create ONNX session: %w", err)
	}
	lstmStates.Store(session, &lstmState{input: input, output: output})
	return session, nil
}

// ScanWithLSTM extracts byte opcodes, runs inference, and returns its score.
func ScanWithLSTM(filePath string, session *ort.AdvancedSession) (float32, error) {
	if session == nil {
		return 0, errors.New("ONNX session is nil")
	}
	value, ok := lstmStates.Load(session)
	if !ok {
		return 0, errors.New("ONNX session was not initialized by InitONNX")
	}
	state := value.(*lstmState)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return 0, errors.New("ONNX session is closed")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("open file for LSTM: %w", err)
	}
	defer file.Close()
	opcodes := make([]float32, lstmSequenceLength)
	for i := range opcodes {
		var b [1]byte
		if _, err := file.Read(b[:]); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return 0, fmt.Errorf("read file for LSTM: %w", err)
		}
		opcodes[i] = float32(b[0]) / 255
	}
	copy(state.input.GetData(), opcodes)
	if err := session.Run(); err != nil {
		return 0, fmt.Errorf("run LSTM inference: %w", err)
	}
	if len(state.output.GetData()) == 0 {
		return 0, errors.New("LSTM returned no confidence score")
	}
	score := state.output.GetData()[0]
	fmt.Printf("[LSTM] Confidence for %s: %.4f\n", filePath, score)
	return score, nil
}

// DestroyONNX releases session tensors and the session itself.
func DestroyONNX(session *ort.AdvancedSession) error {
	if session == nil {
		return nil
	}
	if value, ok := lstmStates.Load(session); ok {
		state := value.(*lstmState)
		state.mu.Lock()
		if state.closed {
			state.mu.Unlock()
			return session.Destroy()
		}
		state.closed = true
		lstmStates.Delete(session)
		if err := state.input.Destroy(); err != nil {
			state.mu.Unlock()
			return err
		}
		if err := state.output.Destroy(); err != nil {
			state.mu.Unlock()
			return err
		}
		state.mu.Unlock()
	}
	return session.Destroy()
}
