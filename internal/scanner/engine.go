package scanner

import (
	"context"
	"errors"
	"runtime"
	"sync"
)

// Engine is the concurrent, offline malware scanning service.
type Engine struct {
	db                  *Database
	target              string
	workers             int
	mu                  sync.Mutex
	running             bool
	paused              bool
	pauseCond           *sync.Cond
	pauseMu             sync.Mutex
	stats               ScanStats
	cancel              context.CancelFunc
	done                chan struct{}
	deep                *deepBackend
	deepEnabled         bool
	confidenceThreshold float32
	assetError          string
}

// NewEngine opens the databases and configures the scan root and worker count.
// A worker count <= 0 selects one worker per logical CPU.
func NewEngine(target, localDB, signaturesDB string, workers int) (*Engine, error) {
	if target == "" {
		return nil, errors.New("scan target must not be empty")
	}
	db, err := OpenDatabase(localDB, signaturesDB)
	if err != nil {
		return nil, err
	}
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	e := &Engine{db: db, target: target, workers: workers, confidenceThreshold: 0.80}
	e.pauseCond = sync.NewCond(&e.pauseMu)
	return e, nil
}

func (e *Engine) Close() error {
	e.mu.Lock()
	cancel := e.cancel
	done := e.done
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	e.mu.Lock()
	deep := e.deep
	e.deep = nil
	e.mu.Unlock()
	var deepErr error
	if deep != nil {
		deepErr = deep.close()
	}
	return errors.Join(deepErr, e.db.Close())
}

// ConfigureDeepInspection initializes the native YARA and ONNX engines.
func (e *Engine) ConfigureDeepInspection(rulesPath, modelPath, runtimePath string, threshold float32) error {
	if threshold < 0 || threshold > 1 {
		return errors.New("deep inspection confidence threshold must be between 0 and 1")
	}
	backend, err := newDeepBackend(rulesPath, modelPath, runtimePath)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return ErrScanInProgress
	}
	if err != nil {
		e.assetError = err.Error()
		e.deepEnabled = false
		return err
	}
	if e.deep != nil {
		_ = e.deep.close()
	}
	e.deep = backend
	e.deepEnabled = true
	e.confidenceThreshold = threshold
	e.assetError = ""
	return nil
}

func (e *Engine) SetDeepInspectionEnabled(enabled bool) {
	e.mu.Lock()
	e.deepEnabled = enabled && e.deep != nil
	e.mu.Unlock()
}

func (e *Engine) DeepInspectionEnabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.deepEnabled && e.deep != nil
}

func (e *Engine) SetDeepInspectionError(err error) {
	e.mu.Lock()
	if err == nil {
		e.assetError = ""
	} else {
		e.assetError = err.Error()
	}
	e.deepEnabled = false
	e.mu.Unlock()
}

func (e *Engine) Stats() Stats {
	return e.stats.snapshot()
}

func (e *Engine) Health() Health {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Health{SignaturesUpdated: true, EngineActive: true,
		ActiveCores: e.workers, TotalCores: runtime.NumCPU(),
		YaraReady:      e.deep != nil && e.assetError == "",
		OnnxReady:      e.deep != nil && e.assetError == "",
		DeepInspection: e.deepEnabled, AssetError: e.assetError}
}

// Start scans the configured target. Mode is retained for scanner.Service
// Start scans the configured target.
func (e *Engine) Start(ctx context.Context, mode Mode) (<-chan Event, error) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil, ErrScanInProgress
	}
	e.running = true
	e.stats.Reset()
	scanCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.done = make(chan struct{})
	done := e.done
	target := e.target
	e.mu.Unlock()

	out := make(chan Event, e.workers)
	go e.run(scanCtx, target, out, done, mode)
	return out, nil
}

// ScanPath scans an explicitly supplied directory and waits for completion.
func (e *Engine) ScanPath(ctx context.Context, path string) error {
	if path == "" {
		return errors.New("scan path must not be empty")
	}
	events, err := e.StartPath(ctx, path, ModeQuick)
	if err != nil {
		return err
	}
	for range events {
	}
	return nil
}

func (e *Engine) run(ctx context.Context, target string, out chan Event, done chan struct{}, mode Mode) {
	defer e.setRunning(false)
	defer close(done)
	finished := e.startJobs(ctx, target, out, mode)
	<-finished
}

func (e *Engine) startPath(ctx context.Context, path string, mode Mode) (<-chan Event, error) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil, ErrScanInProgress
	}
	e.running = true
	e.stats.Reset()
	scanCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.done = make(chan struct{})
	done := e.done
	e.mu.Unlock()
	out := make(chan Event, e.workers)
	go e.run(scanCtx, path, out, done, mode)
	return out, nil
}

func (e *Engine) StartPath(ctx context.Context, path string, mode Mode) (<-chan Event, error) {
	if path == "" {
		return nil, errors.New("scan path must not be empty")
	}
	return e.startPath(ctx, path, mode)
}

func (e *Engine) QuarantineIncidents() ([]QuarantineIncident, error) {
	return e.db.QuarantineIncidents()
}

func (e *Engine) RestoreFile(incidentID int, targetPath string) error {
	return RestoreFile(incidentID, targetPath, e.db.local)
}

func (e *Engine) Pause() {
	e.pauseMu.Lock()
	e.paused = true
	e.pauseMu.Unlock()
}

func (e *Engine) Resume() {
	e.pauseMu.Lock()
	e.paused = false
	e.pauseCond.Broadcast()
	e.pauseMu.Unlock()
}

func (e *Engine) IsPaused() bool {
	e.pauseMu.Lock()
	defer e.pauseMu.Unlock()
	return e.paused
}

func (e *Engine) Target() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.target
}

func (e *Engine) SetTarget(target string) {
	e.mu.Lock()
	e.target = target
	e.mu.Unlock()
}

func (e *Engine) QuarantineFileDirect(path, threatName string) error {
	err := QuarantineFile(path, threatName, e.db.local)
	if err == nil {
		e.stats.addQuarantined()
	}
	return err
}

func (e *Engine) checkPause(ctx context.Context) error {
	e.pauseMu.Lock()
	for e.paused {
		if ctx.Err() != nil {
			e.pauseMu.Unlock()
			return ctx.Err()
		}
		e.pauseCond.Wait()
	}
	e.pauseMu.Unlock()
	return nil
}

func (e *Engine) startJobs(ctx context.Context, root string, out chan Event, mode Mode) <-chan struct{} {
	e.mu.Lock()
	deep := e.deep
	threshold := e.confidenceThreshold
	deepEnabled := (mode == ModeDeep || e.deepEnabled) && deep != nil
	e.mu.Unlock()

	jobs := make(chan FileJob, e.workers*2)
	var workers sync.WaitGroup
	for i := 0; i < e.workers; i++ {
		workers.Add(1)
		go worker(jobs, e.db, deep, deepEnabled, threshold, func(path string, size int64, threat bool, detected *DetectedFile) {
			e.stats.analyzed(size, threat)
			if detected != nil && detected.Score >= threshold {
				e.stats.addZeroDay()
			}
			snapshot := e.stats.snapshot()
			progress := 0.0
			if snapshot.TotalDiscovered > 0 {
				progress = float64(snapshot.AnalyzedCount+snapshot.SkippedCount) / float64(snapshot.TotalDiscovered)
			}
			select {
			case out <- Event{Path: path, Progress: progress, Stats: snapshot, Detected: detected}:
			case <-ctx.Done():
			}
		}, e.stats.failed, e.checkPause, ctx, &workers)
	}
	var walker sync.WaitGroup
	go func() {
		e.db.startScan(ctx, root, jobs, &walker, func() {
			e.stats.discovered()
		}, func() {
			e.stats.skipped()
		}, e.checkPause)
		walker.Wait()
		close(jobs)
	}()
	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(out)
		close(done)
	}()
	return done
}

func (e *Engine) setRunning(value bool) {
	e.mu.Lock()
	e.running = value
	if !value {
		e.cancel = nil
		e.done = nil
	}
	e.mu.Unlock()
}

var (
	_ Service        = (*Engine)(nil)
	_ ScanController = (*Engine)(nil)
	_ PathService    = (*Engine)(nil)
	_ VaultService   = (*Engine)(nil)
)
