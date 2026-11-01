package scanner

import (
	"context"
	"sync"
	"time"
)

const (
	quickFiles = 200
	deepFiles  = 800
)

var samplePaths = []string{
	`C:\Users\Public\Downloads\game_mod.exe`,
	`C:\Users\Public\Documents\setup_helper.dll`,
	`C:\Program Files\Common Files\updater.exe`,
	`C:\Users\Public\AppData\Local\Temp\cache_7f2a.tmp`,
}

// Mock is a simulated engine used for UI development and tests.
type Mock struct {
	mu      sync.Mutex
	running bool
	stats   Stats
	tick    time.Duration
}

// MockOption customises a Mock.
type MockOption func(*Mock)

// WithTick sets the delay between simulated files.
func WithTick(d time.Duration) MockOption { return func(m *Mock) { m.tick = d } }

func NewMock(opts ...MockOption) *Mock {
	m := &Mock{
		stats: Stats{FilesAnalyzed: 41209, ZeroDayBlocked: 14},
		tick:  40 * time.Millisecond,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

func (m *Mock) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
}

func (m *Mock) Health() Health {
	return Health{SignaturesUpdated: true, EngineActive: true, ActiveCores: 4, TotalCores: 8}
}

func (m *Mock) Start(ctx context.Context, mode Mode) (<-chan Event, error) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil, ErrScanInProgress
	}
	m.running = true
	m.mu.Unlock()

	total := quickFiles
	if mode == ModeDeep {
		total = deepFiles
	}
	out := make(chan Event, 8)
	go m.run(ctx, total, out)
	return out, nil
}

func (m *Mock) run(ctx context.Context, total int, out chan<- Event) {
	defer close(out) // runs last, so "running" is already false when consumers see the close
	defer m.setRunning(false)

	ticker := time.NewTicker(m.tick)
	defer ticker.Stop()

	for i := 1; i <= total; i++ {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		m.mu.Lock()
		m.stats.FilesAnalyzed++
		snap := m.stats
		m.mu.Unlock()

		ev := Event{
			Path:     samplePaths[i%len(samplePaths)],
			Progress: float64(i) / float64(total),
			Stats:    snap,
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return
		}
	}
}

func (m *Mock) setRunning(v bool) {
	m.mu.Lock()
	m.running = v
	m.mu.Unlock()
}

func (m *Mock) Pause() {}
func (m *Mock) Resume() {}
func (m *Mock) IsPaused() bool { return false }
func (m *Mock) Target() string { return "C:\\Mock\\Directory" }
func (m *Mock) SetTarget(string) {}
func (m *Mock) QuarantineFileDirect(string, string) error { return nil }

var (
	_ Service        = (*Mock)(nil)
	_ ScanController = (*Mock)(nil)
)
