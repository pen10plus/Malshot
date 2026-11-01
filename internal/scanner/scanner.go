// Package scanner defines the contract between the UI and the detection
// engine. The UI only depends on Service, so the real engine can replace the
// simulated one in mock.go without touching any UI code.
package scanner

import (
	"context"
	"errors"
)

// ErrScanInProgress is returned by Start when a scan is already running.
var ErrScanInProgress = errors.New("scanner: a scan is already running")

// Mode selects how deep a scan goes.
type Mode int

const (
	ModeQuick Mode = iota
	ModeDeep
)

func (m Mode) String() string {
	if m == ModeDeep {
		return "deep"
	}
	return "quick"
}

// Stats is a point-in-time snapshot of the engine counters.
type Stats struct {
	TotalDiscovered int64
	SkippedCount    int64
	AnalyzedCount   int64
	ThreatsCount    int64
	ProcessedBytes  int64
	FilesAnalyzed   int
	Skipped         int
	ZeroDayBlocked  int
	Quarantined     int
	ThreatsFound    int
	Errors          int
}

// Health describes the engine's local state (shown in the status bar).
type Health struct {
	SignaturesUpdated bool
	EngineActive      bool
	ActiveCores       int
	TotalCores        int
	YaraReady         bool
	OnnxReady         bool
	DeepInspection    bool
	AssetError        string
}

// DetectedFile represents an identified threat during scanning.
type DetectedFile struct {
	Path            string
	ThreatName      string
	DetectionSource string
	Score           float32
	Quarantined     bool
	Size            int64
	Timestamp       int64
}

// Event is emitted for every file the engine analyzes.
type Event struct {
	Path     string
	Progress float64 // 0.0 - 1.0
	Stats    Stats
	Detected *DetectedFile
}

// Service is what the UI needs from the engine.
type QuarantineIncident struct {
	IncidentID      int
	OriginalPath    string
	VaultPath       string
	DetectionSource string
	Timestamp       int64
}

type PathService interface {
	StartPath(ctx context.Context, path string, mode Mode) (<-chan Event, error)
}

type VaultService interface {
	QuarantineIncidents() ([]QuarantineIncident, error)
	RestoreFile(incidentID int, targetPath string) error
}

type DeepInspectionService interface {
	SetDeepInspectionEnabled(bool)
	DeepInspectionEnabled() bool
}

type ScanController interface {
	Pause()
	Resume()
	IsPaused() bool
	Target() string
	SetTarget(string)
	QuarantineFileDirect(path, threatName string) error
}

type Service interface {
	// Start begins a scan. Events are streamed on the returned channel, which
	// is closed when the scan finishes or ctx is cancelled.
	Start(ctx context.Context, mode Mode) (<-chan Event, error)
	Stats() Stats
	Health() Health
}
