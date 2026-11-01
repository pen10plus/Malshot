package scanner

import "sync/atomic"

// ScanStats contains counters for one scan lifecycle.
type ScanStats struct {
	TotalDiscovered atomic.Int64
	SkippedCount    atomic.Int64
	AnalyzedCount   atomic.Int64
	ThreatsCount    atomic.Int64
	Quarantined     atomic.Int64
	ZeroDayBlocked  atomic.Int64
	ProcessedBytes  atomic.Int64
	ErrorCount      atomic.Int64
}

// Reset clears every counter before a new scan starts.
func (s *ScanStats) Reset() {
	s.TotalDiscovered.Store(0)
	s.SkippedCount.Store(0)
	s.AnalyzedCount.Store(0)
	s.ThreatsCount.Store(0)
	s.Quarantined.Store(0)
	s.ZeroDayBlocked.Store(0)
	s.ProcessedBytes.Store(0)
	s.ErrorCount.Store(0)
}

func (s *ScanStats) failed() { s.ErrorCount.Add(1) }

func (s *ScanStats) discovered() {
	s.TotalDiscovered.Add(1)
}

func (s *ScanStats) skipped() {
	s.SkippedCount.Add(1)
}

func (s *ScanStats) analyzed(bytes int64, threat bool) {
	s.AnalyzedCount.Add(1)
	s.ProcessedBytes.Add(bytes)
	if threat {
		s.ThreatsCount.Add(1)
	}
}

func (s *ScanStats) addQuarantined() {
	s.Quarantined.Add(1)
}

func (s *ScanStats) addZeroDay() {
	s.ZeroDayBlocked.Add(1)
}

func (s *ScanStats) snapshot() Stats {
	return Stats{
		TotalDiscovered: s.TotalDiscovered.Load(),
		SkippedCount:    s.SkippedCount.Load(),
		AnalyzedCount:   s.AnalyzedCount.Load(),
		ThreatsCount:    s.ThreatsCount.Load(),
		Quarantined:     int(s.Quarantined.Load()),
		ZeroDayBlocked:  int(s.ZeroDayBlocked.Load()),
		ProcessedBytes:  s.ProcessedBytes.Load(),
		FilesAnalyzed:   int(s.AnalyzedCount.Load()),
		Skipped:         int(s.SkippedCount.Load()),
		ThreatsFound:    int(s.ThreatsCount.Load()),
		Errors:          int(s.ErrorCount.Load()),
	}
}
