package scanner

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMockScanCompletes(t *testing.T) {
	m := NewMock(WithTick(time.Microsecond))
	before := m.Stats().FilesAnalyzed

	events, err := m.Start(context.Background(), ModeQuick)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(context.Background(), ModeQuick); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("second Start: got %v, want ErrScanInProgress", err)
	}

	var last Event
	n := 0
	for ev := range events {
		last = ev
		n++
	}
	if n != quickFiles {
		t.Fatalf("got %d events, want %d", n, quickFiles)
	}
	if last.Progress != 1 {
		t.Fatalf("final progress = %v, want 1", last.Progress)
	}
	if got := m.Stats().FilesAnalyzed; got != before+quickFiles {
		t.Fatalf("FilesAnalyzed = %d, want %d", got, before+quickFiles)
	}
}

func TestMockCancelReleasesScanner(t *testing.T) {
	m := NewMock(WithTick(time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())

	events, err := m.Start(ctx, ModeDeep)
	if err != nil {
		t.Fatal(err)
	}
	<-events
	cancel()
	for range events {
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if _, err := m.Start(ctx2, ModeQuick); err != nil {
		t.Fatalf("Start after cancel: %v", err)
	}
}
