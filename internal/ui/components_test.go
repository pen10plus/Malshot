package ui

import (
	"testing"
	"time"

	"fyne.io/fyne/v2/test"

	"malshot/internal/scanner"
)

func TestCircularProgressComponent(t *testing.T) {
	cp := NewCircularProgress()
	if cp == nil {
		t.Fatal("NewCircularProgress returned nil")
	}

	cp.SetProgress(0.5, 50, 100)
	if cp.percent.Text != "50%" {
		t.Errorf("expected 50%%, got %s", cp.percent.Text)
	}

	cp.SetState("SCANNING", 0)
	if cp.status.Text != "SCANNING" {
		t.Errorf("expected SCANNING, got %s", cp.status.Text)
	}

	cp.SetState("AT RISK", 2)
	if cp.status.Text != "AT RISK" {
		t.Errorf("expected AT RISK, got %s", cp.status.Text)
	}
}

func TestDetectedListComponent(t *testing.T) {
	quarantinedPaths := make([]string, 0)
	dl := NewDetectedList(func(path, threatName string) error {
		quarantinedPaths = append(quarantinedPaths, path)
		return nil
	})

	countChangedCalled := false
	dl.SetOnCountChange(func(total, quarantined int) {
		countChangedCalled = true
	})

	item := scanner.DetectedFile{
		Path:            "C:\\Test\\malware.exe",
		ThreatName:      "Test.Trojan.Generic",
		DetectionSource: "SHA-256",
		Size:            1024,
	}

	dl.AddItem(item)
	if !countChangedCalled {
		t.Error("expected onCountChange to be called")
	}

	dl.QuarantineAll()
	if len(quarantinedPaths) != 1 || quarantinedPaths[0] != "C:\\Test\\malware.exe" {
		t.Errorf("expected C:\\Test\\malware.exe to be quarantined, got %v", quarantinedPaths)
	}

	dl.Clear()
	if len(dl.items) != 0 {
		t.Errorf("expected items to be empty after Clear, got %d", len(dl.items))
	}
}

func TestScannerViewComponent(t *testing.T) {
	mockSvc := scanner.NewMock(scanner.WithTick(100 * time.Millisecond))
	window := test.NewWindow(nil)
	defer window.Close()

	sv := NewScannerView(mockSvc, window, nil)
	if sv == nil {
		t.Fatal("NewScannerView returned nil")
	}

	test.Tap(sv.playBtn)
	if !sv.scanning {
		t.Error("expected scanning to be true after playBtn tap")
	}

	test.Tap(sv.pauseBtn)
	if !sv.paused {
		t.Error("expected paused to be true after pauseBtn tap")
	}

	test.Tap(sv.stopBtn)
	if sv.scanning {
		t.Error("expected scanning to be false after stopBtn tap")
	}
	sv.Wait()
}

func TestScannerViewImmediateStopComponent(t *testing.T) {
	mockSvc := scanner.NewMock(scanner.WithTick(100 * time.Millisecond))
	window := test.NewWindow(nil)
	defer window.Close()

	sv := NewScannerView(mockSvc, window, nil)
	test.Tap(sv.playBtn)
	test.Tap(sv.stopBtn)
	sv.Wait()

	if sv.scanning {
		t.Error("expected scanning to be false after immediate stop")
	}
}

func TestSettingsViewComponent(t *testing.T) {
	mockSvc := scanner.NewMock()
	sv := newSettingsView(mockSvc)
	if sv == nil || sv.Object() == nil {
		t.Fatal("newSettingsView returned nil object")
	}
}
