package ui

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"malshot/internal/scanner"
)

// ScannerView provides the dedicated scanner dashboard with circular progress bar,
// player controls (Play/Pause/Resume/Stop), target directory selection, and real-time detected files.
type ScannerView struct {
	svc    scanner.Service
	window fyne.Window
	root   fyne.CanvasObject

	targetDir string
	dirLabel  *widget.Label
	browseBtn *widget.Button

	circle      *CircularProgress
	thinBar     *ThinProgress
	currentFile *canvas.Text

	playBtn   *widget.Button
	pauseBtn  *widget.Button
	stopBtn   *widget.Button
	modeRadio *widget.RadioGroup

	detectedList *DetectedList

	scanning      bool
	paused        bool
	cancel        context.CancelFunc
	generation    atomic.Uint64
	onVaultUpdate func()
	scanWg        sync.WaitGroup
}

func NewScannerView(svc scanner.Service, window fyne.Window, onVaultUpdate func()) *ScannerView {
	sv := &ScannerView{
		svc:           svc,
		window:        window,
		targetDir:     ".",
		onVaultUpdate: onVaultUpdate,
	}

	if ctrl, ok := svc.(scanner.ScanController); ok && ctrl.Target() != "" {
		sv.targetDir = ctrl.Target()
	}

	// 1. Target Directory Section
	absTarget, _ := filepath.Abs(sv.targetDir)
	sv.dirLabel = widget.NewLabelWithStyle(absTarget, fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true})
	sv.browseBtn = widget.NewButton("Browse Folder", sv.chooseFolder)
	sv.browseBtn.Importance = widget.LowImportance

	dirCard := newPanel(
		container.NewBorder(nil, nil, widget.NewLabelWithStyle("Target Directory:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), sv.browseBtn, sv.dirLabel),
		panelStyle{fill: colPanel, stroke: colBorderDim, strokeW: 1, radius: 8, inset: 10},
	)

	// 2. Circular Progress & Current File
	sv.circle = NewCircularProgress()
	sv.thinBar = NewThinProgress()

	sv.currentFile = canvas.NewText("Ready to scan. Select target and click Start.", colTextDim)
	sv.currentFile.TextSize = 12
	sv.currentFile.TextStyle = fyne.TextStyle{Monospace: true}

	progressCenter := container.NewVBox(
		sv.circle.Object(),
		container.NewCenter(sv.currentFile),
		sv.thinBar,
	)

	// 3. Player Control Bar
	sv.playBtn = widget.NewButton("▶ Start Scan", sv.handlePlay)
	sv.playBtn.Importance = widget.HighImportance

	sv.pauseBtn = widget.NewButton("⏸ Pause", sv.handlePause)
	sv.pauseBtn.Disable()

	sv.stopBtn = widget.NewButton("⏹ Stop", sv.handleStop)
	sv.stopBtn.Importance = widget.DangerImportance
	sv.stopBtn.Disable()

	sv.modeRadio = widget.NewRadioGroup([]string{"Quick Scan", "Deep Inspection (YARA + ONNX)"}, func(s string) {
		if deepSvc, ok := sv.svc.(scanner.DeepInspectionService); ok {
			deepSvc.SetDeepInspectionEnabled(s == "Deep Inspection (YARA + ONNX)")
		}
	})
	sv.modeRadio.Horizontal = true
	sv.modeRadio.SetSelected("Quick Scan")

	controlsBar := container.NewHBox(
		sv.playBtn,
		sv.pauseBtn,
		sv.stopBtn,
		widget.NewSeparator(),
		sv.modeRadio,
	)

	playerCard := newPanel(
		container.NewCenter(controlsBar),
		panelStyle{fill: colPanel, stroke: colBorder, strokeW: 1, radius: 8, inset: 10},
	)

	// 4. Detected Threats List
	sv.detectedList = NewDetectedList(func(path, threatName string) error {
		if ctrl, ok := sv.svc.(scanner.ScanController); ok {
			err := ctrl.QuarantineFileDirect(path, threatName)
			if err == nil && sv.onVaultUpdate != nil {
				sv.onVaultUpdate()
			}
			return err
		}
		return fmt.Errorf("quarantine service unavailable")
	})

	sv.detectedList.SetOnCountChange(func(total, quarantined int) {
		if total > 0 {
			sv.circle.SetState("AT RISK", total-quarantined)
		}
	})

	// Layout assemble
	topSection := container.NewVBox(dirCard, playerCard, progressCenter)
	mainLayout := container.NewBorder(topSection, nil, nil, nil, sv.detectedList.Object())
	sv.root = newPanel(mainLayout, panelStyle{fill: colBackground, stroke: colBorder, strokeW: 1, radius: 10, inset: 12})

	return sv
}

func (sv *ScannerView) Object() fyne.CanvasObject {
	return sv.root
}

func (sv *ScannerView) chooseFolder() {
	if sv.scanning {
		return
	}
	dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
		if err != nil || uri == nil {
			return
		}
		sv.targetDir = uri.Path()
		if ctrl, ok := sv.svc.(scanner.ScanController); ok {
			ctrl.SetTarget(sv.targetDir)
		}
		absPath, _ := filepath.Abs(sv.targetDir)
		sv.dirLabel.SetText(fmt.Sprintf("Target: %s", absPath))
	}, sv.window)
}

func (sv *ScannerView) handlePlay() {
	if sv.paused {
		// Resume paused scan
		if ctrl, ok := sv.svc.(scanner.ScanController); ok {
			ctrl.Resume()
		}
		sv.paused = false
		sv.playBtn.SetText("▶ Scanning...")
		sv.playBtn.Disable()
		sv.pauseBtn.SetText("⏸ Pause")
		sv.pauseBtn.Enable()
		sv.circle.SetState("SCANNING", 0)
		return
	}

	if sv.scanning {
		return
	}

	// Start new scan
	mode := scanner.ModeQuick
	if sv.modeRadio.Selected == "Deep Inspection (YARA + ONNX)" {
		mode = scanner.ModeDeep
	}

	sv.scanning = true
	sv.paused = false
	generation := sv.generation.Add(1)

	sv.playBtn.SetText("▶ Scanning...")
	sv.playBtn.Disable()
	sv.pauseBtn.SetText("⏸ Pause")
	sv.pauseBtn.Enable()
	sv.stopBtn.Enable()
	sv.browseBtn.Disable()
	sv.modeRadio.Disable()

	sv.detectedList.Clear()
	sv.circle.SetProgress(0, 0, 0)
	sv.circle.SetState("SCANNING", 0)
	sv.thinBar.SetValue(0)
	sv.currentFile.Text = "Initializing scan pipeline..."
	sv.currentFile.Refresh()

	ctx, cancel := context.WithCancel(context.Background())
	sv.cancel = cancel

	var events <-chan scanner.Event
	var err error
	if pathSvc, ok := sv.svc.(scanner.PathService); ok {
		events, err = pathSvc.StartPath(ctx, sv.targetDir, mode)
	} else {
		events, err = sv.svc.Start(ctx, mode)
	}

	if err != nil {
		cancel()
		sv.finishScan()
		sv.currentFile.Text = "Cannot start scan: " + err.Error()
		sv.currentFile.Refresh()
		return
	}

	sv.scanWg.Add(1)
	go sv.consumeEvents(events, generation)
}

func (sv *ScannerView) handlePause() {
	if !sv.scanning {
		return
	}
	if sv.paused {
		// Resume
		sv.handlePlay()
		return
	}
	if ctrl, ok := sv.svc.(scanner.ScanController); ok {
		ctrl.Pause()
	}
	sv.paused = true
	sv.pauseBtn.SetText("▶ Resume")
	sv.playBtn.SetText("▶ Resume")
	sv.playBtn.Enable()
	sv.circle.SetState("PAUSED", 0)
	sv.currentFile.Text = "Scan paused by user."
	sv.currentFile.Refresh()
}

func (sv *ScannerView) handleStop() {
	if sv.cancel != nil {
		sv.cancel()
		sv.cancel = nil
	}
	sv.generation.Add(1)
	if ctrl, ok := sv.svc.(scanner.ScanController); ok && sv.paused {
		ctrl.Resume()
	}
	sv.finishScan()
	sv.currentFile.Text = "Scan cancelled by user."
	sv.currentFile.Refresh()
}

// Wait blocks until in-flight scan event consumption completes.
func (sv *ScannerView) Wait() {
	sv.scanWg.Wait()
}

func (sv *ScannerView) consumeEvents(events <-chan scanner.Event, generation uint64) {
	defer sv.scanWg.Done()
	for ev := range events {
		event := ev
		fyne.Do(func() {
			if generation != sv.generation.Load() {
				return
			}
			sv.thinBar.SetValue(event.Progress)
			sv.circle.SetProgress(event.Progress, int(event.Stats.AnalyzedCount), int(event.Stats.TotalDiscovered))
			sv.currentFile.Text = "Scanning: " + filepath.Base(event.Path)
			sv.currentFile.Refresh()

			if event.Detected != nil {
				sv.detectedList.AddItem(*event.Detected)
			}
		})
	}
	done := make(chan struct{})
	fyne.Do(func() {
		defer close(done)
		if generation == sv.generation.Load() {
			sv.finishScan()
		}
	})
	<-done
}

func (sv *ScannerView) finishScan() {
	sv.scanning = false
	sv.paused = false
	sv.playBtn.SetText("▶ Start Scan")
	sv.playBtn.Enable()
	sv.pauseBtn.SetText("⏸ Pause")
	sv.pauseBtn.Disable()
	sv.stopBtn.Disable()
	sv.browseBtn.Enable()
	sv.modeRadio.Enable()

	stats := sv.svc.Stats()
	threats := stats.ThreatsFound
	if threats == 0 {
		threats = int(stats.ThreatsCount)
	}

	if threats > 0 {
		sv.circle.SetState("AT RISK", threats)
		sv.currentFile.Text = fmt.Sprintf("Scan completed with %d threat(s) detected!", threats)
	} else {
		sv.circle.SetState("PROTECTED", 0)
		sv.currentFile.Text = "Scan completed. No threats found."
	}
	sv.currentFile.Refresh()
	sv.thinBar.SetValue(1.0)
}
