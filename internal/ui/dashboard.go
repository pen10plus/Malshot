package ui

import (
	"context"
	"fmt"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"malshot/internal/scanner"
)

// Dashboard is the main operational view with circular progress, player controls,
// selected directory information, and real-time detected threat quarantine actions.
type Dashboard struct {
	svc          scanner.Service
	root         fyne.CanvasObject
	window       fyne.Window

	targetDir    string
	dirLabel     *widget.Label
	browseBtn    *widget.Button

	circle       *CircularProgress
	files        *StatCard
	zeroDay      *StatCard
	quarantine   *StatCard
	threats      *StatCard
	progress     *ThinProgress
	log          *LogView

	playBtn      *widget.Button
	pauseBtn     *widget.Button
	stopBtn      *widget.Button
	deepToggle   *widget.Check
	health       *widget.Label
	errorCount   *widget.Label

	detectedList *DetectedList

	cancel        context.CancelFunc
	scanning      bool
	paused        bool
	generation    uint64
	onVaultUpdate func()
}

func newDashboard(svc scanner.Service, window fyne.Window, onVaultUpdate func()) *Dashboard {
	d := &Dashboard{
		svc:           svc,
		window:        window,
		targetDir:     ".",
		circle:        NewCircularProgress(),
		files:         NewColoredStatCard("Total Files Scanned", colText, "30,703 Signatures"),
		threats:       NewColoredStatCard("Threats Identified", colDanger, "Signatures & YARA"),
		quarantine:    NewColoredStatCard("Items Quarantined", colText, "AES-256-GCM Vault"),
		zeroDay:       NewColoredStatCard("AI Zero-Day Anomaly", colWarning, "LSTM Opcode Model"),
		progress:      NewThinProgress(),
		log:           NewLogView(),
		onVaultUpdate: onVaultUpdate,
	}

	if ctrl, ok := svc.(scanner.ScanController); ok && ctrl.Target() != "" {
		d.targetDir = ctrl.Target()
	}

	// 1. Target Directory Bar (High-contrast clean layout)
	absTarget, _ := filepath.Abs(d.targetDir)
	d.dirLabel = widget.NewLabelWithStyle(absTarget, fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true})
	d.browseBtn = widget.NewButton("Browse Folder", d.chooseFolder)
	d.browseBtn.Importance = widget.LowImportance

	dirCard := newPanel(
		container.NewBorder(nil, nil, widget.NewLabelWithStyle("Target Directory:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), d.browseBtn, d.dirLabel),
		panelStyle{fill: colPanel, stroke: colBorderDim, strokeW: 1, radius: 8, inset: 10},
	)

	// 2. Scanner Primary Controls
	d.playBtn = widget.NewButton("▶ Start Scan", func() { d.handlePlay(scanner.ModeQuick) })
	d.playBtn.Importance = widget.HighImportance

	d.pauseBtn = widget.NewButton("⏸ Pause", d.handlePause)
	d.pauseBtn.Disable()

	d.stopBtn = widget.NewButton("⏹ Cancel", d.handleStop)
	d.stopBtn.Importance = widget.DangerImportance
	d.stopBtn.Disable()

	d.deepToggle = widget.NewCheck("Deep Inspection Engine (YARA + ONNX)", func(enabled bool) {
		if controller, ok := d.svc.(scanner.DeepInspectionService); ok {
			controller.SetDeepInspectionEnabled(enabled)
		}
		d.refreshHealth()
	})

	playerControls := container.NewHBox(
		d.playBtn,
		d.pauseBtn,
		d.stopBtn,
		widget.NewSeparator(),
		d.deepToggle,
	)

	// 3. Stats Cards (4-column grid matching modern template)
	stats := container.NewGridWithColumns(4, d.files.Object(), d.threats.Object(), d.quarantine.Object(), d.zeroDay.Object())

	// 4. Detected Threats List with Quarantine button in front of each name
	d.detectedList = NewDetectedList(func(path, threatName string) error {
		if ctrl, ok := d.svc.(scanner.ScanController); ok {
			err := ctrl.QuarantineFileDirect(path, threatName)
			if err == nil {
				d.showStats(d.svc.Stats())
				if d.onVaultUpdate != nil {
					d.onVaultUpdate()
				}
			}
			return err
		}
		return fmt.Errorf("quarantine service unavailable")
	})

	d.detectedList.SetOnCountChange(func(total, quarantined int) {
		if total > 0 {
			d.circle.SetState("AT RISK", total-quarantined)
		}
	})

	// 5. Diagnostics and Monospace Log
	d.health = widget.NewLabel("")
	d.errorCount = widget.NewLabel("Scan errors: 0")
	logPanel := newPanel(
		container.NewVBox(d.health, d.errorCount, d.log.Object()),
		panelStyle{fill: colLogBg, radius: 8, inset: 10},
	)

	// Assemble Main Body
	body := container.NewVBox(
		dirCard,
		container.NewCenter(d.circle.Object()),
		d.progress,
		container.NewCenter(playerControls),
		stats,
		d.detectedList.Object(),
		logPanel,
	)

	scroll := container.NewVScroll(body)
	d.root = newPanel(scroll, panelStyle{fill: colBackground, stroke: colBorder, strokeW: 1, radius: 10, inset: 12})

	d.showStats(svc.Stats())
	d.refreshHealth()
	return d
}

func (d *Dashboard) chooseFolder() {
	if d.scanning {
		return
	}
	dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
		if err != nil || uri == nil {
			return
		}
		d.targetDir = uri.Path()
		if ctrl, ok := d.svc.(scanner.ScanController); ok {
			ctrl.SetTarget(d.targetDir)
		}
		absTarget, _ := filepath.Abs(d.targetDir)
		d.dirLabel.SetText(fmt.Sprintf("Target: %s", absTarget))
	}, d.window)
}

func (d *Dashboard) Object() fyne.CanvasObject { return d.root }

func (d *Dashboard) Shutdown() {
	if d.cancel != nil {
		d.cancel()
	}
	if ctrl, ok := d.svc.(scanner.ScanController); ok && d.paused {
		ctrl.Resume()
	}
}

func (d *Dashboard) handlePlay(mode scanner.Mode) {
	if d.paused {
		// Resume paused scan
		if ctrl, ok := d.svc.(scanner.ScanController); ok {
			ctrl.Resume()
		}
		d.paused = false
		d.pauseBtn.SetText("⏸ Pause")
		d.playBtn.Disable()
		d.circle.SetState("SCANNING", 0)
		d.log.Append("Scan resumed.")
		return
	}

	if d.scanning {
		return
	}

	d.startScan(mode, d.targetDir)
}

func (d *Dashboard) handlePause() {
	if !d.scanning {
		return
	}
	if d.paused {
		d.handlePlay(scanner.ModeQuick)
		return
	}
	if ctrl, ok := d.svc.(scanner.ScanController); ok {
		ctrl.Pause()
	}
	d.paused = true
	d.pauseBtn.SetText("▶ Resume")
	d.playBtn.SetText("▶ Resume")
	d.playBtn.Enable()
	d.circle.SetState("PAUSED", 0)
	d.log.Append("Scan paused.")
}

func (d *Dashboard) handleStop() {
	if d.cancel != nil {
		d.cancel()
	}
	if ctrl, ok := d.svc.(scanner.ScanController); ok && d.paused {
		ctrl.Resume()
	}
	d.finish()
	d.log.Append("Scan stopped by user.")
}

func (d *Dashboard) startScan(mode scanner.Mode, path string) {
	d.scanning = true
	d.paused = false
	d.generation++
	generation := d.generation

	d.playBtn.SetText("▶ Scanning...")
	d.playBtn.Disable()
	d.pauseBtn.SetText("⏸ Pause")
	d.pauseBtn.Enable()
	d.stopBtn.Enable()
	d.browseBtn.Disable()

	d.progress.SetValue(0)
	d.circle.SetProgress(0, 0, 0)
	d.circle.SetState("SCANNING", 0)
	d.detectedList.Clear()
	d.log.Append("Starting " + mode.String() + " scan on " + path + "...")

	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel

	var events <-chan scanner.Event
	var err error
	if pathSvc, ok := d.svc.(scanner.PathService); ok {
		events, err = pathSvc.StartPath(ctx, path, mode)
	} else {
		events, err = d.svc.Start(ctx, mode)
	}

	if err != nil {
		cancel()
		d.finish()
		d.log.Append("Cannot start scan: " + err.Error())
		return
	}

	go d.consume(events, generation)
}

func (d *Dashboard) consume(events <-chan scanner.Event, generation uint64) {
	for ev := range events {
		event := ev
		fyne.Do(func() {
			if generation == d.generation {
				d.apply(event)
			}
		})
	}
	fyne.Do(func() {
		if generation == d.generation {
			d.finish()
		}
	})
}

func (d *Dashboard) apply(ev scanner.Event) {
	d.progress.SetValue(ev.Progress)
	d.circle.SetProgress(ev.Progress, int(ev.Stats.AnalyzedCount), int(ev.Stats.TotalDiscovered))
	d.log.Append("Analyzing: " + ev.Path)
	d.showStats(ev.Stats)

	if ev.Detected != nil {
		d.detectedList.AddItem(*ev.Detected)
	}
}

func (d *Dashboard) finish() {
	d.scanning = false
	d.paused = false
	d.playBtn.SetText("▶ Start Scan")
	d.playBtn.Enable()
	d.pauseBtn.SetText("⏸ Pause")
	d.pauseBtn.Disable()
	d.stopBtn.Disable()
	d.browseBtn.Enable()

	d.progress.SetValue(1)
	d.log.Append("Scan finished.")

	stats := d.svc.Stats()
	d.showStats(stats)

	threats := stats.ThreatsFound
	if threats == 0 {
		threats = int(stats.ThreatsCount)
	}
	if threats > 0 {
		d.circle.SetState("AT RISK", threats)
	} else {
		d.circle.SetState("PROTECTED", 0)
	}
}

func (d *Dashboard) showStats(s scanner.Stats) {
	total := s.TotalDiscovered
	if total == 0 {
		total = int64(s.FilesAnalyzed + s.Skipped)
	}
	d.files.SetValue(int(total))
	d.zeroDay.SetValue(s.ZeroDayBlocked)
	d.quarantine.SetValue(s.Quarantined)
	threats := s.ThreatsCount
	if threats == 0 {
		threats = int64(s.ThreatsFound)
	}
	d.threats.SetValue(int(threats))
	d.errorCount.SetText(fmt.Sprintf("Scan errors: %d", s.Errors))
}

func (d *Dashboard) refreshHealth() {
	health := d.svc.Health()
	yaraState, onnxState := "Missing", "Disabled"
	if health.YaraReady {
		yaraState = "Ready"
	}
	if health.OnnxReady && health.DeepInspection {
		onnxState = "Active"
	}
	text := fmt.Sprintf("YARA Rules: %s | ONNX Engine: %s", yaraState, onnxState)
	if health.AssetError != "" {
		text += " | " + health.AssetError
	}
	d.health.SetText(text)
}
