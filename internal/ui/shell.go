package ui

import (
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"malshot/internal/scanner"
)

// Run builds the window and blocks until it is closed.
func Run(svc scanner.Service) {
	a := app.NewWithID("io.malshot.desktop")
	a.Settings().SetTheme(NewTheme())

	w := a.NewWindow("MalShot - Enterprise Endpoint Defender & Neural Threat Engine")
	sh := newShell(svc, w)
	w.SetContent(sh.root)
	if health := svc.Health(); health.AssetError != "" {
		dialog.ShowError(fmt.Errorf("deep inspection is disabled: %s", health.AssetError), w)
	}
	w.SetOnClosed(func() {
		sh.dashboard.Shutdown()
		sh.scannerView.handleStop()
	})
	w.Resize(fyne.NewSize(1100, 720))
	w.ShowAndRun()
}

type view struct {
	title string
	obj   fyne.CanvasObject
}

type shell struct {
	root        fyne.CanvasObject
	dashboard   *Dashboard
	scannerView *ScannerView
}

func newShell(svc scanner.Service, window fyne.Window) *shell {
	vault := newVaultView(svc)
	dash := newDashboard(svc, window, func() { vault.refresh() })
	scView := NewScannerView(svc, window, func() { vault.refresh() })
	settings := newSettingsView(svc)
	views := []view{
		{"Overview & Scan", dash.Object()},
		{"Real-Time Guard", scView.Object()},
		{"Quarantine Vault", vault.Object()},
		{"Settings & Intel", settings.Object()},
	}

	body := container.NewStack()
	titles := make([]string, len(views))
	for i, v := range views {
		titles[i] = v.title
		body.Add(v.obj)
	}

	sidebar := newSidebar(titles, func(selected int) {
		for i, v := range views {
			if i == selected {
				v.obj.Show()
			} else {
				v.obj.Hide()
			}
		}
		body.Refresh()
	})

	status := NewStatusBar()
	status.Update(svc.Health())

	topBar := newTopBar()
	layoutRoot := container.NewBorder(topBar, container.NewPadded(status.Object()), sidebar, nil, body)
	root := newPanel(layoutRoot, panelStyle{fill: colBackground, stroke: colBorderDim, strokeW: 1, radius: 10, inset: 8})
	return &shell{root: root, dashboard: dash, scannerView: scView}
}

func newTopBar() fyne.CanvasObject {
	logo := canvas.NewImageFromResource(logoIcon)
	logo.FillMode = canvas.ImageFillContain
	logo.SetMinSize(fyne.NewSize(24, 24))

	name := canvas.NewText("malshot-engine", colText)
	name.TextSize = 13
	name.TextStyle = fyne.TextStyle{Bold: true}

	slash := canvas.NewText("/", colTextDim)
	slash.TextSize = 12

	version := canvas.NewText("daemon-v2.4.0", colTextDim)
	version.TextSize = 11
	version.TextStyle = fyne.TextStyle{Monospace: true}

	badge := newBadge("SHIELD ACTIVE")

	telemetry := canvas.NewText("CPU: 1.4%  |  RAM: 128 MB  |  Signatures: 30,703  |  YARA: 193", colTextDim)
	telemetry.TextSize = 10
	telemetry.TextStyle = fyne.TextStyle{Monospace: true}

	left := container.NewHBox(
		container.NewCenter(logo),
		container.NewCenter(name),
		container.NewCenter(slash),
		container.NewCenter(version),
		container.NewCenter(badge),
	)

	topRow := container.NewBorder(nil, nil, left, container.NewCenter(telemetry))
	return newPanel(topRow, panelStyle{fill: colNavBar, stroke: colBorderDim, strokeW: 1, radius: 8, inset: 6})
}

// newSidebar renders a sleek vertical navigation panel on the left.
func newSidebar(titles []string, onSelect func(int)) fyne.CanvasObject {
	buttons := make([]*widget.Button, len(titles))
	sidebarItems := make([]fyne.CanvasObject, 0, len(titles)+2)

	hdr := canvas.NewText("OPERATIONS", colTextDim)
	hdr.TextSize = 10
	hdr.TextStyle = fyne.TextStyle{Bold: true, Monospace: true}
	sidebarItems = append(sidebarItems, container.NewPadded(hdr))

	selectTab := func(idx int) {
		for i, b := range buttons {
			if i == idx {
				b.Importance = widget.HighImportance
			} else {
				b.Importance = widget.LowImportance
			}
			b.Refresh()
		}
		onSelect(idx)
	}

	for i, t := range titles {
		idx := i
		btn := widget.NewButton(t, func() { selectTab(idx) })
		btn.Alignment = widget.ButtonAlignLeading
		buttons[i] = btn
		sidebarItems = append(sidebarItems, btn)
	}

	// Bottom Engine Info Card matching the modern template
	infoTitle := canvas.NewText("ENGINE STATUS", colTextDim)
	infoTitle.TextSize = 9
	infoTitle.TextStyle = fyne.TextStyle{Bold: true, Monospace: true}

	engineTxt := canvas.NewText("Engine: Hybrid-CGO", colAccent)
	engineTxt.TextSize = 10
	engineTxt.TextStyle = fyne.TextStyle{Monospace: true}

	inferTxt := canvas.NewText("Inference: Tesla T4 / ONNX", colText)
	inferTxt.TextSize = 10
	inferTxt.TextStyle = fyne.TextStyle{Monospace: true}

	sigTxt := canvas.NewText("Database: 30.7k Hashes", colTextDim)
	sigTxt.TextSize = 10
	sigTxt.TextStyle = fyne.TextStyle{Monospace: true}

	infoCard := newPanel(
		container.NewVBox(infoTitle, engineTxt, inferTxt, sigTxt),
		panelStyle{fill: colPanel, stroke: colBorderDim, strokeW: 1, radius: 8, inset: 8},
	)

	navBox := container.NewVBox(sidebarItems...)
	sideContainer := container.NewBorder(navBox, infoCard, nil, nil, layout.NewSpacer())

	selectTab(0)
	return newPanel(sideContainer, panelStyle{fill: colNavBar, stroke: colBorderDim, strokeW: 1, radius: 8, inset: 8})
}

// newNavBar kept for backwards compatibility.
func newNavBar(titles []string, onSelect func(int)) fyne.CanvasObject {
	return newSidebar(titles, onSelect)
}
