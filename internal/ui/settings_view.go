package ui

import (
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"malshot/internal/scanner"
)

type settingsView struct {
	svc  scanner.Service
	root fyne.CanvasObject
}

func newSettingsView(svc scanner.Service) *settingsView {
	sv := &settingsView{svc: svc}

	// 1. Title Header
	header := widget.NewLabelWithStyle("Settings & Threat Intelligence", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	// 2. Google Colab Compute Section
	colabTitle := canvas.NewText("Google Colab GPU Compute Acceleration", colProgress)
	colabTitle.TextSize = 14
	colabTitle.TextStyle = fyne.TextStyle{Bold: true}

	colabDesc := widget.NewLabel("Accelerate zero-day deep inspection using free Google Colab NVIDIA GPUs (Tesla T4 / A100).\nRun MalShot_Colab_Compute.ipynb in Colab and paste the generated Cloudflare/ngrok tunnel URL below.")
	colabDesc.Wrapping = fyne.TextWrapWord

	urlEntry := widget.NewEntry()
	urlEntry.SetPlaceHolder("https://xxxx.trycloudflare.com or https://xxxx.ngrok-free.app")
	if envURL := os.Getenv("MALSHOT_COLAB_URL"); envURL != "" {
		urlEntry.SetText(envURL)
	}

	statusBadge := widget.NewLabel("Status: Local CPU ONNX Mode (Colab not connected)")
	statusBadge.TextStyle = fyne.TextStyle{Italic: true}

	var testBtn *widget.Button
	testBtn = widget.NewButton("Connect & Test Colab GPU", func() {
		rawURL := strings.TrimSpace(urlEntry.Text)
		if rawURL == "" {
			statusBadge.SetText("Status: Please enter a valid Colab tunnel URL")
			return
		}
		if _, err := url.ParseRequestURI(rawURL); err != nil {
			statusBadge.SetText("Status: Invalid URL format")
			return
		}
		testBtn.Disable()
		statusBadge.SetText("Status: Testing connection to Colab GPU...")
		go func() {
			meta, err := scanner.CheckColabHealth(rawURL)
			fyne.Do(func() {
				testBtn.Enable()
				if err != nil {
					statusBadge.SetText(fmt.Sprintf("Status: Connection failed (%s)", err.Error()))
				} else {
					_ = os.Setenv("MALSHOT_COLAB_URL", rawURL)
					statusBadge.SetText(fmt.Sprintf("Status: CONNECTED - %s", meta))
				}
			})
		}()
	})
	testBtn.Importance = widget.HighImportance

	disconnectBtn := widget.NewButton("Disconnect (Revert to Local)", func() {
		_ = os.Unsetenv("MALSHOT_COLAB_URL")
		urlEntry.SetText("")
		statusBadge.SetText("Status: Disconnected. Local CPU ONNX Mode active.")
	})

	colabControls := container.NewVBox(
		colabTitle,
		colabDesc,
		container.NewBorder(nil, nil, widget.NewLabel("Colab URL:"), nil, urlEntry),
		container.NewHBox(testBtn, disconnectBtn),
		statusBadge,
	)
	colabPanel := newPanel(colabControls, panelStyle{fill: colPanel, stroke: colProgress, strokeW: 1.5, radius: 10, inset: 16})

	// 3. Threat Intelligence Database Status Section
	intelTitle := canvas.NewText("Threat Intelligence Feeds & Heuristics", colAccent)
	intelTitle.TextSize = 14
	intelTitle.TextStyle = fyne.TextStyle{Bold: true}

	health := svc.Health()
	sigCount := "30,703 Verified SHA-256 Hashes"
	if !health.SignaturesUpdated {
		sigCount = "Signatures Available"
	}

	intelGrid := container.NewGridWithColumns(2,
		newMetricItem("Threat Signatures DB", sigCount, "MalwareBazaar, ThreatFox, URLhaus, VX-Underground"),
		newMetricItem("Heuristic Engine", "10 YARA Rulesets (193 Rules)", "APTs, Ransomware, Packers, Droppers"),
		newMetricItem("Cache Anti-Tamper", "SQLite WAL Mode", "Validates (mtime, size, sha256) per scan"),
		newMetricItem("Quarantine Cryptography", "AES-256-GCM + Windows DPAPI", "Hardware-bound master key encryption"),
	)

	intelPanel := newPanel(container.NewVBox(intelTitle, layout.NewSpacer(), intelGrid),
		panelStyle{fill: colPanel, stroke: colBorderDim, strokeW: 1, radius: 10, inset: 16})

	// 4. Hardware & Worker Configuration Section
	configTitle := canvas.NewText("Scanner Engine Tuning", colText)
	configTitle.TextSize = 14
	configTitle.TextStyle = fyne.TextStyle{Bold: true}

	configGrid := container.NewGridWithColumns(2,
		newMetricItem("Worker Pool", fmt.Sprintf("%d / %d CPU Cores", health.ActiveCores, runtime.NumCPU()), "Multi-threaded parallel file processing"),
		newMetricItem("Zero-Day Confidence Threshold", "80% (Score >= 0.80)", "Alert trigger for deep inspection neural output"),
	)
	configPanel := newPanel(container.NewVBox(configTitle, layout.NewSpacer(), configGrid),
		panelStyle{fill: colPanel, stroke: colBorderDim, strokeW: 1, radius: 10, inset: 16})

	content := container.NewVBox(
		header,
		colabPanel,
		intelPanel,
		configPanel,
	)

	sv.root = container.NewVScroll(container.NewPadded(content))
	return sv
}

func newMetricItem(title, value, subtext string) fyne.CanvasObject {
	t := canvas.NewText(title, colTextDim)
	t.TextSize = 11

	v := canvas.NewText(value, colText)
	v.TextSize = 13
	v.TextStyle = fyne.TextStyle{Bold: true}

	s := canvas.NewText(subtext, colTextDim)
	s.TextSize = 10

	return container.NewVBox(t, v, s)
}

func (sv *settingsView) Object() fyne.CanvasObject {
	return sv.root
}
