package ui

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"malshot/internal/scanner"
)

// DetectedList manages and displays real-time identified threats with individual quarantine actions.
type DetectedList struct {
	root         fyne.CanvasObject
	itemsBox     *fyne.Container
	scroll       *container.Scroll
	titleLabel   *widget.Label
	quarantineAll *widget.Button
	emptyLabel   *canvas.Text

	mu           sync.RWMutex
	items        []scanner.DetectedFile
	onQuarantine func(path, threatName string) error
	onCountChange func(total, quarantined int)
}

func NewDetectedList(onQuarantine func(path, threatName string) error) *DetectedList {
	dl := &DetectedList{
		itemsBox:     container.NewVBox(),
		onQuarantine: onQuarantine,
	}

	dl.emptyLabel = canvas.NewText("✓ No threats detected. Scan is clean.", colAccent)
	dl.emptyLabel.TextSize = 13
	dl.emptyLabel.Alignment = fyne.TextAlignCenter

	dl.titleLabel = widget.NewLabelWithStyle("Detected Threats (0)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	dl.quarantineAll = widget.NewButton("Quarantine All", func() {
		dl.QuarantineAll()
	})
	dl.quarantineAll.Importance = widget.DangerImportance
	dl.quarantineAll.Hide()

	header := container.NewBorder(nil, nil, dl.titleLabel, dl.quarantineAll)

	dl.itemsBox.Add(container.NewCenter(dl.emptyLabel))

	dl.scroll = container.NewVScroll(dl.itemsBox)
	dl.scroll.SetMinSize(fyne.NewSize(0, 160))

	content := container.NewBorder(header, nil, nil, nil, dl.scroll)
	dl.root = newPanel(content, panelStyle{fill: colPanel, stroke: colBorderDim, strokeW: 1, radius: 8, inset: 10})

	return dl
}

func (dl *DetectedList) Object() fyne.CanvasObject {
	return dl.root
}

func (dl *DetectedList) SetOnCountChange(fn func(total, quarantined int)) {
	dl.mu.Lock()
	dl.onCountChange = fn
	dl.mu.Unlock()
}

func (dl *DetectedList) Clear() {
	dl.mu.Lock()
	dl.items = nil
	dl.mu.Unlock()

	dl.itemsBox.Objects = nil
	dl.itemsBox.Add(container.NewCenter(dl.emptyLabel))
	dl.emptyLabel.Show()
	dl.titleLabel.SetText("Detected Threats (0)")
	dl.quarantineAll.Hide()
	dl.itemsBox.Refresh()
	dl.scroll.Refresh()

	if dl.onCountChange != nil {
		dl.onCountChange(0, 0)
	}
}

func (dl *DetectedList) AddItem(item scanner.DetectedFile) {
	dl.mu.Lock()
	// Check for duplicates
	for i := range dl.items {
		if dl.items[i].Path == item.Path {
			dl.mu.Unlock()
			return
		}
	}
	index := len(dl.items)
	dl.items = append(dl.items, item)
	total := len(dl.items)
	dl.mu.Unlock()

	dl.emptyLabel.Hide()
	dl.titleLabel.SetText(fmt.Sprintf("Detected Threats (%d)", total))
	dl.quarantineAll.Show()

	row := dl.buildRow(item, index)
	dl.itemsBox.Add(row)
	dl.itemsBox.Refresh()
	dl.scroll.ScrollToBottom()

	if dl.onCountChange != nil {
		quarantined := dl.quarantinedCount()
		dl.onCountChange(total, quarantined)
	}
}

func (dl *DetectedList) quarantinedCount() int {
	dl.mu.RLock()
	defer dl.mu.RUnlock()
	count := 0
	for _, it := range dl.items {
		if it.Quarantined {
			count++
		}
	}
	return count
}

func (dl *DetectedList) buildRow(item scanner.DetectedFile, index int) fyne.CanvasObject {
	fileName := filepath.Base(item.Path)

	isZeroDay := strings.Contains(strings.ToUpper(item.DetectionSource), "ONNX") || strings.Contains(strings.ToUpper(item.ThreatName), "ZERO-DAY")
	nameColor := colDanger
	sourceBadgeText := "SHA-256 DB Feed"
	if isZeroDay {
		nameColor = colWarning
		sourceBadgeText = "LSTM Neural Engine"
	}

	nameText := canvas.NewText(fileName, nameColor)
	nameText.TextSize = 13
	nameText.TextStyle = fyne.TextStyle{Bold: true}

	detailText := canvas.NewText(fmt.Sprintf("%s  •  [%s]", item.ThreatName, sourceBadgeText), colText)
	detailText.TextSize = 11

	pathText := canvas.NewText(item.Path, colTextDim)
	pathText.TextSize = 10
	pathText.TextStyle = fyne.TextStyle{Monospace: true}

	infoBox := container.NewVBox(nameText, detailText, pathText)

	var qBtn *widget.Button
	statusBadge := canvas.NewText("[DETECTED]", colDanger)
	statusBadge.TextSize = 11
	statusBadge.TextStyle = fyne.TextStyle{Bold: true}

	qBtn = widget.NewButton("Quarantine", func() {
		qBtn.SetText("Quarantining...")
		qBtn.Disable()
		go func() {
			var err error
			if dl.onQuarantine != nil {
				err = dl.onQuarantine(item.Path, item.ThreatName)
			}
			fyne.Do(func() {
				if err != nil {
					qBtn.SetText("Retry Quarantine")
					qBtn.Enable()
					return
				}
				dl.mu.Lock()
				if index < len(dl.items) {
					dl.items[index].Quarantined = true
				}
				total := len(dl.items)
				dl.mu.Unlock()

				qBtn.SetText("✓ Quarantined")
				statusBadge.Text = "[QUARANTINED]"
				statusBadge.Color = colAccent
				statusBadge.Refresh()

				if dl.onCountChange != nil {
					dl.onCountChange(total, dl.quarantinedCount())
				}
			})
		}()
	})
	qBtn.Importance = widget.DangerImportance

	// Front button: [Quarantine Button] in front of name, followed by info and status
	leftControls := container.NewHBox(qBtn)
	rowLayout := container.NewBorder(nil, nil, leftControls, container.NewCenter(statusBadge), infoBox)
	return newPanel(rowLayout, panelStyle{fill: colCard, stroke: colBorderDim, strokeW: 1, radius: 8, inset: 10})
}

func (dl *DetectedList) QuarantineAll() {
	dl.mu.Lock()
	unquarantined := make([]scanner.DetectedFile, 0)
	for _, it := range dl.items {
		if !it.Quarantined {
			unquarantined = append(unquarantined, it)
		}
	}
	dl.mu.Unlock()

	for _, it := range unquarantined {
		if dl.onQuarantine != nil {
			_ = dl.onQuarantine(it.Path, it.ThreatName)
		}
	}
	dl.RefreshAll()
}

func (dl *DetectedList) RefreshAll() {
	dl.mu.Lock()
	for i := range dl.items {
		dl.items[i].Quarantined = true
	}
	itemsCopy := append([]scanner.DetectedFile(nil), dl.items...)
	total := len(itemsCopy)
	dl.mu.Unlock()

	dl.itemsBox.Objects = nil
	for i, it := range itemsCopy {
		dl.itemsBox.Add(dl.buildRow(it, i))
	}
	dl.itemsBox.Refresh()

	if dl.onCountChange != nil {
		dl.onCountChange(total, total)
	}
}
