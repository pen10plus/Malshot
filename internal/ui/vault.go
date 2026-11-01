package ui

import (
	"fmt"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"malshot/internal/scanner"
)

type vaultView struct {
	svc       scanner.Service
	list      *widget.List
	mu        sync.RWMutex
	incidents []scanner.QuarantineIncident
	err       error
	selected  int
	root      fyne.CanvasObject
}

func newVaultView(svc scanner.Service) *vaultView {
	title := widget.NewLabelWithStyle("Quarantine Vault", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	view := &vaultView{svc: svc}
	list := widget.NewList(
		func() int {
			view.mu.RLock()
			defer view.mu.RUnlock()
			return len(view.incidents)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			label := obj.(*widget.Label)
			view.mu.RLock()
			defer view.mu.RUnlock()
			if view.err != nil {
				label.SetText("Unable to load quarantine records: " + view.err.Error())
				return
			}
			if id >= len(view.incidents) {
				return
			}
			incident := view.incidents[id]
			label.SetText(fmt.Sprintf("%s | %s | %s",
				incident.OriginalPath,
				incident.DetectionSource,
				time.Unix(incident.Timestamp, 0).Format(time.RFC3339)))
		},
	)
	view.list = list
	view.selected = -1
	list.OnSelected = func(id widget.ListItemID) {
		view.mu.Lock()
		view.selected = id
		view.mu.Unlock()
	}
	refresh := widget.NewButton("Refresh", view.refresh)
	restore := widget.NewButton("Restore Selected File", func() { view.restoreSelected() })
	restore.Importance = widget.HighImportance
	view.refresh()
	headerBox := container.NewBorder(nil, nil, title, container.NewHBox(refresh, restore))
	view.root = newPanel(container.NewBorder(container.NewVBox(headerBox, widget.NewSeparator()), nil, nil, nil, list), panelStyle{fill: colPanel, stroke: colBorderDim, strokeW: 1, radius: 8, inset: 12})
	return view
}

func (v *vaultView) Object() fyne.CanvasObject {
	return v.root
}

func (v *vaultView) restoreSelected() {
	v.mu.RLock()
	index := v.selected
	if index < 0 || index >= len(v.incidents) {
		v.mu.RUnlock()
		return
	}
	incident := v.incidents[index]
	v.mu.RUnlock()
	v.list.UnselectAll()
	vault, ok := v.svc.(scanner.VaultService)
	if !ok {
		return
	}
	go func() {
		err := vault.RestoreFile(incident.IncidentID, incident.OriginalPath)
		fyne.Do(func() {
			if err != nil {
				v.err = err
			}
			v.refresh()
		})
	}()
}

func (v *vaultView) refresh() {
	vault, ok := v.svc.(scanner.VaultService)
	if !ok {
		v.mu.Lock()
		v.incidents = nil
		v.err = fmt.Errorf("vault unavailable")
		v.mu.Unlock()
		v.list.Refresh()
		return
	}
	go func() {
		incidents, err := vault.QuarantineIncidents()
		fyne.Do(func() {
			v.mu.Lock()
			v.incidents = incidents
			v.err = err
			v.mu.Unlock()
			v.list.Refresh()
		})
	}()
}
