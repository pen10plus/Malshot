package ui

import (
	"math"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

// ---------------------------------------------------------------------------
// ActionButton: large, outlined button (Quick Scan / Deep Scan).
// ---------------------------------------------------------------------------

type ActionButton struct {
	widget.BaseWidget
	label    string
	onTap    func()
	hovered  bool
	disabled bool
}

var (
	_ fyne.Tappable      = (*ActionButton)(nil)
	_ desktop.Hoverable  = (*ActionButton)(nil)
	_ desktop.Cursorable = (*ActionButton)(nil)
)

func NewActionButton(label string, onTap func()) *ActionButton {
	b := &ActionButton{label: label, onTap: onTap}
	b.ExtendBaseWidget(b)
	return b
}

func (b *ActionButton) SetDisabled(disabled bool) {
	b.disabled = disabled
	b.hovered = false
	b.Refresh()
}

func (b *ActionButton) Tapped(*fyne.PointEvent) {
	if !b.disabled && b.onTap != nil {
		b.onTap()
	}
}

func (b *ActionButton) MouseIn(*desktop.MouseEvent)    { b.hovered = true; b.Refresh() }
func (b *ActionButton) MouseMoved(*desktop.MouseEvent) {}
func (b *ActionButton) MouseOut()                      { b.hovered = false; b.Refresh() }

func (b *ActionButton) Cursor() desktop.Cursor {
	if b.disabled {
		return desktop.DefaultCursor
	}
	return desktop.PointerCursor
}

func (b *ActionButton) CreateRenderer() fyne.WidgetRenderer {
	bg := canvas.NewRectangle(colCard)
	bg.CornerRadius = 10
	bg.StrokeWidth = 2
	text := canvas.NewText(b.label, colText)
	text.TextSize = 20
	r := &actionButtonRenderer{b: b, bg: bg, text: text}
	r.applyState()
	return r
}

type actionButtonRenderer struct {
	b    *ActionButton
	bg   *canvas.Rectangle
	text *canvas.Text
}

func (r *actionButtonRenderer) applyState() {
	switch {
	case r.b.disabled:
		r.bg.FillColor, r.bg.StrokeColor, r.text.Color = colPanel, colBorderDim, colTextDim
	case r.b.hovered:
		r.bg.FillColor, r.bg.StrokeColor, r.text.Color = colCardHover, colBorder, colText
	default:
		r.bg.FillColor, r.bg.StrokeColor, r.text.Color = colCard, colBorder, colText
	}
}

func (r *actionButtonRenderer) Layout(size fyne.Size) {
	r.bg.Resize(size)
	ts := r.text.MinSize()
	r.text.Resize(ts)
	r.text.Move(fyne.NewPos((size.Width-ts.Width)/2, (size.Height-ts.Height)/2))
}

func (r *actionButtonRenderer) MinSize() fyne.Size {
	ts := r.text.MinSize()
	return fyne.NewSize(ts.Width+48, ts.Height+28)
}

func (r *actionButtonRenderer) Refresh() {
	r.text.Text = r.b.label
	r.applyState()
	r.bg.Refresh()
	r.text.Refresh()
}

func (r *actionButtonRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.bg, r.text}
}
func (r *actionButtonRenderer) Destroy() {}

// ---------------------------------------------------------------------------
// ThinProgress: slim, text-free progress bar.
// ---------------------------------------------------------------------------

type ThinProgress struct {
	widget.BaseWidget
	value float64
}

func NewThinProgress() *ThinProgress {
	p := &ThinProgress{}
	p.ExtendBaseWidget(p)
	return p
}

// SetValue clamps v to [0, 1]. Call from the UI goroutine.
func (p *ThinProgress) SetValue(v float64) {
	p.value = math.Max(0, math.Min(1, v))
	p.Refresh()
}

func (p *ThinProgress) CreateRenderer() fyne.WidgetRenderer {
	track := canvas.NewRectangle(colTrack)
	track.CornerRadius = 4
	fill := canvas.NewRectangle(colProgress)
	fill.CornerRadius = 4
	return &thinProgressRenderer{p: p, track: track, fill: fill}
}

type thinProgressRenderer struct {
	p           *ThinProgress
	track, fill *canvas.Rectangle
}

func (r *thinProgressRenderer) Layout(size fyne.Size) {
	r.track.Resize(size)
	r.fill.Resize(fyne.NewSize(size.Width*float32(r.p.value), size.Height))
}
func (r *thinProgressRenderer) MinSize() fyne.Size { return fyne.NewSize(100, 8) }
func (r *thinProgressRenderer) Refresh() {
	r.Layout(r.p.Size())
	r.track.Refresh()
	r.fill.Refresh()
}
func (r *thinProgressRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.track, r.fill}
}
func (r *thinProgressRenderer) Destroy() {}
