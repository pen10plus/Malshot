package ui

import (
	"fmt"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"malshot/internal/scanner"
)

// ---------------------------------------------------------------------------
// Panel: rounded, optionally outlined container.
// ---------------------------------------------------------------------------

type panelStyle struct {
	fill    color.Color
	stroke  color.Color // nil = no outline
	strokeW float32
	radius  float32
	inset   float32
}

func newPanel(content fyne.CanvasObject, s panelStyle) fyne.CanvasObject {
	bg := canvas.NewRectangle(s.fill)
	bg.CornerRadius = s.radius
	if s.stroke != nil {
		bg.StrokeColor = s.stroke
		bg.StrokeWidth = s.strokeW
	}
	padded := container.New(layout.NewCustomPaddedLayout(s.inset, s.inset, s.inset, s.inset), content)
	return container.NewStack(bg, padded)
}

// ---------------------------------------------------------------------------
// Badge ("SECURE").
// ---------------------------------------------------------------------------

func newBadge(text string) fyne.CanvasObject {
	icon := canvas.NewImageFromResource(shieldIcon)
	icon.FillMode = canvas.ImageFillContain
	icon.SetMinSize(fyne.NewSize(16, 16))

	label := canvas.NewText(text, colAccent)
	label.TextSize = 13
	label.TextStyle = fyne.TextStyle{Bold: true}

	return newPanel(
		container.NewHBox(container.NewCenter(icon), label),
		panelStyle{fill: colAccentDim, stroke: colAccent, strokeW: 1, radius: 8, inset: 6},
	)
}

// ---------------------------------------------------------------------------
// StatCard: title + large centered number.
// ---------------------------------------------------------------------------

type StatCard struct {
	root     fyne.CanvasObject
	value    *canvas.Text
	subtitle *canvas.Text
}

func NewStatCard(title string) *StatCard {
	return NewColoredStatCard(title, colText, "")
}

func NewColoredStatCard(title string, valColor color.Color, subtitle string) *StatCard {
	t := canvas.NewText(title, colTextDim)
	t.TextSize = 12
	t.Alignment = fyne.TextAlignCenter

	v := canvas.NewText("0", valColor)
	v.TextSize = 28
	v.TextStyle = fyne.TextStyle{Bold: true}
	v.Alignment = fyne.TextAlignCenter

	box := container.NewVBox(t, v)
	var subText *canvas.Text
	if subtitle != "" {
		subText = canvas.NewText(subtitle, colTextDim)
		subText.TextSize = 10
		subText.Alignment = fyne.TextAlignCenter
		box.Add(subText)
	}

	return &StatCard{
		root:     newPanel(box, panelStyle{fill: colCard, stroke: colBorderDim, strokeW: 1, radius: 10, inset: 12}),
		value:    v,
		subtitle: subText,
	}
}

func (c *StatCard) Object() fyne.CanvasObject { return c.root }

func (c *StatCard) SetValue(n int) {
	c.value.Text = formatInt(n)
	c.value.Refresh()
}

// ---------------------------------------------------------------------------
// StatusRing: circular protection indicator.
// ---------------------------------------------------------------------------

type RingState int

const (
	RingProtected RingState = iota
	RingScanning
	RingThreat
)

const ringSize = 170

type StatusRing struct {
	root       fyne.CanvasObject
	circle     *canvas.Circle
	title, sub *canvas.Text
	labels     *fyne.Container
}

func NewStatusRing() *StatusRing {
	circle := canvas.NewCircle(color.Transparent)
	circle.StrokeWidth = 6
	circle.StrokeColor = colAccent

	title := canvas.NewText("PROTECTED", colAccent)
	title.TextSize = 20
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	sub := canvas.NewText("0 Threats Found", colText)
	sub.TextSize = 13
	sub.Alignment = fyne.TextAlignCenter

	labels := container.NewVBox(title, sub)
	stack := container.NewStack(circle, container.NewCenter(labels))

	return &StatusRing{
		root:   container.NewCenter(container.NewGridWrap(fyne.NewSize(ringSize, ringSize), stack)),
		circle: circle, title: title, sub: sub, labels: labels,
	}
}

func (r *StatusRing) Object() fyne.CanvasObject { return r.root }

func (r *StatusRing) Set(state RingState, threats int) {
	label, c := "PROTECTED", color.Color(colAccent)
	switch state {
	case RingScanning:
		label, c = "SCANNING", colProgress
	case RingThreat:
		label, c = "AT RISK", colDanger
	}
	r.title.Text, r.title.Color = label, c
	r.circle.StrokeColor = c
	if threats == 1 {
		r.sub.Text = "1 Threat Found"
	} else {
		r.sub.Text = fmt.Sprintf("%d Threats Found", threats)
	}
	r.title.Refresh()
	r.sub.Refresh()
	r.circle.Refresh()
	r.labels.Refresh()
}

// ---------------------------------------------------------------------------
// LogView: capped, auto-scrolling monospace log.
// ---------------------------------------------------------------------------

const maxLogLines = 200

type LogView struct {
	lines  *fyne.Container
	scroll *container.Scroll
}

func NewLogView() *LogView {
	lines := container.NewVBox()
	scroll := container.NewVScroll(lines)
	scroll.SetMinSize(fyne.NewSize(0, 96))
	return &LogView{lines: lines, scroll: scroll}
}

func (l *LogView) Object() fyne.CanvasObject { return l.scroll }

// Append adds a line. Call from the UI goroutine.
func (l *LogView) Append(msg string) {
	t := canvas.NewText(msg, colLogText)
	t.TextSize = 12
	t.TextStyle = fyne.TextStyle{Monospace: true}
	l.lines.Add(t)
	if len(l.lines.Objects) > maxLogLines {
		l.lines.Remove(l.lines.Objects[0])
	}
	l.scroll.ScrollToBottom()
}

// ---------------------------------------------------------------------------
// StatusBar: footer with colour-coded engine state.
// ---------------------------------------------------------------------------

type StatusBar struct{ text *widget.RichText }

func NewStatusBar() *StatusBar { return &StatusBar{text: widget.NewRichText()} }

func (s *StatusBar) Object() fyne.CanvasObject { return s.text }

func (s *StatusBar) Update(h scanner.Health) {
	seg := func(text string, c fyne.ThemeColorName) widget.RichTextSegment {
		return &widget.TextSegment{Text: text, Style: widget.RichTextStyle{ColorName: c, Inline: true}}
	}
	pick := func(ok bool, yes, no string) (string, fyne.ThemeColorName) {
		if ok {
			return yes, theme.ColorNameSuccess
		}
		return no, theme.ColorNameWarning
	}

	sig, sigC := pick(h.SignaturesUpdated, "Updated", "Outdated")
	state, stateC := pick(h.EngineActive, "Active", "Stopped")
	dim := theme.ColorNamePlaceHolder

	s.text.Segments = []widget.RichTextSegment{
		seg("signatures.db: ", dim), seg(sig, sigC),
		seg("  |  Local State: ", dim), seg(state, stateC),
		seg("  |  Cores: ", dim), seg(fmt.Sprintf("%d/%d", h.ActiveCores, h.TotalCores), theme.ColorNameSuccess),
	}
	s.text.Refresh()
}
