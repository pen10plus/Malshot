package ui

import (
	"fmt"
	"image/color"
	"math"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
)

// CircularProgress is a custom circular sweep progress indicator with centered telemetry.
type CircularProgress struct {
	root     fyne.CanvasObject
	raster   *canvas.Raster
	percent  *canvas.Text
	status   *canvas.Text
	subtext  *canvas.Text
	labels   *fyne.Container

	mu       sync.Mutex
	progress float64
	state    string
	threats  int
	color    color.NRGBA
}

const circularSize = 180

func NewCircularProgress() *CircularProgress {
	cp := &CircularProgress{
		progress: 0.0,
		state:    "IDLE",
		threats:  0,
		color:    colAccent,
	}

	raster := canvas.NewRasterWithPixels(cp.renderPixels)
	raster.SetMinSize(fyne.NewSize(circularSize, circularSize))
	cp.raster = raster

	percent := canvas.NewText("0%", colText)
	percent.TextSize = 28
	percent.TextStyle = fyne.TextStyle{Bold: true}
	percent.Alignment = fyne.TextAlignCenter
	cp.percent = percent

	status := canvas.NewText("READY", colAccent)
	status.TextSize = 13
	status.TextStyle = fyne.TextStyle{Bold: true}
	status.Alignment = fyne.TextAlignCenter
	cp.status = status

	subtext := canvas.NewText("0 Files Scanned", colTextDim)
	subtext.TextSize = 11
	subtext.Alignment = fyne.TextAlignCenter
	cp.subtext = subtext

	labels := container.NewVBox(status, percent, subtext)
	cp.labels = labels

	stack := container.NewStack(raster, container.NewCenter(labels))
	cp.root = container.NewCenter(container.NewGridWrap(fyne.NewSize(circularSize, circularSize), stack))

	return cp
}

func (cp *CircularProgress) Object() fyne.CanvasObject {
	return cp.root
}

func (cp *CircularProgress) renderPixels(x, y, w, h int) color.Color {
	cp.mu.Lock()
	prog := cp.progress
	fillColor := cp.color
	cp.mu.Unlock()

	cx := float64(w) / 2.0
	cy := float64(h) / 2.0
	dx := float64(x) - cx
	dy := float64(y) - cy
	r := math.Hypot(dx, dy)

	ro := math.Min(cx, cy) - 6.0
	thickness := 8.0
	ri := ro - thickness

	// Antialiased edge boundaries
	if r < ri-1.0 || r > ro+1.0 {
		return color.Transparent
	}

	// Calculate angle clockwise starting from 12 o'clock (-pi/2)
	theta := math.Atan2(dy, dx) + math.Pi/2.0
	if theta < 0 {
		theta += 2.0 * math.Pi
	}

	trackColor := color.NRGBA{R: 0x1E, G: 0x27, B: 0x36, A: 0xFF}

	// Determine if pixel belongs to progress arc or track
	var pixelColor color.NRGBA
	if prog > 0 && theta <= prog*2.0*math.Pi {
		pixelColor = fillColor
	} else {
		pixelColor = trackColor
	}

	// Anti-aliasing alpha blending near inner/outer edges
	alpha := 1.0
	if r < ri {
		alpha = math.Max(0.0, 1.0-(ri-r))
	} else if r > ro {
		alpha = math.Max(0.0, 1.0-(r-ro))
	}

	if alpha < 1.0 {
		pixelColor.A = uint8(float64(pixelColor.A) * alpha)
	}

	return pixelColor
}

func (cp *CircularProgress) SetProgress(v float64, scanned, total int) {
	cp.mu.Lock()
	cp.progress = math.Max(0.0, math.Min(1.0, v))
	if total > 0 {
		cp.subtext.Text = fmt.Sprintf("%s / %s Files", formatInt(scanned), formatInt(total))
	} else if scanned > 0 {
		cp.subtext.Text = fmt.Sprintf("%s Files Scanned", formatInt(scanned))
	} else {
		cp.subtext.Text = "0 Files Scanned"
	}
	pct := int(cp.progress * 100)
	cp.percent.Text = fmt.Sprintf("%d%%", pct)
	cp.mu.Unlock()

	cp.percent.Refresh()
	cp.subtext.Refresh()
	cp.raster.Refresh()
}

func (cp *CircularProgress) SetState(state string, threats int) {
	cp.mu.Lock()
	cp.state = state
	cp.threats = threats

	c := colAccent
	switch state {
	case "SCANNING":
		c = colProgress
		if threats > 0 {
			c = colDanger
		}
	case "PAUSED":
		c = colWarning
	case "THREAT", "AT RISK":
		c = colDanger
	case "PROTECTED", "FINISHED", "READY":
		if threats > 0 {
			c = colDanger
		} else {
			c = colAccent
		}
	}
	cp.color = c
	cp.status.Text = state
	cp.status.Color = c
	cp.mu.Unlock()

	cp.status.Refresh()
	cp.raster.Refresh()
}
