package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

func rgb(r, g, b uint8) color.NRGBA { return color.NRGBA{R: r, G: g, B: b, A: 0xFF} }

// Design tokens, sampled from the sleek dark zinc endpoint defender design system.
var (
	colBackground = rgb(0x09, 0x09, 0x0B) // zinc-950
	colNavBar     = rgb(0x14, 0x14, 0x17) // zinc-900/850 sidebar
	colPanel      = rgb(0x18, 0x18, 0x1B) // zinc-900 panel
	colCard       = rgb(0x27, 0x27, 0x2A) // zinc-800 card
	colCardHover  = rgb(0x3F, 0x3F, 0x46) // zinc-700
	colLogBg      = rgb(0x09, 0x09, 0x0B) // console background
	colTrack      = rgb(0x18, 0x18, 0x1B) // progress track
	colBorder     = rgb(0x3F, 0x3F, 0x46) // zinc-700 border
	colBorderDim  = rgb(0x27, 0x27, 0x2A) // zinc-800 subtle border
	colProgress   = rgb(0x06, 0xB6, 0xD4) // cyan-500
	colAccent     = rgb(0x10, 0xB9, 0x81) // emerald-500
	colAccentDim  = rgb(0x06, 0x4E, 0x3B) // emerald-950
	colText       = rgb(0xF4, 0xF4, 0xF5) // zinc-100
	colTextDim    = rgb(0x71, 0x71, 0x7A) // zinc-500
	colLogText    = rgb(0xD4, 0xD4, 0xD8) // zinc-300
	colDanger     = rgb(0xF4, 0x3F, 0x5E) // rose-500 threat
	colWarning    = rgb(0xF5, 0x9E, 0x0B) // amber-500 zero-day
	colHover      = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0x0E}
)

type malShotTheme struct{ fyne.Theme }

// NewTheme returns the MalShot dark theme. Fonts and icons fall through to
// the default theme.
func NewTheme() fyne.Theme { return &malShotTheme{Theme: theme.DefaultTheme()} }

func (t *malShotTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground, theme.ColorNameMenuBackground, theme.ColorNameOverlayBackground:
		return colBackground
	case theme.ColorNameForeground:
		return colText
	case theme.ColorNameForegroundOnPrimary:
		return colBackground
	case theme.ColorNamePrimary, theme.ColorNameSuccess:
		return colAccent
	case theme.ColorNameButton, theme.ColorNameInputBackground:
		return colCard
	case theme.ColorNameDisabled, theme.ColorNamePlaceHolder:
		return colTextDim
	case theme.ColorNameHover:
		return colHover
	case theme.ColorNameError:
		return colDanger
	case theme.ColorNameWarning:
		return colWarning
	case theme.ColorNameSeparator, theme.ColorNameInputBorder:
		return colBorderDim
	case theme.ColorNameShadow:
		return color.Transparent
	}
	return t.Theme.Color(name, theme.VariantDark)
}

func (t *malShotTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameInputRadius:
		return 8
	case theme.SizeNameSelectionRadius:
		return 6
	}
	return t.Theme.Size(name)
}
