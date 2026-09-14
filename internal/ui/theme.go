package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

var accent = color.NRGBA{R: 92, G: 224, B: 183, A: 255}
var muted = color.NRGBA{R: 154, G: 171, B: 193, A: 255}
var panel = color.NRGBA{R: 23, G: 33, B: 49, A: 255}

type appTheme struct{ fyne.Theme }

func (t appTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 13, G: 21, B: 35, A: 255}
	case theme.ColorNameForeground:
		return color.NRGBA{R: 235, G: 242, B: 251, A: 255}
	case theme.ColorNamePrimary, theme.ColorNameSuccess:
		return accent
	case theme.ColorNameForegroundOnPrimary:
		return color.NRGBA{R: 10, G: 35, B: 31, A: 255}
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 14, G: 23, B: 38, A: 255}
	case theme.ColorNameInputBorder, theme.ColorNameSeparator:
		return color.NRGBA{R: 53, G: 68, B: 88, A: 255}
	case theme.ColorNameButton:
		return color.NRGBA{R: 37, G: 51, B: 70, A: 255}
	case theme.ColorNamePlaceHolder, theme.ColorNameDisabled:
		return muted
	case theme.ColorNameOverlayBackground:
		return panel
	}
	return t.Theme.Color(name, theme.VariantDark)
}

func (t appTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return 15
	case theme.SizeNamePadding:
		return 10
	case theme.SizeNameInputRadius, theme.SizeNameSelectionRadius:
		return 8
	}
	return t.Theme.Size(name)
}
