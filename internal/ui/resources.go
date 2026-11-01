package ui

import "fyne.io/fyne/v2"

// Inline SVGs keep the binary self-contained (offline-first).
var (
	logoIcon = fyne.NewStaticResource("logo.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none" stroke="#2AA7F5" stroke-width="2" stroke-linecap="round"><circle cx="16" cy="16" r="9"/><circle cx="16" cy="16" r="2" fill="#2AA7F5"/><path d="M16 2v7M16 23v7M2 16h7M23 16h7"/></svg>`))

	shieldIcon = fyne.NewStaticResource("shield.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#22E07A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg>`))
)
