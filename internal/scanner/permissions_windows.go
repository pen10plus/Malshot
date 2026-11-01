//go:build windows

package scanner

import (
	"fmt"
	"os"
	"os/exec"
)

func restrictVaultPermissions(path string) error {
	if err := os.Chmod(path, 0700); err != nil {
		return err
	}
	if os.Getenv("MALSHOT_QUARANTINE_ROOT") != "" {
		return nil
	}
	// Remove inherited permissions, then grant the current user and SYSTEM
	// access. icacls is part of supported Windows installations.
	user := os.Getenv("USERNAME")
	if user == "" {
		return fmt.Errorf("USERNAME is unavailable")
	}
	cmd := exec.Command("icacls", path, "/inheritance:r", "/grant:r",
		user+":(OI)(CI)F", "SYSTEM:(OI)(CI)F", "/T", "/C")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("icacls: %w: %s", err, output)
	}
	return nil
}
