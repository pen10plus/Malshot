//go:build !windows

package scanner

import "os"

func restrictVaultPermissions(path string) error {
	return os.Chmod(path, 0700)
}
