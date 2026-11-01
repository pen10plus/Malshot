//go:build !windows

package scanner

import "errors"

func protectData([]byte) ([]byte, error) {
	return nil, errors.New("Windows DPAPI is only available on Windows")
}

func unprotectData([]byte) ([]byte, error) {
	return nil, errors.New("Windows DPAPI is only available on Windows")
}
