//go:build windows

package scanner

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const cryptProtectUIForbidden = 0x1

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32                = windows.NewLazySystemDLL("crypt32.dll")
	cryptProtectDataProc   = crypt32.NewProc("CryptProtectData")
	cryptUnprotectDataProc = crypt32.NewProc("CryptUnprotectData")
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	localFreeProc          = kernel32.NewProc("LocalFree")
)

func protectData(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("cannot protect empty data")
	}
	input := dataBlob{cbData: uint32(len(plaintext)), pbData: &plaintext[0]}
	var output dataBlob
	r1, _, callErr := cryptProtectDataProc.Call(
		uintptr(unsafe.Pointer(&input)),
		0, 0, 0, 0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&output)),
	)
	if r1 == 0 {
		return nil, fmt.Errorf("CryptProtectData: %w", callErr)
	}
	if output.pbData == nil || output.cbData == 0 {
		_ = freeDPAPIData(output.pbData)
		return nil, fmt.Errorf("CryptProtectData returned empty output")
	}
	protected := unsafe.Slice(output.pbData, output.cbData)
	result := append([]byte(nil), protected...)
	if err := freeDPAPIData(output.pbData); err != nil {
		return nil, err
	}
	return result, nil
}

func unprotectData(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("cannot unprotect empty data")
	}
	input := dataBlob{cbData: uint32(len(ciphertext)), pbData: &ciphertext[0]}
	var output dataBlob
	r1, _, callErr := cryptUnprotectDataProc.Call(
		uintptr(unsafe.Pointer(&input)),
		0, 0, 0, 0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&output)),
	)
	if r1 == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", callErr)
	}
	if output.pbData == nil || output.cbData == 0 {
		_ = freeDPAPIData(output.pbData)
		return nil, fmt.Errorf("CryptUnprotectData returned empty output")
	}
	plaintext := unsafe.Slice(output.pbData, output.cbData)
	result := append([]byte(nil), plaintext...)
	if err := freeDPAPIData(output.pbData); err != nil {
		zeroBytes(result)
		return nil, err
	}
	return result, nil
}

func freeDPAPIData(data *byte) error {
	if data == nil {
		return nil
	}
	result, _, err := localFreeProc.Call(uintptr(unsafe.Pointer(data)))
	if result != 0 {
		return fmt.Errorf("LocalFree DPAPI buffer: %w", err)
	}
	return nil
}
