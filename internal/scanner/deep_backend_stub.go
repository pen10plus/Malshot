//go:build !deepinspection

package scanner

import "errors"

type deepBackend struct{}

func newDeepBackend(_, _, _ string) (*deepBackend, error) {
	return nil, errors.New("deep inspection is unavailable in this build; rebuild with -tags deepinspection")
}

func (b *deepBackend) close() error { return nil }
func (b *deepBackend) scan(path string) (bool, float32, error) {
	return false, 0, errors.New("deep inspection is unavailable in this build")
}
