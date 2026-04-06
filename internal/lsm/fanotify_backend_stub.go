//go:build !linux

package lsm

import "fmt"

type fanotifyBackend struct{}

func newFanotifyBackend(_ string, _ *SharedLogger) (*fanotifyBackend, error) {
	return nil, fmt.Errorf("fanotify backend is only supported on linux")
}

func (b *fanotifyBackend) UpdatePolicies(_ *PolicySet) error { return nil }

func (b *fanotifyBackend) Run() error { return nil }
