//go:build !linux

package lsm

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// Stub loader functions for non-Linux environments to satisfy tooling.
// On Linux builds, bpf2go-generated functions will be used instead.

func loadLsmOpen() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("bpf2go generated loader not available on non-linux")
}

func loadLsmExec() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("bpf2go generated loader not available on non-linux")
}

func loadLsmConnect() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("bpf2go generated loader not available on non-linux")
}
