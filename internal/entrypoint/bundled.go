package entrypoint

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
)

//go:generate bash -c "set -euo pipefail; mkdir -p embed"
//go:generate bash -c "set -euo pipefail; env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags=skip_leash_entry_embeds -trimpath -ldflags='-s -w' -o embed/leash-entry-linux-amd64 ../../cmd/leash-entry"
//go:generate bash -c "set -euo pipefail; GOOS= GOARCH= go run ./cmd/compress embed/leash-entry-linux-amd64 entrypoint embeddedEntryLinuxAMD64 bundled_linux_amd64_gen.go"
//go:generate bash -c "set -euo pipefail; env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags=skip_leash_entry_embeds -trimpath -ldflags='-s -w' -o embed/leash-entry-linux-arm64 ../../cmd/leash-entry"
//go:generate bash -c "set -euo pipefail; GOOS= GOARCH= go run ./cmd/compress embed/leash-entry-linux-arm64 entrypoint embeddedEntryLinuxARM64 bundled_linux_arm64_gen.go"

const (
	ReadyFileName          = "leash-entry.ready"
	BootstrapReadyFileName = "bootstrap.ready"
)

var (
	embeddedEntryLinuxAMD64 []byte
	embeddedEntryLinuxARM64 []byte
)

// InflateBinaries expands the bundled leash-entry binaries into dir and writes a
// ready marker once complete. The operation is idempotent and safe to call
// concurrently.
func InflateBinaries(dir string) error {
	if dir == "" {
		return fmt.Errorf("directory required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create directory %q: %w", dir, err)
	}

	specs := []struct {
		name string
		data []byte
	}{
		{name: "leash-entry-linux-amd64", data: embeddedEntryLinuxAMD64},
		{name: "leash-entry-linux-arm64", data: embeddedEntryLinuxARM64},
	}

	// Only inflate the binary for the current architecture to reduce work and memory.
	switch runtime.GOARCH {
	case "amd64":
		specs = specs[:1]
	case "arm64":
		specs = specs[1:]
	}

	errCh := make(chan error, len(specs))
	var wg sync.WaitGroup
	for _, spec := range specs {
		spec := spec
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := extractBinary(dir, spec.name, spec.data); err != nil {
				errCh <- fmt.Errorf("extract %s: %w", spec.name, err)
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}

	marker := filepath.Join(dir, ReadyFileName)
	if err := os.WriteFile(marker, []byte("1"), 0o644); err != nil {
		return fmt.Errorf("failed to write ready marker: %w", err)
	}
	return nil
}

func extractBinary(dir, name string, blob []byte) error {
	if len(blob) == 0 {
		// Fallback: try to copy an existing leash-entry binary instead of using embedded data.
		if src, err := locateExternalLeashEntry(); err == nil && src != "" {
			target := filepath.Join(dir, name)
			return copyFile(src, target, 0o755)
		}
		return fmt.Errorf("embedded binary %s missing", name)
	}

	target := filepath.Join(dir, name)
	tmp, err := os.CreateTemp(dir, name+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	zr, err := zstd.NewReader(bytes.NewReader(blob))
	if err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("create zstd reader: %w", err)
	}
	defer zr.Close()

	if _, err := io.Copy(tmp, zr); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("decompress binary: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// locateExternalLeashEntry attempts to find a usable leash-entry binary on the system.
// Priority:
//  1. LEASH_ENTRY_BIN environment variable
//  2. /usr/local/bin/leash-entry
//  3. $PATH (via exec.LookPath)
func locateExternalLeashEntry() (string, error) {
	if p := strings.TrimSpace(os.Getenv("LEASH_ENTRY_BIN")); p != "" {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	if fi, err := os.Stat("/usr/local/bin/leash-entry"); err == nil && !fi.IsDir() {
		return "/usr/local/bin/leash-entry", nil
	}
	if p, err := exec.LookPath("leash-entry"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("leash-entry not found on system")
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if mode != 0 {
		if err := tmp.Chmod(mode); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}
