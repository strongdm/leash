//go:build !darwin

package darwind

import "fmt"

func Main(args []string) error {
	return fmt.Errorf("darwin runtime is only available on macOS builds")
}
