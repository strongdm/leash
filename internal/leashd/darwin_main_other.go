//go:build !darwin

package leashd

import "fmt"

func MainDarwin(args []string) error {
	return fmt.Errorf("darwin subcommand is only supported on macOS builds")
}
