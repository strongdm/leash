package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/strongdm/leash/internal/darwind"
	"github.com/strongdm/leash/internal/leashd"
	"github.com/strongdm/leash/internal/runner"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	args := os.Args
	if len(args) > 1 {
		switch args[1] {
		case "--version":
			printVersion()
			return
		case "--daemon": // "Secret" flag to run leashd.
			daemonArgs := append([]string{args[0]}, args[2:]...)
			if err := leashd.Main(daemonArgs); err != nil {
				log.Fatal(err)
			}
			return
		case "--darwin": // macOS path.
			if err := darwind.Main(args[2:]); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return
				}
				log.Fatal(err)
			}
			return
		default: // Docker-Leash CLI frontend.
			runner.SetVersion(version)
			if err := runner.Main(args); err != nil {
				var exitErr *runner.ExitCodeError
				if errors.As(err, &exitErr) {
					os.Exit(exitErr.ExitCode())
				}
				log.Fatal(err)
			}
		}
	}
}

func printVersion() {
	shortHash := commit
	if len(shortHash) > 7 {
		shortHash = shortHash[:7]
	}
	fmt.Printf("version: %s\n", version)
	fmt.Printf("git hash: %s\n", shortHash)
	fmt.Printf("build date: %s\n", buildDate)
}
