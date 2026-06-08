package main

import (
	"context"
	"fmt"
	"os"

	"github.com/outgate-ai/og-local/internal/models"
)

var (
	version = "0.0.0-dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		printVersion()
		return
	}
	switch args[0] {
	case "version", "--version", "-V":
		printVersion()
	case "model":
		os.Exit(runModel(args[1:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		os.Exit(2)
	}
}

func printVersion() {
	fmt.Printf("ogl %s (commit=%s, built=%s)\n", version, commit, date)
}

func runModel(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ogl model <pull|list> [name]")
		return 2
	}
	switch args[0] {
	case "list":
		for _, c := range models.List() {
			status := "not downloaded"
			if c.Present {
				status = "cached"
			}
			fmt.Printf("%-40s %s\n", c.Name, status)
		}
		return 0
	case "pull":
		name := ""
		if len(args) > 1 {
			name = args[1]
		}
		err := models.Pull(context.Background(), name, func(f models.File, done, total int64) {
			if total > 0 {
				fmt.Fprintf(os.Stderr, "\r%s %d/%d bytes", f.Path, done, total)
			}
		})
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pull failed: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown model subcommand %q\n", args[0])
		return 2
	}
}
