package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/outgate-ai/og-local/internal/models"
)

var (
	version = "0.0.0-dev"
	commit  = "unknown"
	date    = "unknown"
)

const usage = `ogl - a local privacy proxy for coding agents

Usage:
  ogl <command> [arguments]

Commands:
  model pull [name]   Download a model into the cache (default: openai/privacy-filter)
  model list          List catalog models and their cache status
  version             Print build information
  help                Print this help

Environment:
  OGL_CACHE_DIR       Override the model cache directory (default: ~/.cache/og-local)
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		printUsage(os.Stdout)
		return
	}
	switch args[0] {
	case "version", "--version", "-V":
		printVersion()
	case "help", "--help", "-h":
		printUsage(os.Stdout)
	case "model":
		os.Exit(runModel(args[1:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

func printUsage(w io.Writer) {
	_, _ = io.WriteString(w, usage)
}

func printModelUsage(w io.Writer) {
	_, _ = io.WriteString(w, modelUsage)
}

func printVersion() {
	fmt.Printf("ogl %s (commit=%s, built=%s)\n", version, commit, date)
}

const modelUsage = `Usage:
  ogl model pull [name]   Download a model into the cache
  ogl model list          List catalog models and their cache status
`

func runModel(args []string) int {
	if len(args) == 0 {
		printModelUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "help", "--help", "-h":
		printModelUsage(os.Stdout)
		return 0
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
			} else {
				fmt.Fprintf(os.Stderr, "\r%s %d bytes", f.Path, done)
			}
		})
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pull failed: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown model subcommand %q\n\n", args[0])
		printModelUsage(os.Stderr)
		return 2
	}
}
