package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/outgate-ai/og-local/internal/launch"
	"github.com/outgate-ai/og-local/internal/models"
	"github.com/outgate-ai/og-local/internal/provider"
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
  claude [args...]    Run the Claude agent through the local privacy proxy
  codex [args...]     Run the Codex agent through the local privacy proxy
  model pull [name]   Download a model into the cache (default: openai/privacy-filter)
  model list          List catalog models and their cache status
  model delete <name> Remove a cached model from disk
  version             Print build information
  help                Print this help

Environment:
  OGL_CACHE_DIR       Override the model cache directory (default: ~/.cache/og-local)
  OGL_DEBUG           Set to 1 to log proxy activity to a file (no PII values);
                      set to a path to choose the file. The path is printed at startup.
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
	case "claude":
		os.Exit(runAgent(provider.Anthropic, "claude", args[1:], nil))
	case "codex":
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ogl: %v\n", err)
			os.Exit(1)
		}
		os.Exit(runAgent(provider.OpenAIChat, "codex", args[1:], launch.CodexPrepare(home)))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

func runAgent(kind provider.Kind, command string, args []string, prepare func(loopbackURL, token string) (map[string]string, error)) int {
	argv := append([]string{command}, args...)
	app := launch.DefaultApp()
	app.PrepareChild = prepare
	code, err := app.Main(context.Background(), kind, argv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ogl: %v\n", err)
		return 1
	}
	return code
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
  ogl model pull [name]     Download a model into the cache
  ogl model list            List catalog models and their cache status
  ogl model delete <name>   Remove a cached model from disk
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
	case "delete":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: ogl model delete <name>")
			return 2
		}
		present, err := models.Delete(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "delete failed: %v\n", err)
			return 1
		}
		if present {
			fmt.Printf("removed %s\n", args[1])
		} else {
			fmt.Printf("%s was not cached\n", args[1])
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown model subcommand %q\n\n", args[0])
		printModelUsage(os.Stderr)
		return 2
	}
}
