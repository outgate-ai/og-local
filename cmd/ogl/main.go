package main

import (
	"fmt"
	"os"
)

var (
	version = "0.0.0-dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-V":
			fmt.Printf("ogl %s (commit=%s, built=%s)\n", version, commit, date)
			return
		}
	}
	fmt.Printf("ogl %s (commit=%s, built=%s)\n", version, commit, date)
	fmt.Fprintln(os.Stderr, "this is the milestone-0 skeleton; subcommands arrive in later milestones")
	os.Exit(0)
}
