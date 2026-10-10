package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const gateCallUsage = `Usage:
  ogl gate-call [--socket PATH] [REQUEST]

Sends one JSON request line to the gate (REQUEST, or stdin) and prints the response
line. For tests and debugging on the device: og-gate gate-call '{"op":"health"}'.
`

func runGateCall(args []string) int {
	fs := flag.NewFlagSet("gate-call", flag.ContinueOnError)
	fs.Usage = func() { _, _ = os.Stderr.WriteString(gateCallUsage) }
	socket := fs.String("socket", "/dev/socket/og_gate", "gate socket")
	timeout := fs.Duration("timeout", 60*time.Second, "give up after this long")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var line string
	if fs.NArg() > 0 {
		line = strings.Join(fs.Args(), " ")
	} else {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gate-call: %v\n", err)
			return 1
		}
		line = string(b)
	}
	line = strings.TrimSpace(line)
	c, err := net.DialTimeout("unix", *socket, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate-call: %v\n", err)
		return 1
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(*timeout))
	if _, err := io.WriteString(c, line+"\n"); err != nil {
		fmt.Fprintf(os.Stderr, "gate-call: %v\n", err)
		return 1
	}
	out, err := bufio.NewReaderSize(c, 1<<20).ReadString('\n')
	if err != nil && out == "" {
		fmt.Fprintf(os.Stderr, "gate-call: %v\n", err)
		return 1
	}
	fmt.Print(out)
	return 0
}
