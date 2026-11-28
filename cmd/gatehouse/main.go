// Command gatehouse runs the edge proxy and validates its configuration.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/zekihan/gatehouse/internal/config"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 {
		switch args[0] {
		case "version", "--version":
			fmt.Fprintln(stdout, version)
			return 0
		case "schema":
			if _, err := stdout.Write(config.Schema()); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			return 0
		}
	}
	if len(args) > 0 && args[0] == "serve" {
		if err := serveFile(args[1:], stdout, stderr); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	if len(args) != 2 || args[0] != "validate" {
		fmt.Fprintln(
			stderr,
			"usage: gatehouse serve --config <file> --snapshot <file> | validate <file> | schema | version",
		)
		return 2
	}

	data, err := os.ReadFile(args[1])
	if err == nil {
		_, err = config.Parse(data)
	}
	if err != nil {
		fmt.Fprintf(stderr, "gatehouse validate %q: %v\n", args[1], err)
		return 1
	}
	return 0
}
