// SPDX-License-Identifier: MIT

// Command jwt-sign-hs256 signs input lines with HS256 using a shared secret.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/danilkiff/jwt-token-generator/internal/sign"
)

// run parses CLI flags, resolves the HS256 secret from a value or file,
// and signs each non-empty input line with HS256. It returns a process
// exit code.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("jwt-sign-hs256", flag.ContinueOnError)
	fs.SetOutput(stderr)

	secretFile := fs.String("key-file", "", "Path to HS256 secret (text)")
	secretStr := fs.String("key", "", "HS256 secret value")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, "parse flags:", err)
		return 2
	}

	var secret []byte
	if *secretFile != "" {
		data, err := os.ReadFile(*secretFile)
		if err != nil {
			fmt.Fprintln(stderr, "read key file:", err)
			return 1
		}
		secret = data
	} else if *secretStr != "" {
		secret = []byte(*secretStr)
	} else {
		fmt.Fprintln(stderr, "either --key or --key-file must be set")
		return 2
	}

	if err := sign.SignLinesHS256(stdin, stdout, secret); err != nil {
		fmt.Fprintln(stderr, "sign:", err)
		return 1
	}
	return 0
}

// main is the entry point that delegates to run and exits with its status code.
func main() {
	code := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	os.Exit(code)
}
