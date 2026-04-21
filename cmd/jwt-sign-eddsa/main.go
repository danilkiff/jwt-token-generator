// SPDX-License-Identifier: MIT

// Command jwt-sign-eddsa signs input lines with EdDSA using
// an Ed25519 private key (PEM, PKCS8).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/danilkiff/jwt-token-generator/internal/sign"
)

// run parses CLI flags, loads the Ed25519 private key, and signs each input line
// with EdDSA. It returns a process exit code (0 on success, non-zero on error).
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("jwt-sign-eddsa", flag.ContinueOnError)
	fs.SetOutput(stderr)

	keyFile := fs.String("key-file", "", "Path to Ed25519 private key (PEM, PKCS8)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, "parse flags:", err)
		return 2
	}
	if *keyFile == "" {
		fmt.Fprintln(stderr, "--key-file is required")
		return 2
	}

	key, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintln(stderr, "read key file:", err)
		return 1
	}

	if err := sign.SignLinesEdDSA(stdin, stdout, key); err != nil {
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
