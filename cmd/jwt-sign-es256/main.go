package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/danilkiff/jwt-token-generator/internal/sign"
)

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("jwt-sign-es256", flag.ContinueOnError)
	fs.SetOutput(stderr)

	keyFile := fs.String("key-file", "", "Path to EC private key (PEM, P-256)")

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

	if err := sign.SignLinesES256(stdin, stdout, key); err != nil {
		fmt.Fprintln(stderr, "sign:", err)
		return 1
	}
	return 0
}

func main() {
	code := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	os.Exit(code)
}
