package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/danilkiff/jwt-token-generator/internal/sign"
)

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

func main() {
	code := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	os.Exit(code)
}

