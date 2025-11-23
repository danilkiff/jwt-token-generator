package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/danilkiff/jwt-token-generator/internal/encrypt"
)

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("jwe-encrypt-rsa-oaep-a256gcm", flag.ContinueOnError)
	fs.SetOutput(stderr)

	pubFile := fs.String("pub-key-file", "", "Path to RSA public key (PEM)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, "parse flags:", err)
		return 2
	}
	if *pubFile == "" {
		fmt.Fprintln(stderr, "--pub-key-file is required")
		return 2
	}

	pub, err := os.ReadFile(*pubFile)
	if err != nil {
		fmt.Fprintln(stderr, "read key file:", err)
		return 1
	}

	if err := encrypt.EncryptLinesRSAOAEP_A256GCM(stdin, stdout, pub); err != nil {
		fmt.Fprintln(stderr, "encrypt:", err)
		return 1
	}
	return 0
}

func main() {
	code := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	os.Exit(code)
}
