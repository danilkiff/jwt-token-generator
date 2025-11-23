package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/danilkiff/jwt-token-generator/internal/claims"
)

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("jwt-claims", flag.ContinueOnError)
	fs.SetOutput(stderr)

	count := fs.Int("count", 1, "Number of claims to generate")
	subLen := fs.Int("sub-len", 16, "Length of random 'sub'")
	rndLen := fs.Int("rnd-len", 16, "Length of random 'rnd'")
	fixedIat := fs.Int64("iat", 0, "Fixed iat value (epoch seconds)")
	useNow := fs.Bool("iat-now", false, "Use current time for iat")
	seed := fs.Int64("seed", 0, "Random seed (0 => time-based)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, "parse flags:", err)
		return 2
	}

	cfg := claims.Config{
		Count:        *count,
		SubRandomLen: *subLen,
		RndRandomLen: *rndLen,
		UseNowIat:    *useNow,
		FixedIat:     *fixedIat,
		Seed:         *seed,
	}

	cs, err := claims.GenerateClaims(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "generate claims:", err)
		return 1
	}
	data, err := claims.EncodeJSONLines(cs)
	if err != nil {
		fmt.Fprintln(stderr, "encode:", err)
		return 1
	}
	if _, err := stdout.Write(data); err != nil {
		fmt.Fprintln(stderr, "write:", err)
		return 1
	}
	return 0
}

func main() {
	code := run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(code)
}

