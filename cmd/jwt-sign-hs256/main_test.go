package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunJwtSignHS256_OK(t *testing.T) {
	var out, errBuf bytes.Buffer
	in := strings.NewReader("{\"a\":1}\n{\"b\":2}\n")
	code := run([]string{"--key=secret"}, in, &out, &errBuf)
	if code != 0 {
		t.Fatalf("expected 0, got %d (stderr=%q)", code, errBuf.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(lines))
	}
}

func TestRunJwtSignHS256_NoKey(t *testing.T) {
	var out, errBuf bytes.Buffer
	in := strings.NewReader("{}\n")
	code := run([]string{}, in, &out, &errBuf)
	if code == 0 {
		t.Fatalf("expected non-zero exit without key")
	}
	if !strings.Contains(errBuf.String(), "either --key or --key-file") {
		t.Fatalf("unexpected stderr: %q", errBuf.String())
	}
}

