package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunJwtClaimsOK(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"-count=2", "-sub-len=4", "-rnd-len=4", "-iat=1"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errBuf.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
}

func TestRunJwtClaimsInvalidConfig(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"-count=0"}, &out, &errBuf)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for invalid count")
	}
	if !strings.Contains(errBuf.String(), "generate claims") {
		t.Fatalf("expected error about generate claims, got %q", errBuf.String())
	}
}

