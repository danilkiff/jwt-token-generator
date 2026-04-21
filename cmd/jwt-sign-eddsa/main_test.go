package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeEdPrivateKeyPEM(t *testing.T, dir string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey Ed25519: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	data := pem.EncodeToMemory(block)
	path := filepath.Join(dir, "eddsa.key")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestRunJwtSignEdDSA_OK(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeEdPrivateKeyPEM(t, dir)

	var out, errBuf bytes.Buffer
	in := strings.NewReader("{\"x\":1}\n{\"y\":2}\n")
	code := run([]string{"--key-file", keyPath}, in, &out, &errBuf)
	if code != 0 {
		t.Fatalf("expected 0, got %d (stderr=%q)", code, errBuf.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(lines))
	}
}

func TestRunJwtSignEdDSA_NoKeyFile(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{}, &bytes.Buffer{}, &out, &errBuf)
	if code == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if !strings.Contains(errBuf.String(), "--key-file is required") {
		t.Fatalf("unexpected stderr: %q", errBuf.String())
	}
}
