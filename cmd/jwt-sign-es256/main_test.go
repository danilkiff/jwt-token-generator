package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeECPrivateKeyPEM(t *testing.T, dir string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey EC: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	data := pem.EncodeToMemory(block)
	path := filepath.Join(dir, "es256.key")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestRunJwtSignES256_OK(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeECPrivateKeyPEM(t, dir)

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

func TestRunJwtSignES256_NoKeyFile(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{}, &bytes.Buffer{}, &out, &errBuf)
	if code == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if !strings.Contains(errBuf.String(), "--key-file is required") {
		t.Fatalf("unexpected stderr: %q", errBuf.String())
	}
}
