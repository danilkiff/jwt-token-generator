package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRSAPrivateKeyPEM(t *testing.T, dir string) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	data := pem.EncodeToMemory(block)
	path := filepath.Join(dir, "rs256.key")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestRunJwtSignRS256_OK(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeRSAPrivateKeyPEM(t, dir)

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

func TestRunJwtSignRS256_NoKeyFile(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{}, &bytes.Buffer{}, &out, &errBuf)
	if code == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if !strings.Contains(errBuf.String(), "--key-file is required") {
		t.Fatalf("unexpected stderr: %q", errBuf.String())
	}
}

