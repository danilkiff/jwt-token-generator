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

func writeRSAPublicKeyPEM(t *testing.T, dir string) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	data := pem.EncodeToMemory(block)
	path := filepath.Join(dir, "rsa.pub")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestRunJweEncrypt_OK(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeRSAPublicKeyPEM(t, dir)

	var out, errBuf bytes.Buffer
	in := strings.NewReader("{\"x\":1}\n{\"y\":2}\n")
	code := run([]string{"--pub-key-file", pubPath}, in, &out, &errBuf)
	if code != 0 {
		t.Fatalf("expected 0, got %d (stderr=%q)", code, errBuf.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JWE tokens, got %d", len(lines))
	}
}

func TestRunJweEncrypt_NoKeyFile(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{}, &bytes.Buffer{}, &out, &errBuf)
	if code == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if !strings.Contains(errBuf.String(), "--pub-key-file is required") {
		t.Fatalf("unexpected stderr: %q", errBuf.String())
	}
}

