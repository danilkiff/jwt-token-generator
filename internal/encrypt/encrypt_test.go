package encrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	jose "github.com/dvsekhvalnov/jose2go"
)

func genRSAPublicPEM(t *testing.T) ([]byte, *rsa.PrivateKey) {
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
	return pem.EncodeToMemory(block), priv
}

func TestEncryptRSAOAEP_A256GCMAndDecrypt(t *testing.T) {
	pubPEM, priv := genRSAPublicPEM(t)

	token, err := EncryptRSAOAEP_A256GCM(`{"x":42}`, pubPEM)
	if err != nil {
		t.Fatalf("EncryptRSAOAEP_A256GCM error: %v", err)
	}
	if !IsCompactJWE(token) {
		t.Fatalf("expected compact JWE, got %q", token)
	}

	payload, hdr, err := jose.Decode(token, priv)
	if err != nil {
		t.Fatalf("jose.Decode: %v", err)
	}
	if hdr["alg"] != "RSA-OAEP" {
		t.Fatalf("expected alg=RSA-OAEP, got %v", hdr["alg"])
	}
	if hdr["enc"] != "A256GCM" {
		t.Fatalf("expected enc=A256GCM, got %v", hdr["enc"])
	}
	if !strings.Contains(payload, `"x":42`) {
		t.Fatalf("unexpected payload: %q", payload)
	}
}

func TestEncryptLinesRSAOAEP_A256GCM(t *testing.T) {
	pubPEM, priv := genRSAPublicPEM(t)

	input := "line1\n\nline2\n"
	var buf bytes.Buffer
	if err := EncryptLinesRSAOAEP_A256GCM(strings.NewReader(input), &buf, pubPEM); err != nil {
		t.Fatalf("EncryptLines... error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JWE tokens, got %d", len(lines))
	}
	for _, tok := range lines {
		if !IsCompactJWE(tok) {
			t.Fatalf("not a compact JWE: %q", tok)
		}
		// ensure that at least one token can be successfully decrypted
		_, _, err := jose.Decode(tok, priv)
		if err != nil {
			t.Fatalf("jose.Decode: %v", err)
		}
	}
}

func TestEncryptRSAOAEP_A256GCMErrors(t *testing.T) {
	_, err := EncryptRSAOAEP_A256GCM("p", nil)
	if err == nil {
		t.Fatalf("expected error for empty key")
	}
	_, err = EncryptRSAOAEP_A256GCM("p", []byte("not a key"))
	if err == nil {
		t.Fatalf("expected error for bad key")
	}
}

func TestEncryptLinesRSAOAEP_A256GCMErrors(t *testing.T) {
	err := EncryptLinesRSAOAEP_A256GCM(strings.NewReader("p"), &bytes.Buffer{}, nil)
	if err == nil {
		t.Fatalf("expected error for empty key")
	}
	err = EncryptLinesRSAOAEP_A256GCM(strings.NewReader("p"), &bytes.Buffer{}, []byte("nope"))
	if err == nil {
		t.Fatalf("expected error for bad key")
	}
}

func TestIsCompactJWE(t *testing.T) {
	if !IsCompactJWE("a.b.c.d.e") {
		t.Fatalf("expected true for 5 parts")
	}
	if IsCompactJWE("a.b.c") {
		t.Fatalf("expected false for 3 parts")
	}
}
