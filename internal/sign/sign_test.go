package sign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	jose "github.com/dvsekhvalnov/jose2go"
)

func TestSignHS256AndLines(t *testing.T) {
	secret := []byte("secret")
	token, err := SignHS256(`{"a":1}`, secret)
	if err != nil {
		t.Fatalf("SignHS256 error: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	input := "line1\n\nline2\n"
	var buf bytes.Buffer
	if err := SignLinesHS256(strings.NewReader(input), &buf, secret); err != nil {
		t.Fatalf("SignLinesHS256 error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(lines))
	}
}

func TestSignHS256EmptySecret(t *testing.T) {
	_, err := SignHS256("payload", nil)
	if err == nil {
		t.Fatalf("expected error for empty secret")
	}
}

// --- RSA helpers ---

func genRSAPrivatePEM(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return pem.EncodeToMemory(block)
}

func TestSignRS256AndLines(t *testing.T) {
	privPEM := genRSAPrivatePEM(t)

	token, err := SignRS256(`{"b":2}`, privPEM)
	if err != nil {
		t.Fatalf("SignRS256 error: %v", err)
	}
	if len(strings.Split(token, ".")) != 3 {
		t.Fatalf("expected 3-part JWT")
	}

	var buf bytes.Buffer
	input := "p1\np2\n"
	if err := SignLinesRS256(strings.NewReader(input), &buf, privPEM); err != nil {
		t.Fatalf("SignLinesRS256 error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(lines))
	}

	// проверяем, что jose.Decode умеет декодировать наш токен тем же ключом
	block, _ := pem.Decode(privPEM)
	if block == nil {
		t.Fatalf("pem.Decode returned nil block")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS1PrivateKey: %v", err)
	}
	_, hdr, err := jose.Decode(token, &priv.PublicKey)
	if err != nil {
		t.Fatalf("jose.Decode: %v", err)
	}
	if hdr["alg"] != "RS256" {
		t.Fatalf("expected alg=RS256, got %v", hdr["alg"])
	}
}

func TestSignRS256BadKey(t *testing.T) {
	_, err := SignRS256("p", []byte("not a key"))
	if err == nil {
		t.Fatalf("expected error for bad PEM")
	}
}

func TestSignLinesRS256BadKey(t *testing.T) {
	err := SignLinesRS256(strings.NewReader("p"), &bytes.Buffer{}, []byte{})
	if err == nil {
		t.Fatalf("expected error for empty key")
	}
}

// --- ES256 helpers ---

func genECPrivatePEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey EC: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	return pem.EncodeToMemory(block)
}

func TestSignES256AndLines(t *testing.T) {
	privPEM := genECPrivatePEM(t)

	token, err := SignES256(`{"c":3}`, privPEM)
	if err != nil {
		t.Fatalf("SignES256 error: %v", err)
	}
	if len(strings.Split(token, ".")) != 3 {
		t.Fatalf("expected 3-part JWT")
	}

	var buf bytes.Buffer
	if err := SignLinesES256(strings.NewReader("a\nb\n"), &buf, privPEM); err != nil {
		t.Fatalf("SignLinesES256 error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(lines))
	}
}

func TestSignES256BadKey(t *testing.T) {
	_, err := SignES256("p", []byte("nope"))
	if err == nil {
		t.Fatalf("expected error for bad EC key")
	}
}

func TestSignLinesES256BadKey(t *testing.T) {
	err := SignLinesES256(strings.NewReader("p"), &bytes.Buffer{}, []byte{})
	if err == nil {
		t.Fatalf("expected error for empty EC key")
	}
}

