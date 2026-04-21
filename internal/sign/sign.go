// SPDX-License-Identifier: MIT

// Package sign provides helper functions for signing payloads as JWTs
// using HS256, RS256, ES256, and EdDSA.
package sign

import (
	"bufio"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	jose "github.com/dvsekhvalnov/jose2go"
	ecc "github.com/dvsekhvalnov/jose2go/keys/ecc"
	Rsa "github.com/dvsekhvalnov/jose2go/keys/rsa"
)

func init() {
	jose.RegisterJws(&edDSAAlgorithm{})
}

// edDSAAlgorithm implements jose.JwsAlgorithm for EdDSA (Ed25519).
type edDSAAlgorithm struct{}

func (a *edDSAAlgorithm) Name() string { return "EdDSA" }

func (a *edDSAAlgorithm) Sign(securedInput []byte, key interface{}) ([]byte, error) {
	privKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("EdDSA Sign: expected ed25519.PrivateKey, got %T", key)
	}
	return ed25519.Sign(privKey, securedInput), nil
}

func (a *edDSAAlgorithm) Verify(securedInput, signature []byte, key interface{}) error {
	pubKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("EdDSA Verify: expected ed25519.PublicKey, got %T", key)
	}
	if !ed25519.Verify(pubKey, securedInput, signature) {
		return fmt.Errorf("EdDSA signature verification failed")
	}
	return nil
}

// -----------------------------------------------------------------------------
// HS256
// -----------------------------------------------------------------------------

// SignHS256 signs a single payload string using HS256 and a shared secret key.
func SignHS256(payload string, secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", fmt.Errorf("secret must not be empty")
	}
	token, err := jose.Sign(payload, jose.HS256, secret)
	if err != nil {
		return "", err
	}
	return token, nil
}

// SignLinesHS256 reads non-empty lines from r, signs each line with HS256,
// and writes resulting JWTs to w.
func SignLinesHS256(r io.Reader, w io.Writer, secret []byte) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		tok, err := SignHS256(line, secret)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(w, tok+"\n"); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// -----------------------------------------------------------------------------
// RS256
// -----------------------------------------------------------------------------

// parseRSAPrivateKey parses an RSA private key from PEM-encoded bytes.
func parseRSAPrivateKey(pemBytes []byte) (interface{}, error) {
	if len(pemBytes) == 0 {
		return nil, fmt.Errorf("empty RSA private key")
	}
	return Rsa.ReadPrivate(pemBytes)
}

// SignRS256 signs a single payload string using RS256 and an RSA private
// key in PEM format.
func SignRS256(payload string, privPEM []byte) (string, error) {
	key, err := parseRSAPrivateKey(privPEM)
	if err != nil {
		return "", err
	}
	return jose.Sign(payload, jose.RS256, key)
}

// SignLinesRS256 reads non-empty lines from r, signs each line with RS256,
// and writes resulting JWTs to w.
func SignLinesRS256(r io.Reader, w io.Writer, privPEM []byte) error {
	key, err := parseRSAPrivateKey(privPEM)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		tok, err := jose.Sign(line, jose.RS256, key)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(w, tok+"\n"); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// -----------------------------------------------------------------------------
// ES256
// -----------------------------------------------------------------------------

// parseECPrivateKey parses an EC private key from PEM-encoded bytes.
func parseECPrivateKey(pemBytes []byte) (interface{}, error) {
	if len(pemBytes) == 0 {
		return nil, fmt.Errorf("empty EC private key")
	}
	return ecc.ReadPrivate(pemBytes)
}

// SignES256 signs a single payload string using ES256 and an EC private
// key in PEM format.
func SignES256(payload string, privPEM []byte) (string, error) {
	key, err := parseECPrivateKey(privPEM)
	if err != nil {
		return "", err
	}
	return jose.Sign(payload, jose.ES256, key)
}

// SignLinesES256 reads non-empty lines from r, signs each line with ES256,
// and writes resulting JWTs to w.
func SignLinesES256(r io.Reader, w io.Writer, privPEM []byte) error {
	key, err := parseECPrivateKey(privPEM)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		tok, err := jose.Sign(line, jose.ES256, key)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(w, tok+"\n"); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// -----------------------------------------------------------------------------
// EdDSA (Ed25519)
// -----------------------------------------------------------------------------

// parseEdPrivateKey parses an Ed25519 private key from PEM-encoded PKCS8 bytes.
func parseEdPrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	if len(pemBytes) == 0 {
		return nil, fmt.Errorf("empty Ed25519 private key")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519, got %T", key)
	}
	return edKey, nil
}

// SignEdDSA signs a single payload string using EdDSA and an Ed25519 private
// key in PEM format (PKCS8).
func SignEdDSA(payload string, privPEM []byte) (string, error) {
	key, err := parseEdPrivateKey(privPEM)
	if err != nil {
		return "", err
	}
	return jose.Sign(payload, "EdDSA", key)
}

// SignLinesEdDSA reads non-empty lines from r, signs each line with EdDSA,
// and writes resulting JWTs to w.
func SignLinesEdDSA(r io.Reader, w io.Writer, privPEM []byte) error {
	key, err := parseEdPrivateKey(privPEM)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		tok, err := jose.Sign(line, "EdDSA", key)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(w, tok+"\n"); err != nil {
			return err
		}
	}
	return scanner.Err()
}
