// SPDX-License-Identifier: MIT

// Package sign provides helper functions for signing payloads as JWTs
// using HS256, RS256, and ES256.
package sign

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	jose "github.com/dvsekhvalnov/jose2go"
	ecc "github.com/dvsekhvalnov/jose2go/keys/ecc"
	Rsa "github.com/dvsekhvalnov/jose2go/keys/rsa"
)

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
