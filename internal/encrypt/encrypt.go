// SPDX-License-Identifier: MIT

// Package encrypt provides helper functions for encrypting payloads
// as compact JWE tokens.
package encrypt

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	jose "github.com/dvsekhvalnov/jose2go"
	Rsa "github.com/dvsekhvalnov/jose2go/keys/rsa"
)

// EncryptRSAOAEP_A256GCM encrypts a payload string into a compact JWE
// using RSA-OAEP and A256GCM.
func EncryptRSAOAEP_A256GCM(payload string, pubPEM []byte) (string, error) {
	if len(pubPEM) == 0 {
		return "", fmt.Errorf("public key must not be empty")
	}
	pub, err := Rsa.ReadPublic(pubPEM)
	if err != nil {
		return "", err
	}
	token, err := jose.Encrypt(payload, jose.RSA_OAEP, jose.A256GCM, pub)
	if err != nil {
		return "", err
	}
	return token, nil
}

// EncryptLinesRSAOAEP_A256GCM encrypts each non-empty line from r
// and writes resulting JWE tokens to w.
func EncryptLinesRSAOAEP_A256GCM(r io.Reader, w io.Writer, pubPEM []byte) error {
	if len(pubPEM) == 0 {
		return fmt.Errorf("public key must not be empty")
	}
	pub, err := Rsa.ReadPublic(pubPEM)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		token, err := jose.Encrypt(line, jose.RSA_OAEP, jose.A256GCM, pub)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(w, token+"\n"); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// IsCompactJWE returns true if the string looks like a compact JWE
// (5 dot-separated parts).
func IsCompactJWE(s string) bool {
	return len(strings.Split(s, ".")) == 5
}
