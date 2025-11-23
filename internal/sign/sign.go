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

// SignHS256 подписывает одну строку payload.
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

// SignLinesHS256 подписывает каждую непустую строку из r и пишет JWT в w.
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

// ----- RS256 -----

func parseRSAPrivateKey(pemBytes []byte) (interface{}, error) {
	if len(pemBytes) == 0 {
		return nil, fmt.Errorf("empty RSA private key")
	}
	return Rsa.ReadPrivate(pemBytes)
}

func SignRS256(payload string, privPEM []byte) (string, error) {
	key, err := parseRSAPrivateKey(privPEM)
	if err != nil {
		return "", err
	}
	return jose.Sign(payload, jose.RS256, key)
}

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

// ----- ES256 -----

func parseECPrivateKey(pemBytes []byte) (interface{}, error) {
	if len(pemBytes) == 0 {
		return nil, fmt.Errorf("empty EC private key")
	}
	return ecc.ReadPrivate(pemBytes)
}

func SignES256(payload string, privPEM []byte) (string, error) {
	key, err := parseECPrivateKey(privPEM)
	if err != nil {
		return "", err
	}
	return jose.Sign(payload, jose.ES256, key)
}

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
