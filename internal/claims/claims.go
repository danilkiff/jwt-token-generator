// SPDX-License-Identifier: MIT

// Package claims provides utilities for generating deterministic
// JWT-like claim sets.
package claims

import (
	"encoding/json"
	"errors"
	"math/rand"
	"time"
)

// Claims is a basic set of claims.
type Claims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Rnd string `json:"rnd"`
}

// Config defines parameters for claims generation.
type Config struct {
	Count        int   // number of claims to generate
	SubRandomLen int   // random length for sub
	RndRandomLen int   // random length for rnd
	UseNowIat    bool  // if true, iat = current time, otherwise FixedIat is used
	FixedIat     int64 // iat value when UseNowIat=false
	Seed         int64 // seed for deterministic generation (0 => use current time)
}

var (
	ErrInvalidCount = errors.New("count must be > 0")
	ErrInvalidLen   = errors.New("random length must be > 0")
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// randomStringDet returns a pseudo-random string of the given length
// using the provided RNG.
func randomStringDet(r *rand.Rand, n int) string {
	b := make([]rune, n)
	for i := 0; i < n; i++ {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

// GenerateClaims creates a slice of Claims according to the provided config.
func GenerateClaims(cfg Config) ([]Claims, error) {
	if cfg.Count <= 0 {
		return nil, ErrInvalidCount
	}
	if cfg.SubRandomLen <= 0 || cfg.RndRandomLen <= 0 {
		return nil, ErrInvalidLen
	}

	seed := cfg.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	r := rand.New(rand.NewSource(seed))

	claims := make([]Claims, cfg.Count)
	var iat int64
	if cfg.UseNowIat {
		iat = time.Now().Unix()
	} else {
		iat = cfg.FixedIat
	}

	for i := 0; i < cfg.Count; i++ {
		claims[i] = Claims{
			Sub: randomStringDet(r, cfg.SubRandomLen),
			Iat: iat,
			Rnd: randomStringDet(r, cfg.RndRandomLen),
		}
	}
	return claims, nil
}

// EncodeJSONLines encodes a slice of claims as JSON Lines (JSONL).
func EncodeJSONLines(cs []Claims) ([]byte, error) {
	if len(cs) == 0 {
		return []byte{}, nil
	}
	// Avoid bytes.Buffer to keep error handling around json.Marshal simple.
	var out []byte
	for _, c := range cs {
		b, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
		out = append(out, '\n')
	}
	return out, nil
}
