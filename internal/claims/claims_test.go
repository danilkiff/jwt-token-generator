package claims

import (
	"strings"
	"testing"
)

func TestGenerateClaimsDeterministic(t *testing.T) {
	cfg := Config{
		Count:        3,
		SubRandomLen: 8,
		RndRandomLen: 8,
		UseNowIat:    false,
		FixedIat:     1234567890,
		Seed:         42,
	}

	cs1, err := GenerateClaims(cfg)
	if err != nil {
		t.Fatalf("GenerateClaims error: %v", err)
	}
	cs2, err := GenerateClaims(cfg)
	if err != nil {
		t.Fatalf("GenerateClaims error: %v", err)
	}

	if len(cs1) != 3 || len(cs2) != 3 {
		t.Fatalf("expected 3 claims, got %d and %d", len(cs1), len(cs2))
	}
	for i := range cs1 {
		if cs1[i] != cs2[i] {
			t.Fatalf("claims must be equal for same seed: %#v vs %#v", cs1[i], cs2[i])
		}
		if len(cs1[i].Sub) != cfg.SubRandomLen {
			t.Fatalf("unexpected Sub len: %d", len(cs1[i].Sub))
		}
		if len(cs1[i].Rnd) != cfg.RndRandomLen {
			t.Fatalf("unexpected Rnd len: %d", len(cs1[i].Rnd))
		}
		if cs1[i].Iat != cfg.FixedIat {
			t.Fatalf("unexpected Iat: %d", cs1[i].Iat)
		}
	}
}

func TestGenerateClaimsErrors(t *testing.T) {
	_, err := GenerateClaims(Config{Count: 0, SubRandomLen: 8, RndRandomLen: 8})
	if err != ErrInvalidCount {
		t.Fatalf("expected ErrInvalidCount, got %v", err)
	}

	_, err = GenerateClaims(Config{Count: 1, SubRandomLen: 0, RndRandomLen: 8})
	if err != ErrInvalidLen {
		t.Fatalf("expected ErrInvalidLen, got %v", err)
	}
}

func TestEncodeJSONLines(t *testing.T) {
	cfg := Config{
		Count:        2,
		SubRandomLen: 4,
		RndRandomLen: 4,
		UseNowIat:    false,
		FixedIat:     1,
		Seed:         1,
	}
	cs, err := GenerateClaims(cfg)
	if err != nil {
		t.Fatalf("GenerateClaims error: %v", err)
	}

	data, err := EncodeJSONLines(cs)
	if err != nil {
		t.Fatalf("EncodeJSONLines error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
}
