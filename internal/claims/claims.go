package claims

import (
	"encoding/json"
	"errors"
	"math/rand"
	"time"
)

// Claims – базовый набор клеймов.
type Claims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Rnd string `json:"rnd"`
}

// Config – параметры генерации.
type Config struct {
	Count        int   // сколько клеймов
	SubRandomLen int   // длина случайного sub
	RndRandomLen int   // длина случайного rnd
	UseNowIat    bool  // если true – iat = now, иначе FixedIat
	FixedIat     int64 // при UseNowIat=false
	Seed         int64 // seed для детерминированности (0 => now)
}

var (
	ErrInvalidCount = errors.New("count must be > 0")
	ErrInvalidLen   = errors.New("random length must be > 0")
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// randomStringDet возвращает псевдослучайную строку заданной длины.
func randomStringDet(r *rand.Rand, n int) string {
	b := make([]rune, n)
	for i := 0; i < n; i++ {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

// GenerateClaims создаёт срез Claims согласно конфигу.
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

// EncodeJSONLines кодирует срез клеймов в JSONL.
func EncodeJSONLines(cs []Claims) ([]byte, error) {
	if len(cs) == 0 {
		return []byte{}, nil
	}
	// без bytes.Buffer – чтобы было проще покрывать ошибки json.Marshal
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
