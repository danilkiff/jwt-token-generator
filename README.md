## Project structure

```text
cmd/
  jwt-claims/
    main.go        # генерация клеймов
  jwt-sign-hs256/
    main.go        # подпись HS256
  jwt-sign-rs256/
    main.go        # подпись RS256
  jwt-sign-es256/
    main.go        # подпись ES256
  jwe-encrypt-rsa-oaep-a256gcm/
    main.go        # JWE
internal/
  claims/          # общая логика генерации клеймов
  sign/            # общее для подписи
  encrypt/         # общее для JWE
```

## Usage

```bash
# 1000 HS256 JWT
jwt-claims -count=1000 -sub-len=16 -rnd-len=16 -iat-now |
  jwt-sign-hs256 --key-file secrets/hs256-secret.txt \
  > output/hs256-tokens.txt

# 1000 RS256
jwt-claims -count=1000 |
  jwt-sign-rs256 --key-file secrets/rs256-private.pem \
  > output/rs256-tokens.txt

# 1000 ES256
jwt-claims -count=1000 |
  jwt-sign-es256 --key-file secrets/es256-private.pem \
  > output/es256-tokens.txt

# 1000 JWE
jwt-claims -count=1000 |
  jwe-encrypt-rsa-oaep-a256gcm --pub-key-file secrets/rsa-public.pem \
  > output/jwe-tokens.txt
```
