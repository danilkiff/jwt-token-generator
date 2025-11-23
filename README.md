# JWT Token Generator (Unix-style CLI tools)

A collection of small, composable Go utilities for generating JWT/JWE tokens for
load testing and benchmarking. Each tool does one thing, works via stdin/stdout, 
and integrates cleanly with shell pipelines and `openssl`.

## Tools

### Claims generator

- `jwt-claims` — produces JSON/JSONL claims, deterministic with seed.

### JWT signers

- `jwt-sign-hs256` — sign payload lines with HS256.
- `jwt-sign-rs256` — sign payload lines with RS256 (RSA private key).
- `jwt-sign-es256` — sign payload lines with ES256 (EC private key).

### JWE encryption

- `jwe-encrypt-rsa-oaep-a256gcm` — RSA-OAEP + A256GCM compact JWE encryption.

## Usage

```bash
# 1000 HS256 JWT
jwt-claims -count=1000 -sub-len=16 -rnd-len=16 -iat-now |
  jwt-sign-hs256 --key-file secrets/hs256-secret.txt > output/hs256-tokens.txt

# 1000 RS256
jwt-claims -count=1000 |
  jwt-sign-rs256 --key-file secrets/rs256-private.pem > output/rs256-tokens.txt

# 1000 ES256
jwt-claims -count=1000 |
  jwt-sign-es256 --key-file secrets/es256-private.pem > output/es256-tokens.txt

# 1000 JWE
jwt-claims -count=1000 |
  jwe-encrypt-rsa-oaep-a256gcm --pub-key-file secrets/rsa-public.pem > output/jwe-tokens.txt
```

## License

MIT.