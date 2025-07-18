# Encrypt API

A simple Go-based REST API for encrypting and decrypting text and files using XChaCha20-Poly1305.

## Installation

```bash
git clone https://github.com/Drax-dr/encrypt-api.git
cd encrypt-api
go mod tidy
go run main.go
```
## Encryption text
```bashcurl -X POST http://localhost:8080/encrypt-text \
  -H "Content-Type: application/json" \
  -d '{"text":"hello world", "password":"my-secret"}'
```
## Encryption text
```bash
curl -X POST http://localhost:8080/decrypt-text \
  -H "Content-Type: application/json" \
  -d '{"cipher":"...","nonce":"...","password":"my-secret"}'
```
## Notes
*Uses NaCl’s XChaCha20-Poly1305 with Base64 encoding.*
*File size capped at 50 MB.*
*Basic error handling included.*
