package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Параметры Argon2id по рекомендациям OWASP Password Storage Cheat Sheet
// (m=19 MiB, t=2, p=1 — минимальный безопасный профиль для интерактивного логина).
// При необходимости можно поднять memory/time за счёт нагрузки на CPU/RAM.
const (
	argonMemoryKiB  = 19 * 1024
	argonIterations = 2
	argonThreads    = 1
	argonKeyLen     = 32
	argonSaltLen    = 16
)

var ErrInvalidHashFormat = errors.New("invalid password hash format")
var ErrPasswordMismatch = errors.New("password does not match")

// HashPassword хэширует пароль и возвращает строку вида
// $argon2id$v=19$m=19456,t=2,p=1$<salt-base64>$<hash-base64>
// Пароль в открытом виде нигде дальше не сохраняется и не логируется.
func HashPassword(password string) (string, error) {
	if len(password) == 0 {
		return "", errors.New("password must not be empty")
	}

	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemoryKiB, argonThreads, argonKeyLen)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemoryKiB, argonIterations, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	return encoded, nil
}

// VerifyPassword сверяет пароль с сохранённым хэшем за константное время
// (subtle.ConstantTimeCompare), чтобы не давать канал утечки через тайминг-атаку.
func VerifyPassword(password, encodedHash string) error {
	parts := strings.Split(encodedHash, "$")
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return ErrInvalidHashFormat
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return ErrInvalidHashFormat
	}

	var memory uint32
	var iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return ErrInvalidHashFormat
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return ErrInvalidHashFormat
	}
	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return ErrInvalidHashFormat
	}

	computedHash := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(expectedHash)))

	if subtle.ConstantTimeCompare(computedHash, expectedHash) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}
