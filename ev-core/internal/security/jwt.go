package security

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims — набор данных, зашитых в access-токен.
// Специально НЕ кладём сюда конкретные permissions: права проверяются
// в момент запроса через Authorizer (БД/кэш), а не доверяются токену,
// чтобы отзыв роли действовал мгновенно, а не только после истечения токена.
type Claims struct {
	UserID   uuid.UUID `json:"uid"`
	TenantID uuid.UUID `json:"tid"`
	Email    string    `json:"email"`
	jwt.RegisteredClaims
}

// TokenManager инкапсулирует ключи RS256 и TTL токенов.
// RS256 (а не HS256) выбран осознанно: приватный ключ подписи и публичный
// ключ проверки разделены, что совпадает со схемой большинства OIDC-провайдеров
// (JWKS). Когда подключим внешний IdP, ядру нужно будет лишь добавить ещё
// один источник публичных ключей, а не переделывать схему токенов.
type TokenManager struct {
	privateKey     *rsa.PrivateKey
	publicKey      *rsa.PublicKey
	accessTokenTTL time.Duration
}

func NewTokenManager(privateKeyPath, publicKeyPath string, accessTTL time.Duration) (*TokenManager, error) {
	priv, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load private key: %w", err)
	}
	pub, err := loadPublicKey(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load public key: %w", err)
	}
	return &TokenManager{privateKey: priv, publicKey: pub, accessTokenTTL: accessTTL}, nil
}

func (tm *TokenManager) GenerateAccessToken(userID, tenantID uuid.UUID, email string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:   userID,
		TenantID: tenantID,
		Email:    email,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tm.accessTokenTTL)),
			Subject:   userID.String(),
			ID:        uuid.NewString(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(tm.privateKey)
}

// ValidateAccessToken проверяет подпись и срок действия токена.
// Явно ограничиваем допустимые алгоритмы (только RS256), чтобы исключить
// классическую атаку подмены алгоритма на "none" или на HS256 с публичным
// ключом в качестве секрета.
func (tm *TokenManager) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return tm.publicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Name}))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("token is not valid")
	}
	return claims, nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Поддержка ключей в формате PKCS1 (openssl genrsa по умолчанию его выдаёт).
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return rsaKey, nil
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaKey, nil
}
