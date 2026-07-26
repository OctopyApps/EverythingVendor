package authsvc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"platform-core/internal/security"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrEmailTaken         = errors.New("email already registered")
	ErrInvalidEmail       = errors.New("invalid email format")
	ErrWeakPassword       = errors.New("password must be at least 12 characters")
	ErrUserInactive       = errors.New("user account is inactive")
	ErrTokenInvalid       = errors.New("refresh token is invalid or expired")
)

const minPasswordLength = 12

type Service struct {
	pool   *pgxpool.Pool
	tokens *security.TokenManager

	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewService(pool *pgxpool.Pool, tokens *security.TokenManager, accessTTL, refreshTTL time.Duration) *Service {
	return &Service{pool: pool, tokens: tokens, accessTTL: accessTTL, refreshTTL: refreshTTL}
}

type AuthResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64 // секунды
}

// Register создаёт нового пользователя в дефолтном тенанте и назначает
// ему системную роль "member" (без прав по умолчанию — их выдаёт admin).
// Пароль в открытом виде не сохраняется и не логируется нигде далее по стеку.
func (s *Service) Register(ctx context.Context, tenantID uuid.UUID, email, password string) (uuid.UUID, error) {
	if _, err := mail.ParseAddress(email); err != nil {
		return uuid.Nil, ErrInvalidEmail
	}
	if len(password) < minPasswordLength {
		return uuid.Nil, ErrWeakPassword
	}

	hash, err := security.HashPassword(password)
	if err != nil {
		return uuid.Nil, fmt.Errorf("hash password: %w", err)
	}

	var userID uuid.UUID
	err = s.pool.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id
	`, tenantID, email, hash).Scan(&userID)
	if err != nil {
		if isUniqueViolation(err) {
			return uuid.Nil, ErrEmailTaken
		}
		return uuid.Nil, fmt.Errorf("insert user: %w", err)
	}

	// Назначаем базовую системную роль "member" по умолчанию.
	_, err = s.pool.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id)
		SELECT $1, r.id FROM roles r WHERE r.tenant_id = $2 AND r.name = 'member'
	`, userID, tenantID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("assign default role: %w", err)
	}

	return userID, nil
}

// Login проверяет учётные данные и выдаёт пару access/refresh токенов.
// Намеренно не различаем в тексте ошибки "нет такого email" и "неверный
// пароль" — иначе даём атакующему возможность перебором узнавать
// существующие email-адреса (user enumeration).
func (s *Service) Login(ctx context.Context, tenantID uuid.UUID, email, password string) (*AuthResult, error) {
	var userID uuid.UUID
	var passwordHash string
	var isActive bool

	err := s.pool.QueryRow(ctx, `
		SELECT id, password_hash, is_active FROM users
		WHERE tenant_id = $1 AND email = $2
	`, tenantID, email).Scan(&userID, &passwordHash, &isActive)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Всё равно тратим время на верификацию несуществующего хэша,
			// чтобы не давать тайминг-канал для user enumeration.
			_ = security.VerifyPassword(password, dummyHash)
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("query user: %w", err)
	}

	if !isActive {
		return nil, ErrUserInactive
	}

	if err := security.VerifyPassword(password, passwordHash); err != nil {
		return nil, ErrInvalidCredentials
	}

	return s.issueTokens(ctx, userID, tenantID, email)
}

// dummyHash - валидный по формату, но заведомо непроходимый хэш,
// используется только для выравнивания времени ответа при user enumeration.
const dummyHash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWY"

func (s *Service) issueTokens(ctx context.Context, userID, tenantID uuid.UUID, email string) (*AuthResult, error) {
	accessToken, err := s.tokens.GenerateAccessToken(userID, tenantID, email)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	refreshToken, refreshHash, err := generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, userID, refreshHash, time.Now().Add(s.refreshTTL))
	if err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	return &AuthResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

// Refresh проверяет refresh-токен по хэшу в БД (не отозван, не истёк)
// и выдаёт новую пару токенов, отзывая старый refresh-токен (token rotation) —
// это ограничивает окно использования украденного токена.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (*AuthResult, error) {
	hash := hashRefreshToken(refreshToken)

	var userID, tenantID uuid.UUID
	var email string
	var expiresAt time.Time
	var revokedAt *time.Time

	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.tenant_id, u.email, rt.expires_at, rt.revoked_at
		FROM refresh_tokens rt
		JOIN users u ON u.id = rt.user_id
		WHERE rt.token_hash = $1
	`, hash).Scan(&userID, &tenantID, &email, &expiresAt, &revokedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTokenInvalid
		}
		return nil, fmt.Errorf("query refresh token: %w", err)
	}

	if revokedAt != nil || time.Now().After(expiresAt) {
		return nil, ErrTokenInvalid
	}

	// Отзываем использованный refresh-токен (rotation).
	if _, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1`, hash); err != nil {
		return nil, fmt.Errorf("revoke old refresh token: %w", err)
	}

	return s.issueTokens(ctx, userID, tenantID, email)
}

// Logout отзывает конкретный refresh-токен (логаут с одного устройства).
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	hash := hashRefreshToken(refreshToken)
	_, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`, hash)
	return err
}

func generateRefreshToken() (token string, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, hashRefreshToken(token), nil
}

// hashRefreshToken хэширует refresh-токен через SHA-256 перед сохранением в БД.
// В отличие от паролей, здесь не нужен медленный argon2id: refresh-токен
// уже обладает высокой энтропией (32 случайных байта), угроза — не подбор,
// а чтение БД, от которого достаточно быстрого криптографического хэша.
func hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
