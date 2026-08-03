package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config хранит всю конфигурацию сервиса, загруженную из переменных окружения.
// Никаких секретов не хардкодим и не логируем целиком.
type Config struct {
	Port string

	DatabaseURL string

	RedisAddr     string
	RedisPassword string

	JWTPrivateKeyPath string
	JWTPublicKeyPath  string

	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	RBACCacheTTL time.Duration

	// Rate limiting (см. internal/ratelimit). Fail mode настраивается отдельно
	// от лимитов, т.к. это осознанный компромисс доступность/безопасность,
	// который может понадобиться менять независимо (см. docs/security.md).
	RateLimitFailMode string // "open" | "closed"

	LoginRateLimitPerIP         int
	LoginRateLimitIPWindow      time.Duration
	LoginRateLimitPerAccount    int
	LoginRateLimitAccountWindow time.Duration

	RegisterRateLimitPerIP    int
	RegisterRateLimitIPWindow time.Duration
}

// Load читает конфигурацию из os.Environ(). Возвращает ошибку, если
// обязательные переменные отсутствуют — сервис не должен стартовать
// с неявными дефолтами для security-критичных параметров.
func Load() (*Config, error) {
	cfg := &Config{
		Port:              getEnvDefault("PORT", "8080"),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		RedisAddr:         getEnvDefault("REDIS_ADDR", "localhost:6379"),
		RedisPassword:     os.Getenv("REDIS_PASSWORD"),
		JWTPrivateKeyPath: os.Getenv("JWT_PRIVATE_KEY_PATH"),
		JWTPublicKeyPath:  os.Getenv("JWT_PUBLIC_KEY_PATH"),
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.JWTPrivateKeyPath == "" || cfg.JWTPublicKeyPath == "" {
		return nil, fmt.Errorf("JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH are required")
	}

	accessMinutes, err := getEnvInt("ACCESS_TOKEN_TTL_MINUTES", 15)
	if err != nil {
		return nil, err
	}
	cfg.AccessTokenTTL = time.Duration(accessMinutes) * time.Minute

	refreshHours, err := getEnvInt("REFRESH_TOKEN_TTL_HOURS", 720)
	if err != nil {
		return nil, err
	}
	cfg.RefreshTokenTTL = time.Duration(refreshHours) * time.Hour

	cacheSeconds, err := getEnvInt("RBAC_CACHE_TTL_SECONDS", 60)
	if err != nil {
		return nil, err
	}
	cfg.RBACCacheTTL = time.Duration(cacheSeconds) * time.Second

	cfg.RateLimitFailMode = getEnvDefault("RATE_LIMIT_FAIL_MODE", "open")
	if cfg.RateLimitFailMode != "open" && cfg.RateLimitFailMode != "closed" {
		return nil, fmt.Errorf("RATE_LIMIT_FAIL_MODE must be 'open' or 'closed', got %q", cfg.RateLimitFailMode)
	}

	loginRatePerIP, err := getEnvInt("LOGIN_RATE_LIMIT_PER_IP", 10)
	if err != nil {
		return nil, err
	}
	cfg.LoginRateLimitPerIP = loginRatePerIP

	loginRateIPWindowMinutes, err := getEnvInt("LOGIN_RATE_LIMIT_IP_WINDOW_MINUTES", 5)
	if err != nil {
		return nil, err
	}
	cfg.LoginRateLimitIPWindow = time.Duration(loginRateIPWindowMinutes) * time.Minute

	loginRatePerAccount, err := getEnvInt("LOGIN_RATE_LIMIT_PER_ACCOUNT", 5)
	if err != nil {
		return nil, err
	}
	cfg.LoginRateLimitPerAccount = loginRatePerAccount

	loginRateAccountWindowMinutes, err := getEnvInt("LOGIN_RATE_LIMIT_ACCOUNT_WINDOW_MINUTES", 15)
	if err != nil {
		return nil, err
	}
	cfg.LoginRateLimitAccountWindow = time.Duration(loginRateAccountWindowMinutes) * time.Minute

	registerRatePerIP, err := getEnvInt("REGISTER_RATE_LIMIT_PER_IP", 20)
	if err != nil {
		return nil, err
	}
	cfg.RegisterRateLimitPerIP = registerRatePerIP

	registerRateIPWindowMinutes, err := getEnvInt("REGISTER_RATE_LIMIT_IP_WINDOW_MINUTES", 60)
	if err != nil {
		return nil, err
	}
	cfg.RegisterRateLimitIPWindow = time.Duration(registerRateIPWindowMinutes) * time.Minute

	return cfg, nil
}

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid value for %s: %w", key, err)
	}
	return n, nil
}
