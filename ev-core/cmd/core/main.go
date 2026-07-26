package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"platform-core/internal/coreapi"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"platform-core/internal/audit"
	"platform-core/internal/authsvc"
	"platform-core/internal/config"
	"platform-core/internal/db"
	"platform-core/internal/httpserver"
	"platform-core/internal/rbac"
	"platform-core/internal/security"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal startup error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
	})
	defer redisClient.Close()

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := redisClient.Ping(pingCtx).Err(); err != nil {
		return err
	}

	tokens, err := security.NewTokenManager(cfg.JWTPrivateKeyPath, cfg.JWTPublicKeyPath, cfg.AccessTokenTTL)
	if err != nil {
		return err
	}

	auditLogger := audit.NewLogger(pool)
	permCache := rbac.NewPermissionCache(redisClient, cfg.RBACCacheTTL)
	authorizer := rbac.NewAuthorizer(pool, permCache, auditLogger)

	authService := authsvc.NewService(pool, tokens, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	authHandlers := authsvc.NewHandlers(authService)

	coreRepo := coreapi.NewRepository(pool)
	coreHandlers := coreapi.NewHandlers(coreRepo, authorizer)

	server := httpserver.NewServer(authHandlers, tokens, authorizer, coreHandlers)
	
	httpSrv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("starting platform-core", "port", cfg.Port)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdownCtx)
}
