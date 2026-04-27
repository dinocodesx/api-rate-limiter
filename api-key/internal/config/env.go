package config

import (
	"fmt"
	"os"
)

type Config struct {
	Port        string
	RedisAddr   string
	JWTSecret   string
	TokenIssuer string
}

func Load() (Config, error) {
	cfg := Config{
		Port:        getenv("PORT", "8080"),
		RedisAddr:   getenv("REDIS_ADDR", "redis:6379"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		TokenIssuer: getenv("TOKEN_ISSUER", "api-key-service"),
	}

	if cfg.JWTSecret == "" {
		return Config{}, fmt.Errorf("JWT_SECRET is required")
	}

	return cfg, nil
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
