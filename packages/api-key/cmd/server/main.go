package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rishi/api-rate-limiter/packages/api-key/internal/config"
	httpapi "github.com/rishi/api-rate-limiter/packages/api-key/internal/http"
	jwtlib "github.com/rishi/api-rate-limiter/packages/api-key/internal/jwt"
	redisstore "github.com/rishi/api-rate-limiter/packages/api-key/internal/store/redis"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx := context.Background()
	client := redisstore.NewClient(cfg.RedisAddr)
	if err := redisstore.Ping(ctx, client); err != nil {
		log.Fatalf("redis unavailable: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("close redis client: %v", err)
		}
	}()

	// Wire the admin API around a shared Redis client so registration and key
	// management stay consistent across all handlers.
	store := redisstore.NewStore(client)
	signer := jwtlib.NewSigner(cfg.JWTSecret, cfg.TokenIssuer)
	verifier := jwtlib.NewVerifier(cfg.JWTSecret)
	handlers := httpapi.NewHandlers(store, signer, verifier)
	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           httpapi.NewRouter(handlers),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("api-key listening on :%s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen api-key: %v", err)
		}
	}()

	shutdown(server)
}

func shutdown(server *http.Server) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh

	// Give in-flight admin requests a short window to finish cleanly.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("shutdown api-key server: %v", err)
	}
}
