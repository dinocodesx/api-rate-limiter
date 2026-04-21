package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/auth"
	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/config"
	httpapi "github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/http"
	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/proxy"
	"github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/ratelimit"
	redisstore "github.com/rishi/api-rate-limiter/packages/rate-limiter/internal/store/redis"
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

	// Compose the request pipeline in the same order each request uses it:
	// auth -> policy lookup -> bucket enforcement -> reverse proxy.
	policyStore := redisstore.NewPolicyStore(client)
	bucketStore := redisstore.NewBucketStore(client)
	revocationStore := redisstore.NewRevocationStore(client)
	verifier := auth.NewVerifier(cfg.JWTSecret, cfg.ExpectedIssuer, revocationStore)
	limiter := ratelimit.NewService(policyStore, bucketStore)
	handler := httpapi.NewHandler(verifier, limiter, proxy.New(), func(ctx context.Context) error {
		return client.Ping(ctx).Err()
	})
	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           httpapi.NewRouter(handler),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("rate-limiter listening on :%s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen rate-limiter: %v", err)
		}
	}()

	shutdown(server)
}

func shutdown(server *http.Server) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh

	// Give proxied upstream calls time to drain before tearing the listener down.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("shutdown rate-limiter server: %v", err)
	}
}
