package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yash-sharma-dev/authsvc/internal/config"
	"github.com/yash-sharma-dev/authsvc/internal/httpapi"
	"github.com/yash-sharma-dev/authsvc/internal/notify"
	"github.com/yash-sharma-dev/authsvc/internal/oauth"
	"github.com/yash-sharma-dev/authsvc/internal/store"
	"github.com/yash-sharma-dev/authsvc/internal/token"
)

func main() {
	// Migrations run as a release command, not on boot: a bad migration should
	// fail the deploy, not crashloop the service.
	migrateOnly := flag.Bool("migrate", false, "apply migrations and exit")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if err := run(log, *migrateOnly); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, migrateOnly bool) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if migrateOnly {
		if err := store.Migrate(ctx, cfg.DatabaseURL); err != nil {
			return err
		}
		log.Info("migrations applied")
		return nil
	}

	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	signer, err := token.NewSigner(token.Config{
		Issuer:     cfg.Issuer,
		AccessTTL:  cfg.AccessTTL,
		PrivateKey: cfg.SigningKey,
		NextKey:    cfg.SigningKeyNext,
	})
	if err != nil {
		return err
	}

	sender, err := buildSender(cfg, log)
	if err != nil {
		return err
	}

	srv := httpapi.New(db, signer, sender, log, httpapi.Options{
		Issuer:      cfg.Issuer,
		AdminAPIKey: cfg.AdminAPIKey,
		Secure:      !cfg.Dev,
	}).WithProviders(providers(cfg, log)...)

	go prune(ctx, db, log)

	h := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", h.Addr, "issuer", cfg.Issuer, "dev", cfg.Dev)
		if err := h.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return h.Shutdown(shutCtx)
	}
}

// providers wires only the OAuth apps that are actually configured. The one
// callback URL below is what gets registered with Google and GitHub, once.
func providers(cfg *config.Config, log *slog.Logger) []oauth.Provider {
	var out []oauth.Provider
	if cfg.Google.Configured() {
		out = append(out, oauth.NewGoogle(cfg.Google.ClientID, cfg.Google.ClientSecret,
			cfg.Issuer+"/v1/oauth/google/callback"))
	} else {
		log.Warn("google oauth not configured; /v1/oauth/google/* will 404")
	}
	if cfg.GitHub.Configured() {
		out = append(out, oauth.NewGitHub(cfg.GitHub.ClientID, cfg.GitHub.ClientSecret,
			cfg.Issuer+"/v1/oauth/github/callback"))
	} else {
		log.Warn("github oauth not configured; /v1/oauth/github/* will 404")
	}
	return out
}

func buildSender(cfg *config.Config, log *slog.Logger) (notify.Sender, error) {
	if cfg.SMTP.Configured() {
		return notify.SMTPSender{
			Host: cfg.SMTP.Host, Port: cfg.SMTP.Port,
			User: cfg.SMTP.User, Pass: cfg.SMTP.Pass, From: cfg.SMTP.From,
		}, nil
	}
	if cfg.Dev {
		log.Warn("SMTP not configured; codes will be logged, not emailed")
		return notify.LogSender{Log: log}, nil
	}
	return nil, errors.New("SMTP_HOST and SMTP_FROM are required outside DEV")
}

// prune keeps the two tables that grow from accumulating dead rows.
func prune(ctx context.Context, db *store.DB, log *slog.Logger) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := db.PruneSessions(ctx, 30*24*time.Hour); err != nil {
				log.Error("prune sessions", "err", err)
			} else if n > 0 {
				log.Info("pruned sessions", "rows", n)
			}
			if n, err := db.PruneCodes(ctx, 24*time.Hour); err != nil {
				log.Error("prune codes", "err", err)
			} else if n > 0 {
				log.Info("pruned codes", "rows", n)
			}
			if _, err := db.PruneRateLimits(ctx, 24*time.Hour); err != nil {
				log.Error("prune rate limits", "err", err)
			}
			if err := db.PruneOAuth(ctx); err != nil {
				log.Error("prune oauth", "err", err)
			}
		}
	}
}
