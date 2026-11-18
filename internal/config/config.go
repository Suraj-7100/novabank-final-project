package config

import (
	"errors"
	"net"
	"net/url"
	"os"
)

type Config struct {
	Port        string
	JWTSecret   string
	DatabaseURL string
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Load reads configuration from the environment. In AWS, JWT_SECRET and
// DB_PASSWORD are injected by ECS from Secrets Manager.
func Load() (*Config, error) {
	secret := os.Getenv("JWT_SECRET")
	if len(secret) < 32 {
		return nil, errors.New("JWT_SECRET must be set and at least 32 characters")
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		host := os.Getenv("DB_HOST")
		if host == "" {
			return nil, errors.New("set DATABASE_URL or DB_HOST")
		}
		u := url.URL{
			Scheme:   "postgres",
			User:     url.UserPassword(env("DB_USER", "bankadmin"), os.Getenv("DB_PASSWORD")),
			Host:     net.JoinHostPort(host, env("DB_PORT", "5432")),
			Path:     "/" + env("DB_NAME", "bank"),
			RawQuery: "sslmode=" + env("DB_SSLMODE", "require"),
		}
		dbURL = u.String()
	}

	return &Config{Port: env("PORT", "8080"), JWTSecret: secret, DatabaseURL: dbURL}, nil
}
