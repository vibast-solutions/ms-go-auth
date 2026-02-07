package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/joho/godotenv"
)

type Config struct {
	HTTPPort           string
	GRPCPort           string
	MySQLDSN           string
	JWTSecret          string
	JWTAccessTokenTTL  time.Duration
	JWTRefreshTokenTTL time.Duration
	ConfirmTokenTTL    time.Duration
	ResetTokenTTL      time.Duration
	PasswordPolicy     PasswordPolicy
}

type PasswordPolicy struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumber    bool
	RequireSpecial   bool
}

func (p PasswordPolicy) Validate(password string) error {
	if len(password) < p.MinLength {
		return fmt.Errorf("password must be at least %d characters long", p.MinLength)
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasNumber = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	var missing []string
	if p.RequireUppercase && !hasUpper {
		missing = append(missing, "uppercase letter")
	}
	if p.RequireLowercase && !hasLower {
		missing = append(missing, "lowercase letter")
	}
	if p.RequireNumber && !hasNumber {
		missing = append(missing, "number")
	}
	if p.RequireSpecial && !hasSpecial {
		missing = append(missing, "special character")
	}

	if len(missing) > 0 {
		return fmt.Errorf("password must contain at least one: %s", strings.Join(missing, ", "))
	}

	return nil
}

func Load() (*Config, error) {
	// Load .env file if it exists (ignores error if not found)
	_ = godotenv.Load()

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, errors.New("JWT_SECRET environment variable is required")
	}

	mysqlDSN := os.Getenv("MYSQL_DSN")
	if mysqlDSN == "" {
		return nil, errors.New("MYSQL_DSN environment variable is required")
	}

	return &Config{
		HTTPPort:           getEnv("HTTP_PORT", "8080"),
		GRPCPort:           getEnv("GRPC_PORT", "9090"),
		MySQLDSN:           mysqlDSN,
		JWTSecret:          jwtSecret,
		JWTAccessTokenTTL:  getDurationEnv("JWT_ACCESS_TOKEN_TTL", 15*time.Minute),
		JWTRefreshTokenTTL: getDurationEnv("JWT_REFRESH_TOKEN_TTL", 7*24*time.Hour),
		ConfirmTokenTTL:    getDurationEnv("CONFIRM_TOKEN_TTL", 24*time.Hour),
		ResetTokenTTL:      getDurationEnv("RESET_TOKEN_TTL", 1*time.Hour),
		PasswordPolicy:     loadPasswordPolicy(),
	}, nil
}

func (c *Config) DSN() string {
	return c.MySQLDSN
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if minutes, err := strconv.Atoi(value); err == nil {
			return time.Duration(minutes) * time.Minute
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if n, err := strconv.Atoi(value); err == nil {
			return n
		}
	}
	return defaultValue
}

func loadPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:        getIntEnv("PASSWORD_MIN_LENGTH", 8),
		RequireUppercase: getBoolEnv("PASSWORD_REQUIRE_UPPERCASE", true),
		RequireLowercase: getBoolEnv("PASSWORD_REQUIRE_LOWERCASE", true),
		RequireNumber:    getBoolEnv("PASSWORD_REQUIRE_NUMBER", true),
		RequireSpecial:   getBoolEnv("PASSWORD_REQUIRE_SPECIAL", true),
	}
}
