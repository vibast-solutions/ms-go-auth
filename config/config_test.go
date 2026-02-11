package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPasswordPolicyValidate(t *testing.T) {
	policy := PasswordPolicy{
		MinLength:        8,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumber:    true,
		RequireSpecial:   true,
	}

	if err := policy.Validate("short"); err == nil {
		t.Fatalf("expected error for short password")
	}
	if err := policy.Validate("lowercase1!"); err == nil {
		t.Fatalf("expected error for missing uppercase")
	}
	if err := policy.Validate("UPPERCASE1!"); err == nil {
		t.Fatalf("expected error for missing lowercase")
	}
	if err := policy.Validate("NoNumber!"); err == nil {
		t.Fatalf("expected error for missing number")
	}
	if err := policy.Validate("NoSpecial1"); err == nil {
		t.Fatalf("expected error for missing special")
	}
	if err := policy.Validate("GoodPass1!"); err != nil {
		t.Fatalf("expected valid password, got %v", err)
	}
}

func TestGetEnvHelpers(t *testing.T) {
	t.Setenv("TEST_STRING", "value")
	if got := getEnv("TEST_STRING", "default"); got != "value" {
		t.Fatalf("expected value, got %q", got)
	}
	if got := getEnv("MISSING_STRING", "default"); got != "default" {
		t.Fatalf("expected default, got %q", got)
	}

	t.Setenv("TEST_DURATION", "30")
	if got := getDurationEnv("TEST_DURATION", 5*time.Minute); got != 30*time.Minute {
		t.Fatalf("expected 30m, got %v", got)
	}
	t.Setenv("TEST_DURATION", "invalid")
	if got := getDurationEnv("TEST_DURATION", 5*time.Minute); got != 5*time.Minute {
		t.Fatalf("expected default duration, got %v", got)
	}

	t.Setenv("TEST_BOOL", "true")
	if got := getBoolEnv("TEST_BOOL", false); got != true {
		t.Fatalf("expected true, got %v", got)
	}
	t.Setenv("TEST_BOOL", "invalid")
	if got := getBoolEnv("TEST_BOOL", true); got != true {
		t.Fatalf("expected default bool, got %v", got)
	}

	t.Setenv("TEST_INT", "42")
	if got := getIntEnv("TEST_INT", 5); got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}
	t.Setenv("TEST_INT", "invalid")
	if got := getIntEnv("TEST_INT", 5); got != 5 {
		t.Fatalf("expected default int, got %d", got)
	}
}

func TestLoadRequiresJWTSecret(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})

	t.Setenv("JWT_SECRET", "")
	t.Setenv("MYSQL_DSN", "")
	if cfg, err := Load(); err == nil || cfg != nil {
		t.Fatalf("expected error when JWT_SECRET is missing")
	}
}

func TestLoadRequiresMySQLDSN(t *testing.T) {
	t.Setenv("JWT_SECRET", "secret")
	t.Setenv("MYSQL_DSN", "")
	if cfg, err := Load(); err == nil || cfg != nil {
		t.Fatalf("expected error when MYSQL_DSN is missing")
	}
}

func TestLoadSuccess(t *testing.T) {
	t.Setenv("JWT_SECRET", "secret")
	t.Setenv("MYSQL_DSN", "user:pass@tcp(db:3306)/authdb?parseTime=true")
	t.Setenv("APP_SERVICE_NAME", "auth-service")
	t.Setenv("APP_API_KEY", "auth-app-key")
	t.Setenv("HTTP_HOST", "127.0.0.1")
	t.Setenv("HTTP_PORT", "8081")
	t.Setenv("GRPC_HOST", "127.0.0.1")
	t.Setenv("GRPC_PORT", "9091")
	t.Setenv("JWT_ACCESS_TOKEN_TTL", "20")
	t.Setenv("JWT_REFRESH_TOKEN_TTL", "60")
	t.Setenv("CONFIRM_TOKEN_TTL", "120")
	t.Setenv("RESET_TOKEN_TTL", "30")
	t.Setenv("PASSWORD_MIN_LENGTH", "10")
	t.Setenv("PASSWORD_REQUIRE_UPPERCASE", "false")
	t.Setenv("PASSWORD_REQUIRE_LOWERCASE", "true")
	t.Setenv("PASSWORD_REQUIRE_NUMBER", "false")
	t.Setenv("PASSWORD_REQUIRE_SPECIAL", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if cfg.HTTP.Host != "127.0.0.1" || cfg.HTTP.Port != "8081" || cfg.GRPC.Host != "127.0.0.1" || cfg.GRPC.Port != "9091" {
		t.Fatalf("unexpected host/port: %s:%s %s:%s", cfg.HTTP.Host, cfg.HTTP.Port, cfg.GRPC.Host, cfg.GRPC.Port)
	}
	if cfg.MySQL.DSN != "user:pass@tcp(db:3306)/authdb?parseTime=true" {
		t.Fatalf("unexpected mysql dsn: %s", cfg.MySQL.DSN)
	}
	if cfg.JWT.AccessTokenTTL != 20*time.Minute || cfg.JWT.RefreshTokenTTL != 60*time.Minute {
		t.Fatalf("unexpected jwt ttl: %v %v", cfg.JWT.AccessTokenTTL, cfg.JWT.RefreshTokenTTL)
	}
	if cfg.Tokens.ConfirmTTL != 120*time.Minute || cfg.Tokens.ResetTTL != 30*time.Minute {
		t.Fatalf("unexpected token ttl: %v %v", cfg.Tokens.ConfirmTTL, cfg.Tokens.ResetTTL)
	}
	if cfg.Password.Policy.MinLength != 10 ||
		cfg.Password.Policy.RequireUppercase != false ||
		cfg.Password.Policy.RequireLowercase != true ||
		cfg.Password.Policy.RequireNumber != false ||
		cfg.Password.Policy.RequireSpecial != false {
		t.Fatalf("unexpected password policy: %+v", cfg.Password.Policy)
	}
	if cfg.App.ServiceName != "auth-service" || cfg.App.APIKey != "auth-app-key" {
		t.Fatalf("unexpected app config: %+v", cfg.App)
	}
	if cfg.JWT.Secret != "secret" {
		t.Fatalf("unexpected JWT secret: %s", cfg.JWT.Secret)
	}
	if cfg.Log.Level != "info" {
		t.Fatalf("unexpected log level: %s", cfg.Log.Level)
	}
}

func TestLoadUsesDefaults(t *testing.T) {
	t.Setenv("JWT_SECRET", "secret")
	t.Setenv("MYSQL_DSN", "user:pass@tcp(localhost:3306)/auth?parseTime=true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if cfg.HTTP.Port == "" || cfg.GRPC.Port == "" || cfg.MySQL.DSN == "" {
		t.Fatalf("expected defaults to be populated")
	}
	if cfg.App.ServiceName == "" {
		t.Fatalf("expected APP_SERVICE_NAME default to be populated")
	}
}

func TestLoadRespectsEnvFileLocation(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})

	envPath := filepath.Join(tmp, ".env")
	if err := os.WriteFile(envPath, []byte("JWT_SECRET=envfile-secret\nMYSQL_DSN=user:pass@tcp(localhost:3306)/auth?parseTime=true\nHTTP_PORT=9099\n"), 0600); err != nil {
		t.Fatalf("write .env failed: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if cfg.JWT.Secret != "envfile-secret" || cfg.HTTP.Port != "9099" {
		t.Fatalf("expected env file values, got %s %s", cfg.JWT.Secret, cfg.HTTP.Port)
	}
}
