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
	t.Setenv("HTTP_PORT", "8081")
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
	if cfg.HTTPPort != "8081" || cfg.GRPCPort != "9091" {
		t.Fatalf("unexpected ports: %s %s", cfg.HTTPPort, cfg.GRPCPort)
	}
	if cfg.MySQLDSN != "user:pass@tcp(db:3306)/authdb?parseTime=true" {
		t.Fatalf("unexpected mysql dsn: %s", cfg.MySQLDSN)
	}
	if cfg.JWTAccessTokenTTL != 20*time.Minute || cfg.JWTRefreshTokenTTL != 60*time.Minute {
		t.Fatalf("unexpected jwt ttl: %v %v", cfg.JWTAccessTokenTTL, cfg.JWTRefreshTokenTTL)
	}
	if cfg.ConfirmTokenTTL != 120*time.Minute || cfg.ResetTokenTTL != 30*time.Minute {
		t.Fatalf("unexpected token ttl: %v %v", cfg.ConfirmTokenTTL, cfg.ResetTokenTTL)
	}
	if cfg.PasswordPolicy.MinLength != 10 ||
		cfg.PasswordPolicy.RequireUppercase != false ||
		cfg.PasswordPolicy.RequireLowercase != true ||
		cfg.PasswordPolicy.RequireNumber != false ||
		cfg.PasswordPolicy.RequireSpecial != false {
		t.Fatalf("unexpected password policy: %+v", cfg.PasswordPolicy)
	}
}

func TestDSN(t *testing.T) {
	cfg := &Config{
		MySQLDSN: "user:pass@tcp(localhost:3306)/auth?parseTime=true",
	}
	got := cfg.DSN()
	if got != cfg.MySQLDSN {
		t.Fatalf("expected %q, got %q", cfg.MySQLDSN, got)
	}
}

func TestLoadUsesDefaults(t *testing.T) {
	t.Setenv("JWT_SECRET", "secret")
	t.Setenv("MYSQL_DSN", "user:pass@tcp(localhost:3306)/auth?parseTime=true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if cfg.HTTPPort == "" || cfg.GRPCPort == "" || cfg.MySQLDSN == "" {
		t.Fatalf("expected defaults to be populated")
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
	if cfg.JWTSecret != "envfile-secret" || cfg.HTTPPort != "9099" {
		t.Fatalf("expected env file values, got %s %s", cfg.JWTSecret, cfg.HTTPPort)
	}
}
