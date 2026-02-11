package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vibast-solutions/ms-go-auth/app/middleware"
	"github.com/vibast-solutions/ms-go-auth/app/repository"
	"github.com/vibast-solutions/ms-go-auth/app/service"
	"github.com/vibast-solutions/ms-go-auth/config"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"
)

var internalAPIKeyColumns = []string{
	"id",
	"service_name",
	"key_hash",
	"allowed_access_json",
	"is_active",
	"expires_at",
	"created_at",
	"updated_at",
}

const findInternalByHashQuery = `(?s)SELECT id, service_name, key_hash, allowed_access_json, is_active, expires_at, created_at, updated_at\s+FROM internal_api_keys\s+WHERE key_hash = \? AND is_active = 1 AND expires_at > NOW\(\)\s+ORDER BY id DESC\s+LIMIT 1`

func newAPIKeyMiddleware(t *testing.T) (*middleware.APIKeyMiddleware, sqlmock.Sqlmock, func()) {
	t.Helper()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}

	cfg := &config.Config{
		JWTSecret:          "test-secret",
		JWTAccessTokenTTL:  15 * time.Minute,
		JWTRefreshTokenTTL: 7 * 24 * time.Hour,
		ConfirmTokenTTL:    24 * time.Hour,
		ResetTokenTTL:      time.Hour,
		PasswordPolicy: config.PasswordPolicy{
			MinLength:        1,
			RequireUppercase: false,
			RequireLowercase: false,
			RequireNumber:    false,
			RequireSpecial:   false,
		},
	}

	userRepo := repository.NewUserRepository(db)
	refreshRepo := repository.NewRefreshTokenRepository(db)
	internalAPIKeyRepo := repository.NewInternalAPIKeyRepository(db)
	authService := service.NewAuthService(db, userRepo, refreshRepo, internalAPIKeyRepo, cfg)

	return middleware.NewAPIKeyMiddleware(authService), mock, func() { _ = db.Close() }
}

func TestRequireAPIKey_MissingHeader(t *testing.T) {
	apiKeyMiddleware, _, cleanup := newAPIKeyMiddleware(t)
	defer cleanup()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	handler := apiKeyMiddleware.RequireAPIKey(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestRequireAPIKey_InvalidAPIKey(t *testing.T) {
	apiKeyMiddleware, mock, cleanup := newAPIKeyMiddleware(t)
	defer cleanup()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "invalid-key")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	mock.ExpectQuery(findInternalByHashQuery).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(internalAPIKeyColumns))

	handler := apiKeyMiddleware.RequireAPIKey(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRequireAPIKey_SetsContextOnValidKey(t *testing.T) {
	apiKeyMiddleware, mock, cleanup := newAPIKeyMiddleware(t)
	defer cleanup()

	now := time.Now()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "valid-key")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	mock.ExpectQuery(findInternalByHashQuery).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(internalAPIKeyColumns).AddRow(
			uint64(1),
			"profile-service",
			"hash",
			`["auth","notifications"]`,
			true,
			now.Add(time.Hour),
			now,
			now,
		))

	handler := apiKeyMiddleware.RequireAPIKey(func(c echo.Context) error {
		if c.Get(middleware.ContextKeyCallerService) != "profile-service" {
			t.Fatalf("expected caller_service profile-service, got %v", c.Get(middleware.ContextKeyCallerService))
		}
		return c.NoContent(http.StatusOK)
	})

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
