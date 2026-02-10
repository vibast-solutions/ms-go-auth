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
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

func newMiddleware(t *testing.T) (*middleware.AuthMiddleware, func()) {
	t.Helper()

	db, _, err := sqlmock.New()
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
	authService := service.NewAuthService(db, userRepo, refreshRepo, cfg)

	return middleware.NewAuthMiddleware(authService), func() { _ = db.Close() }
}

func TestRequireAuth_MissingHeader(t *testing.T) {
	authMiddleware, cleanup := newMiddleware(t)
	defer cleanup()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	handler := authMiddleware.RequireAuth(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestRequireAuth_InvalidHeaderFormat(t *testing.T) {
	authMiddleware, cleanup := newMiddleware(t)
	defer cleanup()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Token abc")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	handler := authMiddleware.RequireAuth(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestRequireAuth_InvalidToken(t *testing.T) {
	authMiddleware, cleanup := newMiddleware(t)
	defer cleanup()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	handler := authMiddleware.RequireAuth(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestRequireAuth_SetsContextOnValidToken(t *testing.T) {
	authMiddleware, cleanup := newMiddleware(t)
	defer cleanup()

	claims := &service.Claims{
		UserID: 1,
		Email:  "user@example.com",
		Roles:  []string{service.RoleUser},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	handler := authMiddleware.RequireAuth(func(c echo.Context) error {
		userID, ok := c.Get("user_id").(uint64)
		if !ok || userID != 1 {
			t.Fatalf("expected user_id 1, got %v", c.Get("user_id"))
		}
		email, ok := c.Get("user_email").(string)
		if !ok || email != "user@example.com" {
			t.Fatalf("expected user_email user@example.com, got %v", c.Get("user_email"))
		}
		roles, ok := c.Get("user_roles").([]string)
		if !ok || len(roles) != 1 || roles[0] != service.RoleUser {
			t.Fatalf("expected user_roles [%q], got %v", service.RoleUser, c.Get("user_roles"))
		}
		return c.NoContent(http.StatusOK)
	})

	if err := handler(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}
