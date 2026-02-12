package controller_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vibast-solutions/ms-go-auth/app/controller"
	"github.com/vibast-solutions/ms-go-auth/app/repository"
	"github.com/vibast-solutions/ms-go-auth/app/service"
	"github.com/vibast-solutions/ms-go-auth/config"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

const (
	findByCanonicalEmailQuery = `(?s)SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,\s+reset_token, reset_token_expires_at, last_login, created_at, updated_at\s+FROM users WHERE canonical_email = \?`
	findByIDQuery             = `(?s)SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,\s+reset_token, reset_token_expires_at, last_login, created_at, updated_at\s+FROM users WHERE id = \?`
	findRefreshTokenForUpdate = `(?s)SELECT id, user_id, token, expires_at, created_at\s+FROM refresh_tokens WHERE token = \? FOR UPDATE`
	insertUserQuery           = `(?s)INSERT INTO users \(email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at, last_login, created_at, updated_at\)\s+VALUES \(\?, \?, \?, \?, \?, \?, \?, \?, \?\)`
	insertUserRoleQuery       = `(?s)INSERT INTO user_roles \(user_id, role\) VALUES \(\?, \?\)`
	listUserRolesQuery        = `(?s)SELECT role FROM user_roles WHERE user_id = \? ORDER BY role`
	findInternalByHashQuery   = `(?s)SELECT id, service_name, key_hash, allowed_access_json, is_active, expires_at, created_at, updated_at\s+FROM internal_api_keys\s+WHERE key_hash = \? AND is_active = 1 AND expires_at > NOW\(\)\s+ORDER BY id DESC\s+LIMIT 1`
)

var userColumns = []string{
	"id",
	"email",
	"canonical_email",
	"password_hash",
	"is_confirmed",
	"confirm_token",
	"confirm_token_expires_at",
	"reset_token",
	"reset_token_expires_at",
	"last_login",
	"created_at",
	"updated_at",
}

var roleColumns = []string{
	"role",
}

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

type authControllerFacade struct {
	user     *controller.UserAuthController
	internal *controller.InternalAuthController
}

func (c *authControllerFacade) Register(ctx echo.Context) error { return c.user.Register(ctx) }
func (c *authControllerFacade) Login(ctx echo.Context) error    { return c.user.Login(ctx) }
func (c *authControllerFacade) Logout(ctx echo.Context) error   { return c.user.Logout(ctx) }
func (c *authControllerFacade) GenerateConfirmToken(ctx echo.Context) error {
	return c.user.GenerateConfirmToken(ctx)
}
func (c *authControllerFacade) RefreshToken(ctx echo.Context) error { return c.user.RefreshToken(ctx) }
func (c *authControllerFacade) ValidateToken(ctx echo.Context) error {
	return c.user.ValidateToken(ctx)
}
func (c *authControllerFacade) ChangePassword(ctx echo.Context) error {
	return c.user.ChangePassword(ctx)
}
func (c *authControllerFacade) ConfirmAccount(ctx echo.Context) error {
	return c.user.ConfirmAccount(ctx)
}
func (c *authControllerFacade) RequestPasswordReset(ctx echo.Context) error {
	return c.user.RequestPasswordReset(ctx)
}
func (c *authControllerFacade) ResetPassword(ctx echo.Context) error {
	return c.user.ResetPassword(ctx)
}
func (c *authControllerFacade) InternalAccess(ctx echo.Context) error {
	return c.internal.InternalAccess(ctx)
}

func newControllerWithMock(t *testing.T) (*authControllerFacade, sqlmock.Sqlmock, func()) {
	t.Helper()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}

	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:          "test-secret",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
		},
		Tokens: config.TokenConfig{
			ConfirmTTL: 24 * time.Hour,
			ResetTTL:   time.Hour,
		},
		Password: config.PasswordConfig{
			Policy: config.PasswordPolicy{
				MinLength:        8,
				RequireUppercase: false,
				RequireLowercase: false,
				RequireNumber:    false,
				RequireSpecial:   false,
			},
		},
	}

	userRepo := repository.NewUserRepository(db)
	refreshRepo := repository.NewRefreshTokenRepository(db)
	internalAPIKeyRepo := repository.NewInternalAPIKeyRepository(db)
	userAuthService := service.NewUserAuthService(db, userRepo, refreshRepo, cfg)
	internalAuthService := service.NewInternalAuthService(internalAPIKeyRepo)

	return &authControllerFacade{
		user:     controller.NewUserAuthController(userAuthService),
		internal: controller.NewInternalAuthController(internalAuthService),
	}, mock, func() { _ = db.Close() }
}

func newJSONRequest(t *testing.T, method, path string, body any) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()

	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	return req, httptest.NewRecorder()
}

func expectUserRolesQuery(mock sqlmock.Sqlmock, userID uint64, roles ...string) {
	rows := sqlmock.NewRows(roleColumns)
	for _, role := range roles {
		rows.AddRow(role)
	}

	mock.ExpectQuery(listUserRolesQuery).
		WithArgs(userID).
		WillReturnRows(rows)
}

func TestRegister_Success(t *testing.T) {
	controllerWithMock, mock, cleanup := newControllerWithMock(t)
	defer cleanup()

	email := "Test.User+tag@gmail.com"
	canonical := service.CanonicalizeEmail(email)

	mock.ExpectQuery(findByCanonicalEmailQuery).
		WithArgs(canonical).
		WillReturnRows(sqlmock.NewRows(userColumns))
	mock.ExpectBegin()
	mock.ExpectExec(insertUserQuery).
		WithArgs(email, canonical, sqlmock.AnyArg(), false, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(insertUserRoleQuery).
		WithArgs(uint64(1), service.RoleUser).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/register", map[string]string{
		"email":    email,
		"password": "password123",
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.Register(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid response json: %v", err)
	}
	if body["email"] != email {
		t.Fatalf("expected email %q, got %v", email, body["email"])
	}
	if body["confirm_token"] == "" {
		t.Fatalf("expected confirm_token to be set")
	}
	roles, ok := body["roles"].([]any)
	if !ok || len(roles) != 1 || roles[0] != service.RoleUser {
		t.Fatalf("expected roles [%q], got %#v", service.RoleUser, body["roles"])
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRegister_WeakPassword(t *testing.T) {
	controllerWithMock, mock, cleanup := newControllerWithMock(t)
	defer cleanup()

	email := "user@example.com"
	canonical := service.CanonicalizeEmail(email)

	mock.ExpectQuery(findByCanonicalEmailQuery).
		WithArgs(canonical).
		WillReturnRows(sqlmock.NewRows(userColumns))

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/register", map[string]string{
		"email":    email,
		"password": "short",
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.Register(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "password") {
		t.Fatalf("expected password error, got %s", rec.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestLogin_InvalidCredentials(t *testing.T) {
	controllerWithMock, mock, cleanup := newControllerWithMock(t)
	defer cleanup()

	email := "user@example.com"
	canonical := service.CanonicalizeEmail(email)

	mock.ExpectQuery(findByCanonicalEmailQuery).
		WithArgs(canonical).
		WillReturnRows(sqlmock.NewRows(userColumns))

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"email":    email,
		"password": "bad-password",
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.Login(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	controllerWithMock, mock, cleanup := newControllerWithMock(t)
	defer cleanup()

	mock.ExpectBegin()
	mock.ExpectQuery(findRefreshTokenForUpdate).
		WithArgs("missing").
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "token", "expires_at", "created_at"}))
	mock.ExpectRollback()

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/refresh-token", map[string]string{
		"refresh_token": "missing",
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.RefreshToken(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestChangePassword_Mismatch(t *testing.T) {
	controllerWithMock, mock, cleanup := newControllerWithMock(t)
	defer cleanup()

	email := "user@example.com"
	canonical := service.CanonicalizeEmail(email)
	now := time.Now()
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-old"), bcrypt.DefaultCost)

	mock.ExpectQuery(findByIDQuery).
		WithArgs(uint64(1)).
		WillReturnRows(sqlmock.NewRows(userColumns).AddRow(
			uint64(1),
			email,
			canonical,
			string(hash),
			true,
			sql.NullString{Valid: false},
			sql.NullTime{Valid: false},
			sql.NullString{Valid: false},
			sql.NullTime{Valid: false},
			sql.NullTime{Valid: false},
			now,
			now,
		))
	expectUserRolesQuery(mock, 1, service.RoleUser)

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/change-password", map[string]string{
		"old_password": "wrong",
		"new_password": "new-password",
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)
	ctx.Set("user_id", uint64(1))

	if err := controllerWithMock.ChangePassword(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRequestPasswordReset_UnknownUser(t *testing.T) {
	controllerWithMock, mock, cleanup := newControllerWithMock(t)
	defer cleanup()

	email := "missing@example.com"
	canonical := service.CanonicalizeEmail(email)

	mock.ExpectQuery(findByCanonicalEmailQuery).
		WithArgs(canonical).
		WillReturnRows(sqlmock.NewRows(userColumns))

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/request-password-reset", map[string]string{
		"email": email,
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.RequestPasswordReset(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestValidateToken_InvalidToken(t *testing.T) {
	controllerWithMock, _, cleanup := newControllerWithMock(t)
	defer cleanup()

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/validate-token", map[string]string{
		"access_token": "invalid-token",
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.ValidateToken(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"valid":false`) {
		t.Fatalf("expected valid=false response, got %s", rec.Body.String())
	}
}

func TestLogout_MissingRefreshToken(t *testing.T) {
	controllerWithMock, _, cleanup := newControllerWithMock(t)
	defer cleanup()

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/logout", map[string]string{})
	e := echo.New()
	ctx := e.NewContext(req, rec)
	ctx.Set("user_id", uint64(1))

	if err := controllerWithMock.Logout(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestLogout_MissingUserID(t *testing.T) {
	controllerWithMock, _, cleanup := newControllerWithMock(t)
	defer cleanup()

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/logout", map[string]string{
		"refresh_token": "some-token",
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.Logout(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestGenerateConfirmToken_NotFound(t *testing.T) {
	controllerWithMock, mock, cleanup := newControllerWithMock(t)
	defer cleanup()

	email := "missing@example.com"
	canonical := service.CanonicalizeEmail(email)

	mock.ExpectQuery(findByCanonicalEmailQuery).
		WithArgs(canonical).
		WillReturnRows(sqlmock.NewRows(userColumns))

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/generate-confirm-token", map[string]string{
		"email": email,
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.GenerateConfirmToken(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rec.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestConfirmAccount_InvalidToken(t *testing.T) {
	controllerWithMock, mock, cleanup := newControllerWithMock(t)
	defer cleanup()

	mock.ExpectQuery(`(?s)SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,\s+reset_token, reset_token_expires_at, last_login, created_at, updated_at\s+FROM users WHERE confirm_token = \?`).
		WithArgs("bad-token").
		WillReturnRows(sqlmock.NewRows(userColumns))

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/confirm-account", map[string]string{
		"token": "bad-token",
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.ConfirmAccount(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRegister_InvalidBody(t *testing.T) {
	controllerWithMock, _, cleanup := newControllerWithMock(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader("{bad-json"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()

	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.Register(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestRequestPasswordReset_MissingEmail(t *testing.T) {
	controllerWithMock, _, cleanup := newControllerWithMock(t)
	defer cleanup()

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/request-password-reset", map[string]string{})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.RequestPasswordReset(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestChangePassword_MissingUserID(t *testing.T) {
	controllerWithMock, _, cleanup := newControllerWithMock(t)
	defer cleanup()

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/change-password", map[string]string{
		"old_password": "old",
		"new_password": "new",
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.ChangePassword(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestLogin_InvalidBody(t *testing.T) {
	controllerWithMock, _, cleanup := newControllerWithMock(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader("{bad-json"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()

	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.Login(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestResetPassword_ExpiredToken(t *testing.T) {
	controllerWithMock, mock, cleanup := newControllerWithMock(t)
	defer cleanup()

	now := time.Now()
	mock.ExpectQuery(`(?s)SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,\s+reset_token, reset_token_expires_at, last_login, created_at, updated_at\s+FROM users WHERE reset_token = \?`).
		WithArgs("expired-token").
		WillReturnRows(sqlmock.NewRows(userColumns).AddRow(
			uint64(1),
			"user@example.com",
			"user@example.com",
			"hash",
			true,
			sql.NullString{Valid: false},
			sql.NullTime{Valid: false},
			sql.NullString{String: "expired-token", Valid: true},
			sql.NullTime{Time: now.Add(-time.Hour), Valid: true},
			sql.NullTime{Valid: false},
			now,
			now,
		))

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/reset-password", map[string]string{
		"token":        "expired-token",
		"new_password": "new-password",
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.ResetPassword(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestValidateToken_MissingToken(t *testing.T) {
	controllerWithMock, _, cleanup := newControllerWithMock(t)
	defer cleanup()

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/validate-token", map[string]string{})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.ValidateToken(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestRequestPasswordReset_InvalidBody(t *testing.T) {
	controllerWithMock, _, cleanup := newControllerWithMock(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/auth/request-password-reset", strings.NewReader("{bad-json"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()

	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.RequestPasswordReset(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestRegister_DuplicateUser(t *testing.T) {
	controllerWithMock, mock, cleanup := newControllerWithMock(t)
	defer cleanup()

	email := "user@example.com"
	canonical := service.CanonicalizeEmail(email)
	now := time.Now()

	mock.ExpectQuery(findByCanonicalEmailQuery).
		WithArgs(canonical).
		WillReturnRows(sqlmock.NewRows(userColumns).AddRow(
			uint64(1),
			email,
			canonical,
			"hash",
			true,
			sql.NullString{Valid: false},
			sql.NullTime{Valid: false},
			sql.NullString{Valid: false},
			sql.NullTime{Valid: false},
			sql.NullTime{Valid: false},
			now,
			now,
		))
	expectUserRolesQuery(mock, 1, service.RoleUser)

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/register", map[string]string{
		"email":    email,
		"password": "password123",
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.Register(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", rec.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestLogin_InvalidBodyMissingFields(t *testing.T) {
	controllerWithMock, _, cleanup := newControllerWithMock(t)
	defer cleanup()

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"email": "",
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.Login(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestRegister_ContextCancel(t *testing.T) {
	controllerWithMock, mock, cleanup := newControllerWithMock(t)
	defer cleanup()

	email := "user@example.com"
	canonical := service.CanonicalizeEmail(email)

	mock.ExpectQuery(findByCanonicalEmailQuery).
		WithArgs(canonical).
		WillReturnError(context.Canceled)

	req, rec := newJSONRequest(t, http.MethodPost, "/auth/register", map[string]string{
		"email":    email,
		"password": "password123",
	})
	e := echo.New()
	ctx := e.NewContext(req, rec)

	if err := controllerWithMock.Register(ctx); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rec.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
