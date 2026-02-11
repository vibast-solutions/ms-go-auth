package service_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/vibast-solutions/ms-go-auth/app/entity"
	"github.com/vibast-solutions/ms-go-auth/app/repository"
	"github.com/vibast-solutions/ms-go-auth/app/service"
	"github.com/vibast-solutions/ms-go-auth/app/types"
	"github.com/vibast-solutions/ms-go-auth/config"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	userColumns = []string{
		"id",
		"email",
		"canonical_email",
		"password_hash",
		"is_confirmed",
		"confirm_token",
		"confirm_token_expires_at",
		"reset_token",
		"reset_token_expires_at",
		"created_at",
		"updated_at",
	}
	refreshTokenColumns = []string{
		"id",
		"user_id",
		"token",
		"expires_at",
		"created_at",
	}
	roleColumns = []string{
		"role",
	}
	internalAPIKeyColumns = []string{
		"id",
		"service_name",
		"key_hash",
		"allowed_access_json",
		"is_active",
		"expires_at",
		"created_at",
		"updated_at",
	}
)

const (
	findByCanonicalEmailQuery = `(?s)SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,\s+reset_token, reset_token_expires_at, created_at, updated_at\s+FROM users WHERE canonical_email = \?`
	findByIDQuery             = `(?s)SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,\s+reset_token, reset_token_expires_at, created_at, updated_at\s+FROM users WHERE id = \?`
	findByResetTokenQuery     = `(?s)SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,\s+reset_token, reset_token_expires_at, created_at, updated_at\s+FROM users WHERE reset_token = \?`
	findRefreshTokenForUpdate = `(?s)SELECT id, user_id, token, expires_at, created_at\s+FROM refresh_tokens WHERE token = \? FOR UPDATE`
	insertUserQuery           = `(?s)INSERT INTO users \(email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at, created_at, updated_at\)\s+VALUES \(\?, \?, \?, \?, \?, \?, \?, \?\)`
	insertUserRoleQuery       = `(?s)INSERT INTO user_roles \(user_id, role\) VALUES \(\?, \?\)`
	listUserRolesQuery        = `(?s)SELECT role FROM user_roles WHERE user_id = \? ORDER BY role`
	updateUserQuery           = `(?s)UPDATE users SET\s+email = \?,\s+canonical_email = \?,\s+password_hash = \?,\s+is_confirmed = \?,\s+confirm_token = \?,\s+confirm_token_expires_at = \?,\s+reset_token = \?,\s+reset_token_expires_at = \?,\s+updated_at = \?\s+WHERE id = \?`
	insertRefreshTokenQuery   = `(?s)INSERT INTO refresh_tokens \(user_id, token, expires_at, created_at\)\s+VALUES \(\?, \?, \?, \?\)`
	deleteRefreshTokenQuery   = `(?s)DELETE FROM refresh_tokens WHERE token = \? AND user_id = \?`
	deleteByUserIDQuery       = `(?s)DELETE FROM refresh_tokens WHERE user_id = \?`
	findInternalByHashQuery   = `(?s)SELECT id, service_name, key_hash, allowed_access_json, is_active, expires_at, created_at, updated_at\s+FROM internal_api_keys\s+WHERE key_hash = \? AND is_active = 1 AND expires_at > NOW\(\)\s+ORDER BY id DESC\s+LIMIT 1`
	findInternalByServiceName = `(?s)SELECT id, service_name, key_hash, allowed_access_json, is_active, expires_at, created_at, updated_at\s+FROM internal_api_keys\s+WHERE service_name = \? AND is_active = 1 AND expires_at > \?\s+ORDER BY id DESC`
	insertInternalAPIKeyQuery = `(?s)INSERT INTO internal_api_keys \(\s+service_name, key_hash, allowed_access_json, is_active, expires_at, created_at, updated_at\s+\) VALUES \(\?, \?, \?, \?, \?, \?, \?\)`
	updateInternalAPIKeyQuery = `(?s)UPDATE internal_api_keys SET\s+service_name = \?,\s+key_hash = \?,\s+allowed_access_json = \?,\s+is_active = \?,\s+expires_at = \?,\s+updated_at = \?\s+WHERE id = \?`
)

type registerResult struct {
	User         *entity.User
	ConfirmToken string
}

type loginResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	Roles        []string
}

type requestPasswordResetResult struct {
	ResetToken string
}

type internalAccessResult struct {
	ServiceName   string
	AllowedAccess []string
}

type testAuthService struct {
	userAuthService     service.UserAuthService
	internalAuthService service.InternalAuthService
}

func (s *testAuthService) Register(ctx context.Context, email, password string) (*registerResult, error) {
	res, err := s.userAuthService.Register(ctx, &types.RegisterRequest{
		Email:    email,
		Password: password,
	})
	if err != nil {
		return nil, err
	}

	return &registerResult{
		User: &entity.User{
			ID:    res.GetUserId(),
			Email: res.GetEmail(),
			Roles: res.GetRoles(),
		},
		ConfirmToken: res.GetConfirmToken(),
	}, nil
}

func (s *testAuthService) Login(ctx context.Context, email, password string, customTTL time.Duration) (*loginResult, error) {
	req := &types.LoginRequest{
		Email:    email,
		Password: password,
	}
	if customTTL > 0 {
		req.TokenDuration = int64(customTTL / time.Minute)
	}

	res, err := s.userAuthService.Login(ctx, req)
	if err != nil {
		return nil, err
	}

	return &loginResult{
		AccessToken:  res.GetAccessToken(),
		RefreshToken: res.GetRefreshToken(),
		ExpiresIn:    res.GetExpiresIn(),
		Roles:        res.GetRoles(),
	}, nil
}

func (s *testAuthService) RefreshToken(ctx context.Context, refreshToken string) (*loginResult, error) {
	res, err := s.userAuthService.RefreshToken(ctx, &types.RefreshTokenRequest{RefreshToken: refreshToken})
	if err != nil {
		return nil, err
	}

	return &loginResult{
		AccessToken:  res.GetAccessToken(),
		RefreshToken: res.GetRefreshToken(),
		ExpiresIn:    res.GetExpiresIn(),
		Roles:        res.GetRoles(),
	}, nil
}

func (s *testAuthService) ChangePassword(ctx context.Context, userID uint64, oldPassword, newPassword string) error {
	return s.userAuthService.ChangePassword(ctx, userID, &types.ChangePasswordRequest{
		OldPassword: oldPassword,
		NewPassword: newPassword,
	})
}

func (s *testAuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	return s.userAuthService.ResetPassword(ctx, &types.ResetPasswordRequest{
		Token:       token,
		NewPassword: newPassword,
	})
}

func (s *testAuthService) RequestPasswordReset(ctx context.Context, email string) (*requestPasswordResetResult, error) {
	res, err := s.userAuthService.RequestPasswordReset(ctx, &types.RequestPasswordResetRequest{Email: email})
	if err != nil {
		return nil, err
	}

	return &requestPasswordResetResult{ResetToken: res.GetResetToken()}, nil
}

func (s *testAuthService) ValidateAccessToken(tokenString string) (*service.Claims, error) {
	return s.userAuthService.ValidateAccessToken(tokenString)
}

func (s *testAuthService) ValidateInternalAPIKey(ctx context.Context, apiKey string) (*internalAccessResult, error) {
	res, err := s.internalAuthService.ValidateInternalAPIKey(ctx, apiKey)
	if err != nil {
		return nil, err
	}

	return &internalAccessResult{
		ServiceName:   res.GetServiceName(),
		AllowedAccess: res.GetAllowedAccess(),
	}, nil
}

func (s *testAuthService) GenerateInternalAPIKey(ctx context.Context, serviceName string) (string, error) {
	return s.internalAuthService.GenerateInternalAPIKey(ctx, serviceName)
}

func (s *testAuthService) AddInternalAllowedAccess(ctx context.Context, serviceName, allowedService string) error {
	return s.internalAuthService.AddInternalAllowedAccess(ctx, serviceName, allowedService)
}

func (s *testAuthService) RegenerateInternalAPIKey(ctx context.Context, serviceName string, oldKeyTTL time.Duration) (string, error) {
	return s.internalAuthService.RegenerateInternalAPIKey(ctx, serviceName, oldKeyTTL)
}

func newServiceWithMock(t *testing.T) (*testAuthService, sqlmock.Sqlmock, func()) {
	t.Helper()

	return newServiceWithMockAndPolicy(t, config.PasswordPolicy{
		MinLength:        1,
		RequireUppercase: false,
		RequireLowercase: false,
		RequireNumber:    false,
		RequireSpecial:   false,
	})
}

func newServiceWithMockAndPolicy(t *testing.T, policy config.PasswordPolicy) (*testAuthService, sqlmock.Sqlmock, func()) {
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
			Policy: policy,
		},
	}

	userRepo := repository.NewUserRepository(db)
	refreshRepo := repository.NewRefreshTokenRepository(db)
	internalAPIKeyRepo := repository.NewInternalAPIKeyRepository(db)
	svc := &testAuthService{
		userAuthService:     service.NewUserAuthService(db, userRepo, refreshRepo, cfg),
		internalAuthService: service.NewInternalAuthService(internalAPIKeyRepo),
	}

	return svc, mock, func() { _ = db.Close() }
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

func hashInternalAPIKeyForTest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func TestAuthService_Register_CreatesUser(t *testing.T) {
	svc, mock, cleanup := newServiceWithMock(t)
	defer cleanup()

	email := "Test.User+tag@gmail.com"
	canonical := service.CanonicalizeEmail(email)

	mock.ExpectQuery(findByCanonicalEmailQuery).
		WithArgs(canonical).
		WillReturnRows(sqlmock.NewRows(userColumns))
	mock.ExpectBegin()
	mock.ExpectExec(insertUserQuery).
		WithArgs(email, canonical, sqlmock.AnyArg(), false, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(insertUserRoleQuery).
		WithArgs(uint64(1), service.RoleUser).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	res, err := svc.Register(context.Background(), email, "password")
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if res.User.ID != 1 {
		t.Fatalf("expected user ID 1, got %d", res.User.ID)
	}
	if res.ConfirmToken == "" {
		t.Fatalf("expected confirm token to be set")
	}
	if len(res.User.Roles) != 1 || res.User.Roles[0] != service.RoleUser {
		t.Fatalf("expected default role %q, got %#v", service.RoleUser, res.User.Roles)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAuthService_Register_WeakPassword(t *testing.T) {
	svc, mock, cleanup := newServiceWithMockAndPolicy(t, config.PasswordPolicy{
		MinLength:        8,
		RequireUppercase: false,
		RequireLowercase: false,
		RequireNumber:    false,
		RequireSpecial:   false,
	})
	defer cleanup()

	email := "user@example.com"
	canonical := service.CanonicalizeEmail(email)

	mock.ExpectQuery(findByCanonicalEmailQuery).
		WithArgs(canonical).
		WillReturnRows(sqlmock.NewRows(userColumns))

	_, err := svc.Register(context.Background(), email, "short")
	if err == nil || !errors.Is(err, service.ErrWeakPassword) {
		t.Fatalf("expected ErrWeakPassword, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAuthService_Login_ReturnsTokens(t *testing.T) {
	svc, mock, cleanup := newServiceWithMock(t)
	defer cleanup()

	email := "user@example.com"
	canonical := service.CanonicalizeEmail(email)
	hashed, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	now := time.Now()

	mock.ExpectQuery(findByCanonicalEmailQuery).
		WithArgs(canonical).
		WillReturnRows(sqlmock.NewRows(userColumns).AddRow(
			uint64(1),
			email,
			canonical,
			string(hashed),
			true,
			sql.NullString{Valid: false},
			sql.NullTime{Valid: false},
			sql.NullString{Valid: false},
			sql.NullTime{Valid: false},
			now,
			now,
		))
	expectUserRolesQuery(mock, 1, service.RoleUser)
	mock.ExpectExec(insertRefreshTokenQuery).
		WithArgs(uint64(1), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	res, err := svc.Login(context.Background(), email, "password", 0)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatalf("expected tokens to be set")
	}
	if res.ExpiresIn <= 0 {
		t.Fatalf("expected positive expires_in")
	}
	if len(res.Roles) != 1 || res.Roles[0] != service.RoleUser {
		t.Fatalf("expected roles to contain %q, got %#v", service.RoleUser, res.Roles)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAuthService_RefreshToken_RotatesToken(t *testing.T) {
	svc, mock, cleanup := newServiceWithMock(t)
	defer cleanup()

	oldToken := "old-refresh-token"
	now := time.Now()

	mock.ExpectBegin()
	mock.ExpectQuery(findRefreshTokenForUpdate).
		WithArgs(oldToken).
		WillReturnRows(sqlmock.NewRows(refreshTokenColumns).AddRow(
			uint64(10),
			uint64(1),
			oldToken,
			now.Add(time.Hour),
			now,
		))

	email := "user@example.com"
	canonical := service.CanonicalizeEmail(email)
	mock.ExpectQuery(findByIDQuery).
		WithArgs(uint64(1)).
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
			now,
			now,
		))
	expectUserRolesQuery(mock, 1, service.RoleUser)

	mock.ExpectExec(deleteRefreshTokenQuery).
		WithArgs(oldToken, uint64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(insertRefreshTokenQuery).
		WithArgs(uint64(1), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(11, 1))
	mock.ExpectCommit()

	res, err := svc.RefreshToken(context.Background(), oldToken)
	if err != nil {
		t.Fatalf("refresh token failed: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatalf("expected rotated tokens")
	}
	if len(res.Roles) != 1 || res.Roles[0] != service.RoleUser {
		t.Fatalf("expected roles to contain %q, got %#v", service.RoleUser, res.Roles)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAuthService_RefreshToken_Expired(t *testing.T) {
	svc, mock, cleanup := newServiceWithMock(t)
	defer cleanup()

	oldToken := "expired-refresh-token"
	now := time.Now()

	mock.ExpectBegin()
	mock.ExpectQuery(findRefreshTokenForUpdate).
		WithArgs(oldToken).
		WillReturnRows(sqlmock.NewRows(refreshTokenColumns).AddRow(
			uint64(10),
			uint64(1),
			oldToken,
			now.Add(-time.Minute),
			now,
		))
	mock.ExpectRollback()

	_, err := svc.RefreshToken(context.Background(), oldToken)
	if err == nil || !errors.Is(err, service.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAuthService_ChangePassword_RevokesRefreshTokens(t *testing.T) {
	svc, mock, cleanup := newServiceWithMock(t)
	defer cleanup()

	email := "user@example.com"
	canonical := service.CanonicalizeEmail(email)
	oldHash, _ := bcrypt.GenerateFromPassword([]byte("old-pass"), bcrypt.DefaultCost)
	now := time.Now()

	mock.ExpectQuery(findByIDQuery).
		WithArgs(uint64(1)).
		WillReturnRows(sqlmock.NewRows(userColumns).AddRow(
			uint64(1),
			email,
			canonical,
			string(oldHash),
			true,
			sql.NullString{Valid: false},
			sql.NullTime{Valid: false},
			sql.NullString{Valid: false},
			sql.NullTime{Valid: false},
			now,
			now,
		))
	expectUserRolesQuery(mock, 1, service.RoleUser)
	mock.ExpectExec(updateUserQuery).
		WithArgs(email, canonical, sqlmock.AnyArg(), true, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), uint64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(deleteByUserIDQuery).
		WithArgs(uint64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := svc.ChangePassword(context.Background(), 1, "old-pass", "new-pass"); err != nil {
		t.Fatalf("change password failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAuthService_ResetPassword_RevokesRefreshTokens(t *testing.T) {
	svc, mock, cleanup := newServiceWithMock(t)
	defer cleanup()

	email := "user@example.com"
	canonical := service.CanonicalizeEmail(email)
	now := time.Now()

	mock.ExpectQuery(findByResetTokenQuery).
		WithArgs("reset-token").
		WillReturnRows(sqlmock.NewRows(userColumns).AddRow(
			uint64(1),
			email,
			canonical,
			"hash",
			true,
			sql.NullString{Valid: false},
			sql.NullTime{Valid: false},
			sql.NullString{String: "reset-token", Valid: true},
			sql.NullTime{Time: now.Add(time.Hour), Valid: true},
			now,
			now,
		))
	mock.ExpectExec(updateUserQuery).
		WithArgs(email, canonical, sqlmock.AnyArg(), true, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), uint64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(deleteByUserIDQuery).
		WithArgs(uint64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := svc.ResetPassword(context.Background(), "reset-token", "new-pass"); err != nil {
		t.Fatalf("reset password failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAuthService_RequestPasswordReset_ReusesValidToken(t *testing.T) {
	svc, mock, cleanup := newServiceWithMock(t)
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
			sql.NullString{String: "reset-token", Valid: true},
			sql.NullTime{Time: now.Add(time.Hour), Valid: true},
			now,
			now,
		))
	expectUserRolesQuery(mock, 1, service.RoleUser)

	res, err := svc.RequestPasswordReset(context.Background(), email)
	if err != nil {
		t.Fatalf("request password reset failed: %v", err)
	}
	if res.ResetToken != "reset-token" {
		t.Fatalf("expected existing reset token to be reused")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAuthService_ValidateAccessToken_RejectsNonHMAC(t *testing.T) {
	svc, _, cleanup := newServiceWithMock(t)
	defer cleanup()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	claims := &service.Claims{
		UserID: 1,
		Email:  "user@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	if _, err := svc.ValidateAccessToken(tokenString); err == nil {
		t.Fatalf("expected validation to fail for non-HMAC token")
	}
}
