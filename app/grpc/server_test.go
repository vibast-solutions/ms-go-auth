package grpc_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	authgrpc "github.com/vibast-solutions/ms-go-auth/app/grpc"
	"github.com/vibast-solutions/ms-go-auth/app/repository"
	"github.com/vibast-solutions/ms-go-auth/app/service"
	"github.com/vibast-solutions/ms-go-auth/app/types"
	"github.com/vibast-solutions/ms-go-auth/config"

	"github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	findByCanonicalEmailQuery = `(?s)SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,\s+reset_token, reset_token_expires_at, last_login, created_at, updated_at\s+FROM users WHERE canonical_email = \?`
	findByConfirmTokenQuery   = `(?s)SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,\s+reset_token, reset_token_expires_at, last_login, created_at, updated_at\s+FROM users WHERE confirm_token = \?`
	insertUserQuery           = `(?s)INSERT INTO users \(email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at, last_login, created_at, updated_at\)\s+VALUES \(\?, \?, \?, \?, \?, \?, \?, \?, \?\)`
	insertUserRoleQuery       = `(?s)INSERT INTO user_roles \(user_id, role\) VALUES \(\?, \?\)`
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

func newGRPCServerWithMock(t *testing.T) (*authgrpc.AuthServer, sqlmock.Sqlmock, func()) {
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

	return authgrpc.NewAuthServer(userAuthService, internalAuthService), mock, func() { _ = db.Close() }
}

func TestRegister_WeakPassword(t *testing.T) {
	server, mock, cleanup := newGRPCServerWithMock(t)
	defer cleanup()

	email := "user@example.com"
	canonical := service.CanonicalizeEmail(email)

	mock.ExpectQuery(findByCanonicalEmailQuery).
		WithArgs(canonical).
		WillReturnRows(sqlmock.NewRows(userColumns))

	_, err := server.Register(context.Background(), &types.RegisterRequest{
		Email:    email,
		Password: "short",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRegister_SuccessIncludesRoles(t *testing.T) {
	server, mock, cleanup := newGRPCServerWithMock(t)
	defer cleanup()

	email := "user@example.com"
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

	res, err := server.Register(context.Background(), &types.RegisterRequest{
		Email:    email,
		Password: "password",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.GetRoles()) != 1 || res.GetRoles()[0] != service.RoleUser {
		t.Fatalf("expected roles [%q], got %#v", service.RoleUser, res.GetRoles())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestLogin_InvalidCredentials(t *testing.T) {
	server, mock, cleanup := newGRPCServerWithMock(t)
	defer cleanup()

	email := "user@example.com"
	canonical := service.CanonicalizeEmail(email)

	mock.ExpectQuery(findByCanonicalEmailQuery).
		WithArgs(canonical).
		WillReturnRows(sqlmock.NewRows(userColumns))

	_, err := server.Login(context.Background(), &types.LoginRequest{
		Email:    email,
		Password: "bad-password",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", status.Code(err))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestLogin_NegativeTokenDuration(t *testing.T) {
	server, _, cleanup := newGRPCServerWithMock(t)
	defer cleanup()

	_, err := server.Login(context.Background(), &types.LoginRequest{
		Email:         "user@example.com",
		Password:      "password",
		TokenDuration: -1,
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestConfirmAccount_InvalidToken(t *testing.T) {
	server, mock, cleanup := newGRPCServerWithMock(t)
	defer cleanup()

	mock.ExpectQuery(findByConfirmTokenQuery).
		WithArgs("bad-token").
		WillReturnRows(sqlmock.NewRows(userColumns))

	_, err := server.ConfirmAccount(context.Background(), &types.ConfirmAccountRequest{
		Token: "bad-token",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRequestPasswordReset_UnknownUser(t *testing.T) {
	server, mock, cleanup := newGRPCServerWithMock(t)
	defer cleanup()

	email := "missing@example.com"
	canonical := service.CanonicalizeEmail(email)

	mock.ExpectQuery(findByCanonicalEmailQuery).
		WithArgs(canonical).
		WillReturnRows(sqlmock.NewRows(userColumns))

	res, err := server.RequestPasswordReset(context.Background(), &types.RequestPasswordResetRequest{
		Email: email,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.Message == "" {
		t.Fatalf("expected message for unknown user")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestValidateToken_InvalidToken(t *testing.T) {
	server, _, cleanup := newGRPCServerWithMock(t)
	defer cleanup()

	res, err := server.ValidateToken(context.Background(), &types.ValidateTokenRequest{
		AccessToken: "invalid-token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.Valid {
		t.Fatalf("expected Valid=false response")
	}
}

func TestValidateInternalAccess_MissingAPIKey(t *testing.T) {
	server, _, cleanup := newGRPCServerWithMock(t)
	defer cleanup()

	_, err := server.ValidateInternalAccess(context.Background(), &types.ValidateInternalAccessRequest{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestValidateInternalAccess_InvalidAPIKey(t *testing.T) {
	server, mock, cleanup := newGRPCServerWithMock(t)
	defer cleanup()

	mock.ExpectQuery(findInternalByHashQuery).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(internalAPIKeyColumns))

	_, err := server.ValidateInternalAccess(context.Background(), &types.ValidateInternalAccessRequest{
		ApiKey: "invalid",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", status.Code(err))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestValidateInternalAccess_Success(t *testing.T) {
	server, mock, cleanup := newGRPCServerWithMock(t)
	defer cleanup()

	now := time.Now()
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

	res, err := server.ValidateInternalAccess(context.Background(), &types.ValidateInternalAccessRequest{
		ApiKey: "valid",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ServiceName != "profile-service" {
		t.Fatalf("expected service_name profile-service, got %q", res.ServiceName)
	}
	if len(res.AllowedAccess) != 2 {
		t.Fatalf("expected allowed access entries, got %#v", res.AllowedAccess)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRegister_InvalidArgument(t *testing.T) {
	server, _, cleanup := newGRPCServerWithMock(t)
	defer cleanup()

	_, err := server.Register(context.Background(), &types.RegisterRequest{
		Email:    "",
		Password: "password",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestConfirmAccount_ExpiredToken(t *testing.T) {
	server, mock, cleanup := newGRPCServerWithMock(t)
	defer cleanup()

	now := time.Now()
	mock.ExpectQuery(findByConfirmTokenQuery).
		WithArgs("expired-token").
		WillReturnRows(sqlmock.NewRows(userColumns).AddRow(
			uint64(1),
			"user@example.com",
			"user@example.com",
			"hash",
			false,
			sql.NullString{String: "expired-token", Valid: true},
			sql.NullTime{Time: now.Add(-time.Hour), Valid: true},
			sql.NullString{Valid: false},
			sql.NullTime{Valid: false},
			sql.NullTime{Valid: false},
			now,
			now,
		))

	_, err := server.ConfirmAccount(context.Background(), &types.ConfirmAccountRequest{
		Token: "expired-token",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	server, mock, cleanup := newGRPCServerWithMock(t)
	defer cleanup()

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, user_id, token, expires_at, created_at\s+FROM refresh_tokens WHERE token = \? FOR UPDATE`).
		WithArgs("missing").
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "token", "expires_at", "created_at"}))
	mock.ExpectRollback()

	_, err := server.RefreshToken(context.Background(), &types.RefreshTokenRequest{
		RefreshToken: "missing",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", status.Code(err))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
