package grpc_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	authgrpc "auth/app/grpc"
	"auth/app/repository"
	"auth/app/service"
	"auth/app/types"
	"auth/config"

	"github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	findByCanonicalEmailQuery = `(?s)SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,\s+reset_token, reset_token_expires_at, created_at, updated_at\s+FROM users WHERE canonical_email = \?`
	findByConfirmTokenQuery   = `(?s)SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,\s+reset_token, reset_token_expires_at, created_at, updated_at\s+FROM users WHERE confirm_token = \?`
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
		JWTSecret:          "test-secret",
		JWTAccessTokenTTL:  15 * time.Minute,
		JWTRefreshTokenTTL: 7 * 24 * time.Hour,
		ConfirmTokenTTL:    24 * time.Hour,
		ResetTokenTTL:      time.Hour,
		PasswordPolicy: config.PasswordPolicy{
			MinLength:        8,
			RequireUppercase: false,
			RequireLowercase: false,
			RequireNumber:    false,
			RequireSpecial:   false,
		},
	}

	userRepo := repository.NewUserRepository(db)
	refreshRepo := repository.NewRefreshTokenRepository(db)
	authService := service.NewAuthService(db, userRepo, refreshRepo, cfg)

	return authgrpc.NewAuthServer(authService), mock, func() { _ = db.Close() }
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
