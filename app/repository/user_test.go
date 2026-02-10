package repository_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/vibast-solutions/ms-go-auth/app/entity"
	"github.com/vibast-solutions/ms-go-auth/app/repository"
	"github.com/vibast-solutions/ms-go-auth/app/service"

	"github.com/DATA-DOG/go-sqlmock"
)

const (
	insertUserQuery           = `(?s)INSERT INTO users \(email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at, created_at, updated_at\)\s+VALUES \(\?, \?, \?, \?, \?, \?, \?, \?\)`
	insertUserRoleQuery       = `(?s)INSERT INTO user_roles \(user_id, role\) VALUES \(\?, \?\)`
	updateUserQuery           = `(?s)UPDATE users SET\s+email = \?,\s+canonical_email = \?,\s+password_hash = \?,\s+is_confirmed = \?,\s+confirm_token = \?,\s+confirm_token_expires_at = \?,\s+reset_token = \?,\s+reset_token_expires_at = \?,\s+updated_at = \?\s+WHERE id = \?`
	findByCanonicalEmailQuery = `(?s)SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,\s+reset_token, reset_token_expires_at, created_at, updated_at\s+FROM users WHERE canonical_email = \?`
	listUserRolesQuery        = `(?s)SELECT role FROM user_roles WHERE user_id = \? ORDER BY role`
	findRefreshTokenForUpdate = `(?s)SELECT id, user_id, token, expires_at, created_at\s+FROM refresh_tokens WHERE token = \? FOR UPDATE`
	deleteRefreshTokenQuery   = `(?s)DELETE FROM refresh_tokens WHERE token = \? AND user_id = \?`
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

var refreshTokenColumns = []string{
	"id",
	"user_id",
	"token",
	"expires_at",
	"created_at",
}

var roleColumns = []string{
	"role",
}

func newMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock, func()) {
	t.Helper()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	return db, mock, func() { _ = db.Close() }
}

func TestUserRepository_Create(t *testing.T) {
	db, mock, cleanup := newMockDB(t)
	defer cleanup()

	repo := repository.NewUserRepository(db)
	now := time.Now()
	user := &entity.User{
		Email:          "user@example.com",
		CanonicalEmail: "user@example.com",
		PasswordHash:   "hash",
		IsConfirmed:    false,
		ConfirmToken:   sql.NullString{String: "token", Valid: true},
		ConfirmTokenExpiresAt: sql.NullTime{
			Time:  now.Add(time.Hour),
			Valid: true,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	mock.ExpectExec(insertUserQuery).
		WithArgs(
			user.Email,
			user.CanonicalEmail,
			user.PasswordHash,
			user.IsConfirmed,
			user.ConfirmToken,
			user.ConfirmTokenExpiresAt,
			user.CreatedAt,
			user.UpdatedAt,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Create(context.Background(), user); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if user.ID != 1 {
		t.Fatalf("expected ID 1, got %d", user.ID)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestUserRepository_FindByCanonicalEmail(t *testing.T) {
	db, mock, cleanup := newMockDB(t)
	defer cleanup()

	repo := repository.NewUserRepository(db)
	now := time.Now()

	mock.ExpectQuery(findByCanonicalEmailQuery).
		WithArgs("user@example.com").
		WillReturnRows(sqlmock.NewRows(userColumns).AddRow(
			uint64(1),
			"user@example.com",
			"user@example.com",
			"hash",
			true,
			sql.NullString{Valid: false},
			sql.NullTime{Valid: false},
			sql.NullString{Valid: false},
			sql.NullTime{Valid: false},
			now,
			now,
		))
	mock.ExpectQuery(listUserRolesQuery).
		WithArgs(uint64(1)).
		WillReturnRows(sqlmock.NewRows(roleColumns).AddRow(service.RoleUser))

	user, err := repo.FindByCanonicalEmail(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("find failed: %v", err)
	}
	if user == nil || user.ID != 1 {
		t.Fatalf("expected user ID 1, got %+v", user)
	}
	if len(user.Roles) != 1 || user.Roles[0] != service.RoleUser {
		t.Fatalf("expected roles [%q], got %#v", service.RoleUser, user.Roles)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestUserRepository_Update(t *testing.T) {
	db, mock, cleanup := newMockDB(t)
	defer cleanup()

	repo := repository.NewUserRepository(db)
	user := &entity.User{
		ID:             1,
		Email:          "user@example.com",
		CanonicalEmail: "user@example.com",
		PasswordHash:   "hash",
		IsConfirmed:    true,
	}

	mock.ExpectExec(updateUserQuery).
		WithArgs(
			user.Email,
			user.CanonicalEmail,
			user.PasswordHash,
			user.IsConfirmed,
			user.ConfirmToken,
			user.ConfirmTokenExpiresAt,
			user.ResetToken,
			user.ResetTokenExpiresAt,
			sqlmock.AnyArg(),
			user.ID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repo.Update(context.Background(), user); err != nil {
		t.Fatalf("update failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRefreshTokenRepository_FindByTokenForUpdate(t *testing.T) {
	db, mock, cleanup := newMockDB(t)
	defer cleanup()

	repo := repository.NewRefreshTokenRepository(db)
	now := time.Now()

	mock.ExpectQuery(findRefreshTokenForUpdate).
		WithArgs("token").
		WillReturnRows(sqlmock.NewRows(refreshTokenColumns).AddRow(
			uint64(1),
			uint64(2),
			"token",
			now.Add(time.Hour),
			now,
		))

	rt, err := repo.FindByTokenForUpdate(context.Background(), "token")
	if err != nil {
		t.Fatalf("find failed: %v", err)
	}
	if rt == nil || rt.ID != 1 || rt.UserID != 2 {
		t.Fatalf("unexpected refresh token: %+v", rt)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRefreshTokenRepository_DeleteByToken(t *testing.T) {
	db, mock, cleanup := newMockDB(t)
	defer cleanup()

	repo := repository.NewRefreshTokenRepository(db)

	mock.ExpectExec(deleteRefreshTokenQuery).
		WithArgs("token", uint64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	rows, err := repo.DeleteByToken(context.Background(), "token", 1)
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if rows != 1 {
		t.Fatalf("expected 1 row affected, got %d", rows)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestUserRepository_AddRole(t *testing.T) {
	db, mock, cleanup := newMockDB(t)
	defer cleanup()

	repo := repository.NewUserRepository(db)

	mock.ExpectExec(insertUserRoleQuery).
		WithArgs(uint64(1), service.RoleUser).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repo.AddRole(context.Background(), 1, service.RoleUser); err != nil {
		t.Fatalf("add role failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
