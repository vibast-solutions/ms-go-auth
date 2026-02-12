package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/vibast-solutions/ms-go-auth/app/entity"
)

type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

type UserRepository struct {
	db DBTX
}

func NewUserRepository(db DBTX) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *entity.User) error {
	query := `
		INSERT INTO users (email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at, last_login, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	result, err := r.db.ExecContext(ctx, query,
		user.Email,
		user.CanonicalEmail,
		user.PasswordHash,
		user.IsConfirmed,
		user.ConfirmToken,
		user.ConfirmTokenExpiresAt,
		user.LastLogin,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	user.ID = uint64(id)
	return nil
}

func (r *UserRepository) FindByCanonicalEmail(ctx context.Context, canonicalEmail string) (*entity.User, error) {
	query := `
		SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,
		       reset_token, reset_token_expires_at, last_login, created_at, updated_at
		FROM users WHERE canonical_email = ?
	`
	user := &entity.User{}
	err := r.db.QueryRowContext(ctx, query, canonicalEmail).Scan(
		&user.ID,
		&user.Email,
		&user.CanonicalEmail,
		&user.PasswordHash,
		&user.IsConfirmed,
		&user.ConfirmToken,
		&user.ConfirmTokenExpiresAt,
		&user.ResetToken,
		&user.ResetTokenExpiresAt,
		&user.LastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	roles, err := r.ListRolesByUserID(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	user.Roles = roles
	return user, nil
}

func (r *UserRepository) FindByID(ctx context.Context, id uint64) (*entity.User, error) {
	query := `
		SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,
		       reset_token, reset_token_expires_at, last_login, created_at, updated_at
		FROM users WHERE id = ?
	`
	user := &entity.User{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.CanonicalEmail,
		&user.PasswordHash,
		&user.IsConfirmed,
		&user.ConfirmToken,
		&user.ConfirmTokenExpiresAt,
		&user.ResetToken,
		&user.ResetTokenExpiresAt,
		&user.LastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	roles, err := r.ListRolesByUserID(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	user.Roles = roles
	return user, nil
}

func (r *UserRepository) AddRole(ctx context.Context, userID uint64, role string) error {
	query := `INSERT INTO user_roles (user_id, role) VALUES (?, ?)`
	_, err := r.db.ExecContext(ctx, query, userID, role)
	return err
}

func (r *UserRepository) ListRolesByUserID(ctx context.Context, userID uint64) ([]string, error) {
	query := `SELECT role FROM user_roles WHERE user_id = ? ORDER BY role`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := make([]string, 0)
	for rows.Next() {
		var role string
		if err = rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return roles, nil
}

func (r *UserRepository) FindByConfirmToken(ctx context.Context, token string) (*entity.User, error) {
	query := `
		SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,
		       reset_token, reset_token_expires_at, last_login, created_at, updated_at
		FROM users WHERE confirm_token = ?
	`
	user := &entity.User{}
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&user.ID,
		&user.Email,
		&user.CanonicalEmail,
		&user.PasswordHash,
		&user.IsConfirmed,
		&user.ConfirmToken,
		&user.ConfirmTokenExpiresAt,
		&user.ResetToken,
		&user.ResetTokenExpiresAt,
		&user.LastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) FindByResetToken(ctx context.Context, token string) (*entity.User, error) {
	query := `
		SELECT id, email, canonical_email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,
		       reset_token, reset_token_expires_at, last_login, created_at, updated_at
		FROM users WHERE reset_token = ?
	`
	user := &entity.User{}
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&user.ID,
		&user.Email,
		&user.CanonicalEmail,
		&user.PasswordHash,
		&user.IsConfirmed,
		&user.ConfirmToken,
		&user.ConfirmTokenExpiresAt,
		&user.ResetToken,
		&user.ResetTokenExpiresAt,
		&user.LastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) Update(ctx context.Context, user *entity.User) error {
	query := `
		UPDATE users SET
			email = ?,
			canonical_email = ?,
			password_hash = ?,
			is_confirmed = ?,
			confirm_token = ?,
			confirm_token_expires_at = ?,
			reset_token = ?,
			reset_token_expires_at = ?,
			last_login = ?,
			updated_at = ?
		WHERE id = ?
	`
	user.UpdatedAt = time.Now()
	_, err := r.db.ExecContext(ctx, query,
		user.Email,
		user.CanonicalEmail,
		user.PasswordHash,
		user.IsConfirmed,
		user.ConfirmToken,
		user.ConfirmTokenExpiresAt,
		user.ResetToken,
		user.ResetTokenExpiresAt,
		user.LastLogin,
		user.UpdatedAt,
		user.ID,
	)
	return err
}

func (r *UserRepository) UpdateLastLogin(ctx context.Context, userID uint64, lastLogin time.Time) error {
	query := `
		UPDATE users
		SET last_login = ?, updated_at = ?
		WHERE id = ?
	`
	_, err := r.db.ExecContext(ctx, query, lastLogin, time.Now(), userID)
	return err
}

type RefreshTokenRepository struct {
	db DBTX
}

func NewRefreshTokenRepository(db DBTX) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

func (r *RefreshTokenRepository) Create(ctx context.Context, token *entity.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (user_id, token, expires_at, created_at)
		VALUES (?, ?, ?, ?)
	`
	result, err := r.db.ExecContext(ctx, query,
		token.UserID,
		token.Token,
		token.ExpiresAt,
		token.CreatedAt,
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	token.ID = uint64(id)
	return nil
}

func (r *RefreshTokenRepository) FindByToken(ctx context.Context, token string) (*entity.RefreshToken, error) {
	query := `
		SELECT id, user_id, token, expires_at, created_at
		FROM refresh_tokens WHERE token = ?
	`
	rt := &entity.RefreshToken{}
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&rt.ID,
		&rt.UserID,
		&rt.Token,
		&rt.ExpiresAt,
		&rt.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rt, nil
}

func (r *RefreshTokenRepository) FindByTokenForUpdate(ctx context.Context, token string) (*entity.RefreshToken, error) {
	query := `
		SELECT id, user_id, token, expires_at, created_at
		FROM refresh_tokens WHERE token = ? FOR UPDATE
	`
	rt := &entity.RefreshToken{}
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&rt.ID,
		&rt.UserID,
		&rt.Token,
		&rt.ExpiresAt,
		&rt.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rt, nil
}

func (r *RefreshTokenRepository) DeleteByToken(ctx context.Context, token string, userID uint64) (int64, error) {
	query := `DELETE FROM refresh_tokens WHERE token = ? AND user_id = ?`
	result, err := r.db.ExecContext(ctx, query, token, userID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (r *RefreshTokenRepository) DeleteByUserID(ctx context.Context, userID uint64) error {
	query := `DELETE FROM refresh_tokens WHERE user_id = ?`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM refresh_tokens WHERE expires_at < ?`
	_, err := r.db.ExecContext(ctx, query, time.Now())
	return err
}
