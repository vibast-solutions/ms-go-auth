package repository

import (
	"context"
	"database/sql"
	"time"

	"auth/app/entity"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *entity.User) error {
	query := `
		INSERT INTO users (email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	result, err := r.db.ExecContext(ctx, query,
		user.Email,
		user.PasswordHash,
		user.IsConfirmed,
		user.ConfirmToken,
		user.ConfirmTokenExpiresAt,
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

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*entity.User, error) {
	query := `
		SELECT id, email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,
		       reset_token, reset_token_expires_at, created_at, updated_at
		FROM users WHERE email = ?
	`
	user := &entity.User{}
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.IsConfirmed,
		&user.ConfirmToken,
		&user.ConfirmTokenExpiresAt,
		&user.ResetToken,
		&user.ResetTokenExpiresAt,
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

func (r *UserRepository) FindByID(ctx context.Context, id uint64) (*entity.User, error) {
	query := `
		SELECT id, email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,
		       reset_token, reset_token_expires_at, created_at, updated_at
		FROM users WHERE id = ?
	`
	user := &entity.User{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.IsConfirmed,
		&user.ConfirmToken,
		&user.ConfirmTokenExpiresAt,
		&user.ResetToken,
		&user.ResetTokenExpiresAt,
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

func (r *UserRepository) FindByConfirmToken(ctx context.Context, token string) (*entity.User, error) {
	query := `
		SELECT id, email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,
		       reset_token, reset_token_expires_at, created_at, updated_at
		FROM users WHERE confirm_token = ?
	`
	user := &entity.User{}
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.IsConfirmed,
		&user.ConfirmToken,
		&user.ConfirmTokenExpiresAt,
		&user.ResetToken,
		&user.ResetTokenExpiresAt,
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
		SELECT id, email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at,
		       reset_token, reset_token_expires_at, created_at, updated_at
		FROM users WHERE reset_token = ?
	`
	user := &entity.User{}
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.IsConfirmed,
		&user.ConfirmToken,
		&user.ConfirmTokenExpiresAt,
		&user.ResetToken,
		&user.ResetTokenExpiresAt,
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
			password_hash = ?,
			is_confirmed = ?,
			confirm_token = ?,
			confirm_token_expires_at = ?,
			reset_token = ?,
			reset_token_expires_at = ?,
			updated_at = ?
		WHERE id = ?
	`
	user.UpdatedAt = time.Now()
	_, err := r.db.ExecContext(ctx, query,
		user.Email,
		user.PasswordHash,
		user.IsConfirmed,
		user.ConfirmToken,
		user.ConfirmTokenExpiresAt,
		user.ResetToken,
		user.ResetTokenExpiresAt,
		user.UpdatedAt,
		user.ID,
	)
	return err
}

type RefreshTokenRepository struct {
	db *sql.DB
}

func NewRefreshTokenRepository(db *sql.DB) *RefreshTokenRepository {
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

func (r *RefreshTokenRepository) DeleteByToken(ctx context.Context, token string) error {
	query := `DELETE FROM refresh_tokens WHERE token = ?`
	_, err := r.db.ExecContext(ctx, query, token)
	return err
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
