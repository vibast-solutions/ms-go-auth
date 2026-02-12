package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/vibast-solutions/ms-go-auth/app/entity"
)

type InternalAPIKeyRepository struct {
	db DBTX
}

func NewInternalAPIKeyRepository(db DBTX) *InternalAPIKeyRepository {
	return &InternalAPIKeyRepository{db: db}
}

func (r *InternalAPIKeyRepository) Create(ctx context.Context, key *entity.InternalAPIKey) error {
	allowedAccess, err := json.Marshal(key.AllowedAccess)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO internal_api_keys (
			service_name, key_hash, allowed_access_json, is_active, expires_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	result, err := r.db.ExecContext(ctx, query,
		key.ServiceName,
		key.KeyHash,
		string(allowedAccess),
		key.IsActive,
		key.ExpiresAt,
		key.CreatedAt,
		key.UpdatedAt,
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	key.ID = uint64(id)
	return nil
}

func (r *InternalAPIKeyRepository) FindActiveByHash(ctx context.Context, keyHash string) (*entity.InternalAPIKey, error) {
	query := `
		SELECT id, service_name, key_hash, allowed_access_json, is_active, expires_at, created_at, updated_at
		FROM internal_api_keys
		WHERE key_hash = ? AND is_active = 1 AND expires_at > NOW()
		ORDER BY id DESC
		LIMIT 1
	`
	return r.findOne(ctx, query, keyHash)
}

func (r *InternalAPIKeyRepository) FindActiveByServiceName(ctx context.Context, serviceName string, now time.Time) ([]*entity.InternalAPIKey, error) {
	query := `
		SELECT id, service_name, key_hash, allowed_access_json, is_active, expires_at, created_at, updated_at
		FROM internal_api_keys
		WHERE service_name = ? AND is_active = 1 AND expires_at > ?
		ORDER BY id DESC
	`
	rows, err := r.db.QueryContext(ctx, query, serviceName, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]*entity.InternalAPIKey, 0)
	for rows.Next() {
		key, err := scanInternalAPIKey(rows.Scan)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return keys, nil
}

func (r *InternalAPIKeyRepository) Update(ctx context.Context, key *entity.InternalAPIKey) error {
	allowedAccess, err := json.Marshal(key.AllowedAccess)
	if err != nil {
		return err
	}

	query := `
		UPDATE internal_api_keys SET
			service_name = ?,
			key_hash = ?,
			allowed_access_json = ?,
			is_active = ?,
			expires_at = ?,
			updated_at = ?
		WHERE id = ?
	`
	_, err = r.db.ExecContext(ctx, query,
		key.ServiceName,
		key.KeyHash,
		string(allowedAccess),
		key.IsActive,
		key.ExpiresAt,
		key.UpdatedAt,
		key.ID,
	)
	return err
}

func (r *InternalAPIKeyRepository) findOne(ctx context.Context, query string, args ...interface{}) (*entity.InternalAPIKey, error) {
	row := r.db.QueryRowContext(ctx, query, args...)
	key, err := scanInternalAPIKey(row.Scan)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return key, nil
}

type rowScanner func(dest ...interface{}) error

func scanInternalAPIKey(scan rowScanner) (*entity.InternalAPIKey, error) {
	key := &entity.InternalAPIKey{}
	var allowedAccessJSON string
	if err := scan(
		&key.ID,
		&key.ServiceName,
		&key.KeyHash,
		&allowedAccessJSON,
		&key.IsActive,
		&key.ExpiresAt,
		&key.CreatedAt,
		&key.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(allowedAccessJSON), &key.AllowedAccess); err != nil {
		return nil, err
	}

	return key, nil
}
