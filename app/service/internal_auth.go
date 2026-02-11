package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/vibast-solutions/ms-go-auth/app/entity"
	"github.com/vibast-solutions/ms-go-auth/app/types"
)

var (
	ErrInvalidInternalAPIKey    = errors.New("invalid or expired internal api key")
	ErrServiceHasActiveAPIKey   = errors.New("service already has an active api key")
	ErrServiceHasNoActiveAPIKey = errors.New("service has no active api key")
	ErrInvalidRegenerationTTL   = errors.New("invalid regeneration ttl")
)

type InternalAPIKeyRepository interface {
	Create(ctx context.Context, key *entity.InternalAPIKey) error
	FindActiveByHash(ctx context.Context, keyHash string) (*entity.InternalAPIKey, error)
	FindActiveByServiceName(ctx context.Context, serviceName string, now time.Time) ([]*entity.InternalAPIKey, error)
	Update(ctx context.Context, key *entity.InternalAPIKey) error
}

type InternalAuthService interface {
	ValidateInternalAPIKey(ctx context.Context, apiKey string) (*types.ValidateInternalAccessResponse, error)
	GenerateInternalAPIKey(ctx context.Context, serviceName string) (string, error)
	AddInternalAllowedAccess(ctx context.Context, serviceName, allowedService string) error
	DeactivateInternalAPIKeys(ctx context.Context, serviceName string) (int, error)
	RegenerateInternalAPIKey(ctx context.Context, serviceName string, oldKeyTTL time.Duration) (string, error)
}

type internalAuthService struct {
	internalAPIKeyRepo InternalAPIKeyRepository
}

func NewInternalAuthService(internalAPIKeyRepo InternalAPIKeyRepository) InternalAuthService {
	return &internalAuthService{internalAPIKeyRepo: internalAPIKeyRepo}
}

func (s *internalAuthService) ValidateInternalAPIKey(ctx context.Context, apiKey string) (*types.ValidateInternalAccessResponse, error) {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, ErrInvalidInternalAPIKey
	}

	keyHash := hashInternalAPIKey(apiKey)
	key, err := s.internalAPIKeyRepo.FindActiveByHash(ctx, keyHash)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, ErrInvalidInternalAPIKey
	}

	return &types.ValidateInternalAccessResponse{
		ServiceName:   key.ServiceName,
		AllowedAccess: key.AllowedAccess,
	}, nil
}

func (s *internalAuthService) GenerateInternalAPIKey(ctx context.Context, serviceName string) (string, error) {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		return "", errors.New("service name is required")
	}

	activeKeys, err := s.internalAPIKeyRepo.FindActiveByServiceName(ctx, serviceName, time.Now())
	if err != nil {
		return "", err
	}
	if len(activeKeys) > 0 {
		return "", ErrServiceHasActiveAPIKey
	}

	rawKey, keyHash, err := generateInternalAPIKey()
	if err != nil {
		return "", err
	}

	now := time.Now()
	internalKey := &entity.InternalAPIKey{
		ServiceName:   serviceName,
		KeyHash:       keyHash,
		AllowedAccess: []string{},
		IsActive:      true,
		ExpiresAt:     now.AddDate(100, 0, 0),
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err = s.internalAPIKeyRepo.Create(ctx, internalKey); err != nil {
		return "", err
	}

	return rawKey, nil
}

func (s *internalAuthService) AddInternalAllowedAccess(ctx context.Context, serviceName, allowedService string) error {
	serviceName = strings.TrimSpace(serviceName)
	allowedService = strings.TrimSpace(allowedService)
	if serviceName == "" {
		return errors.New("service name is required")
	}
	if allowedService == "" {
		return errors.New("allowed service is required")
	}

	activeKeys, err := s.internalAPIKeyRepo.FindActiveByServiceName(ctx, serviceName, time.Now())
	if err != nil {
		return err
	}
	if len(activeKeys) == 0 {
		return ErrServiceHasNoActiveAPIKey
	}

	now := time.Now()
	for _, key := range activeKeys {
		if containsString(key.AllowedAccess, allowedService) {
			continue
		}

		key.AllowedAccess = append(key.AllowedAccess, allowedService)
		sort.Strings(key.AllowedAccess)
		key.UpdatedAt = now

		if err = s.internalAPIKeyRepo.Update(ctx, key); err != nil {
			return err
		}
	}

	return nil
}

func (s *internalAuthService) DeactivateInternalAPIKeys(ctx context.Context, serviceName string) (int, error) {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		return 0, errors.New("service name is required")
	}

	activeKeys, err := s.internalAPIKeyRepo.FindActiveByServiceName(ctx, serviceName, time.Now())
	if err != nil {
		return 0, err
	}
	if len(activeKeys) == 0 {
		return 0, ErrServiceHasNoActiveAPIKey
	}

	now := time.Now()
	for _, key := range activeKeys {
		key.IsActive = false
		key.ExpiresAt = now
		key.UpdatedAt = now
		if err = s.internalAPIKeyRepo.Update(ctx, key); err != nil {
			return 0, err
		}
	}

	return len(activeKeys), nil
}

func (s *internalAuthService) RegenerateInternalAPIKey(ctx context.Context, serviceName string, oldKeyTTL time.Duration) (string, error) {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		return "", errors.New("service name is required")
	}
	if oldKeyTTL <= 5*time.Minute {
		return "", ErrInvalidRegenerationTTL
	}

	activeKeys, err := s.internalAPIKeyRepo.FindActiveByServiceName(ctx, serviceName, time.Now())
	if err != nil {
		return "", err
	}
	if len(activeKeys) == 0 {
		return "", ErrServiceHasNoActiveAPIKey
	}

	allowedAccessSet := make(map[string]struct{})
	for _, key := range activeKeys {
		for _, allowed := range key.AllowedAccess {
			allowedAccessSet[allowed] = struct{}{}
		}
	}

	allowedAccess := make([]string, 0, len(allowedAccessSet))
	for allowed := range allowedAccessSet {
		allowedAccess = append(allowedAccess, allowed)
	}
	sort.Strings(allowedAccess)

	now := time.Now()
	expireOldAt := now.Add(oldKeyTTL)
	for _, key := range activeKeys {
		key.ExpiresAt = expireOldAt
		key.UpdatedAt = now
		if err = s.internalAPIKeyRepo.Update(ctx, key); err != nil {
			return "", err
		}
	}

	rawKey, keyHash, err := generateInternalAPIKey()
	if err != nil {
		return "", err
	}

	newKey := &entity.InternalAPIKey{
		ServiceName:   serviceName,
		KeyHash:       keyHash,
		AllowedAccess: allowedAccess,
		IsActive:      true,
		ExpiresAt:     now.AddDate(100, 0, 0),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err = s.internalAPIKeyRepo.Create(ctx, newKey); err != nil {
		return "", err
	}

	return rawKey, nil
}

func generateInternalAPIKey() (string, string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", err
	}

	rawKey := "msint_" + hex.EncodeToString(secret)
	return rawKey, hashInternalAPIKey(rawKey), nil
}

func hashInternalAPIKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
