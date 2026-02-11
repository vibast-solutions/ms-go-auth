package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vibast-solutions/ms-go-auth/app/dto"
	"github.com/vibast-solutions/ms-go-auth/app/entity"
	"github.com/vibast-solutions/ms-go-auth/app/repository"
	"github.com/vibast-solutions/ms-go-auth/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserExists               = errors.New("user already exists")
	ErrUserNotFound             = errors.New("user not found")
	ErrInvalidCredentials       = errors.New("invalid credentials")
	ErrAccountNotConfirmed      = errors.New("account not confirmed")
	ErrInvalidToken             = errors.New("invalid or expired token")
	ErrTokenExpired             = errors.New("token has expired")
	ErrPasswordMismatch         = errors.New("old password is incorrect")
	ErrAccountAlreadyConfirmed  = errors.New("account is already confirmed")
	ErrWeakPassword             = errors.New("password does not meet policy requirements")
	ErrInvalidInternalAPIKey    = errors.New("invalid or expired internal api key")
	ErrServiceHasActiveAPIKey   = errors.New("service already has an active api key")
	ErrServiceHasNoActiveAPIKey = errors.New("service has no active api key")
	ErrInvalidRegenerationTTL   = errors.New("invalid regeneration ttl")
)

const (
	RoleUser = "ROLE_USER"
)

type Claims struct {
	UserID uint64   `json:"user_id"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

type AuthService struct {
	db                 *sql.DB
	userRepo           *repository.UserRepository
	refreshTokenRepo   *repository.RefreshTokenRepository
	internalAPIKeyRepo InternalAPIKeyRepository
	cfg                *config.Config
}

type InternalAPIKeyRepository interface {
	Create(ctx context.Context, key *entity.InternalAPIKey) error
	FindActiveByHash(ctx context.Context, keyHash string) (*entity.InternalAPIKey, error)
	FindActiveByServiceName(ctx context.Context, serviceName string, now time.Time) ([]*entity.InternalAPIKey, error)
	Update(ctx context.Context, key *entity.InternalAPIKey) error
}

func NewAuthService(
	db *sql.DB,
	userRepo *repository.UserRepository,
	refreshTokenRepo *repository.RefreshTokenRepository,
	internalAPIKeyRepo InternalAPIKeyRepository,
	cfg *config.Config,
) *AuthService {
	return &AuthService{
		db:                 db,
		userRepo:           userRepo,
		refreshTokenRepo:   refreshTokenRepo,
		internalAPIKeyRepo: internalAPIKeyRepo,
		cfg:                cfg,
	}
}

func (s *AuthService) Register(ctx context.Context, email, password string) (*dto.RegisterResult, error) {
	canonicalEmail := CanonicalizeEmail(email)

	existing, err := s.userRepo.FindByCanonicalEmail(ctx, canonicalEmail)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrUserExists
	}

	if err := s.cfg.PasswordPolicy.Validate(password); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrWeakPassword, err.Error())
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	confirmToken := uuid.New().String()
	now := time.Now()

	user := &entity.User{
		Email:          email,
		CanonicalEmail: canonicalEmail,
		PasswordHash:   string(hashedPassword),
		IsConfirmed:    false,
		ConfirmToken:   sql.NullString{String: confirmToken, Valid: true},
		ConfirmTokenExpiresAt: sql.NullTime{
			Time:  now.Add(s.cfg.ConfirmTokenTTL),
			Valid: true,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	txUserRepo := s.userRepo.WithTx(tx)
	if err := txUserRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	if err := txUserRepo.AddRole(ctx, user.ID, RoleUser); err != nil {
		return nil, err
	}

	user.Roles = []string{RoleUser}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &dto.RegisterResult{
		User:         user,
		ConfirmToken: confirmToken,
	}, nil
}

func (s *AuthService) Login(ctx context.Context, email, password string, customTTL time.Duration) (*dto.LoginResult, error) {
	canonicalEmail := CanonicalizeEmail(email)
	user, err := s.userRepo.FindByCanonicalEmail(ctx, canonicalEmail)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	if !user.IsConfirmed {
		return nil, ErrAccountNotConfirmed
	}

	accessToken, err := s.generateAccessToken(user, customTTL)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.generateRefreshToken(ctx, user)
	if err != nil {
		return nil, err
	}

	effectiveTTL := s.cfg.JWTAccessTokenTTL
	if customTTL > 0 {
		effectiveTTL = customTTL
	}

	return &dto.LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(effectiveTTL.Seconds()),
		Roles:        user.Roles,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, userID uint64, refreshToken string) error {
	_, err := s.refreshTokenRepo.DeleteByToken(ctx, refreshToken, userID)
	return err
}

func (s *AuthService) ChangePassword(ctx context.Context, userID uint64, oldPassword, newPassword string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return ErrPasswordMismatch
	}

	if err := s.cfg.PasswordPolicy.Validate(newPassword); err != nil {
		return fmt.Errorf("%w: %s", ErrWeakPassword, err.Error())
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.PasswordHash = string(hashedPassword)
	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	return s.refreshTokenRepo.DeleteByUserID(ctx, user.ID)
}

func (s *AuthService) ConfirmAccount(ctx context.Context, token string) error {
	user, err := s.userRepo.FindByConfirmToken(ctx, token)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrInvalidToken
	}

	if !user.ConfirmTokenExpiresAt.Valid || user.ConfirmTokenExpiresAt.Time.Before(time.Now()) {
		return ErrTokenExpired
	}

	user.IsConfirmed = true
	user.ConfirmToken = sql.NullString{Valid: false}
	user.ConfirmTokenExpiresAt = sql.NullTime{Valid: false}

	return s.userRepo.Update(ctx, user)
}

func (s *AuthService) GenerateConfirmToken(ctx context.Context, email string) (string, error) {
	canonicalEmail := CanonicalizeEmail(email)
	user, err := s.userRepo.FindByCanonicalEmail(ctx, canonicalEmail)
	if err != nil {
		return "", err
	}
	if user == nil {
		return "", ErrUserNotFound
	}

	if user.IsConfirmed {
		return "", ErrAccountAlreadyConfirmed
	}

	if user.ConfirmToken.Valid && user.ConfirmTokenExpiresAt.Valid && user.ConfirmTokenExpiresAt.Time.After(time.Now()) {
		return user.ConfirmToken.String, nil
	}

	confirmToken := uuid.New().String()
	user.ConfirmToken = sql.NullString{String: confirmToken, Valid: true}
	user.ConfirmTokenExpiresAt = sql.NullTime{
		Time:  time.Now().Add(s.cfg.ConfirmTokenTTL),
		Valid: true,
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return "", err
	}

	return confirmToken, nil
}

func (s *AuthService) RequestPasswordReset(ctx context.Context, email string) (*dto.RequestPasswordResetResult, error) {
	canonicalEmail := CanonicalizeEmail(email)
	user, err := s.userRepo.FindByCanonicalEmail(ctx, canonicalEmail)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	if user.ResetToken.Valid && user.ResetTokenExpiresAt.Valid && user.ResetTokenExpiresAt.Time.After(time.Now()) {
		return &dto.RequestPasswordResetResult{
			ResetToken: user.ResetToken.String,
		}, nil
	}

	resetToken := uuid.New().String()
	user.ResetToken = sql.NullString{String: resetToken, Valid: true}
	user.ResetTokenExpiresAt = sql.NullTime{
		Time:  time.Now().Add(s.cfg.ResetTokenTTL),
		Valid: true,
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	return &dto.RequestPasswordResetResult{
		ResetToken: resetToken,
	}, nil
}

func (s *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	user, err := s.userRepo.FindByResetToken(ctx, token)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrInvalidToken
	}

	if !user.ResetTokenExpiresAt.Valid || user.ResetTokenExpiresAt.Time.Before(time.Now()) {
		return ErrTokenExpired
	}

	if err := s.cfg.PasswordPolicy.Validate(newPassword); err != nil {
		return fmt.Errorf("%w: %s", ErrWeakPassword, err.Error())
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.PasswordHash = string(hashedPassword)
	user.ResetToken = sql.NullString{Valid: false}
	user.ResetTokenExpiresAt = sql.NullTime{Valid: false}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	return s.refreshTokenRepo.DeleteByUserID(ctx, user.ID)
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*dto.LoginResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	txRefreshRepo := s.refreshTokenRepo.WithTx(tx)

	token, err := txRefreshRepo.FindByTokenForUpdate(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, ErrInvalidToken
	}

	if token.ExpiresAt.Before(time.Now()) {
		return nil, ErrTokenExpired
	}

	txUserRepo := s.userRepo.WithTx(tx)
	user, err := txUserRepo.FindByID(ctx, token.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrInvalidToken
	}

	rowsDeleted, err := txRefreshRepo.DeleteByToken(ctx, refreshToken, token.UserID)
	if err != nil {
		return nil, err
	}
	if rowsDeleted == 0 {
		return nil, ErrInvalidToken
	}

	accessToken, err := s.generateAccessToken(user, 0)
	if err != nil {
		return nil, err
	}

	newRefreshToken, err := s.generateRefreshTokenWithRepo(ctx, txRefreshRepo, user)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &dto.LoginResult{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(s.cfg.JWTAccessTokenTTL.Seconds()),
		Roles:        user.Roles,
	}, nil
}

func (s *AuthService) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.cfg.JWTSecret), nil
	})
	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func (s *AuthService) generateAccessToken(user *entity.User, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = s.cfg.JWTAccessTokenTTL
	}

	claims := &Claims{
		UserID: user.ID,
		Email:  user.Email,
		Roles:  user.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   user.Email,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWTSecret))
}

func (s *AuthService) generateRefreshToken(ctx context.Context, user *entity.User) (string, error) {
	return s.generateRefreshTokenWithRepo(ctx, s.refreshTokenRepo, user)
}

func (s *AuthService) generateRefreshTokenWithRepo(ctx context.Context, repo *repository.RefreshTokenRepository, user *entity.User) (string, error) {
	tokenString := uuid.New().String()
	now := time.Now()

	refreshToken := &entity.RefreshToken{
		UserID:    user.ID,
		Token:     tokenString,
		ExpiresAt: now.Add(s.cfg.JWTRefreshTokenTTL),
		CreatedAt: now,
	}

	if err := repo.Create(ctx, refreshToken); err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *AuthService) ValidateInternalAPIKey(ctx context.Context, apiKey string) (*dto.InternalAccessResult, error) {
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

	return &dto.InternalAccessResult{
		ServiceName:   key.ServiceName,
		AllowedAccess: key.AllowedAccess,
	}, nil
}

func (s *AuthService) GenerateInternalAPIKey(ctx context.Context, serviceName string) (string, error) {
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

func (s *AuthService) AddInternalAllowedAccess(ctx context.Context, serviceName, allowedService string) error {
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

func (s *AuthService) DeactivateInternalAPIKeys(ctx context.Context, serviceName string) (int, error) {
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

func (s *AuthService) RegenerateInternalAPIKey(ctx context.Context, serviceName string, oldKeyTTL time.Duration) (string, error) {
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
