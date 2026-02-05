package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"auth/app/dto"
	"auth/app/entity"
	"auth/app/repository"
	"auth/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserExists              = errors.New("user already exists")
	ErrUserNotFound            = errors.New("user not found")
	ErrInvalidCredentials      = errors.New("invalid credentials")
	ErrAccountNotConfirmed     = errors.New("account not confirmed")
	ErrInvalidToken            = errors.New("invalid or expired token")
	ErrTokenExpired            = errors.New("token has expired")
	ErrPasswordMismatch        = errors.New("old password is incorrect")
	ErrAccountAlreadyConfirmed = errors.New("account is already confirmed")
	ErrWeakPassword            = errors.New("password does not meet policy requirements")
)

type Claims struct {
	UserID uint64 `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

type AuthService struct {
	db               *sql.DB
	userRepo         *repository.UserRepository
	refreshTokenRepo *repository.RefreshTokenRepository
	cfg              *config.Config
}

func NewAuthService(
	db *sql.DB,
	userRepo *repository.UserRepository,
	refreshTokenRepo *repository.RefreshTokenRepository,
	cfg *config.Config,
) *AuthService {
	return &AuthService{
		db:               db,
		userRepo:         userRepo,
		refreshTokenRepo: refreshTokenRepo,
		cfg:              cfg,
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

	if err := s.userRepo.Create(ctx, user); err != nil {
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
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	_, err := s.refreshTokenRepo.DeleteByToken(ctx, refreshToken)
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

	rowsDeleted, err := txRefreshRepo.DeleteByToken(ctx, refreshToken)
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
