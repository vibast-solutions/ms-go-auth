package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/vibast-solutions/ms-go-auth/app/entity"
	"github.com/vibast-solutions/ms-go-auth/app/repository"
	"github.com/vibast-solutions/ms-go-auth/app/types"
	"github.com/vibast-solutions/ms-go-auth/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
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

const (
	RoleUser = "ROLE_USER"
)

type Claims struct {
	UserID uint64   `json:"user_id"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

type userRepository interface {
	Create(ctx context.Context, user *entity.User) error
	FindByCanonicalEmail(ctx context.Context, canonicalEmail string) (*entity.User, error)
	FindByID(ctx context.Context, id uint64) (*entity.User, error)
	AddRole(ctx context.Context, userID uint64, role string) error
	FindByConfirmToken(ctx context.Context, token string) (*entity.User, error)
	FindByResetToken(ctx context.Context, token string) (*entity.User, error)
	Update(ctx context.Context, user *entity.User) error
	UpdateLastLogin(ctx context.Context, userID uint64, lastLogin time.Time) error
}

type refreshTokenRepository interface {
	Create(ctx context.Context, token *entity.RefreshToken) error
	FindByTokenForUpdate(ctx context.Context, token string) (*entity.RefreshToken, error)
	DeleteByToken(ctx context.Context, token string, userID uint64) (int64, error)
	DeleteByUserID(ctx context.Context, userID uint64) error
}

type refreshTokenCreator interface {
	Create(ctx context.Context, token *entity.RefreshToken) error
}

type UserAuthService interface {
	Register(ctx context.Context, req *types.RegisterRequest) (*types.RegisterResponse, error)
	Login(ctx context.Context, req *types.LoginRequest) (*types.LoginResponse, error)
	Logout(ctx context.Context, userID uint64, req *types.LogoutRequest) error
	ChangePassword(ctx context.Context, userID uint64, req *types.ChangePasswordRequest) error
	ConfirmAccount(ctx context.Context, req *types.ConfirmAccountRequest) error
	GenerateConfirmToken(ctx context.Context, req *types.GenerateConfirmTokenRequest) (*types.GenerateConfirmTokenResponse, error)
	RequestPasswordReset(ctx context.Context, req *types.RequestPasswordResetRequest) (*types.RequestPasswordResetResponse, error)
	ResetPassword(ctx context.Context, req *types.ResetPasswordRequest) error
	RefreshToken(ctx context.Context, req *types.RefreshTokenRequest) (*types.RefreshTokenResponse, error)
	ValidateAccessToken(tokenString string) (*Claims, error)
}

type AsyncRunner func(task func())

type UserAuthServiceOption func(*userAuthService)

type userAuthService struct {
	db               *sql.DB
	userRepo         userRepository
	refreshTokenRepo refreshTokenRepository
	cfg              *config.Config
	asyncRunner      AsyncRunner
}

func NewUserAuthService(
	db *sql.DB,
	userRepo userRepository,
	refreshTokenRepo refreshTokenRepository,
	cfg *config.Config,
	opts ...UserAuthServiceOption,
) UserAuthService {
	svc := &userAuthService{
		db:               db,
		userRepo:         userRepo,
		refreshTokenRepo: refreshTokenRepo,
		cfg:              cfg,
		asyncRunner: func(task func()) {
			go task()
		},
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

func WithAsyncRunner(runner AsyncRunner) UserAuthServiceOption {
	return func(s *userAuthService) {
		if runner != nil {
			s.asyncRunner = runner
		}
	}
}

func (s *userAuthService) Register(ctx context.Context, req *types.RegisterRequest) (*types.RegisterResponse, error) {
	email := req.GetEmail()
	canonicalEmail := CanonicalizeEmail(email)

	existing, err := s.userRepo.FindByCanonicalEmail(ctx, canonicalEmail)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrUserExists
	}

	if err = s.cfg.Password.Policy.Validate(req.GetPassword()); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrWeakPassword, err.Error())
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.GetPassword()), bcrypt.DefaultCost)
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
			Time:  now.Add(s.cfg.Tokens.ConfirmTTL),
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

	txUserRepo := repository.NewUserRepository(tx)
	if err = txUserRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	if err = txUserRepo.AddRole(ctx, user.ID, RoleUser); err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return &types.RegisterResponse{
		UserId:       user.ID,
		Email:        user.Email,
		ConfirmToken: confirmToken,
		Message:      "registration successful, please confirm your account",
		Roles:        []string{RoleUser},
	}, nil
}

func (s *userAuthService) Login(ctx context.Context, req *types.LoginRequest) (*types.LoginResponse, error) {
	canonicalEmail := CanonicalizeEmail(req.GetEmail())
	user, err := s.userRepo.FindByCanonicalEmail(ctx, canonicalEmail)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrInvalidCredentials
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.GetPassword())); err != nil {
		return nil, ErrInvalidCredentials
	}

	if !user.IsConfirmed {
		return nil, ErrAccountNotConfirmed
	}

	s.asyncRunner(func() {
		updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if updateErr := s.userRepo.UpdateLastLogin(updateCtx, user.ID, time.Now()); updateErr != nil {
			logrus.WithError(updateErr).WithField("user_id", user.ID).Error("failed to update last_login")
		}
	})

	customTTL := time.Duration(0)
	if req.GetTokenDuration() > 0 {
		customTTL = time.Duration(req.GetTokenDuration()) * time.Minute
	}

	accessToken, err := s.generateAccessToken(user, customTTL)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.generateRefreshToken(ctx, user)
	if err != nil {
		return nil, err
	}

	effectiveTTL := s.cfg.JWT.AccessTokenTTL
	if customTTL > 0 {
		effectiveTTL = customTTL
	}

	return &types.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(effectiveTTL.Seconds()),
		Roles:        user.Roles,
	}, nil
}

func (s *userAuthService) Logout(ctx context.Context, userID uint64, req *types.LogoutRequest) error {
	_, err := s.refreshTokenRepo.DeleteByToken(ctx, req.GetRefreshToken(), userID)
	return err
}

func (s *userAuthService) ChangePassword(ctx context.Context, userID uint64, req *types.ChangePasswordRequest) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.GetOldPassword())); err != nil {
		return ErrPasswordMismatch
	}

	if err = s.cfg.Password.Policy.Validate(req.GetNewPassword()); err != nil {
		return fmt.Errorf("%w: %s", ErrWeakPassword, err.Error())
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.GetNewPassword()), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.PasswordHash = string(hashedPassword)
	if err = s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	return s.refreshTokenRepo.DeleteByUserID(ctx, user.ID)
}

func (s *userAuthService) ConfirmAccount(ctx context.Context, req *types.ConfirmAccountRequest) error {
	user, err := s.userRepo.FindByConfirmToken(ctx, req.GetToken())
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

func (s *userAuthService) GenerateConfirmToken(ctx context.Context, req *types.GenerateConfirmTokenRequest) (*types.GenerateConfirmTokenResponse, error) {
	canonicalEmail := CanonicalizeEmail(req.GetEmail())
	user, err := s.userRepo.FindByCanonicalEmail(ctx, canonicalEmail)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	if user.IsConfirmed {
		return nil, ErrAccountAlreadyConfirmed
	}

	if user.ConfirmToken.Valid && user.ConfirmTokenExpiresAt.Valid && user.ConfirmTokenExpiresAt.Time.After(time.Now()) {
		return &types.GenerateConfirmTokenResponse{
			ConfirmToken: user.ConfirmToken.String,
			Message:      "confirm token generated successfully",
		}, nil
	}

	confirmToken := uuid.New().String()
	user.ConfirmToken = sql.NullString{String: confirmToken, Valid: true}
	user.ConfirmTokenExpiresAt = sql.NullTime{
		Time:  time.Now().Add(s.cfg.Tokens.ConfirmTTL),
		Valid: true,
	}

	if err = s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	return &types.GenerateConfirmTokenResponse{
		ConfirmToken: confirmToken,
		Message:      "confirm token generated successfully",
	}, nil
}

func (s *userAuthService) RequestPasswordReset(ctx context.Context, req *types.RequestPasswordResetRequest) (*types.RequestPasswordResetResponse, error) {
	canonicalEmail := CanonicalizeEmail(req.GetEmail())
	user, err := s.userRepo.FindByCanonicalEmail(ctx, canonicalEmail)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	if user.ResetToken.Valid && user.ResetTokenExpiresAt.Valid && user.ResetTokenExpiresAt.Time.After(time.Now()) {
		return &types.RequestPasswordResetResponse{
			ResetToken: user.ResetToken.String,
			Message:    "reset token generated successfully",
		}, nil
	}

	resetToken := uuid.New().String()
	user.ResetToken = sql.NullString{String: resetToken, Valid: true}
	user.ResetTokenExpiresAt = sql.NullTime{
		Time:  time.Now().Add(s.cfg.Tokens.ResetTTL),
		Valid: true,
	}

	if err = s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	return &types.RequestPasswordResetResponse{
		ResetToken: resetToken,
		Message:    "reset token generated successfully",
	}, nil
}

func (s *userAuthService) ResetPassword(ctx context.Context, req *types.ResetPasswordRequest) error {
	user, err := s.userRepo.FindByResetToken(ctx, req.GetToken())
	if err != nil {
		return err
	}
	if user == nil {
		return ErrInvalidToken
	}

	if !user.ResetTokenExpiresAt.Valid || user.ResetTokenExpiresAt.Time.Before(time.Now()) {
		return ErrTokenExpired
	}

	if err = s.cfg.Password.Policy.Validate(req.GetNewPassword()); err != nil {
		return fmt.Errorf("%w: %s", ErrWeakPassword, err.Error())
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.GetNewPassword()), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.PasswordHash = string(hashedPassword)
	user.ResetToken = sql.NullString{Valid: false}
	user.ResetTokenExpiresAt = sql.NullTime{Valid: false}

	if err = s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	return s.refreshTokenRepo.DeleteByUserID(ctx, user.ID)
}

func (s *userAuthService) RefreshToken(ctx context.Context, req *types.RefreshTokenRequest) (*types.RefreshTokenResponse, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	txRefreshRepo := repository.NewRefreshTokenRepository(tx)

	token, err := txRefreshRepo.FindByTokenForUpdate(ctx, req.GetRefreshToken())
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, ErrInvalidToken
	}

	if token.ExpiresAt.Before(time.Now()) {
		return nil, ErrTokenExpired
	}

	txUserRepo := repository.NewUserRepository(tx)
	user, err := txUserRepo.FindByID(ctx, token.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrInvalidToken
	}

	rowsDeleted, err := txRefreshRepo.DeleteByToken(ctx, req.GetRefreshToken(), token.UserID)
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

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return &types.RefreshTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(s.cfg.JWT.AccessTokenTTL.Seconds()),
		Roles:        user.Roles,
	}, nil
}

func (s *userAuthService) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.cfg.JWT.Secret), nil
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

func (s *userAuthService) generateAccessToken(user *entity.User, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = s.cfg.JWT.AccessTokenTTL
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
	return token.SignedString([]byte(s.cfg.JWT.Secret))
}

func (s *userAuthService) generateRefreshToken(ctx context.Context, user *entity.User) (string, error) {
	return s.generateRefreshTokenWithRepo(ctx, s.refreshTokenRepo, user)
}

func (s *userAuthService) generateRefreshTokenWithRepo(ctx context.Context, repo refreshTokenCreator, user *entity.User) (string, error) {
	tokenString := uuid.New().String()
	now := time.Now()

	refreshToken := &entity.RefreshToken{
		UserID:    user.ID,
		Token:     tokenString,
		ExpiresAt: now.Add(s.cfg.JWT.RefreshTokenTTL),
		CreatedAt: now,
	}

	if err := repo.Create(ctx, refreshToken); err != nil {
		return "", err
	}

	return tokenString, nil
}
