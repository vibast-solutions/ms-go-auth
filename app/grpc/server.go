package grpc

import (
	"context"
	"errors"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vibast-solutions/ms-go-auth/app/service"
	"github.com/vibast-solutions/ms-go-auth/app/types"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthServer struct {
	types.UnimplementedAuthServiceServer
	authService *service.AuthService
}

func NewAuthServer(authService *service.AuthService) *AuthServer {
	return &AuthServer{authService: authService}
}

func (s *AuthServer) Register(ctx context.Context, req *types.RegisterRequest) (*types.RegisterResponse, error) {
	if req.Email == "" || req.Password == "" {
		logrus.WithField("email", req.Email).Debug("Register validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	logrus.WithField("email", req.Email).Info("Register request received (grpc)")
	result, err := s.authService.Register(ctx, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrUserExists) {
			logrus.WithField("email", req.Email).Warn("Register failed: user already exists (grpc)")
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		if errors.Is(err, service.ErrWeakPassword) {
			logrus.WithField("email", req.Email).Warn("Register failed: weak password (grpc)")
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		logrus.WithError(err).WithField("email", req.Email).Error("Register failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	logrus.WithFields(logrus.Fields{
		"user_id": result.User.ID,
		"email":   result.User.Email,
	}).Info("User registered (grpc)")
	return &types.RegisterResponse{
		UserId:       result.User.ID,
		Email:        result.User.Email,
		ConfirmToken: result.ConfirmToken,
		Message:      "registration successful, please confirm your account",
	}, nil
}

func (s *AuthServer) Login(ctx context.Context, req *types.LoginRequest) (*types.LoginResponse, error) {
	if req.Email == "" || req.Password == "" {
		logrus.WithField("email", req.Email).Debug("Login validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	var customTTL time.Duration
	if req.TokenDuration < 0 {
		logrus.WithField("email", req.Email).Debug("Login validation failed: invalid token_duration (grpc)")
		return nil, status.Error(codes.InvalidArgument, "token_duration must be greater than 0")
	}
	if req.TokenDuration > 0 {
		customTTL = time.Duration(req.TokenDuration) * time.Minute
	}
	logrus.WithField("email", req.Email).Info("Login request received (grpc)")
	result, err := s.authService.Login(ctx, req.Email, req.Password, customTTL)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			logrus.WithField("email", req.Email).Warn("Login failed: invalid credentials (grpc)")
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		if errors.Is(err, service.ErrAccountNotConfirmed) {
			logrus.WithField("email", req.Email).Warn("Login failed: account not confirmed (grpc)")
			return nil, status.Error(codes.PermissionDenied, "account not confirmed")
		}
		logrus.WithError(err).WithField("email", req.Email).Error("Login failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	logrus.WithField("email", req.Email).Info("Login successful (grpc)")
	return &types.LoginResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}, nil
}

func (s *AuthServer) Logout(ctx context.Context, req *types.LogoutRequest) (*types.LogoutResponse, error) {
	if req.AccessToken == "" || req.RefreshToken == "" {
		logrus.Debug("Logout validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, "access_token and refresh_token are required")
	}

	claims, err := s.authService.ValidateAccessToken(req.AccessToken)
	if err != nil {
		logrus.Warn("Logout failed: invalid access token (grpc)")
		return nil, status.Error(codes.Unauthenticated, "invalid access token")
	}

	logrus.WithField("user_id", claims.UserID).Info("Logout request received (grpc)")
	if err := s.authService.Logout(ctx, claims.UserID, req.RefreshToken); err != nil {
		logrus.WithError(err).WithField("user_id", claims.UserID).Error("Logout failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	logrus.WithField("user_id", claims.UserID).Info("Logout successful (grpc)")
	return &types.LogoutResponse{
		Message: "logged out successfully",
	}, nil
}

func (s *AuthServer) ChangePassword(ctx context.Context, req *types.ChangePasswordRequest) (*types.ChangePasswordResponse, error) {
	if req.AccessToken == "" || req.OldPassword == "" || req.NewPassword == "" {
		logrus.Debug("Change password validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, "access_token, old_password, and new_password are required")
	}

	claims, err := s.authService.ValidateAccessToken(req.AccessToken)
	if err != nil {
		logrus.Warn("Change password failed: invalid access token (grpc)")
		return nil, status.Error(codes.Unauthenticated, "invalid access token")
	}

	logrus.WithField("user_id", claims.UserID).Info("Change password request received (grpc)")
	err = s.authService.ChangePassword(ctx, claims.UserID, req.OldPassword, req.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			logrus.WithField("user_id", claims.UserID).Warn("Change password failed: user not found (grpc)")
			return nil, status.Error(codes.NotFound, "user not found")
		}
		if errors.Is(err, service.ErrPasswordMismatch) {
			logrus.WithField("user_id", claims.UserID).Warn("Change password failed: old password mismatch (grpc)")
			return nil, status.Error(codes.InvalidArgument, "old password is incorrect")
		}
		if errors.Is(err, service.ErrWeakPassword) {
			logrus.WithField("user_id", claims.UserID).Warn("Change password failed: weak password (grpc)")
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		logrus.WithError(err).WithField("user_id", claims.UserID).Error("Change password failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	logrus.WithField("user_id", claims.UserID).Info("Password changed (grpc)")
	return &types.ChangePasswordResponse{
		Message: "password changed successfully",
	}, nil
}

func (s *AuthServer) ConfirmAccount(ctx context.Context, req *types.ConfirmAccountRequest) (*types.ConfirmAccountResponse, error) {
	if req.Token == "" {
		logrus.Debug("Confirm account validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	logrus.Info("Confirm account request received (grpc)")
	err := s.authService.ConfirmAccount(ctx, req.Token)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			logrus.Warn("Confirm account failed: invalid token (grpc)")
			return nil, status.Error(codes.InvalidArgument, "invalid token")
		}
		if errors.Is(err, service.ErrTokenExpired) {
			logrus.Warn("Confirm account failed: token expired (grpc)")
			return nil, status.Error(codes.InvalidArgument, "token has expired")
		}
		logrus.WithError(err).Error("Confirm account failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	logrus.Info("Account confirmed (grpc)")
	return &types.ConfirmAccountResponse{
		Message: "account confirmed successfully",
	}, nil
}

func (s *AuthServer) RequestPasswordReset(ctx context.Context, req *types.RequestPasswordResetRequest) (*types.RequestPasswordResetResponse, error) {
	if req.Email == "" {
		logrus.Debug("Request password reset validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	logrus.WithField("email", req.Email).Info("Password reset requested (grpc)")
	result, err := s.authService.RequestPasswordReset(ctx, req.Email)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			logrus.WithField("email", req.Email).Debug("Password reset requested for unknown email (grpc)")
			return &types.RequestPasswordResetResponse{
				Message: "if the email exists, a reset token has been generated",
			}, nil
		}
		logrus.WithError(err).WithField("email", req.Email).Error("Request password reset failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	logrus.WithField("email", req.Email).Info("Password reset token generated (grpc)")
	return &types.RequestPasswordResetResponse{
		ResetToken: result.ResetToken,
		Message:    "reset token generated successfully",
	}, nil
}

func (s *AuthServer) ResetPassword(ctx context.Context, req *types.ResetPasswordRequest) (*types.ResetPasswordResponse, error) {
	if req.Token == "" || req.NewPassword == "" {
		logrus.Debug("Reset password validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, "token and new_password are required")
	}

	logrus.Info("Reset password request received (grpc)")
	err := s.authService.ResetPassword(ctx, req.Token, req.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			logrus.Warn("Reset password failed: invalid token (grpc)")
			return nil, status.Error(codes.InvalidArgument, "invalid token")
		}
		if errors.Is(err, service.ErrTokenExpired) {
			logrus.Warn("Reset password failed: token expired (grpc)")
			return nil, status.Error(codes.InvalidArgument, "token has expired")
		}
		if errors.Is(err, service.ErrWeakPassword) {
			logrus.Warn("Reset password failed: weak password (grpc)")
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		logrus.WithError(err).Error("Reset password failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	logrus.Info("Password reset successful (grpc)")
	return &types.ResetPasswordResponse{
		Message: "password reset successfully",
	}, nil
}

func (s *AuthServer) GenerateConfirmToken(ctx context.Context, req *types.GenerateConfirmTokenRequest) (*types.GenerateConfirmTokenResponse, error) {
	if req.Email == "" {
		logrus.Debug("Generate confirm token validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	logrus.WithField("email", req.Email).Info("Generate confirm token request received (grpc)")
	token, err := s.authService.GenerateConfirmToken(ctx, req.Email)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			logrus.WithField("email", req.Email).Warn("Generate confirm token failed: user not found (grpc)")
			return nil, status.Error(codes.NotFound, "user not found")
		}
		if errors.Is(err, service.ErrAccountAlreadyConfirmed) {
			logrus.WithField("email", req.Email).Warn("Generate confirm token failed: account already confirmed (grpc)")
			return nil, status.Error(codes.FailedPrecondition, "account is already confirmed")
		}
		logrus.WithError(err).WithField("email", req.Email).Error("Generate confirm token failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	logrus.WithField("email", req.Email).Info("Confirm token generated (grpc)")
	return &types.GenerateConfirmTokenResponse{
		ConfirmToken: token,
		Message:      "confirm token generated successfully",
	}, nil
}

func (s *AuthServer) ValidateToken(_ context.Context, req *types.ValidateTokenRequest) (*types.ValidateTokenResponse, error) {
	if req.AccessToken == "" {
		logrus.Debug("Validate token validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, "access_token is required")
	}

	claims, err := s.authService.ValidateAccessToken(req.AccessToken)
	if err != nil {
		logrus.Debug("Validate token failed (grpc)")
		return &types.ValidateTokenResponse{
			Valid: false,
		}, nil
	}

	logrus.WithField("user_id", claims.UserID).Debug("Validate token succeeded (grpc)")
	return &types.ValidateTokenResponse{
		Valid:  true,
		UserId: claims.UserID,
		Email:  claims.Email,
	}, nil
}

func (s *AuthServer) RefreshToken(ctx context.Context, req *types.RefreshTokenRequest) (*types.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		logrus.Debug("Refresh token validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	logrus.Info("Refresh token request received (grpc)")
	result, err := s.authService.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) || errors.Is(err, service.ErrTokenExpired) {
			logrus.Warn("Refresh token failed: invalid or expired token (grpc)")
			return nil, status.Error(codes.Unauthenticated, "invalid or expired refresh token")
		}
		logrus.WithError(err).Error("Refresh token failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	logrus.Info("Refresh token successful (grpc)")
	return &types.RefreshTokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}, nil
}
