package grpc

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"
	"github.com/vibast-solutions/ms-go-auth/app/service"
	"github.com/vibast-solutions/ms-go-auth/app/types"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthServer struct {
	types.UnimplementedAuthServiceServer
	userAuthService     service.UserAuthService
	internalAuthService service.InternalAuthService
}

func NewAuthServer(userAuthService service.UserAuthService, internalAuthService service.InternalAuthService) *AuthServer {
	return &AuthServer{
		userAuthService:     userAuthService,
		internalAuthService: internalAuthService,
	}
}

func (s *AuthServer) Register(ctx context.Context, req *types.RegisterRequest) (*types.RegisterResponse, error) {
	if err := req.Validate(); err != nil {
		logrus.WithField("email", req.GetEmail()).Debug("Register validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	logrus.WithField("email", req.GetEmail()).Info("Register request received (grpc)")
	res, err := s.userAuthService.Register(ctx, req)
	if err != nil {
		if errors.Is(err, service.ErrUserExists) {
			logrus.WithField("email", req.GetEmail()).Warn("Register failed: user already exists (grpc)")
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		if errors.Is(err, service.ErrWeakPassword) {
			logrus.WithField("email", req.GetEmail()).Warn("Register failed: weak password (grpc)")
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		logrus.WithError(err).WithField("email", req.GetEmail()).Error("Register failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	logrus.WithFields(logrus.Fields{
		"user_id": res.GetUserId(),
		"email":   res.GetEmail(),
	}).Info("User registered (grpc)")

	return res, nil
}

func (s *AuthServer) Login(ctx context.Context, req *types.LoginRequest) (*types.LoginResponse, error) {
	if err := req.Validate(); err != nil {
		logrus.WithField("email", req.GetEmail()).Debug("Login validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	logrus.WithField("email", req.GetEmail()).Info("Login request received (grpc)")
	res, err := s.userAuthService.Login(ctx, req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			logrus.WithField("email", req.GetEmail()).Warn("Login failed: invalid credentials (grpc)")
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		if errors.Is(err, service.ErrAccountNotConfirmed) {
			logrus.WithField("email", req.GetEmail()).Warn("Login failed: account not confirmed (grpc)")
			return nil, status.Error(codes.PermissionDenied, "account not confirmed")
		}
		logrus.WithError(err).WithField("email", req.GetEmail()).Error("Login failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	logrus.WithField("email", req.GetEmail()).Info("Login successful (grpc)")
	return res, nil
}

func (s *AuthServer) Logout(ctx context.Context, req *types.LogoutRequest) (*types.LogoutResponse, error) {
	if req.GetAccessToken() == "" {
		logrus.Debug("Logout validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, "access_token and refresh_token are required")
	}
	if req.GetRefreshToken() == "" {
		logrus.Debug("Logout validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, "access_token and refresh_token are required")
	}

	claims, err := s.userAuthService.ValidateAccessToken(req.GetAccessToken())
	if err != nil {
		logrus.Warn("Logout failed: invalid access token (grpc)")
		return nil, status.Error(codes.Unauthenticated, "invalid access token")
	}

	logrus.WithField("user_id", claims.UserID).Info("Logout request received (grpc)")
	if err = s.userAuthService.Logout(ctx, claims.UserID, req); err != nil {
		logrus.WithError(err).WithField("user_id", claims.UserID).Error("Logout failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	logrus.WithField("user_id", claims.UserID).Info("Logout successful (grpc)")
	return &types.LogoutResponse{Message: "logged out successfully"}, nil
}

func (s *AuthServer) ChangePassword(ctx context.Context, req *types.ChangePasswordRequest) (*types.ChangePasswordResponse, error) {
	if req.GetAccessToken() == "" {
		logrus.Debug("Change password validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, "access_token, old_password, and new_password are required")
	}
	if req.GetOldPassword() == "" || req.GetNewPassword() == "" {
		logrus.Debug("Change password validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, "access_token, old_password, and new_password are required")
	}

	claims, err := s.userAuthService.ValidateAccessToken(req.GetAccessToken())
	if err != nil {
		logrus.Warn("Change password failed: invalid access token (grpc)")
		return nil, status.Error(codes.Unauthenticated, "invalid access token")
	}

	logrus.WithField("user_id", claims.UserID).Info("Change password request received (grpc)")
	err = s.userAuthService.ChangePassword(ctx, claims.UserID, req)
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
	return &types.ChangePasswordResponse{Message: "password changed successfully"}, nil
}

func (s *AuthServer) ConfirmAccount(ctx context.Context, req *types.ConfirmAccountRequest) (*types.ConfirmAccountResponse, error) {
	if err := req.Validate(); err != nil {
		logrus.Debug("Confirm account validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	logrus.Info("Confirm account request received (grpc)")
	err := s.userAuthService.ConfirmAccount(ctx, req)
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
	return &types.ConfirmAccountResponse{Message: "account confirmed successfully"}, nil
}

func (s *AuthServer) RequestPasswordReset(ctx context.Context, req *types.RequestPasswordResetRequest) (*types.RequestPasswordResetResponse, error) {
	if err := req.Validate(); err != nil {
		logrus.Debug("Request password reset validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	logrus.WithField("email", req.GetEmail()).Info("Password reset requested (grpc)")
	res, err := s.userAuthService.RequestPasswordReset(ctx, req)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			logrus.WithField("email", req.GetEmail()).Debug("Password reset requested for unknown email (grpc)")
			return &types.RequestPasswordResetResponse{Message: "if the email exists, a reset token has been generated"}, nil
		}
		logrus.WithError(err).WithField("email", req.GetEmail()).Error("Request password reset failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	logrus.WithField("email", req.GetEmail()).Info("Password reset token generated (grpc)")
	return res, nil
}

func (s *AuthServer) ResetPassword(ctx context.Context, req *types.ResetPasswordRequest) (*types.ResetPasswordResponse, error) {
	if err := req.Validate(); err != nil {
		logrus.Debug("Reset password validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	logrus.Info("Reset password request received (grpc)")
	err := s.userAuthService.ResetPassword(ctx, req)
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
	return &types.ResetPasswordResponse{Message: "password reset successfully"}, nil
}

func (s *AuthServer) GenerateConfirmToken(ctx context.Context, req *types.GenerateConfirmTokenRequest) (*types.GenerateConfirmTokenResponse, error) {
	if err := req.Validate(); err != nil {
		logrus.Debug("Generate confirm token validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	logrus.WithField("email", req.GetEmail()).Info("Generate confirm token request received (grpc)")
	res, err := s.userAuthService.GenerateConfirmToken(ctx, req)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			logrus.WithField("email", req.GetEmail()).Warn("Generate confirm token failed: user not found (grpc)")
			return nil, status.Error(codes.NotFound, "user not found")
		}
		if errors.Is(err, service.ErrAccountAlreadyConfirmed) {
			logrus.WithField("email", req.GetEmail()).Warn("Generate confirm token failed: account already confirmed (grpc)")
			return nil, status.Error(codes.FailedPrecondition, "account is already confirmed")
		}
		logrus.WithError(err).WithField("email", req.GetEmail()).Error("Generate confirm token failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	logrus.WithField("email", req.GetEmail()).Info("Confirm token generated (grpc)")
	return res, nil
}

func (s *AuthServer) ValidateToken(_ context.Context, req *types.ValidateTokenRequest) (*types.ValidateTokenResponse, error) {
	if err := req.Validate(); err != nil {
		logrus.Debug("Validate token validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	claims, err := s.userAuthService.ValidateAccessToken(req.GetAccessToken())
	if err != nil {
		logrus.Debug("Validate token failed (grpc)")
		return &types.ValidateTokenResponse{Valid: false}, nil
	}

	logrus.WithField("user_id", claims.UserID).Debug("Validate token succeeded (grpc)")
	return &types.ValidateTokenResponse{
		Valid:  true,
		UserId: claims.UserID,
		Email:  claims.Email,
		Roles:  claims.Roles,
	}, nil
}

func (s *AuthServer) ValidateInternalAccess(ctx context.Context, req *types.ValidateInternalAccessRequest) (*types.ValidateInternalAccessResponse, error) {
	if err := req.Validate(); err != nil {
		logrus.Debug("Validate internal access validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	res, err := s.internalAuthService.ValidateInternalAPIKey(ctx, req.GetApiKey())
	if err != nil {
		if errors.Is(err, service.ErrInvalidInternalAPIKey) {
			logrus.Debug("Validate internal access failed: inspected api key not found (grpc)")
			return nil, status.Error(codes.NotFound, "api key not found")
		}
		logrus.WithError(err).Error("Validate internal access failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return res, nil
}

func (s *AuthServer) RefreshToken(ctx context.Context, req *types.RefreshTokenRequest) (*types.RefreshTokenResponse, error) {
	if err := req.Validate(); err != nil {
		logrus.Debug("Refresh token validation failed (grpc)")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	logrus.Info("Refresh token request received (grpc)")
	res, err := s.userAuthService.RefreshToken(ctx, req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) || errors.Is(err, service.ErrTokenExpired) {
			logrus.Warn("Refresh token failed: invalid or expired token (grpc)")
			return nil, status.Error(codes.Unauthenticated, "invalid or expired refresh token")
		}
		logrus.WithError(err).Error("Refresh token failed (grpc)")
		return nil, status.Error(codes.Internal, "internal server error")
	}

	logrus.Info("Refresh token successful (grpc)")
	return res, nil
}
