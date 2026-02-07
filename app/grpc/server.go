package grpc

import (
	"context"
	"errors"
	"time"

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
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	result, err := s.authService.Register(ctx, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		if errors.Is(err, service.ErrWeakPassword) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &types.RegisterResponse{
		UserId:       result.User.ID,
		Email:        result.User.Email,
		ConfirmToken: result.ConfirmToken,
		Message:      "registration successful, please confirm your account",
	}, nil
}

func (s *AuthServer) Login(ctx context.Context, req *types.LoginRequest) (*types.LoginResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	var customTTL time.Duration
	if req.TokenDuration < 0 {
		return nil, status.Error(codes.InvalidArgument, "token_duration must be greater than 0")
	}
	if req.TokenDuration > 0 {
		customTTL = time.Duration(req.TokenDuration) * time.Minute
	}
	result, err := s.authService.Login(ctx, req.Email, req.Password, customTTL)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		if errors.Is(err, service.ErrAccountNotConfirmed) {
			return nil, status.Error(codes.PermissionDenied, "account not confirmed")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &types.LoginResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}, nil
}

func (s *AuthServer) Logout(ctx context.Context, req *types.LogoutRequest) (*types.LogoutResponse, error) {
	if req.AccessToken == "" || req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "access_token and refresh_token are required")
	}

	claims, err := s.authService.ValidateAccessToken(req.AccessToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid access token")
	}

	if err := s.authService.Logout(ctx, claims.UserID, req.RefreshToken); err != nil {
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &types.LogoutResponse{
		Message: "logged out successfully",
	}, nil
}

func (s *AuthServer) ChangePassword(ctx context.Context, req *types.ChangePasswordRequest) (*types.ChangePasswordResponse, error) {
	if req.AccessToken == "" || req.OldPassword == "" || req.NewPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "access_token, old_password, and new_password are required")
	}

	claims, err := s.authService.ValidateAccessToken(req.AccessToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid access token")
	}

	err = s.authService.ChangePassword(ctx, claims.UserID, req.OldPassword, req.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		if errors.Is(err, service.ErrPasswordMismatch) {
			return nil, status.Error(codes.InvalidArgument, "old password is incorrect")
		}
		if errors.Is(err, service.ErrWeakPassword) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &types.ChangePasswordResponse{
		Message: "password changed successfully",
	}, nil
}

func (s *AuthServer) ConfirmAccount(ctx context.Context, req *types.ConfirmAccountRequest) (*types.ConfirmAccountResponse, error) {
	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	err := s.authService.ConfirmAccount(ctx, req.Token)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			return nil, status.Error(codes.InvalidArgument, "invalid token")
		}
		if errors.Is(err, service.ErrTokenExpired) {
			return nil, status.Error(codes.InvalidArgument, "token has expired")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &types.ConfirmAccountResponse{
		Message: "account confirmed successfully",
	}, nil
}

func (s *AuthServer) RequestPasswordReset(ctx context.Context, req *types.RequestPasswordResetRequest) (*types.RequestPasswordResetResponse, error) {
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	result, err := s.authService.RequestPasswordReset(ctx, req.Email)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return &types.RequestPasswordResetResponse{
				Message: "if the email exists, a reset token has been generated",
			}, nil
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &types.RequestPasswordResetResponse{
		ResetToken: result.ResetToken,
		Message:    "reset token generated successfully",
	}, nil
}

func (s *AuthServer) ResetPassword(ctx context.Context, req *types.ResetPasswordRequest) (*types.ResetPasswordResponse, error) {
	if req.Token == "" || req.NewPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "token and new_password are required")
	}

	err := s.authService.ResetPassword(ctx, req.Token, req.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			return nil, status.Error(codes.InvalidArgument, "invalid token")
		}
		if errors.Is(err, service.ErrTokenExpired) {
			return nil, status.Error(codes.InvalidArgument, "token has expired")
		}
		if errors.Is(err, service.ErrWeakPassword) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &types.ResetPasswordResponse{
		Message: "password reset successfully",
	}, nil
}

func (s *AuthServer) GenerateConfirmToken(ctx context.Context, req *types.GenerateConfirmTokenRequest) (*types.GenerateConfirmTokenResponse, error) {
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	token, err := s.authService.GenerateConfirmToken(ctx, req.Email)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		if errors.Is(err, service.ErrAccountAlreadyConfirmed) {
			return nil, status.Error(codes.FailedPrecondition, "account is already confirmed")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &types.GenerateConfirmTokenResponse{
		ConfirmToken: token,
		Message:      "confirm token generated successfully",
	}, nil
}

func (s *AuthServer) ValidateToken(_ context.Context, req *types.ValidateTokenRequest) (*types.ValidateTokenResponse, error) {
	if req.AccessToken == "" {
		return nil, status.Error(codes.InvalidArgument, "access_token is required")
	}

	claims, err := s.authService.ValidateAccessToken(req.AccessToken)
	if err != nil {
		return &types.ValidateTokenResponse{
			Valid: false,
		}, nil
	}

	return &types.ValidateTokenResponse{
		Valid:  true,
		UserId: claims.UserID,
		Email:  claims.Email,
	}, nil
}

func (s *AuthServer) RefreshToken(ctx context.Context, req *types.RefreshTokenRequest) (*types.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	result, err := s.authService.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) || errors.Is(err, service.ErrTokenExpired) {
			return nil, status.Error(codes.Unauthenticated, "invalid or expired refresh token")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &types.RefreshTokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}, nil
}
