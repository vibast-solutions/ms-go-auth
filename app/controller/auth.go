package controller

import (
	"errors"
	"net/http"
	"time"

	dto "github.com/vibast-solutions/ms-go-auth/app/dto/http"
	"github.com/vibast-solutions/ms-go-auth/app/service"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

type AuthController struct {
	authService *service.AuthService
}

func NewAuthController(authService *service.AuthService) *AuthController {
	return &AuthController{authService: authService}
}

func (c *AuthController) Register(ctx echo.Context) error {
	var req dto.RegisterRequest
	if err := ctx.Bind(&req); err != nil {
		logrus.WithError(err).Debug("Failed to bind register request")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.Email == "" || req.Password == "" {
		logrus.WithField("email", req.Email).Debug("Register validation failed")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "email and password are required"})
	}

	logrus.WithField("email", req.Email).Info("Register request received")
	result, err := c.authService.Register(ctx.Request().Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrUserExists) {
			logrus.WithField("email", req.Email).Warn("Register failed: user already exists")
			return ctx.JSON(http.StatusConflict, dto.ErrorResponse{Error: "user already exists"})
		}
		if errors.Is(err, service.ErrWeakPassword) {
			logrus.WithField("email", req.Email).Warn("Register failed: weak password")
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: err.Error()})
		}
		logrus.WithError(err).WithField("email", req.Email).Error("Register failed")
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	logrus.WithFields(logrus.Fields{
		"user_id": result.User.ID,
		"email":   result.User.Email,
	}).Info("User registered")
	return ctx.JSON(http.StatusCreated, dto.RegisterResponse{
		UserID:       result.User.ID,
		Email:        result.User.Email,
		ConfirmToken: result.ConfirmToken,
		Message:      "registration successful, please confirm your account",
	})
}

func (c *AuthController) Login(ctx echo.Context) error {
	var req dto.LoginRequest
	if err := ctx.Bind(&req); err != nil {
		logrus.WithError(err).Debug("Failed to bind login request")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.Email == "" || req.Password == "" {
		logrus.WithField("email", req.Email).Debug("Login validation failed")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "email and password are required"})
	}

	var customTTL time.Duration
	if req.TokenDuration != nil {
		if *req.TokenDuration <= 0 {
			logrus.WithField("email", req.Email).Debug("Login validation failed: invalid token_duration")
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "token_duration must be greater than 0"})
		}
		customTTL = time.Duration(*req.TokenDuration) * time.Minute
	}

	logrus.WithField("email", req.Email).Info("Login request received")
	result, err := c.authService.Login(ctx.Request().Context(), req.Email, req.Password, customTTL)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			logrus.WithField("email", req.Email).Warn("Login failed: invalid credentials")
			return ctx.JSON(http.StatusUnauthorized, dto.ErrorResponse{Error: "invalid credentials"})
		}
		if errors.Is(err, service.ErrAccountNotConfirmed) {
			logrus.WithField("email", req.Email).Warn("Login failed: account not confirmed")
			return ctx.JSON(http.StatusForbidden, dto.ErrorResponse{Error: "account not confirmed"})
		}
		logrus.WithError(err).WithField("email", req.Email).Error("Login failed")
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	logrus.WithField("email", req.Email).Info("Login successful")
	return ctx.JSON(http.StatusOK, dto.LoginResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	})
}

func (c *AuthController) Logout(ctx echo.Context) error {
	var req dto.LogoutRequest
	if err := ctx.Bind(&req); err != nil {
		logrus.WithError(err).Debug("Failed to bind logout request")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.RefreshToken == "" {
		logrus.Debug("Logout validation failed: missing refresh_token")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "refresh_token is required"})
	}

	userID, ok := ctx.Get("user_id").(uint64)
	if !ok {
		logrus.Warn("Logout failed: missing user_id in context")
		return ctx.JSON(http.StatusUnauthorized, dto.ErrorResponse{Error: "unauthorized"})
	}

	logrus.WithField("user_id", userID).Info("Logout request received")
	if err := c.authService.Logout(ctx.Request().Context(), userID, req.RefreshToken); err != nil {
		logrus.WithError(err).WithField("user_id", userID).Error("Logout failed")
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	logrus.WithField("user_id", userID).Info("Logout successful")
	return ctx.JSON(http.StatusOK, dto.LogoutResponse{
		Message: "logged out successfully",
	})
}

func (c *AuthController) GenerateConfirmToken(ctx echo.Context) error {
	var req dto.GenerateConfirmTokenRequest
	if err := ctx.Bind(&req); err != nil {
		logrus.WithError(err).Debug("Failed to bind generate confirm token request")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.Email == "" {
		logrus.Debug("Generate confirm token validation failed: missing email")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "email is required"})
	}

	logrus.WithField("email", req.Email).Info("Generate confirm token request received")
	token, err := c.authService.GenerateConfirmToken(ctx.Request().Context(), req.Email)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			logrus.WithField("email", req.Email).Warn("Generate confirm token failed: user not found")
			return ctx.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "user not found"})
		}
		if errors.Is(err, service.ErrAccountAlreadyConfirmed) {
			logrus.WithField("email", req.Email).Warn("Generate confirm token failed: account already confirmed")
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "account is already confirmed"})
		}
		logrus.WithError(err).WithField("email", req.Email).Error("Generate confirm token failed")
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	logrus.WithField("email", req.Email).Info("Confirm token generated")
	return ctx.JSON(http.StatusOK, dto.GenerateConfirmTokenResponse{
		ConfirmToken: token,
		Message:      "confirm token generated successfully",
	})
}

func (c *AuthController) RefreshToken(ctx echo.Context) error {
	var req dto.RefreshTokenRequest
	if err := ctx.Bind(&req); err != nil {
		logrus.WithError(err).Debug("Failed to bind refresh token request")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.RefreshToken == "" {
		logrus.Debug("Refresh token validation failed: missing refresh_token")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "refresh_token is required"})
	}

	logrus.Info("Refresh token request received")
	result, err := c.authService.RefreshToken(ctx.Request().Context(), req.RefreshToken)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) || errors.Is(err, service.ErrTokenExpired) {
			logrus.Warn("Refresh token failed: invalid or expired token")
			return ctx.JSON(http.StatusUnauthorized, dto.ErrorResponse{Error: "invalid or expired refresh token"})
		}
		logrus.WithError(err).Error("Refresh token failed")
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	logrus.Info("Refresh token successful")
	return ctx.JSON(http.StatusOK, dto.RefreshTokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	})
}

func (c *AuthController) ValidateToken(ctx echo.Context) error {
	var req dto.ValidateTokenRequest
	if err := ctx.Bind(&req); err != nil {
		logrus.WithError(err).Debug("Failed to bind validate token request")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.AccessToken == "" {
		logrus.Debug("Validate token failed: missing access_token")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "access_token is required"})
	}

	claims, err := c.authService.ValidateAccessToken(req.AccessToken)
	if err != nil {
		logrus.Debug("Validate token failed")
		return ctx.JSON(http.StatusOK, dto.ValidateTokenResponse{
			Valid: false,
		})
	}

	logrus.WithField("user_id", claims.UserID).Debug("Validate token succeeded")
	return ctx.JSON(http.StatusOK, dto.ValidateTokenResponse{
		Valid:  true,
		UserID: claims.UserID,
		Email:  claims.Email,
	})
}

func (c *AuthController) ChangePassword(ctx echo.Context) error {
	var req dto.ChangePasswordRequest
	if err := ctx.Bind(&req); err != nil {
		logrus.WithError(err).Debug("Failed to bind change password request")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.OldPassword == "" || req.NewPassword == "" {
		logrus.Debug("Change password validation failed: missing fields")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "old_password and new_password are required"})
	}

	userID, ok := ctx.Get("user_id").(uint64)
	if !ok {
		logrus.Warn("Change password failed: missing user_id in context")
		return ctx.JSON(http.StatusUnauthorized, dto.ErrorResponse{Error: "unauthorized"})
	}

	logrus.WithField("user_id", userID).Info("Change password request received")
	err := c.authService.ChangePassword(ctx.Request().Context(), userID, req.OldPassword, req.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			logrus.WithField("user_id", userID).Warn("Change password failed: user not found")
			return ctx.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "user not found"})
		}
		if errors.Is(err, service.ErrPasswordMismatch) {
			logrus.WithField("user_id", userID).Warn("Change password failed: old password mismatch")
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "old password is incorrect"})
		}
		if errors.Is(err, service.ErrWeakPassword) {
			logrus.WithField("user_id", userID).Warn("Change password failed: weak password")
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: err.Error()})
		}
		logrus.WithError(err).WithField("user_id", userID).Error("Change password failed")
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	logrus.WithField("user_id", userID).Info("Password changed")
	return ctx.JSON(http.StatusOK, dto.ChangePasswordResponse{
		Message: "password changed successfully",
	})
}

func (c *AuthController) ConfirmAccount(ctx echo.Context) error {
	var req dto.ConfirmAccountRequest
	if err := ctx.Bind(&req); err != nil {
		logrus.WithError(err).Debug("Failed to bind confirm account request")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.Token == "" {
		logrus.Debug("Confirm account validation failed: missing token")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "token is required"})
	}

	logrus.Info("Confirm account request received")
	err := c.authService.ConfirmAccount(ctx.Request().Context(), req.Token)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			logrus.Warn("Confirm account failed: invalid token")
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid token"})
		}
		if errors.Is(err, service.ErrTokenExpired) {
			logrus.Warn("Confirm account failed: token expired")
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "token has expired"})
		}
		logrus.WithError(err).Error("Confirm account failed")
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	logrus.Info("Account confirmed")
	return ctx.JSON(http.StatusOK, dto.ConfirmAccountResponse{
		Message: "account confirmed successfully",
	})
}

func (c *AuthController) RequestPasswordReset(ctx echo.Context) error {
	var req dto.RequestPasswordResetRequest
	if err := ctx.Bind(&req); err != nil {
		logrus.WithError(err).Debug("Failed to bind request password reset")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.Email == "" {
		logrus.Debug("Request password reset validation failed: missing email")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "email is required"})
	}

	logrus.WithField("email", req.Email).Info("Password reset requested")
	result, err := c.authService.RequestPasswordReset(ctx.Request().Context(), req.Email)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			logrus.WithField("email", req.Email).Debug("Password reset requested for unknown email")
			return ctx.JSON(http.StatusOK, dto.RequestPasswordResetResponse{
				Message: "if the email exists, a reset token has been generated",
			})
		}
		logrus.WithError(err).WithField("email", req.Email).Error("Request password reset failed")
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	logrus.WithField("email", req.Email).Info("Password reset token generated")
	return ctx.JSON(http.StatusOK, dto.RequestPasswordResetResponse{
		ResetToken: result.ResetToken,
		Message:    "reset token generated successfully",
	})
}

func (c *AuthController) ResetPassword(ctx echo.Context) error {
	var req dto.ResetPasswordRequest
	if err := ctx.Bind(&req); err != nil {
		logrus.WithError(err).Debug("Failed to bind reset password request")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.Token == "" || req.NewPassword == "" {
		logrus.Debug("Reset password validation failed: missing token or new_password")
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "token and new_password are required"})
	}

	logrus.Info("Reset password request received")
	err := c.authService.ResetPassword(ctx.Request().Context(), req.Token, req.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			logrus.Warn("Reset password failed: invalid token")
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid token"})
		}
		if errors.Is(err, service.ErrTokenExpired) {
			logrus.Warn("Reset password failed: token expired")
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "token has expired"})
		}
		if errors.Is(err, service.ErrWeakPassword) {
			logrus.Warn("Reset password failed: weak password")
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: err.Error()})
		}
		logrus.WithError(err).Error("Reset password failed")
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	logrus.Info("Password reset successful")
	return ctx.JSON(http.StatusOK, dto.ResetPasswordResponse{
		Message: "password reset successfully",
	})
}
