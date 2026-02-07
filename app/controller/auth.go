package controller

import (
	"errors"
	"net/http"
	"time"

	dto "github.com/vibast-solutions/ms-go-auth/app/dto/http"
	"github.com/vibast-solutions/ms-go-auth/app/service"

	"github.com/labstack/echo/v4"
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
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.Email == "" || req.Password == "" {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "email and password are required"})
	}

	result, err := c.authService.Register(ctx.Request().Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrUserExists) {
			return ctx.JSON(http.StatusConflict, dto.ErrorResponse{Error: "user already exists"})
		}
		if errors.Is(err, service.ErrWeakPassword) {
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: err.Error()})
		}
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

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
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.Email == "" || req.Password == "" {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "email and password are required"})
	}

	var customTTL time.Duration
	if req.TokenDuration != nil {
		if *req.TokenDuration <= 0 {
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "token_duration must be greater than 0"})
		}
		customTTL = time.Duration(*req.TokenDuration) * time.Minute
	}

	result, err := c.authService.Login(ctx.Request().Context(), req.Email, req.Password, customTTL)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			return ctx.JSON(http.StatusUnauthorized, dto.ErrorResponse{Error: "invalid credentials"})
		}
		if errors.Is(err, service.ErrAccountNotConfirmed) {
			return ctx.JSON(http.StatusForbidden, dto.ErrorResponse{Error: "account not confirmed"})
		}
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	return ctx.JSON(http.StatusOK, dto.LoginResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	})
}

func (c *AuthController) Logout(ctx echo.Context) error {
	var req dto.LogoutRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.RefreshToken == "" {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "refresh_token is required"})
	}

	userID, ok := ctx.Get("user_id").(uint64)
	if !ok {
		return ctx.JSON(http.StatusUnauthorized, dto.ErrorResponse{Error: "unauthorized"})
	}

	if err := c.authService.Logout(ctx.Request().Context(), userID, req.RefreshToken); err != nil {
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	return ctx.JSON(http.StatusOK, dto.LogoutResponse{
		Message: "logged out successfully",
	})
}

func (c *AuthController) GenerateConfirmToken(ctx echo.Context) error {
	var req dto.GenerateConfirmTokenRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.Email == "" {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "email is required"})
	}

	token, err := c.authService.GenerateConfirmToken(ctx.Request().Context(), req.Email)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return ctx.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "user not found"})
		}
		if errors.Is(err, service.ErrAccountAlreadyConfirmed) {
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "account is already confirmed"})
		}
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	return ctx.JSON(http.StatusOK, dto.GenerateConfirmTokenResponse{
		ConfirmToken: token,
		Message:      "confirm token generated successfully",
	})
}

func (c *AuthController) RefreshToken(ctx echo.Context) error {
	var req dto.RefreshTokenRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.RefreshToken == "" {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "refresh_token is required"})
	}

	result, err := c.authService.RefreshToken(ctx.Request().Context(), req.RefreshToken)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) || errors.Is(err, service.ErrTokenExpired) {
			return ctx.JSON(http.StatusUnauthorized, dto.ErrorResponse{Error: "invalid or expired refresh token"})
		}
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	return ctx.JSON(http.StatusOK, dto.RefreshTokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	})
}

func (c *AuthController) ValidateToken(ctx echo.Context) error {
	var req dto.ValidateTokenRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.AccessToken == "" {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "access_token is required"})
	}

	claims, err := c.authService.ValidateAccessToken(req.AccessToken)
	if err != nil {
		return ctx.JSON(http.StatusOK, dto.ValidateTokenResponse{
			Valid: false,
		})
	}

	return ctx.JSON(http.StatusOK, dto.ValidateTokenResponse{
		Valid:  true,
		UserID: claims.UserID,
		Email:  claims.Email,
	})
}

func (c *AuthController) ChangePassword(ctx echo.Context) error {
	var req dto.ChangePasswordRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.OldPassword == "" || req.NewPassword == "" {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "old_password and new_password are required"})
	}

	userID, ok := ctx.Get("user_id").(uint64)
	if !ok {
		return ctx.JSON(http.StatusUnauthorized, dto.ErrorResponse{Error: "unauthorized"})
	}

	err := c.authService.ChangePassword(ctx.Request().Context(), userID, req.OldPassword, req.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return ctx.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "user not found"})
		}
		if errors.Is(err, service.ErrPasswordMismatch) {
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "old password is incorrect"})
		}
		if errors.Is(err, service.ErrWeakPassword) {
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: err.Error()})
		}
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	return ctx.JSON(http.StatusOK, dto.ChangePasswordResponse{
		Message: "password changed successfully",
	})
}

func (c *AuthController) ConfirmAccount(ctx echo.Context) error {
	var req dto.ConfirmAccountRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.Token == "" {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "token is required"})
	}

	err := c.authService.ConfirmAccount(ctx.Request().Context(), req.Token)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid token"})
		}
		if errors.Is(err, service.ErrTokenExpired) {
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "token has expired"})
		}
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	return ctx.JSON(http.StatusOK, dto.ConfirmAccountResponse{
		Message: "account confirmed successfully",
	})
}

func (c *AuthController) RequestPasswordReset(ctx echo.Context) error {
	var req dto.RequestPasswordResetRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.Email == "" {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "email is required"})
	}

	result, err := c.authService.RequestPasswordReset(ctx.Request().Context(), req.Email)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return ctx.JSON(http.StatusOK, dto.RequestPasswordResetResponse{
				Message: "if the email exists, a reset token has been generated",
			})
		}
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	return ctx.JSON(http.StatusOK, dto.RequestPasswordResetResponse{
		ResetToken: result.ResetToken,
		Message:    "reset token generated successfully",
	})
}

func (c *AuthController) ResetPassword(ctx echo.Context) error {
	var req dto.ResetPasswordRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request body"})
	}

	if req.Token == "" || req.NewPassword == "" {
		return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "token and new_password are required"})
	}

	err := c.authService.ResetPassword(ctx.Request().Context(), req.Token, req.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid token"})
		}
		if errors.Is(err, service.ErrTokenExpired) {
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "token has expired"})
		}
		if errors.Is(err, service.ErrWeakPassword) {
			return ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: err.Error()})
		}
		return ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal server error"})
	}

	return ctx.JSON(http.StatusOK, dto.ResetPasswordResponse{
		Message: "password reset successfully",
	})
}
