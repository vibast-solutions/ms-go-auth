package controller

import (
	"errors"
	"net/http"

	httpdto "github.com/vibast-solutions/ms-go-auth/app/dto"
	"github.com/vibast-solutions/ms-go-auth/app/service"
	"github.com/vibast-solutions/ms-go-auth/app/types"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type UserAuthController struct {
	userAuthService service.UserAuthService
}

func NewUserAuthController(userAuthService service.UserAuthService) *UserAuthController {
	return &UserAuthController{userAuthService: userAuthService}
}

func (c *UserAuthController) Register(ctx echo.Context) error {
	req, err := types.NewRegisterRequestFromContext(ctx)
	if err != nil {
		logrus.WithError(err).Debug("Failed to bind register request")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "invalid request body"})
	}

	if err = req.Validate(); err != nil {
		logrus.WithField("email", req.GetEmail()).Debug("Register validation failed")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: err.Error()})
	}

	logrus.WithField("email", req.GetEmail()).Info("Register request received")
	result, err := c.userAuthService.Register(ctx.Request().Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrUserExists) {
			logrus.WithField("email", req.GetEmail()).Warn("Register failed: user already exists")
			return ctx.JSON(http.StatusConflict, httpdto.ErrorResponse{Error: "user already exists"})
		}
		if errors.Is(err, service.ErrWeakPassword) {
			logrus.WithField("email", req.GetEmail()).Warn("Register failed: weak password")
			return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: err.Error()})
		}
		logrus.WithError(err).WithField("email", req.GetEmail()).Error("Register failed")
		return ctx.JSON(http.StatusInternalServerError, httpdto.ErrorResponse{Error: "internal server error"})
	}

	logrus.WithFields(logrus.Fields{
		"user_id": result.GetUserId(),
		"email":   result.GetEmail(),
	}).Info("User registered")

	return ctx.JSON(http.StatusCreated, result)
}

func (c *UserAuthController) Login(ctx echo.Context) error {
	req, err := types.NewLoginRequestFromContext(ctx)
	if err != nil {
		logrus.WithError(err).Debug("Failed to bind login request")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "invalid request body"})
	}

	if err = req.Validate(); err != nil {
		logrus.WithField("email", req.GetEmail()).Debug("Login validation failed")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: err.Error()})
	}

	logrus.WithField("email", req.GetEmail()).Info("Login request received")
	result, err := c.userAuthService.Login(ctx.Request().Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			logrus.WithField("email", req.GetEmail()).Warn("Login failed: invalid credentials")
			return ctx.JSON(http.StatusUnauthorized, httpdto.ErrorResponse{Error: "invalid credentials"})
		}
		if errors.Is(err, service.ErrAccountNotConfirmed) {
			logrus.WithField("email", req.GetEmail()).Warn("Login failed: account not confirmed")
			return ctx.JSON(http.StatusForbidden, httpdto.ErrorResponse{Error: "account not confirmed"})
		}
		logrus.WithError(err).WithField("email", req.GetEmail()).Error("Login failed")
		return ctx.JSON(http.StatusInternalServerError, httpdto.ErrorResponse{Error: "internal server error"})
	}

	logrus.WithField("email", req.GetEmail()).Info("Login successful")
	return ctx.JSON(http.StatusOK, result)
}

func (c *UserAuthController) Logout(ctx echo.Context) error {
	req, err := types.NewLogoutRequestFromContext(ctx)
	if err != nil {
		logrus.WithError(err).Debug("Failed to bind logout request")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "invalid request body"})
	}

	if err = req.Validate(); err != nil {
		logrus.Debug("Logout validation failed")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: err.Error()})
	}

	userID, ok := ctx.Get("user_id").(uint64)
	if !ok {
		logrus.Warn("Logout failed: missing user_id in context")
		return ctx.JSON(http.StatusUnauthorized, httpdto.ErrorResponse{Error: "unauthorized"})
	}

	logrus.WithField("user_id", userID).Info("Logout request received")
	if err = c.userAuthService.Logout(ctx.Request().Context(), userID, req); err != nil {
		logrus.WithError(err).WithField("user_id", userID).Error("Logout failed")
		return ctx.JSON(http.StatusInternalServerError, httpdto.ErrorResponse{Error: "internal server error"})
	}

	logrus.WithField("user_id", userID).Info("Logout successful")
	return ctx.JSON(http.StatusOK, &types.LogoutResponse{Message: "logged out successfully"})
}

func (c *UserAuthController) GenerateConfirmToken(ctx echo.Context) error {
	req, err := types.NewGenerateConfirmTokenRequestFromContext(ctx)
	if err != nil {
		logrus.WithError(err).Debug("Failed to bind generate confirm token request")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "invalid request body"})
	}

	if err = req.Validate(); err != nil {
		logrus.Debug("Generate confirm token validation failed")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: err.Error()})
	}

	logrus.WithField("email", req.GetEmail()).Info("Generate confirm token request received")
	res, err := c.userAuthService.GenerateConfirmToken(ctx.Request().Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			logrus.WithField("email", req.GetEmail()).Warn("Generate confirm token failed: user not found")
			return ctx.JSON(http.StatusNotFound, httpdto.ErrorResponse{Error: "user not found"})
		}
		if errors.Is(err, service.ErrAccountAlreadyConfirmed) {
			logrus.WithField("email", req.GetEmail()).Warn("Generate confirm token failed: account already confirmed")
			return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "account is already confirmed"})
		}
		logrus.WithError(err).WithField("email", req.GetEmail()).Error("Generate confirm token failed")
		return ctx.JSON(http.StatusInternalServerError, httpdto.ErrorResponse{Error: "internal server error"})
	}

	logrus.WithField("email", req.GetEmail()).Info("Confirm token generated")
	return ctx.JSON(http.StatusOK, res)
}

func (c *UserAuthController) RefreshToken(ctx echo.Context) error {
	req, err := types.NewRefreshTokenRequestFromContext(ctx)
	if err != nil {
		logrus.WithError(err).Debug("Failed to bind refresh token request")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "invalid request body"})
	}

	if err = req.Validate(); err != nil {
		logrus.Debug("Refresh token validation failed")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: err.Error()})
	}

	logrus.Info("Refresh token request received")
	result, err := c.userAuthService.RefreshToken(ctx.Request().Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) || errors.Is(err, service.ErrTokenExpired) {
			logrus.Warn("Refresh token failed: invalid or expired token")
			return ctx.JSON(http.StatusUnauthorized, httpdto.ErrorResponse{Error: "invalid or expired refresh token"})
		}
		logrus.WithError(err).Error("Refresh token failed")
		return ctx.JSON(http.StatusInternalServerError, httpdto.ErrorResponse{Error: "internal server error"})
	}

	logrus.Info("Refresh token successful")
	return ctx.JSON(http.StatusOK, result)
}

func (c *UserAuthController) ValidateToken(ctx echo.Context) error {
	req, err := types.NewValidateTokenRequestFromContext(ctx)
	if err != nil {
		logrus.WithError(err).Debug("Failed to bind validate token request")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "invalid request body"})
	}

	if err = req.Validate(); err != nil {
		logrus.Debug("Validate token failed")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: err.Error()})
	}

	claims, err := c.userAuthService.ValidateAccessToken(req.GetAccessToken())
	if err != nil {
		logrus.Debug("Validate token failed")
		return writeProtoJSON(ctx, http.StatusOK, &types.ValidateTokenResponse{Valid: false})
	}

	logrus.WithField("user_id", claims.UserID).Debug("Validate token succeeded")
	return writeProtoJSON(ctx, http.StatusOK, &types.ValidateTokenResponse{
		Valid:  true,
		UserId: claims.UserID,
		Email:  claims.Email,
		Roles:  claims.Roles,
	})
}

func (c *UserAuthController) ChangePassword(ctx echo.Context) error {
	req, err := types.NewChangePasswordRequestFromContext(ctx)
	if err != nil {
		logrus.WithError(err).Debug("Failed to bind change password request")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "invalid request body"})
	}

	if err = req.Validate(); err != nil {
		logrus.Debug("Change password validation failed")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: err.Error()})
	}

	userID, ok := ctx.Get("user_id").(uint64)
	if !ok {
		logrus.Warn("Change password failed: missing user_id in context")
		return ctx.JSON(http.StatusUnauthorized, httpdto.ErrorResponse{Error: "unauthorized"})
	}

	logrus.WithField("user_id", userID).Info("Change password request received")
	err = c.userAuthService.ChangePassword(ctx.Request().Context(), userID, req)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			logrus.WithField("user_id", userID).Warn("Change password failed: user not found")
			return ctx.JSON(http.StatusNotFound, httpdto.ErrorResponse{Error: "user not found"})
		}
		if errors.Is(err, service.ErrPasswordMismatch) {
			logrus.WithField("user_id", userID).Warn("Change password failed: old password mismatch")
			return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "old password is incorrect"})
		}
		if errors.Is(err, service.ErrWeakPassword) {
			logrus.WithField("user_id", userID).Warn("Change password failed: weak password")
			return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: err.Error()})
		}
		logrus.WithError(err).WithField("user_id", userID).Error("Change password failed")
		return ctx.JSON(http.StatusInternalServerError, httpdto.ErrorResponse{Error: "internal server error"})
	}

	logrus.WithField("user_id", userID).Info("Password changed")
	return ctx.JSON(http.StatusOK, &types.ChangePasswordResponse{Message: "password changed successfully"})
}

func (c *UserAuthController) ConfirmAccount(ctx echo.Context) error {
	req, err := types.NewConfirmAccountRequestFromContext(ctx)
	if err != nil {
		logrus.WithError(err).Debug("Failed to bind confirm account request")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "invalid request body"})
	}

	if err = req.Validate(); err != nil {
		logrus.Debug("Confirm account validation failed")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: err.Error()})
	}

	logrus.Info("Confirm account request received")
	err = c.userAuthService.ConfirmAccount(ctx.Request().Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			logrus.Warn("Confirm account failed: invalid token")
			return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "invalid token"})
		}
		if errors.Is(err, service.ErrTokenExpired) {
			logrus.Warn("Confirm account failed: token expired")
			return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "token has expired"})
		}
		logrus.WithError(err).Error("Confirm account failed")
		return ctx.JSON(http.StatusInternalServerError, httpdto.ErrorResponse{Error: "internal server error"})
	}

	logrus.Info("Account confirmed")
	return ctx.JSON(http.StatusOK, &types.ConfirmAccountResponse{Message: "account confirmed successfully"})
}

func (c *UserAuthController) RequestPasswordReset(ctx echo.Context) error {
	req, err := types.NewRequestPasswordResetRequestFromContext(ctx)
	if err != nil {
		logrus.WithError(err).Debug("Failed to bind request password reset")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "invalid request body"})
	}

	if err = req.Validate(); err != nil {
		logrus.Debug("Request password reset validation failed")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: err.Error()})
	}

	logrus.WithField("email", req.GetEmail()).Info("Password reset requested")
	result, err := c.userAuthService.RequestPasswordReset(ctx.Request().Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			logrus.WithField("email", req.GetEmail()).Debug("Password reset requested for unknown email")
			return ctx.JSON(http.StatusOK, &types.RequestPasswordResetResponse{
				Message: "if the email exists, a reset token has been generated",
			})
		}
		logrus.WithError(err).WithField("email", req.GetEmail()).Error("Request password reset failed")
		return ctx.JSON(http.StatusInternalServerError, httpdto.ErrorResponse{Error: "internal server error"})
	}

	logrus.WithField("email", req.GetEmail()).Info("Password reset token generated")
	return ctx.JSON(http.StatusOK, result)
}

func (c *UserAuthController) ResetPassword(ctx echo.Context) error {
	req, err := types.NewResetPasswordRequestFromContext(ctx)
	if err != nil {
		logrus.WithError(err).Debug("Failed to bind reset password request")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "invalid request body"})
	}

	if err = req.Validate(); err != nil {
		logrus.Debug("Reset password validation failed")
		return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: err.Error()})
	}

	logrus.Info("Reset password request received")
	err = c.userAuthService.ResetPassword(ctx.Request().Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			logrus.Warn("Reset password failed: invalid token")
			return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "invalid token"})
		}
		if errors.Is(err, service.ErrTokenExpired) {
			logrus.Warn("Reset password failed: token expired")
			return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: "token has expired"})
		}
		if errors.Is(err, service.ErrWeakPassword) {
			logrus.Warn("Reset password failed: weak password")
			return ctx.JSON(http.StatusBadRequest, httpdto.ErrorResponse{Error: err.Error()})
		}
		logrus.WithError(err).Error("Reset password failed")
		return ctx.JSON(http.StatusInternalServerError, httpdto.ErrorResponse{Error: "internal server error"})
	}

	logrus.Info("Password reset successful")
	return ctx.JSON(http.StatusOK, &types.ResetPasswordResponse{Message: "password reset successfully"})
}

func writeProtoJSON(ctx echo.Context, statusCode int, message proto.Message) error {
	payload, err := protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}.Marshal(message)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal protobuf response")
		return ctx.JSON(http.StatusInternalServerError, httpdto.ErrorResponse{Error: "internal server error"})
	}

	return ctx.Blob(statusCode, echo.MIMEApplicationJSONCharsetUTF8, payload)
}
