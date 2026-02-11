package types

import (
	"errors"
	"strings"

	"github.com/labstack/echo/v4"
)

func NewRegisterRequestFromContext(ctx echo.Context) (*RegisterRequest, error) {
	var body RegisterRequest
	if err := ctx.Bind(&body); err != nil {
		return nil, err
	}

	return &body, nil
}

func (r *RegisterRequest) Validate() error {
	if strings.TrimSpace(r.GetEmail()) == "" || strings.TrimSpace(r.GetPassword()) == "" {
		return errors.New("email and password are required")
	}

	return nil
}

func NewLoginRequestFromContext(ctx echo.Context) (*LoginRequest, error) {
	var body LoginRequest
	if err := ctx.Bind(&body); err != nil {
		return nil, err
	}

	return &body, nil
}

func (r *LoginRequest) Validate() error {
	if strings.TrimSpace(r.GetEmail()) == "" || strings.TrimSpace(r.GetPassword()) == "" {
		return errors.New("email and password are required")
	}
	if r.GetTokenDuration() < 0 {
		return errors.New("token_duration must be greater than 0")
	}

	return nil
}

func NewLogoutRequestFromContext(ctx echo.Context) (*LogoutRequest, error) {
	var body LogoutRequest
	if err := ctx.Bind(&body); err != nil {
		return nil, err
	}

	return &body, nil
}

func (r *LogoutRequest) Validate() error {
	if strings.TrimSpace(r.GetRefreshToken()) == "" {
		return errors.New("refresh_token is required")
	}

	return nil
}

func NewChangePasswordRequestFromContext(ctx echo.Context) (*ChangePasswordRequest, error) {
	var body ChangePasswordRequest
	if err := ctx.Bind(&body); err != nil {
		return nil, err
	}

	return &body, nil
}

func (r *ChangePasswordRequest) Validate() error {
	if strings.TrimSpace(r.GetOldPassword()) == "" || strings.TrimSpace(r.GetNewPassword()) == "" {
		return errors.New("old_password and new_password are required")
	}

	return nil
}

func NewConfirmAccountRequestFromContext(ctx echo.Context) (*ConfirmAccountRequest, error) {
	var body ConfirmAccountRequest
	if err := ctx.Bind(&body); err != nil {
		return nil, err
	}

	return &body, nil
}

func (r *ConfirmAccountRequest) Validate() error {
	if strings.TrimSpace(r.GetToken()) == "" {
		return errors.New("token is required")
	}

	return nil
}

func NewRequestPasswordResetRequestFromContext(ctx echo.Context) (*RequestPasswordResetRequest, error) {
	var body RequestPasswordResetRequest
	if err := ctx.Bind(&body); err != nil {
		return nil, err
	}

	return &body, nil
}

func (r *RequestPasswordResetRequest) Validate() error {
	if strings.TrimSpace(r.GetEmail()) == "" {
		return errors.New("email is required")
	}

	return nil
}

func NewResetPasswordRequestFromContext(ctx echo.Context) (*ResetPasswordRequest, error) {
	var body ResetPasswordRequest
	if err := ctx.Bind(&body); err != nil {
		return nil, err
	}

	return &body, nil
}

func (r *ResetPasswordRequest) Validate() error {
	if strings.TrimSpace(r.GetToken()) == "" || strings.TrimSpace(r.GetNewPassword()) == "" {
		return errors.New("token and new_password are required")
	}

	return nil
}

func NewRefreshTokenRequestFromContext(ctx echo.Context) (*RefreshTokenRequest, error) {
	var body RefreshTokenRequest
	if err := ctx.Bind(&body); err != nil {
		return nil, err
	}

	return &body, nil
}

func (r *RefreshTokenRequest) Validate() error {
	if strings.TrimSpace(r.GetRefreshToken()) == "" {
		return errors.New("refresh_token is required")
	}

	return nil
}

func NewGenerateConfirmTokenRequestFromContext(ctx echo.Context) (*GenerateConfirmTokenRequest, error) {
	var body GenerateConfirmTokenRequest
	if err := ctx.Bind(&body); err != nil {
		return nil, err
	}

	return &body, nil
}

func (r *GenerateConfirmTokenRequest) Validate() error {
	if strings.TrimSpace(r.GetEmail()) == "" {
		return errors.New("email is required")
	}

	return nil
}

func NewValidateTokenRequestFromContext(ctx echo.Context) (*ValidateTokenRequest, error) {
	var body ValidateTokenRequest
	if err := ctx.Bind(&body); err != nil {
		return nil, err
	}

	return &body, nil
}

func (r *ValidateTokenRequest) Validate() error {
	if strings.TrimSpace(r.GetAccessToken()) == "" {
		return errors.New("access_token is required")
	}

	return nil
}

func NewValidateInternalAccessRequestFromContext(ctx echo.Context) (*ValidateInternalAccessRequest, error) {
	var body ValidateInternalAccessRequest
	if err := ctx.Bind(&body); err != nil {
		return nil, err
	}

	return &body, nil
}

func (r *ValidateInternalAccessRequest) Validate() error {
	if strings.TrimSpace(r.GetApiKey()) == "" {
		return errors.New("api_key is required")
	}

	return nil
}
