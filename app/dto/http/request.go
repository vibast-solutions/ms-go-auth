package http

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email         string `json:"email"`
	Password      string `json:"password"`
	TokenDuration *int64 `json:"token_duration,omitempty"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type ConfirmAccountRequest struct {
	Token string `json:"token"`
}

type RequestPasswordResetRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type GenerateConfirmTokenRequest struct {
	Email string `json:"email"`
}
