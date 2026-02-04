package http

type RegisterResponse struct {
	UserID       uint64 `json:"user_id"`
	Email        string `json:"email"`
	ConfirmToken string `json:"confirm_token"`
	Message      string `json:"message"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type LogoutResponse struct {
	Message string `json:"message"`
}

type ChangePasswordResponse struct {
	Message string `json:"message"`
}

type ConfirmAccountResponse struct {
	Message string `json:"message"`
}

type RequestPasswordResetResponse struct {
	ResetToken string `json:"reset_token"`
	Message    string `json:"message"`
}

type ResetPasswordResponse struct {
	Message string `json:"message"`
}

type GenerateConfirmTokenResponse struct {
	ConfirmToken string `json:"confirm_token"`
	Message      string `json:"message"`
}

type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
