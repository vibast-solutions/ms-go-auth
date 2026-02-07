package dto

import "github.com/vibast-solutions/ms-go-auth/app/entity"

type RegisterResult struct {
	User         *entity.User
	ConfirmToken string
}

type LoginResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}

type RequestPasswordResetResult struct {
	ResetToken string
}
