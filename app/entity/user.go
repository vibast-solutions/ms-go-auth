package entity

import (
	"database/sql"
	"time"
)

type User struct {
	ID                    uint64
	Email                 string
	CanonicalEmail        string
	PasswordHash          string
	IsConfirmed           bool
	ConfirmToken          sql.NullString
	ConfirmTokenExpiresAt sql.NullTime
	ResetToken            sql.NullString
	ResetTokenExpiresAt   sql.NullTime
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

type RefreshToken struct {
	ID        uint64
	UserID    uint64
	Token     string
	ExpiresAt time.Time
	CreatedAt time.Time
}
