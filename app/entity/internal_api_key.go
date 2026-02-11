package entity

import "time"

type InternalAPIKey struct {
	ID            uint64
	ServiceName   string
	KeyHash       string
	AllowedAccess []string
	IsActive      bool
	ExpiresAt     time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
