# Auth Microservice - Claude Context

## Overview
Authentication microservice built with Go, providing user registration, login, JWT token management, and password reset flows via both HTTP (Echo) and gRPC interfaces.

## Technology Stack
- **Framework**: Echo (HTTP), gRPC
- **CLI**: Cobra
- **Database**: MySQL with raw `database/sql`
- **Auth**: JWT (access + refresh tokens), bcrypt password hashing
- **Dependencies**: See `go.mod`

## Module
- **Path**: `github.com/vibast-solutions/ms-go-auth`
- Importable by other Go modules via `go get github.com/vibast-solutions/ms-go-auth`

## Directory Structure
```
auth/
├── main.go                 # Entry point, calls cmd.Execute()
├── Makefile                # Build targets (native, linux-arm64, linux-amd64)
├── cmd/
│   ├── root.go             # Cobra root command
│   ├── serve.go            # Starts HTTP (8080) + gRPC (9090) servers
│   └── version.go          # Version command (shows git tag + commit hash)
├── config/
│   └── config.go           # Environment-based configuration
├── proto/
│   └── auth.proto          # gRPC service definitions
├── app/
│   ├── controller/
│   │   └── auth.go         # HTTP handlers (Echo)
│   ├── grpc/
│   │   └── server.go       # gRPC handlers
│   ├── service/
│   │   └── auth.go         # Business logic (shared by HTTP & gRPC)
│   ├── repository/
│   │   └── user.go         # Database operations (UserRepository, RefreshTokenRepository)
│   ├── entity/
│   │   └── user.go         # DB models (User, RefreshToken)
│   ├── dto/
│   │   ├── result.go       # Service-layer result DTOs (RegisterResult, LoginResult, etc.)
│   │   └── http/
│   │       ├── request.go  # HTTP request DTOs
│   │       └── response.go # HTTP response DTOs
│   ├── types/
│   │   ├── auth.pb.go      # Generated protobuf types
│   │   └── auth_grpc.pb.go # Generated gRPC service
│   └── middleware/
│       └── auth.go         # JWT validation middleware
```

## Database Schema
Two tables in MySQL database `auth`:
- `users`: id, email, password_hash, is_confirmed, confirm_token, confirm_token_expires_at, reset_token, reset_token_expires_at, created_at, updated_at
- `refresh_tokens`: id, user_id (FK), token, expires_at, created_at

## API Endpoints (HTTP)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /auth/register | No | Create user, returns confirm_token |
| POST | /auth/login | No | Returns access_token + refresh_token |
| POST | /auth/refresh-token | No | Exchange refresh token for new token pair (rotation) |
| POST | /auth/generate-confirm-token | No | Get/regenerate confirm token for unconfirmed account |
| POST | /auth/logout | Yes | Invalidates refresh token |
| POST | /auth/change-password | Yes | Change password (requires old password) |
| POST | /auth/confirm-account | No | Confirm account with token |
| POST | /auth/validate-token | No | Validate JWT access token, returns user_id + email (no DB call) |
| POST | /auth/request-password-reset | No | Get/generate reset token (reuses valid token) |
| POST | /auth/reset-password | No | Reset password with token |

## gRPC Service
Same operations available via gRPC on port 9090. See `proto/auth.proto` for definitions.
Additional RPCs: `ValidateToken` (validates JWT, returns user info), `RefreshToken`, `GenerateConfirmToken`.

## Configuration (Environment Variables)
- `HTTP_PORT` (default: 8080)
- `GRPC_PORT` (default: 9090)
- `MYSQL_DSN`
- `JWT_SECRET`
- `JWT_ACCESS_TOKEN_TTL` (default: 15 min)
- `JWT_REFRESH_TOKEN_TTL` (default: 7 days)
- `CONFIRM_TOKEN_TTL` (default: 24 hours)
- `RESET_TOKEN_TTL` (default: 1 hour)

## Key Implementation Details
- Access tokens are JWTs with user_id and email in claims; validated via signature only (no DB call)
- Refresh tokens are UUIDs stored in database
- Token refresh uses rotation: old refresh token is deleted, new pair is issued
- Confirm token regeneration: returns existing valid token or creates new one; rejects if account already confirmed
- Password reset token reuse: returns existing valid token instead of creating a new one
- Passwords hashed with bcrypt (DefaultCost)
- Account confirmation required before login
- Password reset invalidates all refresh tokens for security
- HTTP auth middleware extracts user_id from JWT and sets it in Echo context
- Service-layer result DTOs live in `app/dto/` package, HTTP DTOs in `app/dto/http/`

## Build
- `make build` — native binary to `build/auth-service`
- `make build-linux-arm64` — Linux ARM64 cross-compile
- `make build-linux-amd64` — Linux AMD64 cross-compile
- `make build-all` — all targets
- `make clean` — remove `build/` directory
- Version and commit hash are injected at build time via `-ldflags` (see `cmd/version.go`)

## Common Tasks
- **Add new endpoint**: Add DTO in `dto/http/`, result struct in `dto/result.go` (if needed), method in `service/auth.go`, handler in `controller/auth.go`, route in `cmd/serve.go`
- **Add gRPC method**: Update `proto/auth.proto`, regenerate types, add handler in `grpc/server.go`
- **Regenerate protobuf**: `protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/auth.proto`
