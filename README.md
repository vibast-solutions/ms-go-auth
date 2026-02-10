# Auth Microservice

`github.com/vibast-solutions/ms-go-auth`

Authentication microservice providing user registration, login, JWT token management, and password flows via HTTP and gRPC.

## Features

- User registration with email confirmation
- Default role assignment (`ROLE_USER`) at registration
- Login with JWT access and refresh tokens
- Token refresh with rotation (old refresh token is invalidated)
- Confirm token regeneration for unconfirmed accounts
- Password change and reset flows
- Password reset token reuse (returns existing token if not expired)
- Token validation endpoint (HTTP and gRPC) for service-to-service JWT verification
- Both HTTP (REST) and gRPC interfaces
- bcrypt password hashing

## Requirements

- Go 1.21+
- MySQL 8.0+
- (Optional) protoc for regenerating gRPC code

## Database Setup

Create the database and tables:

```sql
CREATE DATABASE IF NOT EXISTS auth;
USE auth;

CREATE TABLE users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    canonical_email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_confirmed TINYINT(1) NOT NULL DEFAULT 0,
    confirm_token VARCHAR(255) NULL,
    confirm_token_expires_at DATETIME NULL,
    reset_token VARCHAR(255) NULL,
    reset_token_expires_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE INDEX idx_users_email (email),
    UNIQUE INDEX idx_users_canonical_email (canonical_email),
    INDEX idx_users_confirm_token (confirm_token),
    INDEX idx_users_reset_token (reset_token)
);

CREATE TABLE refresh_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    UNIQUE INDEX idx_refresh_tokens_token (token),
    INDEX idx_refresh_tokens_user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE user_roles (
    user_id BIGINT UNSIGNED NOT NULL,
    role VARCHAR(64) NOT NULL,
    PRIMARY KEY (user_id, role),
    INDEX idx_user_roles_role (role),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

## Configuration

Set environment variables or use defaults:

| Variable | Default | Description |
|----------|---------|-------------|
| HTTP_HOST | 0.0.0.0 | HTTP server bind address |
| HTTP_PORT | 8080 | HTTP server port |
| GRPC_HOST | 0.0.0.0 | gRPC server bind address |
| GRPC_PORT | 9090 | gRPC server port |
| MYSQL_DSN | (required) | MySQL DSN (e.g. `user:pass@tcp(host:3306)/auth?parseTime=true`) |
| JWT_SECRET | (default) | Secret for signing JWTs |
| LOG_LEVEL | info | Log level (trace, debug, info, warn, error, fatal, panic) |
| JWT_ACCESS_TOKEN_TTL | 15 | Access token TTL in minutes |
| JWT_REFRESH_TOKEN_TTL | 10080 | Refresh token TTL in minutes (7 days) |

## Build

```bash
# Download dependencies
go mod tidy

# Build native binary
make build

# Cross-compile for Linux
make build-linux-arm64
make build-linux-amd64

# Cross-compile for macOS
make build-darwin-arm64
make build-darwin-amd64

# Build all targets
make build-all

# Clean build artifacts
make clean
```

Binaries are output to the `build/` directory.

## Run

```bash
# Run directly
go run main.go serve

# Or run the built binary
./build/auth-service serve
```

The service starts:
- HTTP server on 0.0.0.0:8080
- gRPC server on 0.0.0.0:9090

## Version

The binary includes a `version` command that shows the git tag and commit hash used during the build:

```bash
./build/auth-service version
# auth-service v1.0.0 (commit: a3b2c1d)
```

Version info is injected at build time via `-ldflags` in the Makefile. When running with `go run`, it shows `dev (commit: unknown)`.

## Importing

This module can be imported by other Go services:

```bash
go get github.com/vibast-solutions/ms-go-auth
```

## API Endpoints

### POST /auth/register
Create a new user account.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "secretpassword"
}
```

**Response (201):**
```json
{
  "user_id": 1,
  "email": "user@example.com",
  "roles": ["ROLE_USER"],
  "confirm_token": "uuid-token",
  "message": "registration successful, please confirm your account"
}
```

### POST /auth/confirm-account
Confirm user account with token from registration.

**Request:**
```json
{
  "token": "uuid-token"
}
```

### POST /auth/generate-confirm-token
Get a confirmation token for an unconfirmed account. Returns the existing token if it's still valid, or generates a new one.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response (200):**
```json
{
  "confirm_token": "uuid-token",
  "message": "confirm token generated successfully"
}
```

**Errors:** 400 (account already confirmed), 404 (user not found)

### POST /auth/login
Authenticate and get tokens.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "secretpassword"
}
```

**Response (200):**
```json
{
  "access_token": "jwt-token",
  "refresh_token": "uuid-token",
  "expires_in": 900,
  "roles": ["ROLE_USER"]
}
```

### POST /auth/refresh-token
Exchange a refresh token for a new access token and refresh token (token rotation). The old refresh token is invalidated.

**Request:**
```json
{
  "refresh_token": "uuid-token"
}
```

**Response (200):**
```json
{
  "access_token": "jwt-token",
  "refresh_token": "new-uuid-token",
  "expires_in": 900,
  "roles": ["ROLE_USER"]
}
```

**Errors:** 400 (missing refresh_token), 401 (invalid or expired refresh token)

### POST /auth/logout
Invalidate refresh token. Requires `Authorization: Bearer <access_token>` header.

**Request:**
```json
{
  "refresh_token": "uuid-token"
}
```

### POST /auth/change-password
Change password. Requires `Authorization: Bearer <access_token>` header.

**Request:**
```json
{
  "old_password": "currentpassword",
  "new_password": "newpassword"
}
```

### POST /auth/request-password-reset
Request a password reset token. If a valid (non-expired) reset token already exists, it is returned instead of generating a new one.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response (200):**
```json
{
  "reset_token": "uuid-token",
  "message": "reset token generated successfully"
}
```

### POST /auth/validate-token
Validate a JWT access token and get the associated user info. Intended for service-to-service calls. Does not hit the database — only verifies the JWT signature and expiry.

**Request:**
```json
{
  "access_token": "jwt-token"
}
```

**Response (200) — valid token:**
```json
{
  "valid": true,
  "user_id": 1,
  "email": "user@example.com",
  "roles": ["ROLE_USER"]
}
```

**Response (200) — invalid/expired token:**
```json
{
  "valid": false
}
```

### POST /auth/reset-password
Reset password using token.

**Request:**
```json
{
  "token": "uuid-token",
  "new_password": "newpassword"
}
```

## gRPC

The gRPC service runs on port 9090 and provides the same operations. See `proto/auth.proto` for service definitions.

Example with grpcurl:
```bash
grpcurl -plaintext -d '{"email":"user@example.com","password":"secret"}' \
  localhost:9090 auth.AuthService/Register
```

## Example Usage

```bash
# Register a user
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# Confirm account (use token from register response)
curl -X POST http://localhost:8080/auth/confirm-account \
  -H "Content-Type: application/json" \
  -d '{"token":"<confirm-token>"}'

# Generate a new confirm token (if token expired)
curl -X POST http://localhost:8080/auth/generate-confirm-token \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'

# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# Refresh tokens (use refresh_token from login response)
curl -X POST http://localhost:8080/auth/refresh-token \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh-token>"}'

# Validate a token (service-to-service)
curl -X POST http://localhost:8080/auth/validate-token \
  -H "Content-Type: application/json" \
  -d '{"access_token":"<access-token>"}'

# Change password (use access_token from login response)
curl -X POST http://localhost:8080/auth/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access-token>" \
  -d '{"old_password":"password123","new_password":"newpassword"}'
```

## Project Structure

```
auth/
├── main.go              # Entry point
├── Makefile             # Build targets (native, linux, darwin — arm64/amd64)
├── cmd/                 # CLI commands (Cobra)
│   ├── root.go          # Root command
│   ├── serve.go         # HTTP + gRPC servers
│   └── version.go       # Version command (git tag + commit)
├── config/              # Configuration
├── proto/               # gRPC definitions
└── app/
    ├── controller/      # HTTP handlers
    ├── grpc/            # gRPC handlers
    ├── service/         # Business logic
    ├── repository/      # Database operations
    ├── entity/          # Database models
    ├── dto/             # Service-layer result DTOs
    │   └── http/        # HTTP request/response DTOs
    ├── types/           # Generated protobuf types
    └── middleware/      # HTTP middleware
```
