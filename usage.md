# Auth Microservice - Client Integration Guide

You are building a microservice that depends on the auth microservice. This document describes how to interact with it. The auth service handles user registration, login, JWT token management, password changes, and password reset flows. It exposes two interfaces: HTTP (REST) and gRPC. For service-to-service communication, prefer gRPC. For frontend or external clients, use HTTP.

## Connection Details

- HTTP: `http://auth-service:8080`
- gRPC: `auth-service:9090`

## Authentication Model

All callers must send a valid internal API key:
- HTTP: `X-API-Key`
- gRPC: metadata `x-api-key`

The auth service uses a two-token system:
- **Access token**: A short-lived JWT (default 15 minutes). Include it in requests to protected endpoints as `Authorization: Bearer <access_token>`. The JWT payload contains `user_id` (uint64), `email` (string), and `roles` ([]string).
- **Refresh token**: A long-lived opaque UUID (default 7 days), stored in the database. Used to obtain new access tokens via `POST /auth/refresh-token`. Token rotation is enforced: each refresh issues a new token pair and invalidates the old refresh token.

Users must confirm their account before they can log in. Registration returns a `confirm_token` that must be submitted to confirm the account.

## gRPC Integration (service-to-service)

Import the proto file from `auth/proto/auth.proto`. The package is `auth` and the Go package is `auth/app/types`.

### Available RPCs

```protobuf
service AuthService {
  rpc Register(RegisterRequest) returns (RegisterResponse);
  rpc Login(LoginRequest) returns (LoginResponse);
  rpc Logout(LogoutRequest) returns (LogoutResponse);
  rpc ChangePassword(ChangePasswordRequest) returns (ChangePasswordResponse);
  rpc ConfirmAccount(ConfirmAccountRequest) returns (ConfirmAccountResponse);
  rpc RequestPasswordReset(RequestPasswordResetRequest) returns (RequestPasswordResetResponse);
  rpc ResetPassword(ResetPasswordRequest) returns (ResetPasswordResponse);
  rpc ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse);
  rpc ValidateInternalAccess(ValidateInternalAccessRequest) returns (ValidateInternalAccessResponse);
  rpc RefreshToken(RefreshTokenRequest) returns (RefreshTokenResponse);
  rpc GenerateConfirmToken(GenerateConfirmTokenRequest) returns (GenerateConfirmTokenResponse);
}
```

### ValidateToken - the key RPC for other services

When your service receives a request with a JWT access token and needs to verify the user's identity, call `ValidateToken` (available via both gRPC and HTTP). This only checks the JWT signature and expiry — no database call is made:

```
Request:  { access_token: "the-jwt-string" }
Response: { valid: true/false, user_id: 123, email: "user@example.com", roles: ["ROLE_USER"] }
```

If `valid` is `false`, reject the request. If `valid` is `true`, use `user_id`, `email`, and `roles` to identify the caller.

### gRPC Error Codes

| Code | Meaning |
|------|---------|
| InvalidArgument | Missing or empty required fields |
| AlreadyExists | Email already registered (Register) |
| Unauthenticated | Wrong email/password (Login) |
| PermissionDenied | Account not confirmed (Login) |
| NotFound | User not found (ChangePassword, GenerateConfirmToken) |
| FailedPrecondition | Account already confirmed (GenerateConfirmToken) |
| Internal | Server-side failure |

### Go client example

```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    authpb "auth/app/types"
)

conn, _ := grpc.Dial("auth-service:9090", grpc.WithTransportCredentials(insecure.NewCredentials()))
client := authpb.NewAuthServiceClient(conn)

// Validate a token from an incoming request
resp, err := client.ValidateToken(ctx, &authpb.ValidateTokenRequest{
    AccessToken: tokenFromHeader,
})
if err != nil || !resp.Valid {
    // reject request
}
userID := resp.UserId
email := resp.Email
```

## HTTP Integration (frontend/external clients)

All endpoints use JSON. Content-Type is `application/json`. Errors return `{"error": "message"}`.

### POST /auth/register
Create a new user. The response includes a `confirm_token` that must be used to confirm the account before the user can log in.

```
Request:  {"email": "user@example.com", "password": "secret"}
Response: {"user_id": 1, "email": "user@example.com", "roles": ["ROLE_USER"], "confirm_token": "uuid", "message": "..."}
Status:   201 Created
Errors:   400 (missing fields), 409 (email taken)
```

### POST /auth/confirm-account
Confirm a user account using the token from registration.

```
Request:  {"token": "uuid-from-register"}
Response: {"message": "account confirmed successfully"}
Status:   200 OK
Errors:   400 (invalid/expired token)
```

### POST /auth/generate-confirm-token
Get a confirmation token for an unconfirmed account. If the account already has a valid (non-expired) token, it is returned as-is. If the token is expired or missing, a new one is generated.

```
Request:  {"email": "user@example.com"}
Response: {"confirm_token": "uuid", "message": "confirm token generated successfully"}
Status:   200 OK
Errors:   400 (account already confirmed), 404 (user not found)
```

### POST /auth/login
Authenticate a confirmed user. Returns access and refresh tokens.

```
Request:  {"email": "user@example.com", "password": "secret"}
Response: {"access_token": "jwt", "refresh_token": "uuid", "expires_in": 900, "roles": ["ROLE_USER"]}
Status:   200 OK
Errors:   400 (missing fields), 401 (wrong credentials), 403 (not confirmed)
```

`expires_in` is in seconds (default 900 = 15 minutes).

### POST /auth/refresh-token
Exchange a refresh token for a new access token and refresh token. The old refresh token is invalidated (token rotation).

```
Request:  {"refresh_token": "uuid-from-login"}
Response: {"access_token": "new-jwt", "refresh_token": "new-uuid", "expires_in": 900, "roles": ["ROLE_USER"]}
Status:   200 OK
Errors:   400 (missing refresh_token), 401 (invalid or expired refresh token)
```

### POST /auth/logout
Invalidate a refresh token. Requires `Authorization: Bearer <access_token>` header.

```
Request:  {"refresh_token": "uuid-from-login"}
Response: {"message": "logged out successfully"}
Status:   200 OK
Errors:   400 (missing refresh_token), 401 (missing/invalid access token)
```

### POST /auth/change-password
Change the current user's password. Requires `Authorization: Bearer <access_token>` header. The user is identified from the JWT.

```
Request:  {"old_password": "current", "new_password": "new"}
Response: {"message": "password changed successfully"}
Status:   200 OK
Errors:   400 (missing fields, wrong old password), 401 (missing/invalid access token), 404 (user not found)
```

### POST /auth/request-password-reset
Request a password reset token. If a valid (non-expired) reset token already exists, it is returned instead of generating a new one. Does not reveal whether the email exists.

```
Request:  {"email": "user@example.com"}
Response: {"reset_token": "uuid", "message": "reset token generated successfully"}
Status:   200 OK
Errors:   400 (missing email)
```

If the email does not exist, the response is still 200 with `{"message": "if the email exists, a reset token has been generated"}` and no `reset_token` field.

### POST /auth/validate-token
Validate a JWT access token and get the associated user info. This is the HTTP equivalent of the `ValidateToken` gRPC call. Only checks the JWT signature and expiry — no database call is made. Always returns 200; use the `valid` field to determine the result.

```
Request:  {"access_token": "jwt-string"}
Response: {"valid": true, "user_id": 1, "email": "user@example.com", "roles": ["ROLE_USER"]}
Status:   200 OK (always, even for invalid tokens)
```

Invalid or expired tokens return `{"valid": false}`.

### POST /auth/reset-password
Reset password using a reset token. Invalidates all existing refresh tokens for the user.

```
Request:  {"token": "uuid-from-reset-request", "new_password": "newpassword"}
Response: {"message": "password reset successfully"}
Status:   200 OK
Errors:   400 (invalid/expired token, missing fields)
```

## Typical Client Flows

### Registration flow
1. `POST /auth/register` with email + password -> get `confirm_token`
2. `POST /auth/confirm-account` with the token -> account is active
3. If the confirm token expired, call `POST /auth/generate-confirm-token` with email to get a new one
4. `POST /auth/login` -> get `access_token` and `refresh_token`

### Authenticated request flow
1. Include `Authorization: Bearer <access_token>` header in requests to protected endpoints
2. If the access token is expired (401 response), call `POST /auth/refresh-token` with the refresh token to get a new token pair
3. If the refresh token is also expired (401 response), re-login

### Service-to-service token validation flow
1. Receive a JWT access token from the caller (e.g., forwarded from the UI)
2. Call `ValidateToken` via gRPC or `POST /auth/validate-token` via HTTP
3. If `valid` is `true`, use the returned `user_id`, `email`, and `roles` to identify the caller
4. If `valid` is `false`, reject the request

### Service-to-service internal API key flow
1. Call `POST /auth/internal/access` with:
   - header `X-API-Key: <caller-service-api-key>`
   - body `{"api_key":"<key-to-inspect>"}`
2. If auth returns `401`, reject caller (untrusted caller service)
3. If auth returns `404`, reject caller (inspected key not found)
4. If auth returns `200`, use `service_name` and `allowed_access` to verify caller permissions

### Password reset flow
1. `POST /auth/request-password-reset` with email -> get `reset_token`
2. `POST /auth/reset-password` with token + new password -> done
3. All existing sessions are invalidated; user must log in again

## JWT Payload Structure

The access token is an HS256-signed JWT with this payload:

```json
{
  "user_id": 1,
  "email": "user@example.com",
  "roles": ["ROLE_USER"],
  "sub": "user@example.com",
  "exp": 1700000000,
  "iat": 1699999100
}
```

Other services should not parse JWTs themselves. Use the `ValidateToken` gRPC call or `POST /auth/validate-token` HTTP endpoint instead, which handle signature verification and expiry checks.
