# Auth Service Deployment Guide

This document describes what `auth` needs in development and production.

## 1. Runtime Topology

- Service binary: `auth-service` (command: `serve`)
- Protocols: HTTP + gRPC in the same process
- Default ports:
- HTTP: `8080` (configurable with `HTTP_PORT`)
- gRPC: `9090` (configurable with `GRPC_PORT`)
- External dependencies:
- MySQL: required
- Redis: not used

## 2. Environment Variables

Required:

- `MYSQL_DSN`
- `JWT_SECRET`

Optional (with defaults):

- `HTTP_HOST` (default `0.0.0.0`)
- `HTTP_PORT` (default `8080`)
- `GRPC_HOST` (default `0.0.0.0`)
- `GRPC_PORT` (default `9090`)
- `LOG_LEVEL` (default `info`)
- `JWT_ACCESS_TOKEN_TTL` minutes (default `15`)
- `JWT_REFRESH_TOKEN_TTL` minutes (default `10080`)
- `CONFIRM_TOKEN_TTL` minutes (default `1440`)
- `RESET_TOKEN_TTL` minutes (default `60`)
- `PASSWORD_MIN_LENGTH` (default `8`)
- `PASSWORD_REQUIRE_UPPERCASE` (default `true`)
- `PASSWORD_REQUIRE_LOWERCASE` (default `true`)
- `PASSWORD_REQUIRE_NUMBER` (default `true`)
- `PASSWORD_REQUIRE_SPECIAL` (default `true`)

Example DSN:

- `MYSQL_DSN=user:pass@tcp(mysql-host:3306)/auth?parseTime=true`

## 3. MySQL Requirements

Database:

- name: `auth`

Tables and indexes expected by the service:

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

## 4. Development Setup

Recommended local stack:

- MySQL 8.x
- service process (`go run main.go serve` or built binary)

Reference e2e compose:

- `/Users/stefan.balea/projects/microservices-ecosystem/auth/e2e/docker-compose.yml`

## 5. Production Notes

- Keep `JWT_SECRET` in a secrets manager (not plaintext config files).
- Run MySQL with backups and PITR strategy.
- Enable TLS/ingress in front of HTTP/gRPC.
- Use non-root DB user with least privilege on `auth` schema.
- Configure `LOG_LEVEL=info` (or `warn`) for normal production traffic.
