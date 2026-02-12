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
    last_login DATETIME NULL,
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

CREATE TABLE internal_api_keys (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    service_name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    allowed_access_json TEXT NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE INDEX idx_internal_api_keys_key_hash (key_hash)
);
