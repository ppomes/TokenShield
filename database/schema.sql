-- TokenShield Database Schema
-- Complete schema including user management for TokenShield PCI proxy demonstration

CREATE DATABASE IF NOT EXISTS tokenshield;
USE tokenshield;

-- Key management tables (KEK/DEK support)
CREATE TABLE IF NOT EXISTS encryption_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    key_id VARCHAR(64) UNIQUE NOT NULL,
    key_type ENUM('KEK', 'DEK') NOT NULL,
    key_version INT NOT NULL,
    encrypted_key VARBINARY(512) COMMENT 'DEKs encrypted with KEK, KEKs stored as-is (should be in HSM)',
    key_status ENUM('active', 'rotating', 'retired', 'compromised') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    activated_at TIMESTAMP NULL,
    retired_at TIMESTAMP NULL,
    expires_at TIMESTAMP NULL,
    metadata JSON COMMENT 'Additional key metadata (e.g., KEK ID for DEKs)',
    INDEX idx_key_status (key_type, key_status),
    INDEX idx_key_version (key_type, key_version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(64) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    role ENUM('admin', 'operator', 'viewer') NOT NULL DEFAULT 'viewer',
    permissions JSON COMMENT 'Specific permissions: ["tokens.read", "tokens.write", "tokens.delete", "api_keys.manage", "users.manage", "system.admin"]',
    is_active BOOLEAN DEFAULT TRUE,
    is_email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP NULL,
    password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    created_by VARCHAR(64) COMMENT 'user_id of creator',
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table for storing tokenized credit cards
CREATE TABLE IF NOT EXISTS credit_cards (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(64) UNIQUE NOT NULL,
    card_number_encrypted VARBINARY(255) NOT NULL,
    card_holder_name_encrypted VARBINARY(255),
    expiry_month TINYINT NOT NULL,
    expiry_year SMALLINT NOT NULL,
    card_type VARCHAR(20), -- VISA, MASTERCARD, AMEX, etc.
    last_four_digits CHAR(4) NOT NULL,
    first_six_digits CHAR(6) NOT NULL, -- BIN for card type identification
    encryption_key_id VARCHAR(64) COMMENT 'ID of the DEK used to encrypt this card',
    encryption_version INT DEFAULT 1 COMMENT 'Version of encryption algorithm used',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_token (token),
    INDEX idx_last_four (last_four_digits),
    INDEX idx_created_at (created_at),
    CONSTRAINT fk_encryption_key FOREIGN KEY (encryption_key_id) REFERENCES encryption_keys(key_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table for tracking token usage/requests
CREATE TABLE IF NOT EXISTS token_requests (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) COMMENT 'User who initiated the request',
    api_key_used VARCHAR(64) COMMENT 'API key used for the request',
    request_type ENUM('tokenize', 'detokenize', 'forward') NOT NULL,
    source_ip VARCHAR(45),
    destination_url TEXT,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    response_status INT,
    response_time_ms INT,
    FOREIGN KEY (token) REFERENCES credit_cards(token),
    INDEX idx_token_timestamp (token, request_timestamp),
    INDEX idx_request_type (request_type),
    INDEX idx_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table for API keys/authentication
CREATE TABLE IF NOT EXISTS api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(64) COMMENT 'User who owns this API key',
    api_key VARCHAR(64) UNIQUE NOT NULL,
    api_secret_hash VARCHAR(255) NOT NULL,
    client_name VARCHAR(100) NOT NULL,
    permissions JSON,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP NULL,
    created_by VARCHAR(64) COMMENT 'user_id of creator',
    INDEX idx_api_key (api_key),
    INDEX idx_user_id (user_id),
    CONSTRAINT fk_api_key_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- User sessions table for managing login sessions
CREATE TABLE IF NOT EXISTS user_sessions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(128) UNIQUE NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    last_activity_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_session_id (session_id),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Audit log for user actions
CREATE TABLE IF NOT EXISTS user_audit_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(64),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) COMMENT 'tokens, api_keys, users, system',
    resource_id VARCHAR(64) COMMENT 'ID of the affected resource',
    details JSON COMMENT 'Additional action details',
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_action (action),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Password reset tokens
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(128) UNIQUE NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Key rotation audit log
CREATE TABLE IF NOT EXISTS key_rotation_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    rotation_id VARCHAR(64) UNIQUE NOT NULL,
    key_type VARCHAR(10) DEFAULT 'DEK' COMMENT 'Type of key being rotated: KEK or DEK',
    old_key_id VARCHAR(64),
    new_key_id VARCHAR(64),
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    cards_rotated INT DEFAULT 0,
    cards_total INT DEFAULT 0,
    status ENUM('in_progress', 'completed', 'failed', 'cancelled') DEFAULT 'in_progress',
    error_message TEXT,
    initiated_by VARCHAR(100) COMMENT 'User or system that initiated rotation',
    INDEX idx_rotation_status (status, started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Initial KEK (for development only - replace in production)
INSERT IGNORE INTO encryption_keys (
    key_id, 
    key_type, 
    key_version, 
    encrypted_key, 
    key_status,
    activated_at,
    metadata
) VALUES (
    'kek_initial_dev',
    'KEK',
    1,
    UNHEX('0000000000000000000000000000000000000000000000000000000000000000'), -- Placeholder, auto-generated on first run
    'active',
    NOW(),
    JSON_OBJECT('note', 'Development KEK - Auto-generated on first use')
);

-- Permission definitions (for reference)
-- tokens.read: Can view tokens
-- tokens.write: Can create/tokenize
-- tokens.delete: Can revoke tokens
-- api_keys.read: Can view API keys
-- api_keys.write: Can create API keys
-- api_keys.delete: Can revoke API keys
-- users.read: Can view users
-- users.write: Can create/update users
-- users.delete: Can delete users
-- system.admin: Full system access
-- activity.read: Can view activity logs
-- stats.read: Can view statistics

-- Role-based default permissions
-- Admin: ["system.admin"] (implies all permissions)
-- Operator: ["tokens.read", "tokens.write", "tokens.delete", "activity.read", "stats.read"]
-- Viewer: ["tokens.read", "activity.read", "stats.read"]

-- NOTE: Default admin user will be created by the application at startup if none exists
-- Username: admin, Password: [randomly generated 16-character password shown in logs]
-- The password is displayed only once during initial startup - save it immediately!