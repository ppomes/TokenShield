-- TokenShield Database Schema
-- For storing tokenized credit card information

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
    request_type ENUM('tokenize', 'detokenize', 'forward') NOT NULL,
    source_ip VARCHAR(45),
    destination_url TEXT,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    response_status INT,
    response_time_ms INT,
    FOREIGN KEY (token) REFERENCES credit_cards(token),
    INDEX idx_token_timestamp (token, request_timestamp),
    INDEX idx_request_type (request_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table for API keys/authentication
CREATE TABLE IF NOT EXISTS api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    api_key VARCHAR(64) UNIQUE NOT NULL,
    api_secret_hash VARCHAR(255) NOT NULL,
    client_name VARCHAR(100) NOT NULL,
    permissions JSON,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP NULL,
    INDEX idx_api_key (api_key)
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