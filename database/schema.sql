-- TokenShield Database Schema
-- For storing tokenized credit card information

CREATE DATABASE IF NOT EXISTS tokenshield;
USE tokenshield;

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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_token (token),
    INDEX idx_last_four (last_four_digits),
    INDEX idx_created_at (created_at)
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