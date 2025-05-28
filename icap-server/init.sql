-- TokenShield Database Schema

CREATE DATABASE IF NOT EXISTS tokenshield;
USE tokenshield;

-- Tokens table
CREATE TABLE IF NOT EXISTS tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    card_number VARCHAR(19) NOT NULL,
    card_type VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP NULL,
    access_count INT DEFAULT 0,
    expires_at TIMESTAMP NULL,
    INDEX idx_token (token),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(255),
    action VARCHAR(50),
    client_ip VARCHAR(45),
    request_uri TEXT,
    response_code INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_created (created_at),
    INDEX idx_token (token)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert sample test data
INSERT INTO tokens (token, card_number, card_type) VALUES
    ('tok_test_visa_1234', '4111111111111111', 'visa'),
    ('tok_test_mc_5678', '5555555555554444', 'mastercard'),
    ('tok_test_amex_9012', '378282246310005', 'amex')
ON DUPLICATE KEY UPDATE card_number=VALUES(card_number);

-- Create stored procedure for token lookup with audit
DELIMITER //
CREATE PROCEDURE IF NOT EXISTS lookup_token_with_audit(
    IN p_token VARCHAR(255),
    IN p_client_ip VARCHAR(45),
    IN p_request_uri TEXT
)
BEGIN
    DECLARE v_card_number VARCHAR(19);
    
    -- Get card number
    SELECT card_number INTO v_card_number
    FROM tokens
    WHERE token = p_token
    AND (expires_at IS NULL OR expires_at > NOW());
    
    -- Update access stats
    IF v_card_number IS NOT NULL THEN
        UPDATE tokens 
        SET last_accessed = NOW(), 
            access_count = access_count + 1
        WHERE token = p_token;
        
        -- Log successful lookup
        INSERT INTO audit_log (token, action, client_ip, request_uri, response_code)
        VALUES (p_token, 'LOOKUP_SUCCESS', p_client_ip, p_request_uri, 200);
    ELSE
        -- Log failed lookup
        INSERT INTO audit_log (token, action, client_ip, request_uri, response_code)
        VALUES (p_token, 'LOOKUP_FAILED', p_client_ip, p_request_uri, 404);
    END IF;
    
    -- Return result
    SELECT v_card_number AS card_number;
END //
DELIMITER ;