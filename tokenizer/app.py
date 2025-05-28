#!/usr/bin/env python3
import os
import re
import json
import hashlib
import secrets
import logging
from datetime import datetime
from flask import Flask, request, jsonify, Response
import MySQLdb
from cryptography.fernet import Fernet
import requests
from pyicap import ICAPServer, BaseICAPRequestHandler

app = Flask(__name__)

# MySQL configuration
MYSQL_CONFIG = {
    'host': os.getenv('MYSQL_HOST', 'mysql'),
    'user': os.getenv('MYSQL_USER', 'pciproxy'),
    'passwd': os.getenv('MYSQL_PASSWORD', 'pciproxy123'),
    'db': os.getenv('MYSQL_DB', 'tokenshield'),
    'port': 3306
}

def get_db_connection():
    """Get a new database connection"""
    return MySQLdb.connect(**MYSQL_CONFIG)

# Encryption key - in production, use proper key management
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Credit card regex patterns
CARD_PATTERNS = {
    'visa': r'^4[0-9]{12}(?:[0-9]{3})?$',
    'mastercard': r'^5[1-5][0-9]{14}$',
    'amex': r'^3[47][0-9]{13}$',
    'discover': r'^6(?:011|5[0-9]{2})[0-9]{12}$'
}

def luhn_check(card_number):
    """Validate credit card number using Luhn algorithm"""
    def digits_of(n):
        return [int(d) for d in str(n)]
    
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d*2))
    return checksum % 10 == 0

def detect_card_type(card_number):
    """Detect credit card type based on number pattern"""
    clean_number = re.sub(r'[^0-9]', '', card_number)
    for card_type, pattern in CARD_PATTERNS.items():
        if re.match(pattern, clean_number):
            return card_type
    return 'unknown'

def find_and_tokenize_cards(data):
    """Find credit card numbers in data and replace with tokens"""
    if isinstance(data, str):
        text = data
    else:
        text = json.dumps(data)
    
    # Pattern to find credit card numbers
    card_pattern = r'\b(?:\d[ -]*?){13,19}\b'
    
    tokens_map = {}
    
    def replace_card(match):
        potential_card = match.group(0)
        clean_card = re.sub(r'[^0-9]', '', potential_card)
        
        # Validate card number
        if len(clean_card) >= 13 and len(clean_card) <= 19 and luhn_check(clean_card):
            # Generate token
            token = generate_token()
            
            # Store in database
            store_card(clean_card, token)
            
            tokens_map[token] = potential_card
            return token
        
        return potential_card
    
    # Replace all card numbers with tokens
    tokenized_text = re.sub(card_pattern, replace_card, text)
    
    if isinstance(data, str):
        return tokenized_text, tokens_map
    else:
        try:
            return json.loads(tokenized_text), tokens_map
        except:
            return tokenized_text, tokens_map

def generate_token():
    """Generate a secure random token"""
    return f"tok_{secrets.token_urlsafe(32)}"

def store_card(card_number, token):
    """Store encrypted card in database"""
    conn = None
    try:
        encrypted_card = cipher_suite.encrypt(card_number.encode())
        last_four = card_number[-4:]
        first_six = card_number[:6]
        card_type = detect_card_type(card_number)
        
        # Extract expiry if available (this is simplified)
        expiry_month = 12  # Default values
        expiry_year = 2025
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO credit_cards 
            (token, card_number_encrypted, last_four_digits, first_six_digits, 
             card_type, expiry_month, expiry_year)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP
        """, (token, encrypted_card, last_four, first_six, card_type, expiry_month, expiry_year))
        conn.commit()
        cur.close()
        
        logger.info(f"Stored card ending in {last_four} with token {token}")
    except Exception as e:
        logger.error(f"Error storing card: {e}")
        raise
    finally:
        if conn:
            conn.close()

def retrieve_card(token):
    """Retrieve and decrypt card from database"""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT card_number_encrypted FROM credit_cards 
            WHERE token = %s AND is_active = TRUE
        """, (token,))
        result = cur.fetchone()
        cur.close()
        
        if result:
            encrypted_card = result[0]
            card_number = cipher_suite.decrypt(encrypted_card).decode()
            return card_number
        return None
    except Exception as e:
        logger.error(f"Error retrieving card: {e}")
        return None
    finally:
        if conn:
            conn.close()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

@app.route('/proxy', methods=['POST'])
def proxy_request():
    """
    Forward proxy endpoint that detokenizes requests before sending to payment gateway
    This replaces the Squid/ICAP functionality for now
    """
    try:
        # Get the target URL from headers
        target_url = request.headers.get('X-Target-URL')
        if not target_url:
            return jsonify({'error': 'Missing X-Target-URL header'}), 400
        
        # Get request data
        data = request.get_json()
        logger.info(f"Proxy request to {target_url} with data: {json.dumps(data, indent=2)}")
        
        # Check if we have a token in the card_number field
        if data and isinstance(data, dict) and 'card_number' in data:
            card_number = data['card_number']
            if isinstance(card_number, str) and card_number.startswith('tok_'):
                # Retrieve the real card number
                real_card = retrieve_card(card_number)
                if real_card:
                    logger.info(f"Detokenized {card_number} to card ending in {real_card[-4:]}")
                    data['card_number'] = real_card
                else:
                    logger.error(f"Failed to detokenize {card_number}")
                    return jsonify({'error': 'Invalid token'}), 400
        
        # Forward the request with real card data
        headers = dict(request.headers)
        headers.pop('Host', None)
        headers.pop('Content-Length', None)
        headers.pop('X-Target-URL', None)
        
        response = requests.post(
            target_url,
            json=data,
            headers=headers,
            allow_redirects=False
        )
        
        # Log the detokenization
        if 'card_number' in data and isinstance(data.get('card_number'), str) and data['card_number'].startswith('tok_'):
            log_request(data['card_number'], 'detokenize', request.remote_addr, target_url, response.status_code)
        
        # Return the response
        return Response(
            response.content,
            status=response.status_code,
            headers=dict(response.headers)
        )
        
    except Exception as e:
        logger.error(f"Error in proxy request: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def tokenize_request(path):
    """Tokenize credit card data in request and forward to destination"""
    try:
        # Get original destination from headers
        original_dest = request.headers.get('X-Original-Destination', '')
        app_endpoint = os.getenv('APP_ENDPOINT', 'http://dummy-app:8000')
        
        # Get request data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.get_data(as_text=True)
        
        # Tokenize any credit card data
        tokenized_data, tokens_map = find_and_tokenize_cards(data)
        
        # Forward request to application
        headers = dict(request.headers)
        headers.pop('Host', None)
        headers.pop('Content-Length', None)
        
        # Build the forward URL
        forward_url = f"{app_endpoint}/{path}" if path else app_endpoint
        
        # Make request to application
        if request.is_json:
            response = requests.request(
                method=request.method,
                url=forward_url,
                json=tokenized_data,
                headers=headers,
                allow_redirects=False
            )
        else:
            response = requests.request(
                method=request.method,
                url=forward_url,
                data=tokenized_data,
                headers=headers,
                allow_redirects=False
            )
        
        # Log tokenization
        for token in tokens_map:
            log_request(token, 'tokenize', request.remote_addr, forward_url, response.status_code)
        
        # Return response to client
        return Response(
            response.content,
            status=response.status_code,
            headers=dict(response.headers)
        )
        
    except Exception as e:
        logger.error(f"Error in tokenize_request: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def log_request(token, request_type, source_ip, destination_url, response_status):
    """Log token request to database"""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO token_requests 
            (token, request_type, source_ip, destination_url, response_status)
            VALUES (%s, %s, %s, %s, %s)
        """, (token, request_type, source_ip, destination_url, response_status))
        conn.commit()
        cur.close()
    except Exception as e:
        logger.error(f"Error logging request: {e}")
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    import threading
    from icap_server import ICAPServer, DetokenizerICAPHandler
    
    # ICAP server configuration
    icap_port = int(os.getenv('ICAP_PORT', 1344))
    icap_address = os.getenv('ICAP_ADDRESS', '')
    
    # Create ICAP server instance
    icap_server = ICAPServer((icap_address, icap_port), DetokenizerICAPHandler)
    
    # Run ICAP server in a separate thread
    def run_icap_server():
        logger.info(f"Starting ICAP server on {icap_address or '*'}:{icap_port}")
        try:
            icap_server.serve_forever()
        except Exception as e:
            logger.error(f"ICAP server error: {e}")
    
    icap_thread = threading.Thread(target=run_icap_server, daemon=True)
    icap_thread.start()
    
    # Test database connection
    try:
        conn = get_db_connection()
        conn.close()
        logger.info("Database connection successful")
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        logger.warning("Server will start but database operations will fail")
    
    try:
        # Run Flask app in main thread
        logger.info("Starting Flask server on 0.0.0.0:8080")
        app.run(host='0.0.0.0', port=8080, debug=False)  # Disable debug to prevent reloader issues
    finally:
        # Cleanup ICAP server on exit
        logger.info("Shutting down servers...")
        icap_server.shutdown()