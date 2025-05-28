#!/usr/bin/env python3
import os
import re
import json
import hashlib
import secrets
import logging
from datetime import datetime
from flask import Flask, request, jsonify, Response
from flask_mysqldb import MySQL
from cryptography.fernet import Fernet
import requests
from pyicap import ICAPServer, BaseICAPRequestHandler

app = Flask(__name__)

# Configuration
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'mysql')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'pciproxy')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', 'pciproxy123')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'pci_proxy')

# Initialize MySQL
mysql = MySQL(app)

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
    try:
        encrypted_card = cipher_suite.encrypt(card_number.encode())
        last_four = card_number[-4:]
        first_six = card_number[:6]
        card_type = detect_card_type(card_number)
        
        # Extract expiry if available (this is simplified)
        expiry_month = 12  # Default values
        expiry_year = 2025
        
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO credit_cards 
            (token, card_number_encrypted, last_four_digits, first_six_digits, 
             card_type, expiry_month, expiry_year)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP
        """, (token, encrypted_card, last_four, first_six, card_type, expiry_month, expiry_year))
        mysql.connection.commit()
        cur.close()
        
        logger.info(f"Stored card ending in {last_four} with token {token}")
    except Exception as e:
        logger.error(f"Error storing card: {e}")
        raise

def retrieve_card(token):
    """Retrieve and decrypt card from database"""
    try:
        cur = mysql.connection.cursor()
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

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

@app.route('/tokenize', methods=['POST'])
def tokenize_request():
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
        
        if original_dest:
            forward_url = f"{app_endpoint}{original_dest.split('/', 1)[1] if '/' in original_dest else ''}"
        else:
            forward_url = f"{app_endpoint}{request.path}"
        
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
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO token_requests 
            (token, request_type, source_ip, destination_url, response_status)
            VALUES (%s, %s, %s, %s, %s)
        """, (token, request_type, source_ip, destination_url, response_status))
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        logger.error(f"Error logging request: {e}")

# ICAP Server for Squid integration
class TokenizerICAPHandler(BaseICAPRequestHandler):
    def request_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header('Methods', 'REQMOD RESPMOD')
        self.set_icap_header('Service', 'PCI-Proxy Tokenizer')
        self.set_icap_header('Preview', '0')
        self.set_icap_header('Transfer-Complete', '*')
        self.send_headers()
        
    def request_REQMOD(self):
        """Handle request modification (detokenization for outbound)"""
        try:
            # Get request body
            if self.has_body:
                body = self.get_body()
                
                # Find tokens and replace with real card numbers
                token_pattern = r'tok_[A-Za-z0-9_-]{43}'
                
                def replace_token(match):
                    token = match.group(0)
                    card_number = retrieve_card(token)
                    if card_number:
                        log_request(token, 'detokenize', self.client_address[0], 
                                  self.enc_req[1], 200)
                        return card_number
                    return token
                
                # Replace tokens with card numbers
                modified_body = re.sub(token_pattern, replace_token, body)
                
                # Send modified request
                self.set_icap_response(200)
                self.set_enc_request(' '.join(self.enc_req))
                for header in self.enc_headers:
                    self.set_enc_header(header[0], header[1])
                self.send_headers(has_body=True)
                self.write_chunk(modified_body)
                self.write_chunk('')
            else:
                # No body, return 204
                self.set_icap_response(204)
                self.send_headers()
                
        except Exception as e:
            logger.error(f"Error in REQMOD: {e}")
            self.send_error(500)

if __name__ == '__main__':
    # Run Flask app in one thread
    import threading
    flask_thread = threading.Thread(target=lambda: app.run(host='0.0.0.0', port=8080))
    flask_thread.daemon = True
    flask_thread.start()
    
    # Run ICAP server
    server = ICAPServer(('0.0.0.0', 1344), TokenizerICAPHandler)
    server.serve_forever()