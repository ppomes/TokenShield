#!/usr/bin/env python3
"""
ICAP Server for PCI-Proxy TokenShield
Handles detokenization of credit card tokens in HTTP requests
"""

import os
import re
import json
import logging
import MySQLdb
from cryptography.fernet import Fernet
from pyicap import ICAPServer, BaseICAPRequestHandler

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('icap_server')

# MySQL configuration
MYSQL_CONFIG = {
    'host': os.getenv('MYSQL_HOST', 'mysql'),
    'user': os.getenv('MYSQL_USER', 'pciproxy'),
    'passwd': os.getenv('MYSQL_PASSWORD', 'pciproxy123'),
    'db': os.getenv('MYSQL_DB', 'pci_proxy'),
    'port': 3306
}

# Encryption key - in production, use proper key management
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)

def get_db_connection():
    """Get a new database connection"""
    try:
        return MySQLdb.connect(**MYSQL_CONFIG)
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        raise

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
            logger.info(f"Retrieved card for token {token} ending in {card_number[-4:]}")
            return card_number
        else:
            logger.warning(f"Token not found: {token}")
        return None
    except Exception as e:
        logger.error(f"Error retrieving card: {e}")
        return None
    finally:
        if conn:
            conn.close()

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

def detokenize_json(json_str, client_ip, destination):
    """Find and replace tokens in JSON string"""
    try:
        # Parse JSON
        data = json.loads(json_str)
        
        # Convert back to string for regex replacement
        json_text = json.dumps(data)
        
        # Pattern to match tokens
        token_pattern = r'"(tok_[A-Za-z0-9_-]{43})"'
        tokens_found = []
        
        def replace_token(match):
            token = match.group(1)
            tokens_found.append(token)
            card_number = retrieve_card(token)
            if card_number:
                logger.info(f"Detokenizing {token} -> ****{card_number[-4:]}")
                log_request(token, 'detokenize', client_ip, destination, 200)
                return f'"{card_number}"'
            return match.group(0)
        
        # Replace all tokens
        modified_json = re.sub(token_pattern, replace_token, json_text)
        
        # Also check for tokens in specific fields
        modified_data = json.loads(modified_json)
        if isinstance(modified_data, dict):
            for key in ['card_number', 'cardNumber', 'pan', 'creditCard']:
                if key in modified_data and isinstance(modified_data[key], str):
                    if modified_data[key].startswith('tok_') and modified_data[key] not in tokens_found:
                        card_number = retrieve_card(modified_data[key])
                        if card_number:
                            logger.info(f"Detokenizing field {key}: {modified_data[key]} -> ****{card_number[-4:]}")
                            log_request(modified_data[key], 'detokenize', client_ip, destination, 200)
                            modified_data[key] = card_number
                            modified_json = json.dumps(modified_data)
        
        return modified_json
    except json.JSONDecodeError:
        logger.warning("Failed to parse JSON, returning original content")
        return json_str
    except Exception as e:
        logger.error(f"Error in detokenize_json: {e}")
        return json_str

def detokenize_form_data(form_data, client_ip, destination):
    """Find and replace tokens in form data"""
    token_pattern = r'tok_[A-Za-z0-9_-]{43}'
    
    def replace_token(match):
        token = match.group(0)
        card_number = retrieve_card(token)
        if card_number:
            logger.info(f"Detokenizing form data: {token} -> ****{card_number[-4:]}")
            log_request(token, 'detokenize', client_ip, destination, 200)
            return card_number
        return token
    
    return re.sub(token_pattern, replace_token, form_data)

class DetokenizerICAPHandler(BaseICAPRequestHandler):
    """ICAP Request Handler for detokenization"""
    
    def reqmod_OPTIONS(self):
        """Handle OPTIONS request for reqmod service"""
        # Log the ICAP request path
        icap_path = getattr(self, 'path', 'Unknown')
        icap_uri = getattr(self, 'icap_uri', 'Unknown')
        icap_version = getattr(self, 'request_version', 'Unknown')
        
        logger.info(f"Received OPTIONS request - Path: {icap_path}, URI: {icap_uri}, Version: {icap_version}")
        logger.debug(f"OPTIONS handler attributes: {[attr for attr in dir(self) if not attr.startswith('_')]}")
        
        self.set_icap_response(200)
        self.set_icap_header(b'Methods', b'REQMOD')
        self.set_icap_header(b'Service', b'PCI-Proxy Detokenizer')
        self.set_icap_header(b'ISTag', b'PCIProxy-1.0')
        self.set_icap_header(b'Preview', b'0')
        self.set_icap_header(b'Transfer-Preview', b'*')
        self.set_icap_header(b'Transfer-Ignore', b'jpg,jpeg,gif,png,swf,flv,pdf,mp3,mp4,zip')
        self.set_icap_header(b'Transfer-Complete', b'*')
        self.set_icap_header(b'Max-Connections', b'100')
        self.set_icap_header(b'Options-TTL', b'3600')
        self.send_headers(False)
    
    def reqmod_REQMOD(self):
        """Handle REQMOD request for detokenization"""
        try:
            # Log the ICAP request path
            icap_path = getattr(self, 'path', 'Unknown')
            icap_uri = getattr(self, 'icap_uri', 'Unknown')
            icap_version = getattr(self, 'request_version', 'Unknown')
            
            logger.info(f"Received REQMOD request from {self.client_address[0]} - Path: {icap_path}, URI: {icap_uri}, Version: {icap_version}")
            logger.debug(f"REQMOD handler attributes: {[attr for attr in dir(self) if not attr.startswith('_')]}")
            
            # Get the request line
            if hasattr(self, 'enc_req') and self.enc_req:
                method = self.enc_req[0]
                uri = self.enc_req[1]
                version = self.enc_req[2] if len(self.enc_req) > 2 else 'HTTP/1.1'
                logger.info(f"HTTP Request: {method} {uri} {version}")
            else:
                logger.warning("No encapsulated request found")
                self.no_adaptation_required()
                return
            
            # Check if there's a body to process
            if not self.has_body:
                logger.info("No body in request, passing through")
                self.no_adaptation_required()
                return
            
            # Read the body using chunks
            body_chunks = []
            while True:
                chunk = self.read_chunk()
                if chunk == b'':
                    break
                body_chunks.append(chunk)
            
            # Combine all chunks into the complete body
            body = b''.join(body_chunks).decode('utf-8', errors='ignore')
            
            if not body:
                logger.info("Empty body, passing through")
                self.no_adaptation_required()
                return
            
            # Get content type
            content_type = ''
            for header, value in self.enc_headers:
                if header.lower() == 'content-type':
                    content_type = value.lower()
                    break
            
            logger.info(f"Processing body with content-type: {content_type}")
            logger.debug(f"Original body: {body[:200]}...")
            
            # Process based on content type
            modified_body = body
            if 'application/json' in content_type:
                modified_body = detokenize_json(body, self.client_address[0], uri)
            elif 'application/x-www-form-urlencoded' in content_type:
                modified_body = detokenize_form_data(body, self.client_address[0], uri)
            else:
                # Try JSON parsing anyway for non-standard content types
                try:
                    json.loads(body)
                    modified_body = detokenize_json(body, self.client_address[0], uri)
                except:
                    # Not JSON, check for tokens in plain text
                    modified_body = detokenize_form_data(body, self.client_address[0], uri)
            
            # Check if body was modified
            if modified_body == body:
                logger.info("No tokens found, passing through")
                self.no_adaptation_required()
                return
            
            logger.info("Tokens replaced, sending modified request")
            logger.debug(f"Modified body: {modified_body[:200]}...")
            
            # Send modified response
            self.set_icap_response(200)
            self.enc_request = f'{method} {uri} {version}'.encode('utf-8')
            
            # Copy headers, updating Content-Length
            for header, value in self.enc_headers:
                if header.lower() == 'content-length':
                    self.set_enc_header(header, str(len(modified_body)))
                else:
                    self.set_enc_header(header, value)
            
            # If Content-Length wasn't in headers, add it
            has_content_length = any(h[0].lower() == 'content-length' for h in self.enc_headers)
            if not has_content_length:
                self.set_enc_header('Content-Length', str(len(modified_body)))
            
            self.send_headers(True)
            
            # Write the modified body as chunks
            if isinstance(modified_body, str):
                modified_body = modified_body.encode('utf-8')
            self.write_chunk(modified_body)
            self.write_chunk(b'')  # End of chunks
            
        except Exception as e:
            logger.error(f"Error in REQMOD handler: {e}", exc_info=True)
            self.send_error(500)
    
    def no_adaptation_required(self):
        """Send 204 No Content response"""
        self.set_icap_response(204)
        self.send_headers(False)
    
    def send_error(self, code=500):
        """Send error response"""
        try:
            # pyicap's send_error might only take the code parameter
            super().send_error(code)
        except TypeError:
            # If that fails, try to send error manually
            self.set_icap_response(code)
            self.send_headers(False)

def main():
    """Main function to start ICAP server"""
    port = int(os.getenv('ICAP_PORT', 1344))
    address = os.getenv('ICAP_ADDRESS', '')
    
    logger.info(f"Starting ICAP server on {address or '*'}:{port}")
    
    # Test database connection
    try:
        conn = get_db_connection()
        conn.close()
        logger.info("Database connection successful")
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        logger.warning("Server will start but database operations will fail")
    
    # Start ICAP server
    server = ICAPServer((address, port), DetokenizerICAPHandler)
    logger.info(f"ICAP server listening on port {port}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down ICAP server")
        server.shutdown()

if __name__ == '__main__':
    main()