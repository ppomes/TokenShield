#!/usr/bin/env python3
import os
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from cryptography.fernet import Fernet
import secrets

app = Flask(__name__)

# Configuration
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'mysql')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'pciproxy')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', 'pciproxy123')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'tokenshield')

# Initialize MySQL
mysql = MySQL(app)

# Encryption key
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def authenticate_request():
    """Simple API key authentication"""
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return False
    
    # Check API key in database
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT id FROM api_keys 
        WHERE api_key = %s AND is_active = TRUE
    """, (api_key,))
    result = cur.fetchone()
    cur.close()
    
    return result is not None

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

@app.route('/api/v1/tokens', methods=['GET'])
def list_tokens():
    """List all tokens with metadata"""
    if not authenticate_request():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT token, card_type, last_four_digits, first_six_digits, 
                   created_at, is_active
            FROM credit_cards
            ORDER BY created_at DESC
            LIMIT 100
        """)
        
        tokens = []
        for row in cur.fetchall():
            tokens.append({
                'token': row[0],
                'card_type': row[1],
                'last_four': row[2],
                'first_six': row[3],
                'created_at': row[4].isoformat() if row[4] else None,
                'is_active': row[5]
            })
        
        cur.close()
        return jsonify({'tokens': tokens}), 200
        
    except Exception as e:
        logger.error(f"Error listing tokens: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/tokens/<token>', methods=['GET'])
def get_token_info(token):
    """Get information about a specific token"""
    if not authenticate_request():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT card_type, last_four_digits, first_six_digits, 
                   created_at, is_active
            FROM credit_cards
            WHERE token = %s
        """, (token,))
        
        result = cur.fetchone()
        cur.close()
        
        if not result:
            return jsonify({'error': 'Token not found'}), 404
        
        return jsonify({
            'token': token,
            'card_type': result[0],
            'last_four': result[1],
            'first_six': result[2],
            'created_at': result[3].isoformat() if result[3] else None,
            'is_active': result[4]
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting token info: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/tokens/<token>', methods=['DELETE'])
def revoke_token(token):
    """Revoke/deactivate a token"""
    if not authenticate_request():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE credit_cards 
            SET is_active = FALSE 
            WHERE token = %s
        """, (token,))
        
        if cur.rowcount == 0:
            return jsonify({'error': 'Token not found'}), 404
        
        mysql.connection.commit()
        cur.close()
        
        return jsonify({'message': 'Token revoked successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error revoking token: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/stats', methods=['GET'])
def get_stats():
    """Get usage statistics"""
    if not authenticate_request():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        cur = mysql.connection.cursor()
        
        # Get token count
        cur.execute("SELECT COUNT(*) FROM credit_cards WHERE is_active = TRUE")
        active_tokens = cur.fetchone()[0]
        
        # Get request stats
        cur.execute("""
            SELECT request_type, COUNT(*) as count
            FROM token_requests
            WHERE request_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY request_type
        """)
        
        request_stats = {}
        for row in cur.fetchall():
            request_stats[row[0]] = row[1]
        
        cur.close()
        
        return jsonify({
            'active_tokens': active_tokens,
            'requests_24h': request_stats
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/api-keys', methods=['POST'])
def create_api_key():
    """Create a new API key"""
    # This endpoint should be protected by admin authentication
    # For demo purposes, we'll use a simple secret
    admin_secret = request.headers.get('X-Admin-Secret')
    if admin_secret != os.getenv('ADMIN_SECRET', 'admin-secret-123'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        client_name = data.get('client_name')
        
        if not client_name:
            return jsonify({'error': 'client_name is required'}), 400
        
        # Generate API key and secret
        api_key = f"pk_{secrets.token_urlsafe(32)}"
        api_secret = secrets.token_urlsafe(32)
        api_secret_hash = hashlib.sha256(api_secret.encode()).hexdigest()
        
        # Store in database
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO api_keys (api_key, api_secret_hash, client_name)
            VALUES (%s, %s, %s)
        """, (api_key, api_secret_hash, client_name))
        mysql.connection.commit()
        cur.close()
        
        return jsonify({
            'api_key': api_key,
            'api_secret': api_secret,
            'client_name': client_name
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating API key: {e}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8090)