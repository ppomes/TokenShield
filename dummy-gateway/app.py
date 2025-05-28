#!/usr/bin/env python3
"""
Dummy Payment Gateway
Simulates a payment processor like Stripe, PayPal, etc.
Accepts all payments for testing purposes
"""
import os
import json
import logging
import uuid
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory storage for transactions (for demo purposes)
transactions = {}

def validate_card_number(card_number):
    """Basic validation - just check if it's a number"""
    if not card_number:
        return False
    
    # Remove any spaces or dashes
    clean_number = card_number.replace(' ', '').replace('-', '')
    
    # Check if it's a token (from TokenShield)
    if clean_number.startswith('tok_'):
        logger.info(f"Received tokenized card: {clean_number}")
        return False  # This shouldn't happen - tokens should be detokenized by Squid
    
    # Check if it's numeric and has valid length
    return clean_number.isdigit() and 13 <= len(clean_number) <= 19

@app.route('/')
def index():
    """Gateway information page"""
    return jsonify({
        'service': 'Dummy Payment Gateway',
        'version': '1.0',
        'endpoints': {
            'process_payment': '/process',
            'get_transaction': '/transaction/<id>',
            'list_transactions': '/transactions',
            'health': '/health'
        }
    })

@app.route('/process', methods=['POST'])
def process_payment():
    """Process a payment request"""
    try:
        data = request.get_json()
        logger.info(f"Received payment request: {json.dumps({**data, 'card_number': '****' + data.get('card_number', '')[-4:]}, indent=2)}")
        
        # Extract payment details
        card_number = data.get('card_number')
        card_holder = data.get('card_holder')
        amount = float(data.get('amount', 0))
        currency = data.get('currency', 'USD')
        
        # Validate card number
        if not validate_card_number(card_number):
            # If we receive a token, it means Squid/TokenShield failed to detokenize
            if card_number and card_number.startswith('tok_'):
                return jsonify({
                    'status': 'error',
                    'error': 'Received tokenized card - detokenization may have failed',
                    'received_token': card_number
                }), 400
            
            return jsonify({
                'status': 'error',
                'error': 'Invalid card number'
            }), 400
        
        # Generate transaction ID
        transaction_id = str(uuid.uuid4())
        
        # Simulate payment processing
        # In reality, this would connect to banking networks
        transaction = {
            'id': transaction_id,
            'status': 'approved',
            'amount': amount,
            'currency': currency,
            'card_holder': card_holder,
            'card_last_four': card_number[-4:],
            'card_type': detect_card_type(card_number),
            'timestamp': datetime.utcnow().isoformat(),
            'authorization_code': generate_auth_code(),
            'message': 'Payment approved'
        }
        
        # Store transaction
        transactions[transaction_id] = transaction
        
        logger.info(f"Payment approved: {transaction_id}")
        
        return jsonify({
            'status': 'success',
            'transaction_id': transaction_id,
            'authorization_code': transaction['authorization_code'],
            'amount': amount,
            'currency': currency,
            'card_type': transaction['card_type'],
            'card_last_four': transaction['card_last_four'],
            'message': transaction['message']
        }), 200
        
    except Exception as e:
        logger.error(f"Error processing payment: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/transaction/<transaction_id>', methods=['GET'])
def get_transaction(transaction_id):
    """Get transaction details"""
    transaction = transactions.get(transaction_id)
    if not transaction:
        return jsonify({'error': 'Transaction not found'}), 404
    
    return jsonify(transaction), 200

@app.route('/transactions', methods=['GET'])
def list_transactions():
    """List all transactions"""
    return jsonify({
        'transactions': list(transactions.values()),
        'total': len(transactions)
    }), 200

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'dummy-gateway',
        'transactions_processed': len(transactions)
    }), 200

def detect_card_type(card_number):
    """Detect card type based on BIN"""
    if card_number.startswith('4'):
        return 'Visa'
    elif card_number.startswith('5'):
        return 'Mastercard'
    elif card_number.startswith('3'):
        return 'American Express'
    elif card_number.startswith('6'):
        return 'Discover'
    return 'Unknown'

def generate_auth_code():
    """Generate a fake authorization code"""
    return f"AUTH-{uuid.uuid4().hex[:8].upper()}"

if __name__ == '__main__':
    # Run with HTTP for simplicity in this demo
    # In production, payment gateways would use HTTPS
    app.run(host='0.0.0.0', port=9000, debug=True)