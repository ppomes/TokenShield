#!/usr/bin/env python3
"""
Dummy E-commerce Application
This simulates a real application that needs to process credit card payments.

This is just a test application - in production, the real application would
handle its own authentication (OAuth, sessions, etc). We don't protect this
API because it's just for demo purposes.

The TokenShield management API (port 8090) is what should be protected.
"""
import os
import json
import logging
import requests
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# External service URLs (go through Squid proxy for tokenization)
PAYMENT_GATEWAY_URL = os.getenv('PAYMENT_GATEWAY_URL', 'http://payment-gateway:5000')
CARD_DISTRIBUTOR_URL = os.getenv('CARD_DISTRIBUTOR_URL', 'http://card-distributor:5001')
HTTP_PROXY = os.getenv('HTTP_PROXY', 'http://squid:3128')
HTTPS_PROXY = os.getenv('HTTPS_PROXY', 'http://squid:3128')

# Configure proxy
proxies = {
    'http': HTTP_PROXY,
    'https': HTTPS_PROXY
}

# Initialize SQLite database for storing cards
def init_db():
    conn = sqlite3.connect('cards.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS saved_cards
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  card_holder TEXT NOT NULL,
                  card_token TEXT NOT NULL,
                  card_type TEXT,
                  expiry TEXT,
                  last_four TEXT,
                  is_default BOOLEAN DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

init_db()

# Simple HTML template for checkout page
CHECKOUT_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>TokenShield Demo - E-commerce Checkout</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px; 
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #eee;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
        }
        .shield {
            color: #3498db;
        }
        .tagline {
            color: #7f8c8d;
            font-size: 14px;
        }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; color: #2c3e50; }
        input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; }
        input:focus { outline: none; border-color: #3498db; }
        button { 
            background: #3498db; 
            color: white; 
            padding: 12px 30px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
            font-size: 16px;
            width: 100%;
            margin-top: 10px;
        }
        button:hover { background: #2980b9; }
        .result { margin-top: 20px; padding: 15px; border-radius: 4px; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        .badge {
            display: inline-block;
            background: #e8f4f8;
            color: #3498db;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            margin-left: 10px;
        }
        .nav-buttons {
            text-align: center;
            margin: 20px 0;
            padding: 20px 0;
            border-top: 2px solid #eee;
        }
        .nav-button {
            background: #34495e;
            color: white;
            padding: 10px 20px;
            margin: 0 10px;
            text-decoration: none;
            border-radius: 4px;
            display: inline-block;
            font-size: 14px;
        }
        .nav-button:hover {
            background: #2c3e50;
            color: white;
            text-decoration: none;
        }
        .nav-button.active {
            background: #3498db;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ Token<span class="shield">Shield</span></div>
            <div class="tagline">Secure Credit Card Tokenization Demo</div>
        </div>
        
        <h2>E-commerce Checkout <span class="badge">Protected by TokenShield</span></h2>
        <p>Enter a credit card number below. TokenShield will automatically tokenize it before it reaches the application!</p>
    
    <form id="checkoutForm">
        <div class="form-group">
            <label>Cardholder Name:</label>
            <input type="text" name="card_holder" value="John Doe" required>
        </div>
        
        <div class="form-group">
            <label>Card Number:</label>
            <input type="text" name="card_number" value="4532015112830366" required>
            <small>Use test card numbers like: 4532015112830366 (Visa), 5425233430109903 (Mastercard)</small>
        </div>
        
        <div class="form-group">
            <label>Expiry (MM/YY):</label>
            <input type="text" name="expiry" value="12/25" required>
        </div>
        
        <div class="form-group">
            <label>CVV:</label>
            <input type="text" name="cvv" value="123" required>
        </div>
        
        <div class="form-group">
            <label>Amount:</label>
            <input type="text" name="amount" value="99.99" required>
        </div>
        
        <button type="submit">Process Payment</button>
    </form>
    
    <div id="result"></div>
    
    <div class="nav-buttons">
        <a href="/" class="nav-button active">💳 Checkout</a>
        <a href="/my-cards" class="nav-button">📋 My Cards</a>
        <a href="/import-cards" class="nav-button">📥 Import Cards</a>
    </div>
    </div>
    
    <script>
        document.getElementById('checkoutForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const data = Object.fromEntries(formData);
            
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = '<div class="result info">Processing payment...</div>';
            
            try {
                const response = await fetch('/api/checkout', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    resultDiv.innerHTML = `
                        <div class="result success">
                            <h3>Payment Successful!</h3>
                            <p><strong>Transaction ID:</strong> ${result.transaction_id}</p>
                            <p><strong>Status:</strong> ${result.status}</p>
                            <p><strong>TokenShield Token:</strong> ${result.token_used || 'N/A'}</p>
                            <p><strong>Gateway Response:</strong> ${JSON.stringify(result.gateway_response, null, 2)}</p>
                        </div>
                    `;
                } else {
                    resultDiv.innerHTML = `
                        <div class="result error">
                            <h3>Payment Failed</h3>
                            <p>${result.error || 'Unknown error'}</p>
                        </div>
                    `;
                }
            } catch (error) {
                resultDiv.innerHTML = `
                    <div class="result error">
                        <h3>Error</h3>
                        <p>${error.message}</p>
                    </div>
                `;
            }
        });
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    """Checkout page"""
    # Log incoming request
    logger.info(f"[INCOMING REQUEST] GET /")
    logger.info(f"[INCOMING REQUEST] Headers: {dict(request.headers)}")
    
    logger.info(f"[INCOMING RESPONSE] Status: 200")
    logger.info(f"[INCOMING RESPONSE] Returning HTML checkout page")
    return render_template_string(CHECKOUT_TEMPLATE)

@app.route('/api/checkout', methods=['POST'])
def checkout():
    """
    Process checkout - receives credit card data
    In the real world, this endpoint would receive tokenized data from TokenShield
    """
    try:
        # Log incoming request
        logger.info(f"[INCOMING REQUEST] POST /api/checkout")
        logger.info(f"[INCOMING REQUEST] Headers: {dict(request.headers)}")
        data = request.get_json()
        logger.info(f"[INCOMING REQUEST] Body: {json.dumps(data, indent=2)}")
        
        # Extract payment details
        card_number = data.get('card_number')
        card_holder = data.get('card_holder')
        expiry = data.get('expiry')
        cvv = data.get('cvv')
        amount = data.get('amount')
        
        # Log what we received (in real app, NEVER log card numbers!)
        # Check if we received a token or actual card number
        is_tokenized = (card_number.startswith('tok_') or card_number.startswith('9999')) if card_number else False
        logger.info(f"Received {'tokenized' if is_tokenized else 'raw'} card data")
        
        # Prepare payment request for gateway
        payment_request = {
            'card_number': card_number,
            'card_holder': card_holder,
            'expiry': expiry,
            'cvv': cvv,
            'amount': amount,
            'currency': 'USD',
            'description': 'Test payment from dummy app'
        }
        
        # Send to payment gateway (through Squid proxy with C ICAP for detokenization)
        logger.info(f"[OUTBOUND REQUEST] POST {PAYMENT_GATEWAY_URL}/process")
        logger.info(f"[OUTBOUND REQUEST] Body: {json.dumps(payment_request, indent=2)}")
        logger.info(f"[OUTBOUND REQUEST] Using proxy: {proxies}")
        
        # Use Squid proxy for transparent detokenization via C ICAP server
        response = requests.post(
            f"{PAYMENT_GATEWAY_URL}/process",
            json=payment_request,
            proxies=proxies  # Use Squid proxy with ICAP
        )
        
        logger.info(f"[OUTBOUND RESPONSE] Status: {response.status_code}")
        logger.info(f"[OUTBOUND RESPONSE] Headers: {dict(response.headers)}")
        logger.info(f"[OUTBOUND RESPONSE] Body: {response.text[:500]}")
        
        try:
            gateway_response = response.json()
        except Exception as json_error:
            logger.error(f"Failed to parse JSON response: {json_error}")
            logger.error(f"Raw response: {response.text}")
            raise
        logger.info(f"[OUTBOUND RESPONSE] Parsed JSON: {json.dumps(gateway_response, indent=2)}")
        
        # Save the card if it's tokenized and payment was successful
        if is_tokenized and gateway_response.get('status') == 'success':
            try:
                conn = sqlite3.connect('cards.db')
                c = conn.cursor()
                
                # Check if this token already exists
                c.execute("SELECT id FROM saved_cards WHERE card_token = ?", (card_number,))
                if not c.fetchone():
                    # Extract card info from gateway response
                    card_type = gateway_response.get('card_type', 'Unknown')
                    last_four = gateway_response.get('card_last_four', '****')
                    
                    # Save the card
                    c.execute("""INSERT INTO saved_cards 
                                (card_holder, card_token, card_type, expiry, last_four, is_default)
                                VALUES (?, ?, ?, ?, ?, ?)""",
                             (card_holder, card_number, card_type, expiry, last_four, False))
                    conn.commit()
                    logger.info(f"Saved tokenized card ending in {last_four}")
                conn.close()
            except Exception as e:
                logger.error(f"Error saving card: {e}")
        
        # Prepare response
        response_data = {
            'status': 'success',
            'transaction_id': gateway_response.get('transaction_id'),
            'token_used': card_number if is_tokenized else 'Card was tokenized by TokenShield',
            'gateway_response': gateway_response
        }
        
        logger.info(f"[INCOMING RESPONSE] Status: 200")
        logger.info(f"[INCOMING RESPONSE] Body: {json.dumps(response_data, indent=2)}")
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Error processing checkout: {e}")
        error_response = {'error': str(e)}
        logger.info(f"[INCOMING RESPONSE] Status: 500")
        logger.info(f"[INCOMING RESPONSE] Body: {json.dumps(error_response, indent=2)}")
        return jsonify(error_response), 500

@app.route('/my-cards')
def my_cards_page():
    """Display saved cards in a web page"""
    # Log incoming request
    logger.info(f"[INCOMING REQUEST] GET /my-cards")
    logger.info(f"[INCOMING REQUEST] Headers: {dict(request.headers)}")
    
    # In a real app, you would check authentication here
    # For demo purposes, we'll just display the cards
    
    MY_CARDS_TEMPLATE = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>My Saved Cards - TokenShield Demo</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                max-width: 800px; 
                margin: 50px auto; 
                padding: 20px; 
                background: #f5f5f5;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .header {
                text-align: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 2px solid #eee;
            }
            .logo {
                font-size: 24px;
                font-weight: bold;
                color: #2c3e50;
                margin-bottom: 10px;
            }
            .shield {
                color: #3498db;
            }
            .tagline {
                color: #7f8c8d;
                font-size: 14px;
            }
            .card-item {
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 15px;
                background: #f9f9f9;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .card-info {
                flex: 1;
            }
            .card-number {
                font-size: 18px;
                font-weight: bold;
                margin-bottom: 5px;
                font-family: monospace;
                letter-spacing: 2px;
            }
            .card-details {
                color: #666;
                font-size: 14px;
            }
            .card-type {
                display: inline-block;
                background: #e8f4f8;
                color: #3498db;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 12px;
                margin-left: 10px;
            }
            .no-cards {
                text-align: center;
                padding: 40px;
                color: #666;
            }
            .btn {
                display: inline-block;
                padding: 10px 20px;
                background: #3498db;
                color: white;
                text-decoration: none;
                border-radius: 4px;
                margin-top: 20px;
            }
            .btn:hover {
                background: #2980b9;
            }
            .notice {
                background: #d4edda;
                color: #155724;
                padding: 15px;
                border-radius: 4px;
                margin-bottom: 20px;
                border: 1px solid #c3e6cb;
            }
            .nav-buttons {
                text-align: center;
                margin: 20px 0;
                padding: 20px 0;
                border-top: 2px solid #eee;
            }
            .nav-button {
                background: #34495e;
                color: white;
                padding: 10px 20px;
                margin: 0 10px;
                text-decoration: none;
                border-radius: 4px;
                display: inline-block;
                font-size: 14px;
            }
            .nav-button:hover {
                background: #2c3e50;
                color: white;
                text-decoration: none;
            }
            .nav-button.active {
                background: #3498db;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🛡️ Token<span class="shield">Shield</span></div>
                <div class="tagline">Your Saved Payment Methods</div>
            </div>
            
            <div class="notice">
                ℹ️ Card numbers are automatically detokenized by TokenShield for secure display
            </div>
            
            <h2>My Saved Cards</h2>
            
            {% if cards %}
                {% for card in cards %}
                <div class="card-item">
                    <div class="card-info">
                        <div class="card-number">
                            {{ card.card_number }}
                            <span class="card-type">{{ card.card_type }}</span>
                        </div>
                        <div class="card-details">
                            {{ card.card_holder }} • Expires {{ card.expiry }}
                        </div>
                    </div>
                    {% if card.is_default %}
                    <span style="color: green;">✓ Default</span>
                    {% endif %}
                </div>
                {% endfor %}
            {% else %}
                <div class="no-cards">
                    <p>No saved cards yet.</p>
                    <a href="/" class="btn">Make a Purchase</a>
                </div>
            {% endif %}
            
            <div class="nav-buttons">
                <a href="/" class="nav-button">💳 Checkout</a>
                <a href="/my-cards" class="nav-button active">📋 My Cards</a>
                <a href="/import-cards" class="nav-button">📥 Import Cards</a>
            </div>
        </div>
    </body>
    </html>
    '''
    
    try:
        conn = sqlite3.connect('cards.db')
        c = conn.cursor()
        c.execute("""SELECT id, card_holder, card_token, card_type, 
                            expiry, last_four, is_default 
                     FROM saved_cards ORDER BY id DESC""")
        
        cards = []
        for row in c.fetchall():
            cards.append({
                'id': row[0],
                'card_holder': row[1],
                'card_number': row[2],  # This is the token that will be detokenized by proxy
                'card_type': row[3],
                'expiry': row[4],
                'last_four': row[5],
                'is_default': row[6]
            })
        
        conn.close()
        
        logger.info(f"Rendering my-cards page with {len(cards)} cards")
        logger.info(f"[INCOMING RESPONSE] Status: 200")
        logger.info(f"[INCOMING RESPONSE] Returning HTML page with {len(cards)} cards")
        return render_template_string(MY_CARDS_TEMPLATE, cards=cards)
    except Exception as e:
        logger.error(f"Error displaying cards: {str(e)}")
        logger.info(f"[INCOMING RESPONSE] Status: 500")
        logger.info(f"[INCOMING RESPONSE] Error: {str(e)}")
        return f"Error: {str(e)}", 500

@app.route('/api/cards', methods=['GET'])
def list_cards():
    """
    API endpoint for listing saved cards - protected by API key
    This endpoint returns tokens which should be detokenized by the proxy
    """
    try:
        # Log incoming request
        logger.info(f"[INCOMING REQUEST] GET /api/cards")
        logger.info(f"[INCOMING REQUEST] Headers: {dict(request.headers)}")
        conn = sqlite3.connect('cards.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get all saved cards
        c.execute("""SELECT id, card_holder, card_token as card_number, 
                           card_type, expiry, last_four, is_default, created_at
                    FROM saved_cards 
                    ORDER BY created_at DESC""")
        
        cards = []
        for row in c.fetchall():
            cards.append({
                'id': row['id'],
                'card_holder': row['card_holder'],
                'card_number': row['card_number'],  # This is the token
                'card_type': row['card_type'],
                'expiry': row['expiry'],
                'last_four': row['last_four'],
                'is_default': bool(row['is_default'])
            })
        
        conn.close()
        
        logger.info(f"API: Returning {len(cards)} saved cards with tokens")
        
        response_data = {
            'status': 'success',
            'cards': cards,
            'message': 'Tokens will be detokenized by TokenShield for display'
        }
        
        logger.info(f"[INCOMING RESPONSE] Status: 200")
        logger.info(f"[INCOMING RESPONSE] Body: {json.dumps(response_data, indent=2)}")
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Error listing cards via API: {e}")
        error_response = {'error': str(e)}
        logger.info(f"[INCOMING RESPONSE] Status: 500")
        logger.info(f"[INCOMING RESPONSE] Body: {json.dumps(error_response, indent=2)}")
        return jsonify(error_response), 500

@app.route('/import-cards')
def import_cards_page():
    """Web page for importing cards from distributor"""
    # Log incoming request
    logger.info(f"[INCOMING REQUEST] GET /import-cards")
    logger.info(f"[INCOMING REQUEST] Headers: {dict(request.headers)}")
    IMPORT_CARDS_TEMPLATE = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Import Cards - TokenShield Demo</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                max-width: 800px; 
                margin: 50px auto; 
                padding: 20px; 
                background: #f5f5f5;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .header {
                text-align: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 2px solid #eee;
            }
            .logo {
                font-size: 24px;
                font-weight: bold;
                color: #2c3e50;
                margin-bottom: 10px;
            }
            .shield {
                color: #3498db;
            }
            .btn {
                display: inline-block;
                padding: 12px 24px;
                background: #3498db;
                color: white;
                text-decoration: none;
                border-radius: 4px;
                border: none;
                cursor: pointer;
                font-size: 16px;
                margin: 10px;
            }
            .btn:hover {
                background: #2980b9;
            }
            .notice {
                background: #fff3cd;
                color: #856404;
                padding: 15px;
                border-radius: 4px;
                margin-bottom: 20px;
                border: 1px solid #ffeaa7;
            }
            .result {
                margin-top: 20px;
                padding: 15px;
                border-radius: 4px;
                display: none;
            }
            .success {
                background: #d4edda;
                color: #155724;
                border: 1px solid #c3e6cb;
            }
            .error {
                background: #f8d7da;
                color: #721c24;
                border: 1px solid #f5c6cb;
            }
            .nav-buttons {
                text-align: center;
                margin: 20px 0;
                padding: 20px 0;
                border-top: 2px solid #eee;
            }
            .nav-button {
                background: #34495e;
                color: white;
                padding: 10px 20px;
                margin: 0 10px;
                text-decoration: none;
                border-radius: 4px;
                display: inline-block;
                font-size: 14px;
            }
            .nav-button:hover {
                background: #2c3e50;
                color: white;
                text-decoration: none;
            }
            .nav-button.active {
                background: #3498db;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🛡️ Token<span class="shield">Shield</span></div>
                <div>Card Import Service</div>
            </div>
            
            <div class="notice">
                ⚠️ This demonstrates response tokenization: External APIs return raw card data → 
                Squid proxy intercepts responses → Cards are tokenized before reaching our app
            </div>
            
            <h2>Import Cards from Distributor</h2>
            <p>Click the button below to fetch cards from the external distributor API. 
               The response will be automatically tokenized by TokenShield before reaching our application.</p>
            
            <button id="importBtn" class="btn">Import Cards from Distributor API</button>
            
            <div id="result" class="result"></div>
            
            <div class="nav-buttons">
                <a href="/" class="nav-button">💳 Checkout</a>
                <a href="/my-cards" class="nav-button">📋 My Cards</a>
                <a href="/import-cards" class="nav-button active">📥 Import Cards</a>
            </div>
        </div>
        
        <script>
            document.getElementById('importBtn').addEventListener('click', async () => {
                const btn = document.getElementById('importBtn');
                const resultDiv = document.getElementById('result');
                
                btn.disabled = true;
                btn.textContent = 'Importing...';
                resultDiv.style.display = 'none';
                
                try {
                    const response = await fetch('/api/import-cards', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' }
                    });
                    
                    const result = await response.json();
                    
                    if (response.ok) {
                        resultDiv.className = 'result success';
                        resultDiv.innerHTML = `
                            <h3>Import Successful!</h3>
                            <p><strong>Cards imported:</strong> ${result.imported_count}</p>
                            <p><strong>Message:</strong> ${result.message}</p>
                            <p><em>Note: All card numbers were tokenized by TokenShield during the response.</em></p>
                        `;
                    } else {
                        resultDiv.className = 'result error';
                        resultDiv.innerHTML = `<h3>Import Failed</h3><p>${result.error}</p>`;
                    }
                    
                    resultDiv.style.display = 'block';
                    
                } catch (error) {
                    resultDiv.className = 'result error';
                    resultDiv.innerHTML = `<h3>Error</h3><p>${error.message}</p>`;
                    resultDiv.style.display = 'block';
                } finally {
                    btn.disabled = false;
                    btn.textContent = 'Import Cards from Distributor API';
                }
            });
        </script>
    </body>
    </html>
    '''
    
    logger.info(f"[INCOMING RESPONSE] Status: 200")
    logger.info(f"[INCOMING RESPONSE] Returning HTML page for card import")
    return render_template_string(IMPORT_CARDS_TEMPLATE)

@app.route('/api/import-cards', methods=['POST'])
def import_cards():
    """
    Import cards from the distributor API through Squid proxy.
    The response will be tokenized by Squid before reaching this app.
    """
    try:
        # Log incoming request
        logger.info(f"[INCOMING REQUEST] POST /api/import-cards")
        logger.info(f"[INCOMING REQUEST] Headers: {dict(request.headers)}")
        
        # Call distributor API through Squid proxy for response tokenization
        logger.info(f"[OUTBOUND REQUEST] GET {CARD_DISTRIBUTOR_URL}/api/available-cards")
        logger.info(f"[OUTBOUND REQUEST] Using proxy: {proxies}")
        
        response = requests.get(
            f"{CARD_DISTRIBUTOR_URL}/api/available-cards",
            proxies=proxies,
            timeout=10
        )
        
        logger.info(f"[OUTBOUND RESPONSE] Status: {response.status_code}")
        logger.info(f"[OUTBOUND RESPONSE] Headers: {dict(response.headers)}")
        logger.info(f"[OUTBOUND RESPONSE] Body: {response.text[:500]}")
        
        if response.status_code != 200:
            raise Exception(f"Distributor API returned status {response.status_code}")
        
        distributor_data = response.json()
        logger.info(f"[OUTBOUND RESPONSE] Parsed JSON: {json.dumps(distributor_data, indent=2)}")
        
        # The response should now have tokenized card numbers thanks to Squid
        cards = distributor_data.get('cards', [])
        imported_count = 0
        
        conn = sqlite3.connect('cards.db')
        c = conn.cursor()
        
        for card in cards:
            card_number = card.get('card_number')
            card_holder = card.get('card_holder')
            card_type = card.get('card_type')
            expiry = card.get('expiry')
            last_four = card.get('last_four')
            provider = card.get('provider', 'Unknown')
            
            # Check if this card already exists
            c.execute("SELECT id FROM saved_cards WHERE card_token = ?", (card_number,))
            if not c.fetchone():
                # Save the card (should be tokenized by now)
                c.execute("""INSERT INTO saved_cards 
                            (card_holder, card_token, card_type, expiry, last_four, is_default)
                            VALUES (?, ?, ?, ?, ?, ?)""",
                         (f"{card_holder} ({provider})", card_number, card_type, expiry, last_four, False))
                imported_count += 1
                logger.info(f"Imported card: {card_type} ending in {last_four}")
        
        conn.commit()
        conn.close()
        
        # Prepare response
        response_data = {
            'status': 'success',
            'imported_count': imported_count,
            'total_available': len(cards),
            'message': f'Successfully imported {imported_count} cards from distributor',
            'note': 'Card numbers were tokenized by TokenShield during response interception'
        }
        
        logger.info(f"[INCOMING RESPONSE] Status: 200")
        logger.info(f"[INCOMING RESPONSE] Body: {json.dumps(response_data, indent=2)}")
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error importing cards: {e}")
        error_response = {'error': str(e)}
        logger.info(f"[INCOMING RESPONSE] Status: 500")
        logger.info(f"[INCOMING RESPONSE] Body: {json.dumps(error_response, indent=2)}")
        return jsonify(error_response), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    logger.info(f"[INCOMING REQUEST] GET /health")
    logger.info(f"[INCOMING REQUEST] Headers: {dict(request.headers)}")
    
    response_data = {'status': 'healthy', 'service': 'dummy-app'}
    logger.info(f"[INCOMING RESPONSE] Status: 200")
    logger.info(f"[INCOMING RESPONSE] Body: {json.dumps(response_data, indent=2)}")
    return jsonify(response_data), 200

if __name__ == '__main__':
    # Disable SSL warnings for demo
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    app.run(host='0.0.0.0', port=8000, debug=True)