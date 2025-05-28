#!/usr/bin/env python3
"""
Dummy E-commerce Application
This simulates a real application that needs to process credit card payments
"""
import os
import json
import logging
import requests
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Payment gateway URL (goes through Squid proxy)
PAYMENT_GATEWAY_URL = os.getenv('PAYMENT_GATEWAY_URL', 'http://payment-gateway:5000')
HTTP_PROXY = os.getenv('HTTP_PROXY', 'http://squid:3128')
HTTPS_PROXY = os.getenv('HTTPS_PROXY', 'http://squid:3128')

# Configure proxy
proxies = {
    'http': HTTP_PROXY,
    'https': HTTPS_PROXY
}

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
    return render_template_string(CHECKOUT_TEMPLATE)

@app.route('/api/checkout', methods=['POST'])
def checkout():
    """
    Process checkout - receives credit card data
    In the real world, this endpoint would receive tokenized data from PCI-Proxy
    """
    try:
        data = request.get_json()
        logger.info(f"Received checkout request: {json.dumps(data, indent=2)}")
        
        # Extract payment details
        card_number = data.get('card_number')
        card_holder = data.get('card_holder')
        expiry = data.get('expiry')
        cvv = data.get('cvv')
        amount = data.get('amount')
        
        # Log what we received (in real app, NEVER log card numbers!)
        # Check if we received a token or actual card number
        is_tokenized = card_number.startswith('tok_') if card_number else False
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
        logger.info(f"Sending payment request to gateway: {PAYMENT_GATEWAY_URL}/process")
        
        # Use Squid proxy for transparent detokenization via C ICAP server
        response = requests.post(
            f"{PAYMENT_GATEWAY_URL}/process",
            json=payment_request,
            proxies=proxies  # Use Squid proxy with ICAP
        )
        
        logger.info(f"Gateway response status: {response.status_code}")
        logger.info(f"Gateway response headers: {dict(response.headers)}")
        logger.info(f"Gateway response text: {response.text[:500]}")
        
        try:
            gateway_response = response.json()
        except Exception as json_error:
            logger.error(f"Failed to parse JSON response: {json_error}")
            logger.error(f"Raw response: {response.text}")
            raise
        logger.info(f"Gateway response: {json.dumps(gateway_response, indent=2)}")
        
        return jsonify({
            'status': 'success',
            'transaction_id': gateway_response.get('transaction_id'),
            'token_used': card_number if is_tokenized else 'Card was tokenized by TokenShield',
            'gateway_response': gateway_response
        }), 200
        
    except Exception as e:
        logger.error(f"Error processing checkout: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'dummy-app'}), 200

if __name__ == '__main__':
    # Disable SSL warnings for demo
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    app.run(host='0.0.0.0', port=8000, debug=True)