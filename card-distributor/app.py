#!/usr/bin/env python3
"""
Card Distributor API - Simulates a third-party service that provides card data
This represents an external API that returns raw credit card numbers
"""
import json
from flask import Flask, jsonify

app = Flask(__name__)

# Static card data that this "distributor" always returns
DISTRIBUTOR_CARDS = [
    {
        "id": "dist_001",
        "card_number": "4000000000000002",  # Test Visa card
        "card_holder": "John Distributor",
        "card_type": "Visa",
        "expiry": "12/28",
        "last_four": "0002",
        "provider": "Global Card Services"
    },
    {
        "id": "dist_002", 
        "card_number": "5555555555554444",  # Test Mastercard
        "card_holder": "Jane Provider",
        "card_type": "Mastercard", 
        "expiry": "06/27",
        "last_four": "4444",
        "provider": "International Cards Ltd"
    },
    {
        "id": "dist_003",
        "card_number": "378282246310005",  # Test Amex card
        "card_holder": "Bob External",
        "card_type": "American Express",
        "expiry": "09/26", 
        "last_four": "0005",
        "provider": "Premium Card Network"
    }
]

@app.route('/')
def index():
    """API documentation"""
    return jsonify({
        "service": "Card Distributor API",
        "description": "Third-party API that provides card data",
        "endpoints": {
            "/api/available-cards": "GET - Returns available card offers",
            "/health": "GET - Health check"
        },
        "note": "This is a test API that always returns the same cards"
    })

@app.route('/api/available-cards', methods=['GET'])
def get_available_cards():
    """
    Returns available card offers from this distributor.
    In real world, this would be a third-party API returning sensitive card data.
    """
    return jsonify({
        "status": "success",
        "provider": "Card Distributor API v1.0",
        "cards": DISTRIBUTOR_CARDS,
        "total_count": len(DISTRIBUTOR_CARDS),
        "message": "Available card offers - cards contain real numbers that should be tokenized"
    })

@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        "status": "healthy", 
        "service": "card-distributor",
        "cards_available": len(DISTRIBUTOR_CARDS)
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)