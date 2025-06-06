#!/bin/bash

echo "
╔═══════════════════════════════════════════════════════════╗
║          TokenShield - Quick Start                        ║
╚═══════════════════════════════════════════════════════════╝"
echo

# Check if .env exists
if [ ! -f .env ]; then
    echo "Creating .env file..."
    cp .env.example .env
    
    # Generate encryption key
    # Try with python3, fallback to a static key if cryptography is not installed
    ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || echo "zN0Lh6WCqsFg6p77l8k_TL-tZCLbRxqJufRpL2sKVxo=")
    
    # Update .env with the key
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s|ENCRYPTION_KEY=.*|ENCRYPTION_KEY=$ENCRYPTION_KEY|" .env
    else
        # Linux
        sed -i "s|ENCRYPTION_KEY=.*|ENCRYPTION_KEY=$ENCRYPTION_KEY|" .env
    fi
    
    echo "✓ Generated encryption key"
fi

# Generate certificates if they don't exist
if [ ! -f certs/server.pem ]; then
    echo "Generating SSL certificates..."
    cd certs
    ./generate-certs.sh
    cd ..
    echo "✓ Generated SSL certificates"
fi

# Start services
echo "Starting services..."
docker-compose up -d

# Wait for services
echo "Waiting for services to start..."
sleep 10

# Check service health
echo
echo "Checking services:"
docker-compose ps

echo
echo "=== TokenShield is ready! ==="
echo
echo "🖥️  GUI Dashboards:"
echo "   • React GUI:        http://localhost:8082  (Modern interface)"
echo "   • Legacy GUI:       http://localhost:8081  (Classic interface)"
echo
echo "🌐 Core Services:"
echo "   • Demo App:         http://localhost       (E-commerce demo)"
echo "   • Management API:   http://localhost:8090  (REST API)"
echo "   • HAProxy Stats:    http://localhost:8404/stats"
echo
echo "🧪 Development/Testing:"
echo "   • Dummy Gateway:    http://localhost:9000  (Payment simulator)"
echo "   • Card Distributor: http://localhost:5001  (Card data API)"
echo
echo "🔧 Internal Services:"
echo "   • Tokenizer HTTP:   http://localhost:8080  (Direct tokenization)"
echo "   • Squid Proxy:      http://localhost:3128  (Outbound proxy)"
echo "   • MySQL Database:   localhost:3306         (tokenshield/pciproxy123)"
echo
echo "📋 Test Credit Cards:"
echo "   • Visa:        4532015112830366"
echo "   • Mastercard:  5425233430109903"
echo "   • Amex:        378282246310005"
echo "   • Discover:    6011111111111117"
echo
echo "🚀 Quick Actions:"
echo "   • Run './test-flow.sh' to see tokenization in action"
echo "   • Run 'docker-compose logs -f [service]' to view logs"
echo "   • Use CLI: './cli/tokenshield --help' for command-line interface"