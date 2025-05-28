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
    ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    
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
echo "🌐 Web Interface: http://localhost"
echo "📊 HAProxy Stats: http://localhost:8404/stats"
echo "🔧 Management API: http://localhost:8090"
echo
echo "Test credit cards:"
echo "  - Visa: 4532015112830366"
echo "  - Mastercard: 5425233430109903"
echo
echo "Run './test-flow.sh' to see the tokenization in action"
echo "Run 'docker-compose logs -f' to view logs"