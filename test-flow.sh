#!/bin/bash

# Test script to demonstrate the TokenShield flow

echo "
╔═══════════════════════════════════════════════════════════╗
║          TokenShield - Test Flow                          ║
╚═══════════════════════════════════════════════════════════╝"
echo

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Wait for services to be ready
echo "Waiting for services to be ready..."
sleep 5

# Test 1: Direct request to dummy app (should get tokenized)
echo -e "${YELLOW}Test 1: Sending credit card through TokenShield${NC}"
echo "Sending: Card Number: 4532015112830366"
echo

curl -X POST http://localhost/api/checkout \
  -H "Content-Type: application/json" \
  -d '{
    "card_number": "4532015112830366",
    "card_holder": "John Doe",
    "expiry": "12/25",
    "cvv": "123",
    "amount": "99.99"
  }' | jq .

echo
echo -e "${GREEN}✓ The dummy app received a tokenized card (check logs)${NC}"
echo

# Test 2: Check tokenizer health
echo -e "${YELLOW}Test 2: Checking tokenizer health${NC}"
curl -s http://localhost:8080/health | jq .
echo

# Test 3: Check payment gateway
echo -e "${YELLOW}Test 3: Checking payment gateway${NC}"
curl -s -k https://localhost:9000/ | jq .
echo

# Test 4: View HAProxy stats
echo -e "${YELLOW}Test 4: HAProxy Statistics${NC}"
echo "View HAProxy stats at: http://localhost:8404/stats"
echo

# Test 5: Create API key for management
echo -e "${YELLOW}Test 5: Creating API key for management${NC}"
API_RESPONSE=$(curl -s -X POST http://localhost:8090/api/v1/api-keys \
  -H "Content-Type: application/json" \
  -H "X-Admin-Secret: change-this-admin-secret" \
  -d '{"client_name": "Test Client"}')

echo "$API_RESPONSE" | jq .
API_KEY=$(echo "$API_RESPONSE" | jq -r .api_key)
echo

# Test 6: Get statistics
echo -e "${YELLOW}Test 6: Getting statistics${NC}"
curl -s http://localhost:8090/api/v1/stats \
  -H "X-API-Key: $API_KEY" | jq .
echo

# View logs
echo -e "${YELLOW}View real-time logs:${NC}"
echo "docker-compose logs -f tokenizer     # See tokenization in action"
echo "docker-compose logs -f dummy-app     # See what the app receives"
echo "docker-compose logs -f payment-gateway # See final payment processing"
echo

echo -e "${GREEN}Test complete! Visit http://localhost to try the web interface.${NC}"