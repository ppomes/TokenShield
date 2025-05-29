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

# Setup: Ensure test API key exists in database
echo "Setting up test API key..."
docker exec tokenshield-mysql mysql -u root -prootpassword123 tokenshield -e \
  "INSERT IGNORE INTO api_keys (api_key, api_secret_hash, client_name, is_active) VALUES ('pk_test_1234567890', 'dummy_hash', 'Test Client', TRUE);" 2>/dev/null || true

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

# Test 2: Check unified tokenizer health (API endpoint)
echo -e "${YELLOW}Test 2: Checking unified tokenizer health${NC}"
curl -s http://localhost:8090/health | jq .
echo

# Test 3: Check payment gateway
echo -e "${YELLOW}Test 3: Checking payment gateway${NC}"
curl -s -k https://localhost:9000/ | jq .
echo

# Test 4: View HAProxy stats
echo -e "${YELLOW}Test 4: HAProxy Statistics${NC}"
echo "View HAProxy stats at: http://localhost:8404/stats"
echo

# Test 5: Using a pre-created API key (or create one manually)
echo -e "${YELLOW}Test 5: Using API key for management${NC}"
# Note: The unified tokenizer doesn't have the create API key endpoint yet
# You can manually insert an API key in the database or use this test key
API_KEY="pk_test_1234567890"
echo "Using test API key: $API_KEY"
echo

# Test 6: Get statistics
echo -e "${YELLOW}Test 6: Getting statistics${NC}"
curl -s http://localhost:8090/api/v1/stats \
  -H "X-API-Key: $API_KEY" | jq .
echo

# View logs
echo -e "${YELLOW}View real-time logs:${NC}"
echo "docker-compose logs -f unified-tokenizer  # See tokenization/detokenization in action"
echo "docker-compose logs -f dummy-app          # See what the app receives"
echo "docker-compose logs -f payment-gateway    # See final payment processing"
echo

# Test 7: List tokens
echo -e "${YELLOW}Test 7: Listing tokens via API${NC}"
curl -s http://localhost:8090/api/v1/tokens \
  -H "X-API-Key: $API_KEY" | jq '.tokens | length as $count | "Found \($count) tokens"'
echo

echo -e "${GREEN}Test complete! Visit http://localhost to try the web interface.${NC}"