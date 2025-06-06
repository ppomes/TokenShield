#!/bin/bash

echo "=== TokenShield System Test Suite ==="
echo "Testing rolled-back system with clean build..."
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
PASS=0
FAIL=0

# Helper functions
pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASS++))
}

fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((FAIL++))
}

warn() {
    echo -e "${YELLOW}⚠ WARN${NC}: $1"
}

echo "=== 1. Service Health Checks ==="
echo

# Check if services are running
echo "Testing service availability..."
if curl -s http://localhost:8090/api/v1/health > /dev/null; then
    pass "API server is responding"
else
    fail "API server is not responding"
fi

if curl -s http://localhost:8080/ > /dev/null; then
    pass "HTTP tokenizer is responding"
else
    fail "HTTP tokenizer is not responding"
fi

if curl -s http://localhost:8000/ > /dev/null; then
    pass "Demo app is responding"
else
    fail "Demo app is not responding"
fi

if curl -s http://localhost/ > /dev/null; then
    pass "HAProxy is responding"
else
    fail "HAProxy is not responding"
fi

echo
echo "=== 2. Database Connectivity ==="
echo

# Check API key creation (tests DB connectivity)
API_RESPONSE=$(curl -s -X POST http://localhost:8090/api/v1/api-keys \
  -H "Content-Type: application/json" \
  -H "X-Admin-Secret: change-this-admin-secret" \
  -d '{"client_name":"TestClient","permissions":["read","write"]}')

if echo "$API_RESPONSE" | grep -q "api_key"; then
    pass "Database connectivity - API key creation works"
    API_KEY=$(echo "$API_RESPONSE" | jq -r '.api_key')
    echo "  Created API key: ${API_KEY:0:20}..."
else
    fail "Database connectivity - API key creation failed"
    echo "  Response: $API_RESPONSE"
fi

echo
echo "=== 3. Tokenization Flow Tests ==="
echo

# Test 1: Direct tokenization endpoint
echo "Testing direct tokenization..."
TOKENIZE_RESPONSE=$(curl -s -X POST http://localhost:8080/tokenize \
  -H "Content-Type: application/json" \
  -d '{"card_number":"4532015112830366","expiry":"12/25","cvv":"123"}')

if echo "$TOKENIZE_RESPONSE" | grep -q "tok_\|token"; then
    pass "Direct tokenization endpoint works"
else
    warn "Direct tokenization endpoint response: $TOKENIZE_RESPONSE"
fi

# Test 2: Full payment flow through HAProxy
echo "Testing full payment flow..."
PAYMENT_RESPONSE=$(curl -s -X POST http://localhost/api/checkout \
  -H "Content-Type: application/json" \
  -d '{"card_number":"4532015112830366","expiry":"12/25","cvv":"123","amount":100.50}')

if echo "$PAYMENT_RESPONSE" | grep -q "transaction_id"; then
    pass "Full payment flow works"
    if echo "$PAYMENT_RESPONSE" | grep -q "Card was tokenized by TokenShield"; then
        pass "TokenShield reports tokenization occurred"
    else
        fail "TokenShield did not report tokenization"
    fi
else
    fail "Full payment flow failed"
    echo "  Response: $PAYMENT_RESPONSE"
fi

echo
echo "=== 4. Token Storage Verification ==="
echo

# Check if tokens are actually stored
TOKENS_RESPONSE=$(curl -s -H "X-Admin-Secret: change-this-admin-secret" \
  "http://localhost:8090/api/v1/tokens")

TOKEN_COUNT=$(echo "$TOKENS_RESPONSE" | jq '.tokens | length')
if [ "$TOKEN_COUNT" -gt 0 ]; then
    pass "Tokens are being stored in database ($TOKEN_COUNT tokens found)"
else
    fail "No tokens found in database despite successful transactions"
    echo "  Response: $TOKENS_RESPONSE"
fi

echo
echo "=== 5. Direct Database Check ==="
echo

# Test direct database query
DB_CHECK=$(docker exec tokenshield-mysql mysql -u pciproxy -ppciproxy123 tokenshield -e "SELECT COUNT(*) as token_count FROM credit_cards;" 2>/dev/null | grep -v token_count)

if [ ! -z "$DB_CHECK" ] && [ "$DB_CHECK" -gt 0 ]; then
    pass "Database contains $DB_CHECK credit card records"
else
    fail "Database contains no credit card records"
    # Show table structure for debugging
    echo "  Checking table structure..."
    docker exec tokenshield-mysql mysql -u pciproxy -ppciproxy123 tokenshield -e "SHOW TABLES;" 2>/dev/null
fi

echo
echo "=== 6. Logs Analysis ==="
echo

# Check logs for tokenization activity
echo "Checking recent tokenizer logs..."
RECENT_LOGS=$(docker logs tokenshield-unified --tail 50 2>&1)

if echo "$RECENT_LOGS" | grep -q "Tokenized card ending"; then
    pass "Logs show successful card tokenization"
else
    warn "No tokenization activity found in logs"
fi

if echo "$RECENT_LOGS" | grep -q "error\|Error\|ERROR"; then
    warn "Errors found in tokenizer logs"
    echo "$RECENT_LOGS" | grep -i error | tail -3
fi

echo
echo "=== Test Summary ==="
echo -e "Total tests: $((PASS + FAIL))"
echo -e "${GREEN}Passed: $PASS${NC}"
echo -e "${RED}Failed: $FAIL${NC}"

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. System needs investigation.${NC}"
    exit 1
fi