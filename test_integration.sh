#!/bin/bash

echo "=== TokenShield Integration Test Suite ==="
echo "Testing all flows before refactoring..."
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
PASS=0
FAIL=0

# Test configuration
BASE_URL="http://localhost"
API_URL="http://localhost:8090"
ADMIN_SECRET="change-this-admin-secret"
TEST_CARDS=(
    "4532015112830366"  # Visa
    "5425233430109903"  # Mastercard
    "378282246310005"   # Amex
    "6011111111111117"  # Discover
)

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

info() {
    echo -e "${BLUE}ℹ INFO${NC}: $1"
}

# Check prerequisites
check_prerequisites() {
    echo "=== Prerequisites Check ==="
    
    # Check if services are running
    if ! curl -s $BASE_URL > /dev/null; then
        fail "HAProxy not responding on $BASE_URL"
        return 1
    fi
    
    if ! curl -s $API_URL/api/v1/health > /dev/null; then
        fail "API server not responding on $API_URL"
        return 1
    fi
    
    if ! docker ps | grep -q tokenshield; then
        fail "TokenShield containers not running"
        return 1
    fi
    
    pass "All services are running"
    return 0
}

# Test tokenization flow (HAProxy -> HTTP Tokenizer -> App)
test_tokenization_flow() {
    echo
    echo "=== Testing Tokenization Flow ==="
    
    for card in "${TEST_CARDS[@]}"; do
        info "Testing tokenization with card: ${card:0:4}****${card: -4}"
        
        response=$(curl -s -X POST $BASE_URL/api/checkout \
            -H "Content-Type: application/json" \
            -d "{\"card_holder\":\"Test User\",\"card_number\":\"$card\",\"expiry\":\"12/25\",\"cvv\":\"123\",\"amount\":100.50}")
        
        # Check if response contains a token
        if echo "$response" | jq -e '.token_used' | grep -q "tok_"; then
            pass "Card $card was tokenized successfully"
        else
            fail "Card $card was not tokenized"
            echo "  Response: $response"
        fi
        
        # Verify payment went through
        if echo "$response" | jq -e '.gateway_response.status' | grep -q "success"; then
            pass "Payment processed successfully for card $card"
        else
            fail "Payment failed for card $card"
        fi
    done
}

# Test detokenization flow (Squid -> ICAP -> Payment Gateway)
test_detokenization_flow() {
    echo
    echo "=== Testing Detokenization Flow ==="
    
    # First, make a payment to create a token
    response=$(curl -s -X POST $BASE_URL/api/checkout \
        -H "Content-Type: application/json" \
        -d '{"card_holder":"Test User","card_number":"4532015112830366","expiry":"12/25","cvv":"123","amount":100.50}')
    
    # Check if the payment gateway received correct card details
    last_four=$(echo "$response" | jq -r '.gateway_response.card_last_four')
    if [ "$last_four" = "0366" ]; then
        pass "Payment gateway received detokenized card (last 4: $last_four)"
    else
        fail "Payment gateway did not receive correct detokenized card"
        echo "  Expected last 4: 0366, got: $last_four"
    fi
}

# Test card storage and retrieval
test_card_storage() {
    echo
    echo "=== Testing Card Storage and Retrieval ==="
    
    # Make test payment and capture the token
    info "Making test payment to store a card"
    checkout_response=$(curl -s -X POST $BASE_URL/api/checkout \
        -H "Content-Type: application/json" \
        -d '{"card_holder":"Test User","card_number":"4532015112830366","expiry":"12/25","cvv":"123","amount":50.00}')
    
    # Extract the token from checkout response
    token_used=$(echo "$checkout_response" | jq -r '.token_used')
    
    # Check if card was stored
    cards_response=$(curl -s $BASE_URL/api/cards)
    card_count=$(echo "$cards_response" | jq '.cards | length')
    
    if [ "$card_count" -gt 0 ]; then
        pass "Card was stored successfully ($card_count cards found)"
        
        # Find the most recent card by cardholder and verify it was detokenized
        displayed_card=$(echo "$cards_response" | jq -r '.cards[] | select(.card_holder == "Test User") | {id, card_number}' | jq -sr 'sort_by(.id) | reverse | .[0].card_number')
        if [ "$displayed_card" = "4532015112830366" ]; then
            pass "Card was properly detokenized for display"
        else
            fail "Card was not detokenized for display: $displayed_card"
        fi
    else
        fail "No cards were stored"
    fi
}

# Test token formats
test_token_formats() {
    echo
    echo "=== Testing Token Formats ==="
    
    # Test current token format (should be prefix)
    response=$(curl -s -X POST $BASE_URL/api/checkout \
        -H "Content-Type: application/json" \
        -d '{"card_holder":"Test User","card_number":"5425233430109903","expiry":"12/25","cvv":"123","amount":25.00}')
    
    token=$(echo "$response" | jq -r '.token_used')
    
    if echo "$token" | grep -q "^tok_"; then
        pass "Prefix token format working: ${token:0:20}..."
    else
        fail "Token format incorrect: $token"
    fi
}

# Test API endpoints
test_api_endpoints() {
    echo
    echo "=== Testing API Endpoints ==="
    
    # Test health endpoint
    health_response=$(curl -s $API_URL/health)
    if echo "$health_response" | jq -e '.status' | grep -q "healthy"; then
        pass "Health endpoint working"
    else
        fail "Health endpoint not working"
    fi
    
    # Test version endpoint
    version_response=$(curl -s $API_URL/api/v1/version)
    if echo "$version_response" | jq -e '.version' > /dev/null; then
        pass "Version endpoint working"
    else
        fail "Version endpoint not working"
    fi
}

# Test card distributor integration
test_card_distributor() {
    echo
    echo "=== Testing Card Distributor Integration ==="
    
    # Import cards from distributor
    import_response=$(curl -s -X POST $BASE_URL/api/import-cards \
        -H "Content-Type: application/json" \
        -d '{"count": 2}')
    
    if echo "$import_response" | jq -e '.status' | grep -q "success"; then
        imported_count=$(echo "$import_response" | jq -r '.imported_count')
        pass "Imported $imported_count cards from distributor"
        
        # Verify cards are visible
        cards_response=$(curl -s $BASE_URL/api/cards)
        visible_count=$(echo "$cards_response" | jq '.cards | length')
        if [ "$visible_count" -ge "$imported_count" ]; then
            pass "Imported cards are visible ($visible_count total cards)"
        else
            fail "Imported cards not visible"
        fi
    else
        fail "Card import failed"
        echo "  Response: $import_response"
    fi
}

# Test error handling
test_error_handling() {
    echo
    echo "=== Testing Error Handling ==="
    
    # Test invalid card number
    response=$(curl -s -X POST $BASE_URL/api/checkout \
        -H "Content-Type: application/json" \
        -d '{"card_holder":"Test User","card_number":"invalid","expiry":"12/25","cvv":"123","amount":100.50}')
    
    # Should still process (tokenizer doesn't validate card numbers)
    if echo "$response" | jq -e '.status' > /dev/null; then
        pass "Invalid card number handled gracefully"
    else
        fail "Invalid card number not handled properly"
    fi
    
    # Test malformed JSON
    response=$(curl -s -X POST $BASE_URL/api/checkout \
        -H "Content-Type: application/json" \
        -d '{invalid json}')
    
    # Should return error
    if echo "$response" | grep -q "error\|400\|Bad Request"; then
        pass "Malformed JSON handled properly"
    else
        warn "Malformed JSON handling could be improved"
    fi
}

# Test performance
test_performance() {
    echo
    echo "=== Testing Performance ==="
    
    info "Testing 10 concurrent tokenization requests..."
    
    start_time=$(date +%s%N)
    
    for i in {1..10}; do
        (curl -s -X POST $BASE_URL/api/checkout \
            -H "Content-Type: application/json" \
            -d "{\"card_holder\":\"User$i\",\"card_number\":\"4532015112830366\",\"expiry\":\"12/25\",\"cvv\":\"123\",\"amount\":$((i * 10)).00}" > /dev/null) &
    done
    
    wait
    
    end_time=$(date +%s%N)
    duration=$(( (end_time - start_time) / 1000000 )) # Convert to milliseconds
    
    if [ $duration -lt 5000 ]; then # Less than 5 seconds
        pass "Performance test completed in ${duration}ms"
    else
        warn "Performance test took ${duration}ms (might be slow)"
    fi
}

# Main test execution
main() {
    echo "Starting TokenShield Integration Tests at $(date)"
    echo
    
    # Run all tests
    check_prerequisites || exit 1
    test_tokenization_flow
    test_detokenization_flow
    test_card_storage
    test_token_formats
    test_api_endpoints
    test_card_distributor
    test_error_handling
    test_performance
    
    echo
    echo "=== Test Summary ==="
    echo "Tests run: $((PASS + FAIL))"
    echo -e "${GREEN}Passed: $PASS${NC}"
    echo -e "${RED}Failed: $FAIL${NC}"
    
    if [ $FAIL -eq 0 ]; then
        echo -e "${GREEN}🎉 All tests passed! System is ready for refactoring.${NC}"
        exit 0
    else
        echo -e "${RED}❌ $FAIL test(s) failed. Fix issues before refactoring.${NC}"
        exit 1
    fi
}

# Run main function
main "$@"