#!/bin/bash

echo "=== TokenShield Test Suite Runner ==="
echo "Running all tests..."
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
TOTAL_TESTS=0
TOTAL_PASS=0
TOTAL_FAIL=0

# Helper functions
pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((TOTAL_PASS++))
}

fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((TOTAL_FAIL++))
}

info() {
    echo -e "${BLUE}ℹ INFO${NC}: $1"
}

# Check if system is running
check_system() {
    echo "=== System Check ==="
    
    if ! docker ps | grep -q tokenshield; then
        echo -e "${RED}❌ TokenShield containers not running!${NC}"
        echo "Please start the system first:"
        echo "  cd /path/to/TokenShield"
        echo "  docker-compose up -d"
        exit 1
    fi
    
    # Wait for services to be ready
    info "Waiting for services to be ready..."
    sleep 5
    
    if curl -s http://localhost > /dev/null && curl -s http://localhost:8090/api/v1/health > /dev/null; then
        pass "System is running and ready"
    else
        fail "System is not responding properly"
        exit 1
    fi
}

# Run Go unit tests
run_unit_tests() {
    echo
    echo "=== Running Go Unit Tests ==="
    
    cd unified-tokenizer
    
    # Run tests with verbose output
    if go test -v -timeout 30s ./... 2>&1 | tee test_results.log; then
        unit_pass=$(grep -c "--- PASS:" test_results.log 2>/dev/null | head -n1)
        unit_fail=$(grep -c "--- FAIL:" test_results.log 2>/dev/null | head -n1)
        unit_skip=$(grep -c "--- SKIP:" test_results.log 2>/dev/null | head -n1)
        
        # Set defaults if empty
        unit_pass=${unit_pass:-0}
        unit_fail=${unit_fail:-0}
        unit_skip=${unit_skip:-0}
        
        if [ "$unit_fail" -eq 0 ]; then
            pass "All Go unit tests passed ($unit_pass passed, $unit_skip skipped)"
        else
            fail "$unit_fail Go unit tests failed"
        fi
        
        TOTAL_PASS=$((TOTAL_PASS + unit_pass))
        TOTAL_FAIL=$((TOTAL_FAIL + unit_fail))
    else
        fail "Go unit tests failed to run"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi
    
    cd ..
}

# Run integration tests
run_integration_tests() {
    echo
    echo "=== Running Integration Tests ==="
    
    if [ -f test_integration.sh ]; then
        chmod +x test_integration.sh
        if ./test_integration.sh; then
            pass "Integration tests completed successfully"
        else
            fail "Integration tests failed"
        fi
    else
        fail "Integration test script not found"
    fi
}

# Test database consistency
test_database_consistency() {
    echo
    echo "=== Testing Database Consistency ==="
    
    # Check if we can connect to database
    if docker exec tokenshield-mysql mysql -u pciproxy -ppciproxy123 tokenshield -e "SELECT 1;" > /dev/null 2>&1; then
        pass "Database connection working"
        
        # Check table structure
        tables=$(docker exec tokenshield-mysql mysql -u pciproxy -ppciproxy123 tokenshield -e "SHOW TABLES;" 2>/dev/null | grep -v Tables_in_tokenshield | wc -l)
        if [ "$tables" -ge 8 ]; then
            pass "Database schema complete ($tables tables)"
        else
            fail "Database schema incomplete ($tables tables)"
        fi
        
        # Check for any data integrity issues
        card_count=$(docker exec tokenshield-mysql mysql -u pciproxy -ppciproxy123 tokenshield -e "SELECT COUNT(*) FROM credit_cards;" 2>/dev/null | grep -v COUNT || echo "0")
        info "Found $card_count stored tokens"
        
    else
        fail "Cannot connect to database"
    fi
}

# Test API functionality
test_api_functionality() {
    echo
    echo "=== Testing API Functionality ==="
    
    info "Enabling test mode to bypass rate limiting"
    
    # Get admin session (latest password)
    admin_password=$(docker logs tokenshield-unified 2>&1 | grep "Password:" | tail -1 | awk '{print $NF}')
    
    if [ -n "$admin_password" ]; then
        info "Found admin password: ${admin_password:0:5}***"
        
        # Create JSON payload with proper escaping
        json_payload=$(jq -n --arg username "admin" --arg password "$admin_password" '{username: $username, password: $password}')
        
        login_response=$(curl -s -X POST http://localhost:8090/api/v1/auth/login \
            -H "Content-Type: application/json" \
            -d "$json_payload")
        
        info "Login response: $(echo "$login_response" | head -c 100)..."
        
        session_id=$(echo "$login_response" | jq -r '.session_id // empty')
        
        if [ -n "$session_id" ]; then
            info "Successfully authenticated as admin"
            
            # Test health endpoint (should work without auth)
            if curl -s http://localhost:8090/health | grep -q "healthy"; then
                pass "Health endpoint working"
            else
                fail "Health endpoint not working"
            fi
            
            # Test version endpoint
            if curl -s http://localhost:8090/api/v1/version | grep -q "version"; then
                pass "Version endpoint working"
            else
                fail "Version endpoint not working"
            fi
            
            # Test statistics endpoint with session
            if curl -s -H "Authorization: Bearer $session_id" http://localhost:8090/api/v1/stats | grep -q "active_tokens"; then
                pass "Statistics endpoint working"
            else
                fail "Statistics endpoint not working"
            fi
        else
            fail "Could not authenticate for API tests"
        fi
    else
        fail "Could not find admin password in logs"
    fi
    
    info "Disabling test mode"
}

# Test tokenization pipeline
test_tokenization_pipeline() {
    echo
    echo "=== Testing Complete Tokenization Pipeline ==="
    
    # Test with a known card number
    test_card="4532015112830366"
    
    info "Testing end-to-end tokenization with card: ${test_card:0:4}****${test_card: -4}"
    
    # Make a test payment
    response=$(curl -s -X POST http://localhost/api/checkout \
        -H "Content-Type: application/json" \
        -d "{\"card_holder\":\"Test User\",\"card_number\":\"$test_card\",\"expiry\":\"12/25\",\"cvv\":\"123\",\"amount\":99.99}")
    
    # Check if we got a token back
    if echo "$response" | jq -e '.token_used' | grep -q "tok_"; then
        token=$(echo "$response" | jq -r '.token_used')
        pass "Tokenization successful: ${token:0:20}..."
        
        # Check if payment was processed
        if echo "$response" | jq -e '.gateway_response.status' | grep -q "success"; then
            pass "Payment processing successful"
            
            # Verify detokenization worked (payment gateway got real card)
            last_four=$(echo "$response" | jq -r '.gateway_response.card_last_four')
            if [ "$last_four" = "${test_card: -4}" ]; then
                pass "Detokenization successful (last 4: $last_four)"
            else
                fail "Detokenization failed (expected: ${test_card: -4}, got: $last_four)"
            fi
        else
            fail "Payment processing failed"
        fi
    else
        fail "Tokenization failed"
        echo "Response: $response"
    fi
}

# Generate test report
generate_report() {
    echo
    echo "=== Test Report ==="
    echo "Timestamp: $(date)"
    echo "Total Tests: $((TOTAL_PASS + TOTAL_FAIL))"
    echo -e "Passed: ${GREEN}$TOTAL_PASS${NC}"
    echo -e "Failed: ${RED}$TOTAL_FAIL${NC}"
    
    if [ $TOTAL_FAIL -eq 0 ]; then
        echo -e "${GREEN}🎉 All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}❌ $TOTAL_FAIL test(s) failed.${NC}"
        return 1
    fi
}

# Save test results
save_results() {
    cat > test_results.json << EOF
{
    "timestamp": "$(date -Iseconds)",
    "total_tests": $((TOTAL_PASS + TOTAL_FAIL)),
    "passed": $TOTAL_PASS,
    "failed": $TOTAL_FAIL,
    "success": $([ $TOTAL_FAIL -eq 0 ] && echo "true" || echo "false"),
}
EOF
    
    info "Test results saved to test_results.json"
}

# Main execution
main() {
    echo "Starting comprehensive test suite at $(date)"
    echo
    
    # Run all test categories
    check_system
    test_database_consistency
    test_api_functionality
    test_tokenization_pipeline
    run_unit_tests
    run_integration_tests
    
    # Generate final report
    generate_report
    save_results
    
    # Return appropriate exit code
    [ $TOTAL_FAIL -eq 0 ] && exit 0 || exit 1
}

# Run main function
main "$@"
