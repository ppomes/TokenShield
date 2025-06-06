#!/bin/bash

# Simple test script to verify tokenization functions are working

echo "Testing tokenization functionality..."

# Test data with a credit card number
TEST_DATA='{
  "card_number": "4532015112830366",
  "card_holder": "John Doe",
  "amount": "99.99"
}'

echo "Test payload:"
echo "$TEST_DATA"
echo

# Start the unified tokenizer in debug mode in the background
echo "Starting unified tokenizer in debug mode..."
DEBUG=true ./tokenshield-unified &
SERVER_PID=$!

# Wait for server to start
sleep 3

# Test the tokenization endpoint
echo "Testing tokenization via HTTP..."
curl -X POST http://localhost:8080/api/test \
  -H "Content-Type: application/json" \
  -d "$TEST_DATA" \
  -v

echo
echo "Server logs should show tokenization activity above."

# Clean up
kill $SERVER_PID 2>/dev/null

echo "Test completed!"