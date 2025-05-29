package main

import (
	"database/sql"
	"log"
	"os"
	"regexp"

	_ "github.com/go-sql-driver/mysql"
)

func testTokenRegex() {
	log.Println("=== Testing Token Regex ===")
	
	// Test regex pattern
	tokenRegex, err := regexp.Compile(`tok_[a-zA-Z0-9_\-]+`)
	if err != nil {
		log.Printf("ERROR: Failed to compile regex: %v", err)
		return
	}
	
	// Test cases
	testCases := []struct {
		input    string
		expected []string
	}{
		{
			input:    `{"card_number": "tok_abc123", "amount": 100}`,
			expected: []string{"tok_abc123"},
		},
		{
			input:    `{"card_number": "tok_LbZel57Fl0rqHPuLFtMmHtckjZrgM8G-sy2NBtpkQeI", "amount": 100}`,
			expected: []string{"tok_LbZel57Fl0rqHPuLFtMmHtckjZrgM8G-sy2NBtpkQeI"},
		},
		{
			input:    `{"card_number": "4111111111111111", "amount": 100}`,
			expected: []string{},
		},
		{
			input:    `{"token1": "tok_abc", "token2": "tok_def-123_xyz"}`,
			expected: []string{"tok_abc", "tok_def-123_xyz"},
		},
	}
	
	for i, tc := range testCases {
		tokens := tokenRegex.FindAllString(tc.input, -1)
		log.Printf("Test %d: Input: %s", i+1, tc.input)
		log.Printf("Test %d: Found tokens: %v", i+1, tokens)
		log.Printf("Test %d: Expected: %v", i+1, tc.expected)
		
		if len(tokens) == len(tc.expected) {
			match := true
			for j, token := range tokens {
				if j >= len(tc.expected) || token != tc.expected[j] {
					match = false
					break
				}
			}
			if match {
				log.Printf("Test %d: ✅ PASS", i+1)
			} else {
				log.Printf("Test %d: ❌ FAIL - tokens don't match", i+1)
			}
		} else {
			log.Printf("Test %d: ❌ FAIL - wrong number of tokens", i+1)
		}
		log.Println("")
	}
}

func testDatabaseConnection() {
	log.Println("=== Testing Database Connection ===")
	
	// Database configuration
	dbHost := os.Getenv("DB_HOST")
	dbUser := os.Getenv("DB_USER") 
	dbPass := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	
	// Set defaults
	if dbHost == "" {
		dbHost = "mysql"
	}
	if dbUser == "" {
		dbUser = "pciproxy"
	}
	if dbPass == "" {
		dbPass = "pciproxy123"
	}
	if dbName == "" {
		dbName = "pci_proxy"
	}
	
	log.Printf("Connecting to: %s@%s/%s", dbUser, dbHost, dbName)
	
	// Connect to database
	dsn := dbUser + ":" + dbPass + "@tcp(" + dbHost + ":3306)/" + dbName
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("❌ FAIL: Failed to open database: %v", err)
		return
	}
	defer db.Close()
	
	// Test connection
	if err := db.Ping(); err != nil {
		log.Printf("❌ FAIL: Failed to ping database: %v", err)
		return
	}
	
	log.Printf("✅ PASS: Database connection successful")
	
	// Test token lookup query
	testToken := "tok_test123"
	log.Printf("Testing token lookup query for: %s", testToken)
	
	var encryptedCardNumber []byte
	err = db.QueryRow("SELECT card_number_encrypted FROM credit_cards WHERE token = ? AND is_active = TRUE", testToken).Scan(&encryptedCardNumber)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("⚠️  Token not found (expected for non-existent token)")
		} else {
			log.Printf("❌ FAIL: Database query error: %v", err)
		}
	} else {
		log.Printf("✅ Found encrypted card data for token: %s (length: %d bytes)", testToken, len(encryptedCardNumber))
	}
}

func testRealToken() {
	log.Println("=== Testing Real Token from Database ===")
	
	// Database configuration
	dbHost := "mysql"
	dbUser := "pciproxy"
	dbPass := "pciproxy123"
	dbName := "pci_proxy"
	
	log.Printf("Looking for recent tokens in database...")
	
	// Connect to database
	dsn := dbUser + ":" + dbPass + "@tcp(" + dbHost + ":3306)/" + dbName
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("❌ FAIL: Failed to open database: %v", err)
		return
	}
	defer db.Close()
	
	// Get a recent token from the database
	var token string
	var cardNumberEncrypted []byte
	err = db.QueryRow("SELECT token, card_number_encrypted FROM credit_cards WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 1").Scan(&token, &cardNumberEncrypted)
	if err != nil {
		log.Printf("❌ FAIL: No tokens found in database: %v", err)
		return
	}
	
	log.Printf("Found recent token: %s", token)
	log.Printf("Encrypted card data length: %d bytes", len(cardNumberEncrypted))
	
	// Test regex matching on the real token
	tokenRegex, _ := regexp.Compile(`tok_[a-zA-Z0-9_\-]+`)
	matches := tokenRegex.FindAllString(token, -1)
	if len(matches) == 1 && matches[0] == token {
		log.Printf("✅ PASS: Token regex matches real token")
	} else {
		log.Printf("❌ FAIL: Token regex does not match real token")
		log.Printf("  Token: %s", token)
		log.Printf("  Matches: %v", matches)
	}
	
	// Test JSON with real token
	testJSON := `{"card_number": "` + token + `", "amount": 100}`
	matches = tokenRegex.FindAllString(testJSON, -1)
	if len(matches) == 1 && matches[0] == token {
		log.Printf("✅ PASS: Token regex finds token in JSON")
	} else {
		log.Printf("❌ FAIL: Token regex does not find token in JSON")
		log.Printf("  JSON: %s", testJSON)
		log.Printf("  Matches: %v", matches)
	}
}

func main() {
	log.Println("🧪 ICAP Server Test Suite")
	log.Println("========================")
	
	// Test 1: Token Regex
	testTokenRegex()
	
	// Test 2: Database Connection  
	testDatabaseConnection()
	
	// Test 3: Real Token Testing
	testRealToken()
	
	log.Println("🏁 Test Suite Complete")
}