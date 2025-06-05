package tokenizer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	cryptorand "crypto/rand"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fernet/fernet-go"
	"tokenshield-unified/internal/utils"
)

// KeyManager interface for encryption operations
type KeyManager interface {
	EncryptData(data []byte) ([]byte, string, error)
	DecryptData(encryptedData []byte, keyID string) ([]byte, error)
}

// StorageInterface defines methods for token storage
type StorageInterface interface {
	StoreCard(token, cardNumber string) error
	RetrieveCard(token string) string
}

// TokenizerConfig holds configuration for the tokenizer
type TokenizerConfig struct {
	TokenFormat     string // "prefix" or "luhn"
	UseKEKDEK      bool
	DebugMode      bool
	TokenRegex     *regexp.Regexp
	CardRegex      *regexp.Regexp
}

// Tokenizer handles all tokenization and detokenization operations
type Tokenizer struct {
	config        TokenizerConfig
	encryptionKey *fernet.Key
	keyManager    KeyManager
	storage       StorageInterface
}

// NewTokenizer creates a new tokenizer instance
func NewTokenizer(config TokenizerConfig, encryptionKey *fernet.Key, keyManager KeyManager, storage StorageInterface) *Tokenizer {
	return &Tokenizer{
		config:        config,
		encryptionKey: encryptionKey,
		keyManager:    keyManager,
		storage:       storage,
	}
}

// TokenizeJSON tokenizes credit card numbers in JSON content
func (t *Tokenizer) TokenizeJSON(jsonStr string) (string, bool, error) {
	var data interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return jsonStr, false, err
	}
	
	modified := false
	t.processValue(&data, &modified, true) // true for tokenization
	
	result, err := json.Marshal(data)
	if err != nil {
		return jsonStr, false, err
	}
	
	return string(result), modified, nil
}

// DetokenizeJSON detokenizes tokens back to credit card numbers in JSON content
func (t *Tokenizer) DetokenizeJSON(jsonStr string) (string, bool, error) {
	if t.config.DebugMode {
		log.Printf("DEBUG: detokenizeJSON called with: %s", jsonStr[:utils.Min(200, len(jsonStr))])
	}
	
	var data interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return jsonStr, false, err
	}
	
	if t.config.DebugMode {
		log.Printf("DEBUG: Unmarshaled data type: %T", data)
	}
	
	modified := false
	t.processValue(&data, &modified, false) // false for detokenization
	
	if t.config.DebugMode {
		log.Printf("DEBUG: detokenizeJSON modified=%v", modified)
	}
	
	result, err := json.Marshal(data)
	if err != nil {
		return jsonStr, false, err
	}
	
	return string(result), modified, nil
}

// DetokenizeHTML detokenizes tokens in HTML content
func (t *Tokenizer) DetokenizeHTML(htmlStr string) (string, bool, error) {
	if t.config.DebugMode {
		log.Printf("DEBUG: detokenizeHTML called, length: %d", len(htmlStr))
	}
	
	modified := false
	result := htmlStr
	
	// Find all tokens in the HTML content
	matches := t.config.TokenRegex.FindAllString(htmlStr, -1)
	if t.config.DebugMode {
		log.Printf("DEBUG: Found %d potential tokens in HTML", len(matches))
	}
	
	for _, token := range matches {
		if t.config.DebugMode {
			log.Printf("DEBUG: Attempting to detokenize token: %s", token)
		}
		if card := t.storage.RetrieveCard(token); card != "" {
			result = strings.ReplaceAll(result, token, card)
			modified = true
			log.Printf("Detokenized token %s in HTML content", token)
		} else if t.config.DebugMode {
			log.Printf("DEBUG: Failed to retrieve card for token: %s", token)
		}
	}
	
	return result, modified, nil
}

// processValue recursively processes values for tokenization or detokenization
func (t *Tokenizer) processValue(v interface{}, modified *bool, tokenize bool) {
	switch val := v.(type) {
	case *interface{}:
		if t.config.DebugMode && !tokenize {
			log.Printf("DEBUG: Processing pointer to interface{}")
		}
		t.processValue(*val, modified, tokenize)
	case map[string]interface{}:
		if t.config.DebugMode && !tokenize {
			log.Printf("DEBUG: Processing map with keys: %v", t.getMapKeys(val))
		}
		for k, v := range val {
			if t.config.DebugMode && !tokenize {
				log.Printf("DEBUG: Processing map key '%s' with value type %T", k, v)
			}
			if tokenize && t.isCreditCardField(k) {
				if str, ok := v.(string); ok && t.config.CardRegex.MatchString(str) {
					// Don't tokenize if it's already one of our tokens
					if t.config.TokenFormat == "luhn" && strings.HasPrefix(str, "9999") {
						// This is already a token, skip it
						continue
					}
					if t.config.TokenFormat == "prefix" && strings.HasPrefix(str, "tok_") {
						// This is already a token, skip it
						continue
					}
					
					token := t.generateToken()
					if token != "" {
						val[k] = token
						*modified = true
						
						// Store the mapping
						if err := t.storage.StoreCard(token, str); err != nil {
							log.Printf("Error storing card: %v", err)
						} else {
							log.Printf("Tokenized card ending in %s -> %s", str[len(str)-4:], token)
						}
					}
				}
			} else if !tokenize && t.config.TokenRegex.MatchString(fmt.Sprintf("%v", v)) {
				// Detokenization
				if str, ok := v.(string); ok {
					if t.config.DebugMode {
						log.Printf("DEBUG: Found token %s for key %s", str, k)
					}
					if card := t.storage.RetrieveCard(str); card != "" {
						val[k] = card
						*modified = true
						if t.config.DebugMode {
							log.Printf("DEBUG: Detokenized %s to card ending in %s", str, card[len(card)-4:])
						}
					} else if t.config.DebugMode {
						log.Printf("DEBUG: Failed to retrieve card for token %s", str)
					}
				}
			}
			t.processValue(v, modified, tokenize)
		}
	case []interface{}:
		if t.config.DebugMode && !tokenize {
			log.Printf("DEBUG: Processing array with %d elements", len(val))
		}
		for i, elem := range val {
			t.processValue(&val[i], modified, tokenize)
			if val[i] != elem {
				*modified = true
			}
		}
	}
}

// getMapKeys returns sorted keys from a map for consistent debugging
func (t *Tokenizer) getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// isCreditCardField checks if a field name indicates it might contain credit card data
func (t *Tokenizer) isCreditCardField(fieldName string) bool {
	fieldLower := strings.ToLower(fieldName)
	
	// Common field names that contain credit card numbers
	cardFields := []string{
		"card_number", "cardnumber", "card", "pan", "primaryaccountnumber",
		"creditcard", "credit_card", "ccnumber", "cc_number", "account_number",
		"acct_number", "number", "cardno", "card_no",
	}
	
	for _, field := range cardFields {
		if fieldLower == field {
			return true
		}
	}
	
	// Also check for partial matches that are likely credit card fields
	if strings.Contains(fieldLower, "card") && strings.Contains(fieldLower, "number") {
		return true
	}
	
	return false
}

// generateToken creates a new token based on the configured format
func (t *Tokenizer) generateToken() string {
	if t.config.TokenFormat == "luhn" {
		return t.generateLuhnToken()
	}
	
	// Default prefix format - restore original logic
	b := make([]byte, 32)
	cryptorand.Read(b)
	return "tok_" + base64.URLEncoding.EncodeToString(b)
}

// generateLuhnToken creates a Luhn-valid 16-digit token starting with 9999
func (t *Tokenizer) generateLuhnToken() string {
	// Start with our special prefix
	prefix := "9999"
	
	// Generate 11 random digits 
	randomBytes := make([]byte, 11)
	_, err := cryptorand.Read(randomBytes)
	if err != nil {
		// Fallback to time-based generation if crypto/rand fails
		now := time.Now().UnixNano()
		for i := 0; i < 11; i++ {
			randomBytes[i] = byte('0' + (now>>uint(i*6))%10)
		}
	}
	
	// Convert to digit string
	digits := prefix
	for _, b := range randomBytes {
		digits += strconv.Itoa(int(b) % 10)
	}
	
	// Calculate Luhn check digit
	checkDigit := t.calculateLuhnCheckDigit(digits)
	
	return digits + strconv.Itoa(checkDigit)
}


// calculateLuhnCheckDigit calculates the Luhn algorithm check digit
func (t *Tokenizer) calculateLuhnCheckDigit(digits string) int {
	sum := 0
	alternate := true // Start with true since we're calculating for the final digit
	
	// Process digits from right to left, excluding the final position
	for i := len(digits) - 1; i >= 0; i-- {
		digit, _ := strconv.Atoi(string(digits[i]))
		
		if alternate {
			digit *= 2
			if digit > 9 {
				digit = digit/10 + digit%10
			}
		}
		
		sum += digit
		alternate = !alternate
	}
	
	// Return the digit that makes the total sum divisible by 10
	return (10 - (sum % 10)) % 10
}

// EncryptCardNumber encrypts card data using the appropriate method
func (t *Tokenizer) EncryptCardNumber(data string) ([]byte, error) {
	if t.config.UseKEKDEK && t.keyManager != nil {
		// Use KEK/DEK encryption
		encrypted, _, err := t.keyManager.EncryptData([]byte(data))
		return encrypted, err
	} else {
		// Use legacy Fernet encryption
		return fernet.EncryptAndSign([]byte(data), t.encryptionKey)
	}
}

// DecryptCardNumber decrypts card data using the appropriate method
func (t *Tokenizer) DecryptCardNumber(encryptedData []byte) (string, error) {
	if t.config.UseKEKDEK && t.keyManager != nil {
		// Try KEK/DEK decryption first
		decrypted, err := t.keyManager.DecryptData(encryptedData, "")
		if err == nil {
			return string(decrypted), nil
		}
		// Fall back to legacy if KEK/DEK fails
	}
	
	// Use legacy Fernet decryption
	decrypted := fernet.VerifyAndDecrypt(encryptedData, 0, []*fernet.Key{t.encryptionKey})
	if decrypted == nil {
		return "", fmt.Errorf("fernet decryption failed")
	}
	return string(decrypted), nil
}

// GenerateToken creates a new token (exported wrapper for generateToken)
func (t *Tokenizer) GenerateToken() string {
	return t.generateToken()
}