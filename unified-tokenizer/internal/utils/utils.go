package utils

import (
	"html"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Compiled regex patterns for security validation
var (
	// SQL injection patterns
	sqlInjectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(union\s+select|insert\s+into|delete\s+from|update\s+set|drop\s+table|create\s+table)`),
		regexp.MustCompile(`(?i)(exec\s*\(|execute\s*\(|sp_executesql)`),
		regexp.MustCompile(`(?i)(script\s*>|javascript:|vbscript:|onload\s*=|onerror\s*=)`),
		regexp.MustCompile(`(?i)(union.*select|select.*from.*where|1\s*=\s*1|1\s*or\s*1)`),
	}
	
	// XSS patterns
	xssPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`),
		regexp.MustCompile(`(?i)javascript:`),
		regexp.MustCompile(`(?i)vbscript:`),
		regexp.MustCompile(`(?i)on\w+\s*=`),
		regexp.MustCompile(`(?i)<iframe[^>]*>`),
	}
)

// Environment variable helpers

// GetEnv gets an environment variable with a default fallback
func GetEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// ParseTimeEnv parses a duration from environment with default fallback
func ParseTimeEnv(key, defaultValue string) time.Duration {
	value := GetEnv(key, defaultValue)
	duration, err := time.ParseDuration(value)
	if err != nil {
		// If parsing fails, try to parse the default
		duration, _ = time.ParseDuration(defaultValue)
	}
	return duration
}

// ParseIntEnv parses an integer from environment with default fallback
func ParseIntEnv(key string, defaultValue int) int {
	value := GetEnv(key, "")
	if value == "" {
		return defaultValue
	}
	intValue, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return intValue
}

// Math helpers

// Min returns the minimum of two integers
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// String validation and sanitization helpers

// SanitizeString removes dangerous characters and escapes HTML
func SanitizeString(input string) string {
	// Remove null bytes and control characters
	cleaned := strings.Map(func(r rune) rune {
		if r == 0 || (r < 32 && r != 9 && r != 10 && r != 13) {
			return -1
		}
		return r
	}, input)
	
	// HTML escape the string
	cleaned = html.EscapeString(cleaned)
	
	// Remove any remaining dangerous patterns
	for _, pattern := range xssPatterns {
		cleaned = pattern.ReplaceAllString(cleaned, "")
	}
	
	return strings.TrimSpace(cleaned)
}

// DetectSQLInjection checks for SQL injection patterns
func DetectSQLInjection(input string) bool {
	lowercaseInput := strings.ToLower(input)
	for _, pattern := range sqlInjectionPatterns {
		if pattern.MatchString(lowercaseInput) {
			return true
		}
	}
	return false
}

// Card validation helpers

// DetectCardType determines the card type based on the card number
func DetectCardType(cardNumber string) string {
	// Remove any spaces or dashes
	cardNumber = strings.ReplaceAll(cardNumber, " ", "")
	cardNumber = strings.ReplaceAll(cardNumber, "-", "")
	
	// Visa: starts with 4
	if matched, _ := regexp.MatchString(`^4[0-9]{12}(?:[0-9]{3})?$`, cardNumber); matched {
		return "Visa"
	}
	
	// Mastercard: starts with 5[1-5] or 2[2-7]
	if matched, _ := regexp.MatchString(`^5[1-5][0-9]{14}$`, cardNumber); matched {
		return "Mastercard"
	}
	if matched, _ := regexp.MatchString(`^2[2-7][0-9]{14}$`, cardNumber); matched {
		return "Mastercard"
	}
	
	// American Express: starts with 34 or 37
	if matched, _ := regexp.MatchString(`^3[47][0-9]{13}$`, cardNumber); matched {
		return "Amex"
	}
	
	// Discover: starts with 6011, 622126-622925, 644-649, or 65
	if matched, _ := regexp.MatchString(`^6011[0-9]{12}$`, cardNumber); matched {
		return "Discover"
	}
	if matched, _ := regexp.MatchString(`^64[4-9][0-9]{13}$`, cardNumber); matched {
		return "Discover"
	}
	if matched, _ := regexp.MatchString(`^65[0-9]{14}$`, cardNumber); matched {
		return "Discover"
	}
	
	return "Unknown"
}

// IsValidLuhn validates a card number using the Luhn algorithm
func IsValidLuhn(cardNumber string) bool {
	// Remove any spaces or dashes
	cardNumber = strings.ReplaceAll(cardNumber, " ", "")
	cardNumber = strings.ReplaceAll(cardNumber, "-", "")
	
	// Convert to slice of digits
	var digits []int
	for _, char := range cardNumber {
		if char < '0' || char > '9' {
			return false // Invalid character
		}
		digits = append(digits, int(char-'0'))
	}
	
	// Must have at least 2 digits
	if len(digits) < 2 {
		return false
	}
	
	// Apply Luhn algorithm
	sum := 0
	alternate := false
	
	// Process digits from right to left
	for i := len(digits) - 1; i >= 0; i-- {
		digit := digits[i]
		
		if alternate {
			digit *= 2
			if digit > 9 {
				digit = digit/10 + digit%10
			}
		}
		
		sum += digit
		alternate = !alternate
	}
	
	return sum%10 == 0
}

// GenerateLuhnCheckDigit calculates the Luhn check digit for a given number
func GenerateLuhnCheckDigit(number string) int {
	// Remove any non-digits
	digits := ""
	for _, char := range number {
		if char >= '0' && char <= '9' {
			digits += string(char)
		}
	}
	
	sum := 0
	alternate := true // Start with true since we're calculating the check digit
	
	// Process digits from right to left
	for i := len(digits) - 1; i >= 0; i-- {
		digit := int(digits[i] - '0')
		
		if alternate {
			digit *= 2
			if digit > 9 {
				digit = digit/10 + digit%10
			}
		}
		
		sum += digit
		alternate = !alternate
	}
	
	// Calculate check digit
	checkDigit := (10 - (sum % 10)) % 10
	return checkDigit
}