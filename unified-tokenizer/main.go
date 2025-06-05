package main

import (
    "bufio"
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    cryptorand "crypto/rand"
    "database/sql"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "html"
    "io"
    "log"
    "math/rand"
    "net"
    "net/http"
    "os"
    "regexp"
    "strconv"
    "strings"
    "sync"
    "time"

    "github.com/fernet/fernet-go"
    _ "github.com/go-sql-driver/mysql"
    "golang.org/x/crypto/bcrypt"
)

// Rate limiting structures
type RateLimiter struct {
    clients    map[string]*ClientRate
    mutex      sync.RWMutex
    maxAttempts int
    windowSize  time.Duration
    blockDuration time.Duration
}

type ClientRate struct {
    attempts    []time.Time
    blockedUntil time.Time
}

func NewRateLimiter(maxAttempts int, windowSize time.Duration, blockDuration time.Duration) *RateLimiter {
    return &RateLimiter{
        clients:      make(map[string]*ClientRate),
        maxAttempts:  maxAttempts,
        windowSize:   windowSize,
        blockDuration: blockDuration,
    }
}

func (rl *RateLimiter) IsAllowed(clientIP string) bool {
    rl.mutex.Lock()
    defer rl.mutex.Unlock()
    
    now := time.Now()
    
    // Get or create client rate data
    client, exists := rl.clients[clientIP]
    if !exists {
        client = &ClientRate{
            attempts: make([]time.Time, 0),
        }
        rl.clients[clientIP] = client
    }
    
    // Check if client is currently blocked
    if now.Before(client.blockedUntil) {
        return false
    }
    
    // Remove old attempts outside the window
    cutoff := now.Add(-rl.windowSize)
    validAttempts := make([]time.Time, 0)
    for _, attempt := range client.attempts {
        if attempt.After(cutoff) {
            validAttempts = append(validAttempts, attempt)
        }
    }
    client.attempts = validAttempts
    
    // Check if we're at the limit
    if len(client.attempts) >= rl.maxAttempts {
        // Block the client
        client.blockedUntil = now.Add(rl.blockDuration)
        return false
    }
    
    // Add current attempt
    client.attempts = append(client.attempts, now)
    
    return true
}

// Cleanup old entries periodically
func (rl *RateLimiter) Cleanup() {
    rl.mutex.Lock()
    defer rl.mutex.Unlock()
    
    now := time.Now()
    cutoff := now.Add(-rl.windowSize)
    
    for ip, client := range rl.clients {
        // Remove expired attempts
        validAttempts := make([]time.Time, 0)
        for _, attempt := range client.attempts {
            if attempt.After(cutoff) {
                validAttempts = append(validAttempts, attempt)
            }
        }
        client.attempts = validAttempts
        
        // Remove clients with no recent activity and not blocked
        if len(client.attempts) == 0 && now.After(client.blockedUntil) {
            delete(rl.clients, ip)
        }
    }
}

// Input validation and sanitization functions
var (
    // Common regex patterns for validation
    usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,50}$`)
    emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    alphanumericRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
    tokenRegex    = regexp.MustCompile(`^(tok_[a-zA-Z0-9+/=]+|[0-9]{13,19})$`)
    uuidRegex     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
    
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

// sanitizeString removes dangerous characters and escapes HTML
func sanitizeString(input string) string {
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

// detectSQLInjection checks for SQL injection patterns
func detectSQLInjection(input string) bool {
    lowercaseInput := strings.ToLower(input)
    for _, pattern := range sqlInjectionPatterns {
        if pattern.MatchString(lowercaseInput) {
            return true
        }
    }
    return false
}

// validateField validates a single field against its rules
func validateField(fieldName string, value interface{}, rule ValidationRule) []ValidationError {
    var errors []ValidationError
    
    // Convert value to string for most validations
    strValue := fmt.Sprintf("%v", value)
    
    // Check if field is required
    if rule.Required && (value == nil || strValue == "") {
        errors = append(errors, ValidationError{
            Field:   fieldName,
            Message: "field is required",
            Value:   strValue,
        })
        return errors
    }
    
    // Skip validation for empty optional fields
    if !rule.Required && strValue == "" {
        return errors
    }
    
    // Length validation
    if rule.MinLength > 0 && len(strValue) < rule.MinLength {
        errors = append(errors, ValidationError{
            Field:   fieldName,
            Message: fmt.Sprintf("minimum length is %d characters", rule.MinLength),
            Value:   strValue,
        })
    }
    
    if rule.MaxLength > 0 && len(strValue) > rule.MaxLength {
        errors = append(errors, ValidationError{
            Field:   fieldName,
            Message: fmt.Sprintf("maximum length is %d characters", rule.MaxLength),
            Value:   strValue,
        })
    }
    
    // Pattern validation
    if rule.Pattern != nil && !rule.Pattern.MatchString(strValue) {
        errors = append(errors, ValidationError{
            Field:   fieldName,
            Message: "field format is invalid",
            Value:   strValue,
        })
    }
    
    // Character validation
    if rule.AllowedChars != "" {
        allowedRegex := regexp.MustCompile(fmt.Sprintf("^[%s]*$", regexp.QuoteMeta(rule.AllowedChars)))
        if !allowedRegex.MatchString(strValue) {
            errors = append(errors, ValidationError{
                Field:   fieldName,
                Message: fmt.Sprintf("field contains invalid characters. Allowed: %s", rule.AllowedChars),
                Value:   strValue,
            })
        }
    }
    
    // SQL injection detection
    if detectSQLInjection(strValue) {
        errors = append(errors, ValidationError{
            Field:   fieldName,
            Message: "field contains potentially dangerous content",
            Value:   "[REDACTED]",
        })
    }
    
    // Custom validation
    if rule.CustomValidator != nil {
        if err := rule.CustomValidator(value); err != nil {
            errors = append(errors, ValidationError{
                Field:   fieldName,
                Message: err.Error(),
                Value:   strValue,
            })
        }
    }
    
    return errors
}

// validateRequest validates an entire request against validation configuration
func (ut *UnifiedTokenizer) validateRequest(endpoint string, data map[string]interface{}) ValidationResult {
    result := ValidationResult{
        Valid: true,
        Data:  make(map[string]interface{}),
    }
    
    // Get validation config for this endpoint
    config, exists := ut.validationConfigs[endpoint]
    if !exists {
        // No specific validation config, apply basic sanitization
        for key, value := range data {
            if strValue, ok := value.(string); ok {
                result.Data[key] = sanitizeString(strValue)
            } else {
                result.Data[key] = value
            }
        }
        return result
    }
    
    // Validate each field according to rules
    for fieldName, rule := range config.Rules {
        value, exists := data[fieldName]
        
        fieldErrors := validateField(fieldName, value, rule)
        if len(fieldErrors) > 0 {
            result.Valid = false
            result.Errors = append(result.Errors, fieldErrors...)
        }
        
        // Sanitize if required and validation passed
        if rule.Sanitize && exists && len(fieldErrors) == 0 {
            if strValue, ok := value.(string); ok {
                result.Data[fieldName] = sanitizeString(strValue)
            } else {
                result.Data[fieldName] = value
            }
        } else if exists {
            result.Data[fieldName] = value
        }
    }
    
    return result
}

// Audit logging structures
type AuditEvent struct {
    UserID       string                 `json:"user_id,omitempty"`
    Action       string                 `json:"action"`
    ResourceType string                 `json:"resource_type,omitempty"`
    ResourceID   string                 `json:"resource_id,omitempty"`
    Details      map[string]interface{} `json:"details,omitempty"`
    IPAddress    string                 `json:"ip_address"`
    UserAgent    string                 `json:"user_agent,omitempty"`
}

type SecurityEvent struct {
    EventType string                 `json:"event_type"`
    Severity  string                 `json:"severity"` // low, medium, high, critical
    UserID    string                 `json:"user_id,omitempty"`
    Username  string                 `json:"username,omitempty"`
    IPAddress string                 `json:"ip_address"`
    UserAgent string                 `json:"user_agent,omitempty"`
    Endpoint  string                 `json:"endpoint,omitempty"`
    Details   map[string]interface{} `json:"details,omitempty"`
}

// Input validation structures
type ValidationRule struct {
    FieldName    string                 `json:"field_name"`
    Required     bool                   `json:"required"`
    MinLength    int                    `json:"min_length,omitempty"`
    MaxLength    int                    `json:"max_length,omitempty"`
    Pattern      *regexp.Regexp         `json:"-"`
    AllowedChars string                 `json:"allowed_chars,omitempty"`
    Sanitize     bool                   `json:"sanitize"`
    CustomValidator func(interface{}) error `json:"-"`
}

type ValidationConfig struct {
    MaxRequestSize int64                    `json:"max_request_size"`
    AllowedMethods []string                 `json:"allowed_methods"`
    RequiredHeaders []string                `json:"required_headers,omitempty"`
    Rules          map[string]ValidationRule `json:"rules"`
}

type ValidationError struct {
    Field   string `json:"field"`
    Message string `json:"message"`
    Value   string `json:"value,omitempty"`
}

type ValidationResult struct {
    Valid  bool              `json:"valid"`
    Errors []ValidationError `json:"errors,omitempty"`
    Data   map[string]interface{} `json:"data,omitempty"`
}

// Card import structures
type CardImportRequest struct {
    Format            string `json:"format"`             // "json" or "csv"
    DuplicateHandling string `json:"duplicate_handling"` // "skip", "overwrite", "error"
    BatchSize         int    `json:"batch_size"`         // Number of cards to process per batch
    Data              string `json:"data"`               // Base64 encoded card data
}

type CardImportRecord struct {
    CardNumber     string `json:"card_number" csv:"card_number"`
    CardHolder     string `json:"card_holder,omitempty" csv:"card_holder"`
    ExpiryMonth    int    `json:"expiry_month" csv:"expiry_month"`
    ExpiryYear     int    `json:"expiry_year" csv:"expiry_year"`
    ExternalID     string `json:"external_id,omitempty" csv:"external_id"`     // Client's reference ID
    Metadata       string `json:"metadata,omitempty" csv:"metadata"`           // Additional metadata as JSON string
}

type CardImportResult struct {
    TotalRecords    int                     `json:"total_records"`
    ProcessedRecords int                    `json:"processed_records"`
    SuccessfulImports int                  `json:"successful_imports"`
    FailedImports   int                     `json:"failed_imports"`
    Duplicates      int                     `json:"duplicates"`
    ImportID        string                  `json:"import_id"`
    Status          string                  `json:"status"` // "completed", "partial", "failed"
    Errors          []CardImportError       `json:"errors,omitempty"`
    ProcessingTime  string                  `json:"processing_time"`
    TokensGenerated []CardImportSuccess     `json:"tokens_generated,omitempty"`
}

type CardImportError struct {
    RecordIndex int    `json:"record_index"`
    ExternalID  string `json:"external_id,omitempty"`
    CardNumber  string `json:"card_number_masked,omitempty"` // Only last 4 digits
    Error       string `json:"error"`
    Reason      string `json:"reason"`
}

type CardImportSuccess struct {
    RecordIndex int    `json:"record_index"`
    ExternalID  string `json:"external_id,omitempty"`
    Token       string `json:"token"`
    CardType    string `json:"card_type"`
    LastFour    string `json:"last_four"`
}

type UnifiedTokenizer struct {
    db              *sql.DB
    encryptionKey   *fernet.Key  // Legacy, kept for migration
    keyManager      *KeyManager
    appEndpoint     string
    tokenRegex      *regexp.Regexp
    cardRegex       *regexp.Regexp
    httpPort        string
    icapPort        string
    apiPort         string
    debug           bool
    tokenFormat     string // "prefix" for tok_ format, "luhn" for Luhn-valid format
    useKEKDEK       bool   // Whether to use KEK/DEK encryption
    authRateLimiter *RateLimiter // Rate limiter for authentication endpoints
    // Session security configuration
    sessionTimeout       time.Duration // Absolute session timeout
    sessionIdleTimeout   time.Duration // Idle session timeout 
    maxConcurrentSessions int           // Maximum concurrent sessions per user
    // Input validation configuration
    validationConfigs    map[string]ValidationConfig // Endpoint-specific validation rules
    mu              sync.RWMutex
}

// KeyManager handles KEK/DEK encryption
type KeyManager struct {
    db           *sql.DB
    kekCache     map[string][]byte
    dekCache     map[string][]byte
    currentKEKID string
    currentDEKID string
    mu           sync.RWMutex
}

// User represents a system user
type User struct {
    UserID       string    `json:"user_id"`
    Username     string    `json:"username"`
    Email        string    `json:"email"`
    FullName     string    `json:"full_name"`
    Role         string    `json:"role"`
    Permissions  []string  `json:"permissions"`
    IsActive     bool      `json:"is_active"`
    CreatedAt    time.Time `json:"created_at"`
    LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
    PasswordChangedAt *time.Time `json:"-"` // Don't expose in JSON
}

// UserSession represents an active user session
type UserSession struct {
    SessionID    string    `json:"session_id"`
    UserID       string    `json:"user_id"`
    User         *User     `json:"user,omitempty"`
    IPAddress    string    `json:"ip_address"`
    UserAgent    string    `json:"user_agent"`
    CreatedAt    time.Time `json:"created_at"`
    ExpiresAt    time.Time `json:"expires_at"`
    LastActivity time.Time `json:"last_activity"`
}

// AuthRequest represents a login request
type AuthRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

// AuthResponse represents a successful authentication
type AuthResponse struct {
    SessionID            string    `json:"session_id"`
    User                 User      `json:"user"`
    ExpiresAt            time.Time `json:"expires_at"`
    RequirePasswordChange bool     `json:"require_password_change"`
}

// Permission constants
const (
    PermTokensRead    = "tokens.read"
    PermTokensWrite   = "tokens.write"
    PermTokensDelete  = "tokens.delete"
    PermAPIKeysRead   = "api_keys.read"
    PermAPIKeysWrite  = "api_keys.write"
    PermAPIKeysDelete = "api_keys.delete"
    PermUsersRead     = "users.read"
    PermUsersWrite    = "users.write"
    PermUsersDelete   = "users.delete"
    PermSystemAdmin   = "system.admin"
    PermActivityRead  = "activity.read"
    PermStatsRead     = "stats.read"
)

// Role constants
const (
    RoleAdmin    = "admin"
    RoleOperator = "operator"
    RoleViewer   = "viewer"
)

// initializeValidationConfigs sets up validation rules for all API endpoints
func (ut *UnifiedTokenizer) initializeValidationConfigs() {
    // Login endpoint validation
    ut.validationConfigs["/api/v1/auth/login"] = ValidationConfig{
        MaxRequestSize: 1024, // 1KB max
        AllowedMethods: []string{"POST"},
        Rules: map[string]ValidationRule{
            "username": {
                FieldName:    "username",
                Required:     true,
                MinLength:    3,
                MaxLength:    50,
                Pattern:      usernameRegex,
                Sanitize:     true,
            },
            "password": {
                FieldName:    "password",
                Required:     true,
                MinLength:    12,
                MaxLength:    128,
                Sanitize:     false, // Don't sanitize passwords as it might break them
            },
        },
    }
    
    // User creation endpoint validation
    ut.validationConfigs["/api/v1/users"] = ValidationConfig{
        MaxRequestSize: 2048, // 2KB max
        AllowedMethods: []string{"POST"},
        Rules: map[string]ValidationRule{
            "username": {
                FieldName:    "username",
                Required:     true,
                MinLength:    3,
                MaxLength:    50,
                Pattern:      usernameRegex,
                Sanitize:     true,
            },
            "email": {
                FieldName:    "email",
                Required:     true,
                MinLength:    5,
                MaxLength:    255,
                Pattern:      emailRegex,
                Sanitize:     true,
            },
            "password": {
                FieldName:    "password",
                Required:     true,
                MinLength:    12,
                MaxLength:    128,
                Sanitize:     false,
            },
            "full_name": {
                FieldName:    "full_name",
                Required:     false,
                MinLength:    1,
                MaxLength:    100,
                Sanitize:     true,
            },
            "role": {
                FieldName:    "role",
                Required:     true,
                Pattern:      regexp.MustCompile(`^(admin|operator|viewer)$`),
                Sanitize:     true,
            },
        },
    }
    
    // Password change endpoint validation
    ut.validationConfigs["/api/v1/auth/change-password"] = ValidationConfig{
        MaxRequestSize: 512, // 512 bytes max
        AllowedMethods: []string{"POST"},
        Rules: map[string]ValidationRule{
            "current_password": {
                FieldName:    "current_password",
                Required:     true,
                MinLength:    1,
                MaxLength:    128,
                Sanitize:     false,
            },
            "new_password": {
                FieldName:    "new_password",
                Required:     true,
                MinLength:    12,
                MaxLength:    128,
                Sanitize:     false,
            },
        },
    }
    
    // API key creation endpoint validation
    ut.validationConfigs["/api/v1/api-keys"] = ValidationConfig{
        MaxRequestSize: 1024, // 1KB max
        AllowedMethods: []string{"POST"},
        Rules: map[string]ValidationRule{
            "client_name": {
                FieldName:    "client_name",
                Required:     true,
                MinLength:    1,
                MaxLength:    100,
                Pattern:      regexp.MustCompile(`^[a-zA-Z0-9\s_.-]+$`),
                Sanitize:     true,
            },
        },
    }
    
    // Token search endpoint validation
    ut.validationConfigs["/api/v1/tokens/search"] = ValidationConfig{
        MaxRequestSize: 512, // 512 bytes max
        AllowedMethods: []string{"POST"},
        Rules: map[string]ValidationRule{
            "query": {
                FieldName:    "query",
                Required:     false,
                MinLength:    1,
                MaxLength:    50,
                Sanitize:     true,
            },
            "limit": {
                FieldName:    "limit",
                Required:     false,
                MinLength:    1,
                MaxLength:    4,
                Pattern:      regexp.MustCompile(`^[0-9]+$`),
                CustomValidator: func(value interface{}) error {
                    if strVal, ok := value.(string); ok {
                        if intVal, err := strconv.Atoi(strVal); err == nil {
                            if intVal < 1 || intVal > 1000 {
                                return fmt.Errorf("limit must be between 1 and 1000")
                            }
                        }
                    }
                    return nil
                },
            },
        },
    }
    
    // Generic token endpoint validation (for token IDs in URL paths)
    ut.validationConfigs["token_id"] = ValidationConfig{
        Rules: map[string]ValidationRule{
            "token": {
                FieldName:    "token",
                Required:     true,
                MinLength:    10,
                MaxLength:    100,
                Pattern:      tokenRegex,
                Sanitize:     true,
            },
        },
    }
    
    // Card import endpoint validation
    ut.validationConfigs["/api/v1/cards/import"] = ValidationConfig{
        MaxRequestSize: 50 * 1024 * 1024, // 50MB max for bulk imports
        AllowedMethods: []string{"POST"},
        Rules: map[string]ValidationRule{
            "format": {
                FieldName:    "format",
                Required:     true,
                Pattern:      regexp.MustCompile(`^(json|csv)$`),
                Sanitize:     true,
            },
            "duplicate_handling": {
                FieldName:    "duplicate_handling",
                Required:     false,
                Pattern:      regexp.MustCompile(`^(skip|overwrite|error)$`),
                Sanitize:     true,
            },
            "batch_size": {
                FieldName:    "batch_size",
                Required:     false,
                MinLength:    1,
                MaxLength:    4,
                Pattern:      regexp.MustCompile(`^[0-9]+$`),
                CustomValidator: func(value interface{}) error {
                    if strVal, ok := value.(string); ok {
                        if intVal, err := strconv.Atoi(strVal); err == nil {
                            if intVal < 1 || intVal > 1000 {
                                return fmt.Errorf("batch_size must be between 1 and 1000")
                            }
                        }
                    }
                    return nil
                },
            },
        },
    }
}

func NewUnifiedTokenizer() (*UnifiedTokenizer, error) {
    // Database connection
    dbHost := getEnv("DB_HOST", "mysql")
    dbPort := getEnv("DB_PORT", "3306")
    dbUser := getEnv("DB_USER", "pciproxy")
    dbPassword := getEnv("DB_PASSWORD", "pciproxy123")
    dbName := getEnv("DB_NAME", "tokenshield")
    
    dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", dbUser, dbPassword, dbHost, dbPort, dbName)
    db, err := sql.Open("mysql", dsn)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to database: %v", err)
    }
    
    // Test connection
    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("failed to ping database: %v", err)
    }
    
    // Set connection pool settings
    db.SetMaxOpenConns(25)
    db.SetMaxIdleConns(5)
    db.SetConnMaxLifetime(5 * time.Minute)
    
    // Encryption key
    encKeyStr := getEnv("ENCRYPTION_KEY", "")
    if encKeyStr == "" {
        // Generate a key for development
        key := fernet.Key{} 
        key.Generate()
        encKeyStr = base64.URLEncoding.EncodeToString(key[:])
        log.Printf("WARNING: Using generated encryption key. Set ENCRYPTION_KEY in production!")
    }
    
    keyBytes, err := base64.URLEncoding.DecodeString(encKeyStr)
    if err != nil {
        return nil, fmt.Errorf("invalid encryption key: %v", err)
    }
    
    if len(keyBytes) != 32 {
        return nil, fmt.Errorf("encryption key must be 32 bytes")
    }
    
    encKey := new(fernet.Key)
    copy(encKey[:], keyBytes)
    
    tokenFormat := getEnv("TOKEN_FORMAT", "prefix")
    if tokenFormat != "prefix" && tokenFormat != "luhn" {
        tokenFormat = "prefix"
    }
    
    // Adjust token regex based on format
    var tokenRegex *regexp.Regexp
    if tokenFormat == "luhn" {
        // Match 16-digit numbers starting with our special prefix (9999)
        tokenRegex = regexp.MustCompile(`\b9999[0-9]{12}\b`)
    } else {
        tokenRegex = regexp.MustCompile(`tok_[a-zA-Z0-9_\-]+=*`)
    }
    
    // Check if KEK/DEK is enabled
    useKEKDEK := getEnv("USE_KEK_DEK", "false") == "true"
    
    ut := &UnifiedTokenizer{
        db:            db,
        encryptionKey: encKey,
        appEndpoint:   getEnv("APP_ENDPOINT", "http://dummy-app:8000"),
        tokenRegex:    tokenRegex,
        cardRegex:     regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b`),
        httpPort:      getEnv("HTTP_PORT", "8080"),
        icapPort:      getEnv("ICAP_PORT", "1344"),
        apiPort:       getEnv("API_PORT", "8090"),
        debug:         getEnv("DEBUG_MODE", "0") == "1",
        tokenFormat:   tokenFormat,
        useKEKDEK:     useKEKDEK,
        authRateLimiter: NewRateLimiter(5, 15*time.Minute, 15*time.Minute), // 5 attempts per 15 minutes, 15 minute block
        // Session security configuration with environment variable support
        sessionTimeout:       parseTimeEnv("SESSION_TIMEOUT", "24h"),           // Default 24 hours
        sessionIdleTimeout:   parseTimeEnv("SESSION_IDLE_TIMEOUT", "4h"),       // Default 4 hours
        maxConcurrentSessions: parseIntEnv("MAX_CONCURRENT_SESSIONS", 5),       // Default 5 sessions per user
        validationConfigs:    make(map[string]ValidationConfig),                // Initialize validation configs
    }
    
    // Initialize validation configurations for endpoints
    ut.initializeValidationConfigs()
    
    // Initialize KeyManager if KEK/DEK is enabled
    if useKEKDEK {
        km, err := NewKeyManager(db)
        if err != nil {
            log.Printf("Warning: Failed to initialize KeyManager: %v. Falling back to legacy encryption.", err)
            ut.useKEKDEK = false
        } else {
            ut.keyManager = km
        }
    }
    
    // Start rate limiter cleanup goroutine
    go func() {
        ticker := time.NewTicker(5 * time.Minute)
        defer ticker.Stop()
        for range ticker.C {
            ut.authRateLimiter.Cleanup()
        }
    }()
    
    return ut, nil
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

func parseTimeEnv(key, defaultValue string) time.Duration {
    value := getEnv(key, defaultValue)
    duration, err := time.ParseDuration(value)
    if err != nil {
        log.Printf("Warning: Invalid duration for %s: %s, using default: %s", key, value, defaultValue)
        duration, _ = time.ParseDuration(defaultValue)
    }
    return duration
}

func parseIntEnv(key string, defaultValue int) int {
    value := getEnv(key, fmt.Sprintf("%d", defaultValue))
    result, err := strconv.Atoi(value)
    if err != nil {
        log.Printf("Warning: Invalid integer for %s: %s, using default: %d", key, value, defaultValue)
        return defaultValue
    }
    return result
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

// HTTP Tokenization Handler
func (ut *UnifiedTokenizer) handleTokenize(w http.ResponseWriter, r *http.Request) {
    start := time.Now()
    path := r.URL.Path
    
    if ut.debug {
        log.Printf("=== INCOMING REQUEST: %s %s ===", r.Method, path)
        log.Printf("Headers: %v", r.Header)
    }
    
    // Read body
    body, err := io.ReadAll(r.Body)
    if err != nil {
        log.Printf("Error reading body: %v", err)
        http.Error(w, "Error reading request", http.StatusBadRequest)
        return
    }
    r.Body.Close()
    
    // Process body for tokenization
    var processedBody []byte
    contentType := r.Header.Get("Content-Type")
    
    if strings.Contains(contentType, "application/json") && len(body) > 0 {
        tokenized, modified, err := ut.tokenizeJSON(string(body))
        if err != nil {
            log.Printf("Error tokenizing JSON: %v", err)
            processedBody = body
        } else {
            processedBody = []byte(tokenized)
            if modified && ut.debug {
                log.Printf("Tokenized request body")
            }
        }
    } else {
        processedBody = body
    }
    
    // Build forward URL
    forwardURL := ut.appEndpoint
    if path != "" && path != "/" {
        forwardURL = strings.TrimRight(ut.appEndpoint, "/") + path
    }
    
    if r.URL.RawQuery != "" {
        forwardURL += "?" + r.URL.RawQuery
    }
    
    // Create new request
    req, err := http.NewRequest(r.Method, forwardURL, bytes.NewReader(processedBody))
    if err != nil {
        log.Printf("Error creating forward request: %v", err)
        http.Error(w, "Error creating request", http.StatusInternalServerError)
        return
    }
    
    // Copy headers
    for key, values := range r.Header {
        for _, value := range values {
            req.Header.Add(key, value)
        }
    }
    
    // Update Content-Length
    req.ContentLength = int64(len(processedBody))
    req.Header.Set("Content-Length", strconv.Itoa(len(processedBody)))
    
    // Forward request
    client := &http.Client{
        Timeout: 30 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }
    
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Error forwarding request: %v", err)
        http.Error(w, "Error forwarding request", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()
    
    // Read response body
    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Printf("Error reading response body: %v", err)
        http.Error(w, "Error reading response", http.StatusInternalServerError)
        return
    }
    
    // Check if this is an endpoint that needs response detokenization
    processedRespBody := respBody
    needsDetokenization := (path == "/api/cards" || path == "/my-cards") && resp.StatusCode == 200
    
    if needsDetokenization {
        respContentType := resp.Header.Get("Content-Type")
        if ut.debug {
            log.Printf("DEBUG: Response content type: %s", respContentType)
            log.Printf("DEBUG: Response body preview: %s", string(respBody[:min(200, len(respBody))]))
        }
        
        // Handle JSON responses (API)
        if strings.Contains(respContentType, "application/json") {
            detokenized, modified, err := ut.detokenizeJSON(string(respBody))
            if err != nil {
                log.Printf("Error detokenizing JSON response: %v", err)
            } else if modified {
                processedRespBody = []byte(detokenized)
                log.Printf("Detokenized JSON response body for %s", path)
            } else if ut.debug {
                log.Printf("DEBUG: No tokens found to detokenize in JSON response")
            }
        } else if strings.Contains(respContentType, "text/html") {
            // Handle HTML responses (web pages)
            detokenized, modified, err := ut.detokenizeHTML(string(respBody))
            if err != nil {
                log.Printf("Error detokenizing HTML response: %v", err)
            } else if modified {
                processedRespBody = []byte(detokenized)
                log.Printf("Detokenized HTML response body for %s", path)
            } else if ut.debug {
                log.Printf("DEBUG: No tokens found to detokenize in HTML response")
            }
        }
    }
    
    // Copy response headers
    for key, values := range resp.Header {
        if key != "Content-Length" {
            for _, value := range values {
                w.Header().Add(key, value)
            }
        }
    }
    
    // Set correct content length
    w.Header().Set("Content-Length", strconv.Itoa(len(processedRespBody)))
    
    // Set status code
    w.WriteHeader(resp.StatusCode)
    
    // Write response body
    w.Write(processedRespBody)
    
    duration := time.Since(start)
    log.Printf("Request %s %s completed in %v with status %d", r.Method, path, duration, resp.StatusCode)
}

// ICAP Detokenization Server
func (ut *UnifiedTokenizer) handleICAP(conn net.Conn) {
    defer conn.Close()
    
    reader := bufio.NewReader(conn)
    writer := bufio.NewWriter(conn)
    
    // Read request line
    requestLine, err := reader.ReadString('\n')
    if err != nil {
        if err != io.EOF {
            log.Printf("Error reading request line: %v", err)
        }
        return
    }
    
    requestLine = strings.TrimSpace(requestLine)
    parts := strings.Split(requestLine, " ")
    if len(parts) < 3 {
        log.Printf("Invalid request line: %s", requestLine)
        return
    }
    
    method := parts[0]
    icapURI := parts[1]
    version := parts[2]
    
    if ut.debug {
        log.Printf("ICAP Request: %s %s %s", method, icapURI, version)
    }
    
    // Read headers
    headers := make(map[string]string)
    for {
        line, err := reader.ReadString('\n')
        if err != nil {
            log.Printf("Error reading headers: %v", err)
            return
        }
        line = strings.TrimSpace(line)
        if line == "" {
            break
        }
        
        colonIndex := strings.Index(line, ":")
        if colonIndex > 0 {
            key := strings.TrimSpace(line[:colonIndex])
            value := strings.TrimSpace(line[colonIndex+1:])
            headers[key] = value
        }
    }
    
    switch method {
    case "OPTIONS":
        ut.handleICAPOptions(writer, icapURI)
    case "REQMOD":
        ut.handleICAPReqmod(reader, writer, headers)
    case "RESPMOD":
        ut.handleICAPRespmod(reader, writer, headers)
    default:
        log.Printf("Unsupported ICAP method: %s", method)
    }
    
    writer.Flush()
}

func (ut *UnifiedTokenizer) handleICAPOptions(writer *bufio.Writer, icapURI string) {
    response := fmt.Sprintf("ICAP/1.0 200 OK\r\n")
    
    // Support both REQMOD and RESPMOD based on the URI
    if strings.Contains(icapURI, "/respmod") {
        response += "Methods: RESPMOD\r\n"
    } else {
        response += "Methods: REQMOD\r\n"
    }
    response += "Service: TokenShield Unified 1.0\r\n"
    response += "ISTag: \"TS-001\"\r\n"
    response += "Max-Connections: 100\r\n"
    response += "Options-TTL: 3600\r\n"
    response += "Allow: 204\r\n"
    response += "Preview: 0\r\n"
    response += "Transfer-Complete: *\r\n"
    response += "\r\n"
    
    writer.WriteString(response)
    writer.Flush()
    
    if ut.debug {
        log.Printf("Sent OPTIONS response for %s", icapURI)
    }
}

func (ut *UnifiedTokenizer) handleICAPReqmod(reader *bufio.Reader, writer *bufio.Writer, icapHeaders map[string]string) {
    // Parse encapsulated header
    encapHeader := icapHeaders["Encapsulated"]
    if encapHeader == "" {
        log.Printf("Missing Encapsulated header")
        return
    }
    
    // Read HTTP request
    httpRequest, httpHeaders, body, err := ut.parseEncapsulated(reader, encapHeader)
    if err != nil {
        log.Printf("Error parsing encapsulated data: %v", err)
        return
    }
    
    if ut.debug {
        log.Printf("HTTP Request: %s", httpRequest)
        log.Printf("Body length: %d", len(body))
    }
    
    // Check if we need to modify
    modified := false
    modifiedBody := body
    
    if len(body) > 0 {
        detokenized, wasModified, err := ut.detokenizeJSON(string(body))
        if err == nil && wasModified {
            modifiedBody = []byte(detokenized)
            modified = true
            log.Printf("Detokenized request body")
        }
    }
    
    if !modified {
        // Send 204 No Content
        response := "ICAP/1.0 204 No Content\r\n\r\n"
        writer.WriteString(response)
        writer.Flush()
        return
    }
    
    // Send modified response
    response := "ICAP/1.0 200 OK\r\n"
    
    // Calculate positions
    reqHdrLen := len(httpRequest) + 2 // +2 for \r\n
    for _, hdr := range httpHeaders {
        reqHdrLen += len(hdr) + 2
    }
    reqHdrLen += 2 // empty line
    
    response += fmt.Sprintf("Encapsulated: req-hdr=0, req-body=%d\r\n", reqHdrLen)
    response += "\r\n"
    
    // Write HTTP request line
    response += httpRequest + "\r\n"
    
    // Write HTTP headers (update Content-Length)
    contentLengthUpdated := false
    for _, hdr := range httpHeaders {
        if strings.HasPrefix(strings.ToLower(hdr), "content-length:") {
            response += fmt.Sprintf("Content-Length: %d\r\n", len(modifiedBody))
            contentLengthUpdated = true
        } else {
            response += hdr + "\r\n"
        }
    }
    
    if !contentLengthUpdated {
        response += fmt.Sprintf("Content-Length: %d\r\n", len(modifiedBody))
    }
    
    response += "\r\n"
    
    // Write response
    writer.WriteString(response)
    
    // Write body in chunks
    ut.writeChunked(writer, modifiedBody)
    writer.Flush()
}

func (ut *UnifiedTokenizer) handleICAPRespmod(reader *bufio.Reader, writer *bufio.Writer, icapHeaders map[string]string) {
    // Parse encapsulated header for response modification
    encapHeader := icapHeaders["Encapsulated"]
    if encapHeader == "" {
        log.Printf("Missing Encapsulated header in RESPMOD")
        return
    }
    
    if ut.debug {
        log.Printf("RESPMOD: Processing response for tokenization")
        log.Printf("Encapsulated: %s", encapHeader)
    }
    
    // Parse the response (request + response)
    httpRequest, httpHeaders, body, err := ut.parseEncapsulated(reader, encapHeader)
    if err != nil {
        log.Printf("RESPMOD Error parsing encapsulated response data: %v", err)
        return
    }
    
    if ut.debug {
        log.Printf("Response HTTP Request: %s", httpRequest)
        log.Printf("Response body length: %d", len(body))
    }
    
    // Check if we need to tokenize the response
    modified := false
    modifiedBody := body
    
    // Handle null-body case - send 204 No Content
    if len(body) == 0 {
        if ut.debug {
            log.Printf("RESPMOD: No body to process, sending 204 No Content")
        }
        response := "ICAP/1.0 204 No Content\r\n"
        response += "ISTag: \"TS-001\"\r\n"
        response += "\r\n"
        writer.WriteString(response)
        writer.Flush()
        return
    }
    
    // Look for JSON responses that might contain card data
    if len(body) > 0 {
        contentType := ""
        for _, header := range httpHeaders {
            if strings.HasPrefix(strings.ToLower(header), "content-type:") {
                contentType = strings.ToLower(header)
                break
            }
        }
        
        if strings.Contains(contentType, "application/json") {
            if ut.debug {
                log.Printf("RESPMOD: Found JSON response, checking for cards to tokenize")
            }
            
            tokenizedJSON, wasModified, err := ut.tokenizeJSON(string(body))
            if err != nil {
                log.Printf("Error tokenizing JSON response: %v", err)
            } else if wasModified {
                modifiedBody = []byte(tokenizedJSON)
                modified = true
                log.Printf("RESPMOD: Tokenized card numbers in response")
            }
        }
    }
    
    // Send response
    if !modified {
        // No modification - send 204 No Content
        response := "ICAP/1.0 204 No Content\r\n"
        response += "ISTag: \"TS-001\"\r\n"
        response += "\r\n"
        writer.WriteString(response)
    } else {
        // Modified - send 200 OK with new body
        
        // Build HTTP response first to calculate exact positions
        // Include HTTP status line + headers
        httpHeadersStr := httpRequest + "\r\n" // HTTP status line
        for _, header := range httpHeaders {
            if strings.HasPrefix(strings.ToLower(header), "content-length:") {
                // Update content length for modified body
                httpHeadersStr += fmt.Sprintf("Content-Length: %d\r\n", len(modifiedBody))
            } else {
                httpHeadersStr += header + "\r\n"
            }
        }
        httpHeadersStr += "\r\n" // End of headers
        
        // Calculate exact byte positions for Encapsulated header
        resBodyOffset := len(httpHeadersStr)
        
        // Build ICAP response
        response := "ICAP/1.0 200 OK\r\n"
        response += "ISTag: \"TS-001\"\r\n"
        response += fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n", resBodyOffset)
        response += "\r\n"
        
        // Write ICAP headers
        writer.WriteString(response)
        
        // Write HTTP response headers
        writer.WriteString(httpHeadersStr)
        
        // Write modified body in chunks
        ut.writeChunked(writer, modifiedBody)
    }
    
    writer.Flush()
}

func (ut *UnifiedTokenizer) parseEncapsulated(reader *bufio.Reader, encapHeader string) (string, []string, []byte, error) {
    log.Printf("DEBUG_FORCE: parseEncapsulated called with header: %s", encapHeader)
    
    // Parse positions from Encapsulated header
    positions := make(map[string]int)
    parts := strings.Split(encapHeader, ",")
    for _, part := range parts {
        kv := strings.Split(strings.TrimSpace(part), "=")
        if len(kv) == 2 {
            pos, _ := strconv.Atoi(kv[1])
            positions[kv[0]] = pos
        }
    }
    
    if ut.debug {
        log.Printf("DEBUG: parseEncapsulated positions: %+v", positions)
    }
    
    // For RESPMOD: req-hdr=0, res-hdr=175, res-body=322
    // This means: request headers start at 0, response headers at 175, response body at 322
    
    var requestLine string
    var httpHeaders []string
    var body []byte
    var err error
    
    // Determine if this is REQMOD or RESPMOD
    isRespmod := false
    if _, hasResHdr := positions["res-hdr"]; hasResHdr {
        isRespmod = true
    }
    
    if isRespmod {
        // RESPMOD: Skip request headers section if present, then read response headers
        if _, hasReqHdr := positions["req-hdr"]; hasReqHdr {
            if ut.debug {
                log.Printf("DEBUG: Skipping request headers section for RESPMOD")
            }
            // Read and discard request headers
            for {
                line, err := reader.ReadString('\n')
                if err != nil {
                    return "", nil, nil, err
                }
                if strings.TrimSpace(line) == "" {
                    break // End of request headers
                }
            }
        }
        
        // Read response status line and headers  
        if ut.debug {
            log.Printf("DEBUG: Reading response headers section for RESPMOD")
        }
        requestLine, err = reader.ReadString('\n')
        if err != nil {
            return "", nil, nil, err
        }
        requestLine = strings.TrimSpace(requestLine)
        
        // Read HTTP response headers
        for {
            line, err := reader.ReadString('\n')
            if err != nil {
                return "", nil, nil, err
            }
            line = strings.TrimSpace(line)
            if line == "" {
                break // End of headers
            }
            httpHeaders = append(httpHeaders, line)
        }
    } else {
        // REQMOD: Read request line and headers
        if ut.debug {
            log.Printf("DEBUG: Reading request headers section for REQMOD")
        }
        requestLine, err = reader.ReadString('\n')
        if err != nil {
            return "", nil, nil, err
        }
        requestLine = strings.TrimSpace(requestLine)
        
        // Read HTTP request headers
        for {
            line, err := reader.ReadString('\n')
            if err != nil {
                return "", nil, nil, err
            }
            line = strings.TrimSpace(line)
            if line == "" {
                break
            }
            httpHeaders = append(httpHeaders, line)
        }
    }
    
    // Read body if present
    if _, hasReqBody := positions["req-body"]; hasReqBody {
        if ut.debug {
            log.Printf("DEBUG: Reading req-body")
        }
        body, err = ut.readChunked(reader)
        if err != nil {
            return "", nil, nil, err
        }
    } else if _, hasResBody := positions["res-body"]; hasResBody {
        if ut.debug {
            log.Printf("DEBUG: Reading res-body at position %d", positions["res-body"])
        }
        body, err = ut.readChunked(reader)
        if err != nil {
            if ut.debug {
                log.Printf("DEBUG: Error reading res-body: %v", err)
            }
            return "", nil, nil, err
        }
        if ut.debug {
            log.Printf("DEBUG: Successfully read res-body: %d bytes", len(body))
        }
    } else {
        if ut.debug {
            log.Printf("DEBUG: No body found in positions: %+v", positions)
        }
        // For null-body cases, we still need to return a proper response
        // This typically means there's no body to process
    }
    
    if ut.debug {
        log.Printf("DEBUG: parseEncapsulated result - requestLine: '%s', headers: %d, body: %d bytes", 
            requestLine, len(httpHeaders), len(body))
    }
    
    return requestLine, httpHeaders, body, nil
}

func (ut *UnifiedTokenizer) readChunked(reader *bufio.Reader) ([]byte, error) {
    var result []byte
    
    if ut.debug {
        log.Printf("DEBUG: readChunked starting")
    }
    
    for {
        // Read chunk size
        sizeLine, err := reader.ReadString('\n')
        if err != nil {
            if ut.debug {
                log.Printf("DEBUG: readChunked error reading size line: %v", err)
            }
            return nil, err
        }
        
        sizeLine = strings.TrimSpace(sizeLine)
        if ut.debug {
            log.Printf("DEBUG: readChunked size line: '%s'", sizeLine)
        }
        
        size, err := strconv.ParseInt(sizeLine, 16, 64)
        if err != nil {
            if ut.debug {
                log.Printf("DEBUG: readChunked error parsing size: %v", err)
            }
            return nil, err
        }
        
        if ut.debug {
            log.Printf("DEBUG: readChunked chunk size: %d", size)
        }
        
        if size == 0 {
            // Read final CRLF
            reader.ReadString('\n')
            break
        }
        
        // Read chunk data
        chunk := make([]byte, size)
        _, err = io.ReadFull(reader, chunk)
        if err != nil {
            return nil, err
        }
        
        result = append(result, chunk...)
        
        // Read trailing CRLF
        reader.ReadString('\n')
    }
    
    return result, nil
}

func (ut *UnifiedTokenizer) writeChunked(writer *bufio.Writer, data []byte) {
    if len(data) > 0 {
        writer.WriteString(fmt.Sprintf("%x\r\n", len(data)))
        writer.Write(data)
        writer.WriteString("\r\n")
    }
    writer.WriteString("0\r\n\r\n")
}

// Tokenization logic
func (ut *UnifiedTokenizer) tokenizeJSON(jsonStr string) (string, bool, error) {
    var data interface{}
    if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
        return jsonStr, false, err
    }
    
    modified := false
    ut.processValue(&data, &modified, true) // true for tokenization
    
    result, err := json.Marshal(data)
    if err != nil {
        return jsonStr, false, err
    }
    
    return string(result), modified, nil
}

// Detokenization logic
func (ut *UnifiedTokenizer) detokenizeJSON(jsonStr string) (string, bool, error) {
    if ut.debug {
        log.Printf("DEBUG: detokenizeJSON called with: %s", jsonStr[:min(200, len(jsonStr))])
    }
    
    var data interface{}
    if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
        return jsonStr, false, err
    }
    
    if ut.debug {
        log.Printf("DEBUG: Unmarshaled data type: %T", data)
    }
    
    modified := false
    ut.processValue(&data, &modified, false) // false for detokenization
    
    if ut.debug {
        log.Printf("DEBUG: detokenizeJSON modified=%v", modified)
    }
    
    result, err := json.Marshal(data)
    if err != nil {
        return jsonStr, false, err
    }
    
    return string(result), modified, nil
}

// Detokenize HTML content
func (ut *UnifiedTokenizer) detokenizeHTML(htmlStr string) (string, bool, error) {
    if ut.debug {
        log.Printf("DEBUG: detokenizeHTML called, length: %d", len(htmlStr))
    }
    
    modified := false
    result := htmlStr
    
    // Find all tokens in the HTML content
    matches := ut.tokenRegex.FindAllString(htmlStr, -1)
    if ut.debug {
        log.Printf("DEBUG: Found %d potential tokens in HTML", len(matches))
    }
    
    for _, token := range matches {
        if ut.debug {
            log.Printf("DEBUG: Attempting to detokenize token: %s", token)
        }
        if card := ut.retrieveCard(token); card != "" {
            result = strings.ReplaceAll(result, token, card)
            modified = true
            log.Printf("Detokenized token %s in HTML content", token)
        } else if ut.debug {
            log.Printf("DEBUG: Failed to retrieve card for token: %s", token)
        }
    }
    
    return result, modified, nil
}

func (ut *UnifiedTokenizer) processValue(v interface{}, modified *bool, tokenize bool) {
    switch val := v.(type) {
    case *interface{}:
        if ut.debug && !tokenize {
            log.Printf("DEBUG: Processing pointer to interface{}")
        }
        ut.processValue(*val, modified, tokenize)
    case map[string]interface{}:
        if ut.debug && !tokenize {
            log.Printf("DEBUG: Processing map with keys: %v", ut.getMapKeys(val))
        }
        for k, v := range val {
            if ut.debug && !tokenize {
                log.Printf("DEBUG: Processing map key '%s' with value type %T", k, v)
            }
            if tokenize && ut.isCreditCardField(k) {
                if str, ok := v.(string); ok && ut.cardRegex.MatchString(str) {
                    // Don't tokenize if it's already one of our tokens
                    if ut.tokenFormat == "luhn" && strings.HasPrefix(str, "9999") {
                        // This is already a token, skip it
                        continue
                    }
                    token := ut.generateToken()
                    if err := ut.storeCard(token, str); err == nil {
                        val[k] = token
                        *modified = true
                        log.Printf("Tokenized card ending in %s", str[len(str)-4:])
                    }
                }
            } else if !tokenize && ut.isCreditCardField(k) {
                if str, ok := v.(string); ok {
                    if ut.debug {
                        log.Printf("DEBUG: Checking field '%s' with value '%s' for detokenization", k, str)
                    }
                    if ut.tokenRegex.MatchString(str) {
                        if card := ut.retrieveCard(str); card != "" {
                            val[k] = card
                            *modified = true
                            log.Printf("Detokenized token %s in field %s", str, k)
                        } else if ut.debug {
                            log.Printf("DEBUG: Failed to retrieve card for token %s", str)
                        }
                    } else if ut.debug {
                        log.Printf("DEBUG: Value '%s' doesn't match token regex", str)
                    }
                }
            } else {
                if ut.debug && !tokenize {
                    log.Printf("DEBUG: Recursively processing non-card field '%s' with value type %T", k, v)
                }
                ut.processValue(v, modified, tokenize)
            }
        }
    case []interface{}:
        if ut.debug && !tokenize {
            log.Printf("DEBUG: Processing array with %d elements", len(val))
        }
        for i := range val {
            if ut.debug && !tokenize && i == 0 {
                log.Printf("DEBUG: First array element type: %T", val[i])
            }
            ut.processValue(&val[i], modified, tokenize)
        }
    case string:
        // Handle string values that might contain tokens or card numbers
        if tokenize && ut.cardRegex.MatchString(val) {
            // This case is handled by the parent map processor
        } else if !tokenize && ut.tokenRegex.MatchString(val) {
            // This case is handled by the parent map processor  
        }
    }
}

func (ut *UnifiedTokenizer) getMapKeys(m map[string]interface{}) []string {
    keys := make([]string, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }
    return keys
}

func (ut *UnifiedTokenizer) isCreditCardField(fieldName string) bool {
    lowerField := strings.ToLower(fieldName)
    // Exact matches to avoid false positives like "cards" matching "card"
    exactMatches := []string{"card", "pan"}
    for _, field := range exactMatches {
        if lowerField == field {
            return true
        }
    }
    
    // Partial matches for compound names
    cardFields := []string{"card_number", "cardnumber", "creditcard", "credit_card", "account_number"}
    for _, field := range cardFields {
        if strings.Contains(lowerField, field) {
            return true
        }
    }
    return false
}

func (ut *UnifiedTokenizer) generateToken() string {
    if ut.tokenFormat == "luhn" {
        return ut.generateLuhnToken()
    }
    
    // Default prefix format
    b := make([]byte, 32)
    cryptorand.Read(b)
    return "tok_" + base64.URLEncoding.EncodeToString(b)
}

// calculateLuhnCheckDigit calculates the Luhn check digit for a given number
func calculateLuhnCheckDigit(number string) int {
    sum := 0
    alternate := false
    
    // Process from right to left
    for i := len(number) - 1; i >= 0; i-- {
        digit := int(number[i] - '0')
        
        if alternate {
            digit *= 2
            if digit > 9 {
                digit = (digit % 10) + 1
            }
        }
        
        sum += digit
        alternate = !alternate
    }
    
    return (10 - (sum % 10)) % 10
}

// generateLuhnToken generates a token that looks like a valid credit card number
func (ut *UnifiedTokenizer) generateLuhnToken() string {
    // Use prefix 9999 to distinguish tokens from real cards
    // This prefix is not used by any real card issuer
    prefix := "9999"
    
    // Generate 11 random digits
    randomPart := make([]byte, 11)
    for i := 0; i < 11; i++ {
        randomPart[i] = byte(rand.Intn(10)) + '0'
    }
    
    // Combine prefix and random part (15 digits total)
    partial := prefix + string(randomPart)
    
    // Calculate and append Luhn check digit
    checkDigit := calculateLuhnCheckDigit(partial)
    
    return partial + strconv.Itoa(checkDigit)
}

// Detect card type based on card number
func detectCardType(cardNumber string) string {
    if len(cardNumber) < 4 {
        return "Unknown"
    }
    
    // Remove any spaces or dashes
    cardNumber = strings.ReplaceAll(strings.ReplaceAll(cardNumber, " ", ""), "-", "")
    
    // Visa: starts with 4
    if strings.HasPrefix(cardNumber, "4") && (len(cardNumber) == 13 || len(cardNumber) == 16 || len(cardNumber) == 19) {
        return "Visa"
    }
    
    // Mastercard: starts with 5 (51-55) or 2 (2221-2720)
    if len(cardNumber) >= 2 {
        prefix2 := cardNumber[:2]
        if (prefix2 >= "51" && prefix2 <= "55") || (prefix2 >= "22" && prefix2 <= "27") {
            if len(cardNumber) == 16 {
                return "Mastercard"
            }
        }
    }
    
    // American Express: starts with 34 or 37
    if len(cardNumber) >= 2 {
        prefix2 := cardNumber[:2]
        if (prefix2 == "34" || prefix2 == "37") && len(cardNumber) == 15 {
            return "Amex"
        }
    }
    
    // Discover: starts with 6011, 622126-622925, 644-649, or 65
    if len(cardNumber) >= 4 {
        prefix4 := cardNumber[:4]
        prefix2 := cardNumber[:2]
        prefix3 := cardNumber[:3]
        
        if prefix4 == "6011" || prefix2 == "65" {
            if len(cardNumber) == 16 {
                return "Discover"
            }
        }
        
        if len(cardNumber) >= 6 {
            prefix6 := cardNumber[:6]
            if prefix6 >= "622126" && prefix6 <= "622925" {
                return "Discover"
            }
        }
        
        if prefix3 >= "644" && prefix3 <= "649" {
            if len(cardNumber) == 16 {
                return "Discover"
            }
        }
    }
    
    return "Unknown"
}

// isValidLuhn validates a card number using the Luhn algorithm
func isValidLuhn(cardNumber string) bool {
    // Remove spaces and dashes
    cardNumber = strings.ReplaceAll(strings.ReplaceAll(cardNumber, " ", ""), "-", "")
    
    if len(cardNumber) == 0 {
        return false
    }
    
    sum := 0
    alternate := false
    
    // Process from right to left
    for i := len(cardNumber) - 1; i >= 0; i-- {
        digit := int(cardNumber[i] - '0')
        if digit < 0 || digit > 9 {
            return false
        }
        
        if alternate {
            digit *= 2
            if digit > 9 {
                digit = digit%10 + digit/10
            }
        }
        
        sum += digit
        alternate = !alternate
    }
    
    return sum%10 == 0
}

// encryptCardNumber encrypts card data using the appropriate method
func (ut *UnifiedTokenizer) encryptCardNumber(data string) ([]byte, error) {
    if ut.useKEKDEK && ut.keyManager != nil {
        // Use KEK/DEK encryption
        encrypted, _, err := ut.keyManager.EncryptData([]byte(data))
        return encrypted, err
    } else {
        // Use legacy Fernet encryption
        return fernet.EncryptAndSign([]byte(data), ut.encryptionKey)
    }
}

// decryptCardNumber decrypts card data using the appropriate method
func (ut *UnifiedTokenizer) decryptCardNumber(encryptedData []byte) (string, error) {
    if ut.useKEKDEK && ut.keyManager != nil {
        // Try KEK/DEK decryption first
        decrypted, err := ut.keyManager.DecryptData(encryptedData, "")
        if err == nil {
            return string(decrypted), nil
        }
        // Fall back to legacy if KEK/DEK fails
    }
    
    // Use legacy Fernet decryption
    decrypted := fernet.VerifyAndDecrypt(encryptedData, 0, []*fernet.Key{ut.encryptionKey})
    if decrypted == nil {
        return "", fmt.Errorf("fernet decryption failed")
    }
    return string(decrypted), nil
}

func (ut *UnifiedTokenizer) storeCard(token, cardNumber string) error {
    var encrypted []byte
    var keyID string
    var err error
    
    // Detect card type
    cardType := detectCardType(cardNumber)
    
    if ut.useKEKDEK && ut.keyManager != nil {
        // Use KEK/DEK encryption
        encrypted, keyID, err = ut.keyManager.EncryptData([]byte(cardNumber))
        if err != nil {
            return fmt.Errorf("KEK/DEK encryption failed: %v", err)
        }
    } else {
        // Use legacy Fernet encryption
        encrypted, err = fernet.EncryptAndSign([]byte(cardNumber), ut.encryptionKey)
        if err != nil {
            return fmt.Errorf("encryption failed: %v", err)
        }
    }
    
    if ut.useKEKDEK && keyID != "" {
        _, err = ut.db.Exec(`
            INSERT INTO credit_cards (token, card_number_encrypted, card_type, last_four_digits, first_six_digits, 
                                     expiry_month, expiry_year, created_at, is_active, encryption_key_id)
            VALUES (?, ?, ?, ?, ?, 12, 2025, NOW(), TRUE, ?)
        `, token, encrypted, cardType, cardNumber[len(cardNumber)-4:], cardNumber[:6], keyID)
    } else {
        _, err = ut.db.Exec(`
            INSERT INTO credit_cards (token, card_number_encrypted, card_type, last_four_digits, first_six_digits, 
                                     expiry_month, expiry_year, created_at, is_active)
            VALUES (?, ?, ?, ?, ?, 12, 2025, NOW(), TRUE)
        `, token, encrypted, cardType, cardNumber[len(cardNumber)-4:], cardNumber[:6])
    }
    
    if err == nil {
        _, _ = ut.db.Exec(`
            INSERT INTO token_requests (token, request_type, source_ip, destination_url, response_status)
            VALUES (?, 'tokenize', '127.0.0.1', '', 200)
        `, token)
    }
    
    return err
}

func (ut *UnifiedTokenizer) retrieveCard(token string) string {
    if ut.debug {
        log.Printf("DEBUG: retrieveCard called with token: %s", token)
    }
    
    var encryptedCard []byte
    var keyID sql.NullString
    
    err := ut.db.QueryRow(`
        SELECT card_number_encrypted, encryption_key_id FROM credit_cards 
        WHERE token = ? AND is_active = TRUE
    `, token).Scan(&encryptedCard, &keyID)
    
    if err != nil {
        if err == sql.ErrNoRows {
            if ut.debug {
                log.Printf("DEBUG: Token not found in database: %s", token)
            }
        } else {
            log.Printf("Database error: %v", err)
        }
        return ""
    }
    
    var cardBytes []byte
    
    if ut.useKEKDEK && ut.keyManager != nil && keyID.Valid && keyID.String != "" {
        // Use KEK/DEK decryption
        cardBytes, err = ut.keyManager.DecryptData(encryptedCard, keyID.String)
        if err != nil {
            log.Printf("Failed to decrypt card with KEK/DEK for token %s: %v", token, err)
            return ""
        }
    } else {
        // Use legacy Fernet decryption
        cardBytes = fernet.VerifyAndDecrypt(encryptedCard, 0, []*fernet.Key{ut.encryptionKey})
        if cardBytes == nil {
            log.Printf("Failed to decrypt card for token %s", token)
            return ""
        }
    }
    
    _, _ = ut.db.Exec(`
        INSERT INTO token_requests (token, request_type, source_ip, destination_url, response_status)
        VALUES (?, 'detokenize', '127.0.0.1', '', 200)
    `, token)
    
    return string(cardBytes)
}

// API Handlers
func (ut *UnifiedTokenizer) handleAPIHealth(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (ut *UnifiedTokenizer) authenticateAPIRequest(r *http.Request) bool {
    apiKey := r.Header.Get("X-API-Key")
    if apiKey == "" {
        return false
    }
    
    var count int
    err := ut.db.QueryRow(`
        SELECT COUNT(*) FROM api_keys 
        WHERE api_key = ? AND is_active = TRUE
    `, apiKey).Scan(&count)
    
    return err == nil && count > 0
}

func (ut *UnifiedTokenizer) handleAPIListTokens(w http.ResponseWriter, r *http.Request) {
    // Permission check is handled by requirePermission middleware
    
    rows, err := ut.db.Query(`
        SELECT token, card_type, last_four_digits, first_six_digits, 
               created_at, is_active
        FROM credit_cards
        ORDER BY created_at DESC
        LIMIT 100
    `)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Internal server error"})
        return
    }
    defer rows.Close()
    
    tokens := []map[string]interface{}{}
    for rows.Next() {
        var token, cardType, lastFour, firstSix string
        var createdAt sql.NullTime
        var isActive bool
        
        var cardTypeNull sql.NullString
        if err := rows.Scan(&token, &cardTypeNull, &lastFour, &firstSix, &createdAt, &isActive); err != nil {
            log.Printf("Error scanning row: %v", err)
            continue
        }
        
        if cardTypeNull.Valid {
            cardType = cardTypeNull.String
        }
        
        tokenData := map[string]interface{}{
            "token":      token,
            "card_type":  cardType,
            "last_four":  lastFour,
            "first_six":  firstSix,
            "is_active":  isActive,
        }
        
        if createdAt.Valid {
            tokenData["created_at"] = createdAt.Time.Format(time.RFC3339)
        }
        
        tokens = append(tokens, tokenData)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{"tokens": tokens})
}

func (ut *UnifiedTokenizer) handleAPIGetToken(w http.ResponseWriter, r *http.Request) {
    // Permission check is handled by requirePermission middleware
    
    // Extract token from URL path
    token := strings.TrimPrefix(r.URL.Path, "/api/v1/tokens/")
    if token == "" {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Token required"})
        return
    }
    
    var cardType, lastFour, firstSix string
    var createdAt sql.NullTime
    var isActive bool
    var cardTypeNull sql.NullString
    
    err := ut.db.QueryRow(`
        SELECT card_type, last_four_digits, first_six_digits, 
               created_at, is_active
        FROM credit_cards
        WHERE token = ?
    `, token).Scan(&cardTypeNull, &lastFour, &firstSix, &createdAt, &isActive)
    
    if err == sql.ErrNoRows {
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(map[string]string{"error": "Token not found"})
        return
    } else if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Internal server error"})
        return
    }
    
    if cardTypeNull.Valid {
        cardType = cardTypeNull.String
    }
    
    result := map[string]interface{}{
        "token":      token,
        "card_type":  cardType,
        "last_four":  lastFour,
        "first_six":  firstSix,
        "is_active":  isActive,
    }
    
    if createdAt.Valid {
        result["created_at"] = createdAt.Time.Format(time.RFC3339)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(result)
}

func (ut *UnifiedTokenizer) handleAPIRevokeToken(w http.ResponseWriter, r *http.Request) {
    // Permission check is handled by requirePermission middleware
    
    token := strings.TrimPrefix(r.URL.Path, "/api/v1/tokens/")
    
    result, err := ut.db.Exec(`
        UPDATE credit_cards 
        SET is_active = FALSE 
        WHERE token = ?
    `, token)
    
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Internal server error"})
        return
    }
    
    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(map[string]string{"error": "Token not found"})
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "Token revoked successfully"})
}

func (ut *UnifiedTokenizer) handleAPIStats(w http.ResponseWriter, r *http.Request) {
    // Permission check is handled by requirePermission middleware
    
    // Get active token count
    var activeTokens int
    ut.db.QueryRow("SELECT COUNT(*) FROM credit_cards WHERE is_active = TRUE").Scan(&activeTokens)
    
    // Get request stats
    rows, err := ut.db.Query(`
        SELECT request_type, COUNT(*) as count
        FROM token_requests
        WHERE request_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY request_type
    `)
    
    requestStats := make(map[string]int)
    if err == nil {
        defer rows.Close()
        for rows.Next() {
            var reqType string
            var count int
            if err := rows.Scan(&reqType, &count); err == nil {
                requestStats[reqType] = count
            }
        }
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "active_tokens": activeTokens,
        "requests_24h":  requestStats,
    })
}

// Additional API endpoints for GUI/CLI

func (ut *UnifiedTokenizer) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
    // Get user ID from request context (set by requirePermission middleware)
    userID := r.Header.Get("X-User-ID")
    if userID == "" {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "User context not found"})
        return
    }
    
    var req struct {
        ClientName  string   `json:"client_name"`
        Permissions []string `json:"permissions,omitempty"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
        return
    }
    
    if req.ClientName == "" {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "client_name is required"})
        return
    }
    
    // Generate API key
    apiKey := "ts_" + generateRandomID()
    secretHash := "hash_" + generateRandomID() // In production, use proper hashing
    
    permissions, _ := json.Marshal(req.Permissions)
    
    _, err := ut.db.Exec(`
        INSERT INTO api_keys (api_key, api_secret_hash, client_name, permissions, is_active, user_id, created_by)
        VALUES (?, ?, ?, ?, TRUE, ?, ?)
    `, apiKey, secretHash, req.ClientName, permissions, userID, userID)
    
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create API key"})
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "api_key":     apiKey,
        "client_name": req.ClientName,
        "permissions": req.Permissions,
        "created_at":  time.Now().Format(time.RFC3339),
    })
}

func (ut *UnifiedTokenizer) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
    // Permission check is handled by requirePermission middleware
    
    rows, err := ut.db.Query(`
        SELECT api_key, client_name, permissions, is_active, created_at, last_used_at
        FROM api_keys
        ORDER BY created_at DESC
    `)
    
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
        return
    }
    defer rows.Close()
    
    var apiKeys []map[string]interface{}
    
    for rows.Next() {
        var apiKey, clientName string
        var permissions sql.NullString
        var isActive bool
        var createdAt time.Time
        var lastUsedAt sql.NullTime
        
        err := rows.Scan(&apiKey, &clientName, &permissions, &isActive, &createdAt, &lastUsedAt)
        if err != nil {
            continue
        }
        
        keyInfo := map[string]interface{}{
            "api_key":     apiKey,
            "client_name": clientName,
            "is_active":   isActive,
            "created_at":  createdAt.Format(time.RFC3339),
        }
        
        if permissions.Valid {
            var perms []string
            json.Unmarshal([]byte(permissions.String), &perms)
            keyInfo["permissions"] = perms
        }
        
        if lastUsedAt.Valid {
            keyInfo["last_used_at"] = lastUsedAt.Time.Format(time.RFC3339)
        }
        
        apiKeys = append(apiKeys, keyInfo)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "api_keys": apiKeys,
        "total":    len(apiKeys),
    })
}

func (ut *UnifiedTokenizer) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
    // Permission check is handled by requirePermission middleware
    
    apiKey := strings.TrimPrefix(r.URL.Path, "/api/v1/api-keys/")
    
    result, err := ut.db.Exec(`
        UPDATE api_keys SET is_active = FALSE WHERE api_key = ?
    `, apiKey)
    
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
        return
    }
    
    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(map[string]string{"error": "API key not found"})
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "API key revoked successfully"})
}

func (ut *UnifiedTokenizer) handleGetActivity(w http.ResponseWriter, r *http.Request) {
    // Permission check is handled by requirePermission middleware
    
    // Get query parameters
    limit := 50
    if l := r.URL.Query().Get("limit"); l != "" {
        if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
            limit = parsed
        }
    }
    
    rows, err := ut.db.Query(`
        SELECT tr.token, tr.request_type, tr.source_ip, tr.destination_url, 
               tr.request_timestamp, tr.response_status, cc.last_four_digits
        FROM token_requests tr
        LEFT JOIN credit_cards cc ON tr.token = cc.token
        ORDER BY tr.request_timestamp DESC
        LIMIT ?
    `, limit)
    
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
        return
    }
    defer rows.Close()
    
    var activities []map[string]interface{}
    
    for rows.Next() {
        var token, requestType, sourceIP, destinationURL string
        var requestTimestamp time.Time
        var responseStatus sql.NullInt64
        var lastFour sql.NullString
        
        err := rows.Scan(&token, &requestType, &sourceIP, &destinationURL, 
                        &requestTimestamp, &responseStatus, &lastFour)
        if err != nil {
            continue
        }
        
        activity := map[string]interface{}{
            "token":       token,
            "type":        requestType,
            "source_ip":   sourceIP,
            "destination": destinationURL,
            "timestamp":   requestTimestamp.Format(time.RFC3339),
        }
        
        if responseStatus.Valid {
            activity["status"] = responseStatus.Int64
        }
        
        if lastFour.Valid {
            activity["card_last_four"] = lastFour.String
        }
        
        activities = append(activities, activity)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "activities": activities,
        "total":      len(activities),
    })
}

func (ut *UnifiedTokenizer) handleSearchTokens(w http.ResponseWriter, r *http.Request) {
    // Permission check is handled by requirePermission middleware
    
    var req struct {
        LastFour  string `json:"last_four,omitempty"`
        CardType  string `json:"card_type,omitempty"`
        DateFrom  string `json:"date_from,omitempty"`
        DateTo    string `json:"date_to,omitempty"`
        IsActive  *bool  `json:"is_active,omitempty"`
        Limit     int    `json:"limit,omitempty"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
        return
    }
    
    if req.Limit <= 0 || req.Limit > 1000 {
        req.Limit = 100
    }
    
    // Build dynamic query
    query := `SELECT token, card_type, last_four_digits, first_six_digits, 
                     created_at, is_active FROM credit_cards WHERE 1=1`
    args := []interface{}{}
    
    if req.LastFour != "" {
        query += " AND last_four_digits = ?"
        args = append(args, req.LastFour)
    }
    
    if req.CardType != "" {
        query += " AND card_type = ?"
        args = append(args, req.CardType)
    }
    
    if req.DateFrom != "" {
        query += " AND created_at >= ?"
        args = append(args, req.DateFrom)
    }
    
    if req.DateTo != "" {
        query += " AND created_at <= ?"
        args = append(args, req.DateTo)
    }
    
    if req.IsActive != nil {
        query += " AND is_active = ?"
        args = append(args, *req.IsActive)
    }
    
    query += " ORDER BY created_at DESC LIMIT ?"
    args = append(args, req.Limit)
    
    rows, err := ut.db.Query(query, args...)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
        return
    }
    defer rows.Close()
    
    var tokens []map[string]interface{}
    
    for rows.Next() {
        var token, lastFour, firstSix string
        var cardType sql.NullString
        var createdAt time.Time
        var isActive bool
        
        err := rows.Scan(&token, &cardType, &lastFour, &firstSix, &createdAt, &isActive)
        if err != nil {
            continue
        }
        
        tokenInfo := map[string]interface{}{
            "token":      token,
            "last_four":  lastFour,
            "first_six":  firstSix,
            "created_at": createdAt.Format(time.RFC3339),
            "is_active":  isActive,
        }
        
        if cardType.Valid {
            tokenInfo["card_type"] = cardType.String
        }
        
        tokens = append(tokens, tokenInfo)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "tokens": tokens,
        "total":  len(tokens),
    })
}

func (ut *UnifiedTokenizer) handleGetVersion(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "version":     "1.0.0-prototype",
        "build_time":  time.Now().Format(time.RFC3339),
        "token_format": ut.tokenFormat,
        "kek_dek_enabled": ut.useKEKDEK,
        "features": []string{"tokenization", "detokenization", "api", "icap"},
    })
}

func (ut *UnifiedTokenizer) startHTTPServer() {
    http.HandleFunc("/", ut.handleTokenize)
    
    log.Printf("Starting HTTP tokenization server on port %s", ut.httpPort)
    if err := http.ListenAndServe(":"+ut.httpPort, nil); err != nil {
        log.Fatalf("HTTP server failed: %v", err)
    }
}

// CORS middleware
func (ut *UnifiedTokenizer) corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Set CORS headers
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key, X-Admin-Secret, Authorization")
        w.Header().Set("Access-Control-Max-Age", "3600")
        
        // Handle preflight OPTIONS requests
        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusOK)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}

// Rate limiting middleware for authentication endpoints
func (ut *UnifiedTokenizer) rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Skip rate limiting in test mode
        if testMode := getEnv("TEST_MODE", "false"); testMode == "true" {
            next(w, r)
            return
        }
        
        // Get client IP
        clientIP := r.RemoteAddr
        if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
            clientIP = strings.TrimSpace(strings.Split(forwarded, ",")[0])
        }
        
        // Remove port from IP if present
        if host, _, err := net.SplitHostPort(clientIP); err == nil {
            clientIP = host
        }
        
        // Check rate limit
        if !ut.authRateLimiter.IsAllowed(clientIP) {
            // Log security event for rate limiting
            ut.logSecurityEvent(SecurityEvent{
                EventType: "rate_limit_exceeded",
                Severity:  "medium",
                IPAddress: clientIP,
                UserAgent: r.UserAgent(),
                Endpoint:  r.URL.Path,
                Details: map[string]interface{}{
                    "method": r.Method,
                    "limit": "5 attempts per 15 minutes",
                },
            })
            
            log.Printf("Rate limit exceeded for IP: %s on endpoint: %s", clientIP, r.URL.Path)
            w.WriteHeader(http.StatusTooManyRequests)
            json.NewEncoder(w).Encode(map[string]interface{}{
                "error": "Rate limit exceeded. Too many authentication attempts. Please try again later.",
                "retry_after": "15 minutes",
            })
            return
        }
        
        next(w, r)
    }
}

// Input validation middleware
func (ut *UnifiedTokenizer) validationMiddleware(endpoint string) func(http.HandlerFunc) http.HandlerFunc {
    return func(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
            // Get client IP for logging
            clientIP := r.RemoteAddr
            if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
                clientIP = strings.TrimSpace(strings.Split(forwarded, ",")[0])
            }
            if host, _, err := net.SplitHostPort(clientIP); err == nil {
                clientIP = host
            }
            
            // Check if we have validation config for this endpoint
            config, hasConfig := ut.validationConfigs[endpoint]
            
            // Check request size limit
            maxSize := int64(10 * 1024 * 1024) // Default 10MB max
            if hasConfig && config.MaxRequestSize > 0 {
                maxSize = config.MaxRequestSize
            }
            
            // Limit request body size
            r.Body = http.MaxBytesReader(w, r.Body, maxSize)
            
            // Check allowed methods
            if hasConfig && len(config.AllowedMethods) > 0 {
                allowed := false
                for _, method := range config.AllowedMethods {
                    if r.Method == method {
                        allowed = true
                        break
                    }
                }
                if !allowed {
                    ut.logSecurityEvent(SecurityEvent{
                        EventType: "invalid_http_method",
                        Severity:  "medium",
                        IPAddress: clientIP,
                        UserAgent: r.UserAgent(),
                        Endpoint:  r.URL.Path,
                        Details: map[string]interface{}{
                            "method": r.Method,
                            "allowed_methods": config.AllowedMethods,
                        },
                    })
                    w.WriteHeader(http.StatusMethodNotAllowed)
                    json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
                    return
                }
            }
            
            // Check Content-Type for requests with body
            if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
                contentType := r.Header.Get("Content-Type")
                if !strings.Contains(contentType, "application/json") {
                    ut.logSecurityEvent(SecurityEvent{
                        EventType: "invalid_content_type",
                        Severity:  "low",
                        IPAddress: clientIP,
                        UserAgent: r.UserAgent(),
                        Endpoint:  r.URL.Path,
                        Details: map[string]interface{}{
                            "content_type": contentType,
                            "expected": "application/json",
                        },
                    })
                    w.WriteHeader(http.StatusUnsupportedMediaType)
                    json.NewEncoder(w).Encode(map[string]string{"error": "Content-Type must be application/json"})
                    return
                }
                
                // Parse and validate JSON body
                if hasConfig && len(config.Rules) > 0 {
                    var requestData map[string]interface{}
                    
                    // Read and parse request body
                    bodyBytes, err := io.ReadAll(r.Body)
                    if err != nil {
                        ut.logSecurityEvent(SecurityEvent{
                            EventType: "request_body_read_error",
                            Severity:  "medium",
                            IPAddress: clientIP,
                            UserAgent: r.UserAgent(),
                            Endpoint:  r.URL.Path,
                            Details: map[string]interface{}{
                                "error": err.Error(),
                            },
                        })
                        w.WriteHeader(http.StatusBadRequest)
                        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read request body"})
                        return
                    }
                    
                    // Restore body for next handler
                    r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
                    
                    // Parse JSON
                    if len(bodyBytes) > 0 {
                        if err := json.Unmarshal(bodyBytes, &requestData); err != nil {
                            ut.logSecurityEvent(SecurityEvent{
                                EventType: "invalid_json",
                                Severity:  "medium",
                                IPAddress: clientIP,
                                UserAgent: r.UserAgent(),
                                Endpoint:  r.URL.Path,
                                Details: map[string]interface{}{
                                    "error": err.Error(),
                                },
                            })
                            w.WriteHeader(http.StatusBadRequest)
                            json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON format"})
                            return
                        }
                        
                        // Validate request data
                        validationResult := ut.validateRequest(endpoint, requestData)
                        if !validationResult.Valid {
                            ut.logSecurityEvent(SecurityEvent{
                                EventType: "validation_failed",
                                Severity:  "medium",
                                IPAddress: clientIP,
                                UserAgent: r.UserAgent(),
                                Endpoint:  r.URL.Path,
                                Details: map[string]interface{}{
                                    "validation_errors": validationResult.Errors,
                                    "field_count": len(validationResult.Errors),
                                },
                            })
                            w.WriteHeader(http.StatusBadRequest)
                            json.NewEncoder(w).Encode(map[string]interface{}{
                                "error": "Validation failed",
                                "validation_errors": validationResult.Errors,
                            })
                            return
                        }
                        
                        // Store sanitized data in request context for handler use
                        validatedDataBytes, _ := json.Marshal(validationResult.Data)
                        r.Body = io.NopCloser(bytes.NewBuffer(validatedDataBytes))
                    }
                }
            }
            
            // Validate URL parameters for token endpoints
            if strings.Contains(r.URL.Path, "/tokens/") && !strings.HasSuffix(r.URL.Path, "/tokens") {
                pathParts := strings.Split(r.URL.Path, "/")
                for i, part := range pathParts {
                    if part == "tokens" && i+1 < len(pathParts) {
                        tokenID := pathParts[i+1]
                        if tokenID != "search" { // Skip search endpoint
                            tokenData := map[string]interface{}{"token": tokenID}
                            if _, exists := ut.validationConfigs["token_id"]; exists {
                                validationResult := ut.validateRequest("token_id", tokenData)
                                if !validationResult.Valid {
                                    ut.logSecurityEvent(SecurityEvent{
                                        EventType: "invalid_token_format",
                                        Severity:  "medium",
                                        IPAddress: clientIP,
                                        UserAgent: r.UserAgent(),
                                        Endpoint:  r.URL.Path,
                                        Details: map[string]interface{}{
                                            "token_id": tokenID,
                                            "validation_errors": validationResult.Errors,
                                        },
                                    })
                                    w.WriteHeader(http.StatusBadRequest)
                                    json.NewEncoder(w).Encode(map[string]interface{}{
                                        "error": "Invalid token format",
                                        "validation_errors": validationResult.Errors,
                                    })
                                    return
                                }
                            }
                        }
                        break
                    }
                }
            }
            
            // Continue to next handler
            next(w, r)
        }
    }
}

// Audit logging methods
func (ut *UnifiedTokenizer) logAuditEvent(event AuditEvent) {
    detailsJSON, _ := json.Marshal(event.Details)
    
    _, err := ut.db.Exec(`
        INSERT INTO user_audit_log (user_id, action, resource_type, resource_id, details, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `, event.UserID, event.Action, event.ResourceType, event.ResourceID, string(detailsJSON), event.IPAddress, event.UserAgent)
    
    if err != nil {
        log.Printf("Failed to log audit event: %v", err)
    }
}

func (ut *UnifiedTokenizer) logSecurityEvent(event SecurityEvent) {
    detailsJSON, _ := json.Marshal(event.Details)
    
    _, err := ut.db.Exec(`
        INSERT INTO security_audit_log (event_type, severity, user_id, username, ip_address, user_agent, endpoint, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, event.EventType, event.Severity, event.UserID, event.Username, event.IPAddress, event.UserAgent, event.Endpoint, string(detailsJSON))
    
    if err != nil {
        log.Printf("Failed to log security event: %v", err)
    }
    
    // Also log to application logs for immediate visibility
    if event.Severity == "high" || event.Severity == "critical" {
        log.Printf("SECURITY ALERT [%s]: %s from IP %s - %s", 
            strings.ToUpper(event.Severity), event.EventType, event.IPAddress, event.Endpoint)
    }
}

// Helper to extract client info from request
func (ut *UnifiedTokenizer) getClientInfo(r *http.Request) (string, string) {
    // Get client IP
    ipAddress := r.RemoteAddr
    if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
        ipAddress = strings.TrimSpace(strings.Split(forwarded, ",")[0])
    }
    
    // Remove port from IP if present
    if host, _, err := net.SplitHostPort(ipAddress); err == nil {
        ipAddress = host
    }
    
    userAgent := r.UserAgent()
    return ipAddress, userAgent
}

// Authentication handlers

func (ut *UnifiedTokenizer) handleLogin(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }
    
    var authReq AuthRequest
    if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
        return
    }
    
    // Get client info
    ipAddress, userAgent := ut.getClientInfo(r)
    
    // Authenticate user
    user, err := ut.authenticateUser(authReq.Username, authReq.Password)
    if err != nil {
        // Log failed login attempt
        ut.logSecurityEvent(SecurityEvent{
            EventType: "login_failed",
            Severity:  "medium",
            Username:  authReq.Username,
            IPAddress: ipAddress,
            UserAgent: userAgent,
            Endpoint:  r.URL.Path,
            Details: map[string]interface{}{
                "reason": err.Error(),
                "method": r.Method,
            },
        })
        
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
        return
    }
    
    // Create session
    session, err := ut.createSession(user, ipAddress, userAgent)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create session"})
        return
    }
    
    // Log successful login
    ut.logAuditEvent(AuditEvent{
        UserID:       user.UserID,
        Action:       "login_success",
        ResourceType: "session",
        ResourceID:   session.SessionID,
        IPAddress:    ipAddress,
        UserAgent:    userAgent,
        Details: map[string]interface{}{
            "session_duration": "24 hours",
            "method": r.Method,
        },
    })
    
    ut.logSecurityEvent(SecurityEvent{
        EventType: "login_success",
        Severity:  "info",
        UserID:    user.UserID,
        Username:  user.Username,
        IPAddress: ipAddress,
        UserAgent: userAgent,
        Endpoint:  r.URL.Path,
        Details: map[string]interface{}{
            "session_id": session.SessionID,
            "role": user.Role,
        },
    })
    
    // Set session cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "session_id",
        Value:    session.SessionID,
        Path:     "/",
        HttpOnly: true,
        Secure:   false, // Set to true in production with HTTPS
        SameSite: http.SameSiteLaxMode,
        Expires:  session.ExpiresAt,
    })
    
    // Check if password change is required (password_changed_at is zero)
    requirePasswordChange := user.PasswordChangedAt == nil || user.PasswordChangedAt.IsZero()
    
    // Return auth response
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(AuthResponse{
        SessionID:            session.SessionID,
        User:                 *user,
        ExpiresAt:            session.ExpiresAt,
        RequirePasswordChange: requirePasswordChange,
    })
}

func (ut *UnifiedTokenizer) handleLogout(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }
    
    // Get session ID
    var sessionID string
    cookie, err := r.Cookie("session_id")
    if err == nil {
        sessionID = cookie.Value
    }
    
    if sessionID == "" {
        auth := r.Header.Get("Authorization")
        if strings.HasPrefix(auth, "Bearer ") {
            sessionID = strings.TrimPrefix(auth, "Bearer ")
        }
    }
    
    if sessionID != "" {
        // Invalidate session
        ut.db.Exec(`
            UPDATE user_sessions 
            SET is_active = FALSE 
            WHERE session_id = ?
        `, sessionID)
    }
    
    // Clear cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "session_id",
        Value:    "",
        Path:     "/",
        HttpOnly: true,
        MaxAge:   -1,
    })
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

func (ut *UnifiedTokenizer) handleGetCurrentUser(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }
    
    // Get session ID
    var sessionID string
    cookie, err := r.Cookie("session_id")
    if err == nil {
        sessionID = cookie.Value
    }
    
    if sessionID == "" {
        auth := r.Header.Get("Authorization")
        if strings.HasPrefix(auth, "Bearer ") {
            sessionID = strings.TrimPrefix(auth, "Bearer ")
        }
    }
    
    if sessionID == "" {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Authentication required"})
        return
    }
    
    // Validate session
    session, err := ut.validateSession(sessionID)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(session.User)
}

func (ut *UnifiedTokenizer) handleChangePassword(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }

    // Get session ID from cookie or Authorization header
    sessionID := ""
    if cookie, err := r.Cookie("session_id"); err == nil {
        sessionID = cookie.Value
    } else if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
        sessionID = strings.TrimPrefix(auth, "Bearer ")
    }

    if sessionID == "" {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Authentication required"})
        return
    }

    // Validate session
    session, err := ut.validateSession(sessionID)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
        return
    }

    // Parse request body
    var req struct {
        CurrentPassword string `json:"current_password"`
        NewPassword     string `json:"new_password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
        return
    }

    // Validate input
    if req.CurrentPassword == "" || req.NewPassword == "" {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Current password and new password are required"})
        return
    }

    // Validate password strength
    if err := ut.validatePasswordStrength(req.NewPassword); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
        return
    }

    // Get current user's password hash from database
    var currentPasswordHash string
    err = ut.db.QueryRow("SELECT password_hash FROM users WHERE user_id = ?", session.User.UserID).Scan(&currentPasswordHash)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
        return
    }

    // Verify current password
    if err := bcrypt.CompareHashAndPassword([]byte(currentPasswordHash), []byte(req.CurrentPassword)); err != nil {
        // Log failed password change attempt
        ipAddress, userAgent := ut.getClientInfo(r)
        ut.logSecurityEvent(SecurityEvent{
            EventType: "password_change_failed",
            Severity:  "medium",
            UserID:    session.User.UserID,
            Username:  session.User.Username,
            IPAddress: ipAddress,
            UserAgent: userAgent,
            Endpoint:  r.URL.Path,
            Details: map[string]interface{}{
                "reason": "incorrect_current_password",
                "method": r.Method,
            },
        })
        
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Current password is incorrect"})
        return
    }

    // Hash new password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Password hashing failed"})
        return
    }

    // Update password in database
    _, err = ut.db.Exec(`
        UPDATE users 
        SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP 
        WHERE user_id = ?`,
        string(hashedPassword), session.User.UserID)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to update password"})
        return
    }

    // Log successful password change
    ipAddress, userAgent := ut.getClientInfo(r)
    ut.logAuditEvent(AuditEvent{
        UserID:       session.User.UserID,
        Action:       "password_change_success",
        ResourceType: "user",
        ResourceID:   session.User.UserID,
        IPAddress:    ipAddress,
        UserAgent:    userAgent,
        Details: map[string]interface{}{
            "method": r.Method,
        },
    })
    
    ut.logSecurityEvent(SecurityEvent{
        EventType: "password_change_success",
        Severity:  "info",
        UserID:    session.User.UserID,
        Username:  session.User.Username,
        IPAddress: ipAddress,
        UserAgent: userAgent,
        Endpoint:  r.URL.Path,
        Details: map[string]interface{}{
            "initiated_by": "user",
            "method": r.Method,
        },
    })

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "Password changed successfully"})
}

func (ut *UnifiedTokenizer) validatePasswordStrength(password string) error {
    if len(password) < 12 {
        return fmt.Errorf("password must be at least 12 characters long")
    }
    
    var hasUpper, hasLower, hasDigit, hasSpecial bool
    for _, char := range password {
        switch {
        case 'A' <= char && char <= 'Z':
            hasUpper = true
        case 'a' <= char && char <= 'z':
            hasLower = true
        case '0' <= char && char <= '9':
            hasDigit = true
        case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;':\",./<>?", char):
            hasSpecial = true
        }
    }
    
    var missing []string
    if !hasUpper {
        missing = append(missing, "uppercase letter")
    }
    if !hasLower {
        missing = append(missing, "lowercase letter")
    }
    if !hasDigit {
        missing = append(missing, "number")
    }
    if !hasSpecial {
        missing = append(missing, "special character")
    }
    
    if len(missing) > 0 {
        return fmt.Errorf("password must contain at least one %s", strings.Join(missing, ", "))
    }
    
    return nil
}

// User management handlers

func (ut *UnifiedTokenizer) handleListUsers(w http.ResponseWriter, r *http.Request) {
    rows, err := ut.db.Query(`
        SELECT user_id, username, email, full_name, role, permissions, 
               is_active, created_at, last_login_at
        FROM users
        ORDER BY created_at DESC
    `)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
        return
    }
    defer rows.Close()
    
    var users []User
    for rows.Next() {
        var user User
        var permissionsJSON []byte
        var lastLoginAt sql.NullTime
        
        err := rows.Scan(&user.UserID, &user.Username, &user.Email, &user.FullName,
            &user.Role, &permissionsJSON, &user.IsActive, &user.CreatedAt, &lastLoginAt)
        if err != nil {
            continue
        }
        
        json.Unmarshal(permissionsJSON, &user.Permissions)
        if lastLoginAt.Valid {
            user.LastLoginAt = &lastLoginAt.Time
        }
        
        users = append(users, user)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "users": users,
        "total": len(users),
    })
}

func (ut *UnifiedTokenizer) handleCreateUser(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Username    string   `json:"username"`
        Email       string   `json:"email"`
        Password    string   `json:"password"`
        FullName    string   `json:"full_name"`
        Role        string   `json:"role"`
        Permissions []string `json:"permissions"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
        return
    }
    
    // Validate required fields
    if req.Username == "" || req.Email == "" || req.Password == "" {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "username, email, and password are required"})
        return
    }
    
    // Validate role
    if req.Role == "" {
        req.Role = RoleViewer
    }
    if req.Role != RoleAdmin && req.Role != RoleOperator && req.Role != RoleViewer {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid role"})
        return
    }
    
    // Hash password
    passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to hash password"})
        return
    }
    
    // Set default permissions based on role if not provided
    if len(req.Permissions) == 0 {
        switch req.Role {
        case RoleAdmin:
            req.Permissions = []string{PermSystemAdmin}
        case RoleOperator:
            req.Permissions = []string{
                PermTokensRead, PermTokensWrite, PermTokensDelete,
                PermActivityRead, PermStatsRead,
            }
        case RoleViewer:
            req.Permissions = []string{
                PermTokensRead, PermActivityRead, PermStatsRead,
            }
        }
    }
    
    userID := "usr_" + generateRandomID()
    permissionsJSON, _ := json.Marshal(req.Permissions)
    createdBy := r.Header.Get("X-User-ID")
    
    _, err = ut.db.Exec(`
        INSERT INTO users (
            user_id, username, email, password_hash, full_name,
            role, permissions, is_active, is_email_verified, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, FALSE, ?)
    `, userID, req.Username, req.Email, string(passwordHash), req.FullName,
       req.Role, permissionsJSON, createdBy)
    
    if err != nil {
        if strings.Contains(err.Error(), "Duplicate") {
            w.WriteHeader(http.StatusConflict)
            json.NewEncoder(w).Encode(map[string]string{"error": "Username or email already exists"})
        } else {
            w.WriteHeader(http.StatusInternalServerError)
            json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create user"})
        }
        return
    }
    
    // Return created user
    user := User{
        UserID:      userID,
        Username:    req.Username,
        Email:       req.Email,
        FullName:    req.FullName,
        Role:        req.Role,
        Permissions: req.Permissions,
        IsActive:    true,
        CreatedAt:   time.Now(),
    }
    
    w.WriteHeader(http.StatusCreated)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(user)
}

// Card import handler
func (ut *UnifiedTokenizer) handleCardImport(w http.ResponseWriter, r *http.Request) {
    startTime := time.Now()
    
    // Get user ID from request context
    userID := r.Header.Get("X-User-ID")
    if userID == "" {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Authentication required"})
        return
    }
    
    // Parse request
    var req CardImportRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request format"})
        return
    }
    
    // Set defaults
    if req.DuplicateHandling == "" {
        req.DuplicateHandling = "skip"
    }
    if req.BatchSize == 0 {
        req.BatchSize = 100
    }
    
    // Generate import ID
    importID := "imp_" + generateRandomID()
    
    // Decode data
    dataBytes, err := base64.StdEncoding.DecodeString(req.Data)
    if err != nil {
        ut.logSecurityEvent(SecurityEvent{
            EventType: "invalid_import_data",
            Severity:  "medium",
            UserID:    userID,
            IPAddress: r.RemoteAddr,
            UserAgent: r.UserAgent(),
            Endpoint:  r.URL.Path,
            Details: map[string]interface{}{
                "error": "invalid base64 encoding",
                "import_id": importID,
            },
        })
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid data encoding"})
        return
    }
    
    // Parse cards based on format
    var cards []CardImportRecord
    switch req.Format {
    case "json":
        if err := json.Unmarshal(dataBytes, &cards); err != nil {
            w.WriteHeader(http.StatusBadRequest)
            json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON format"})
            return
        }
    case "csv":
        cards, err = ut.parseCSVCards(dataBytes)
        if err != nil {
            w.WriteHeader(http.StatusBadRequest)
            json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("CSV parse error: %v", err)})
            return
        }
    default:
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Unsupported format. Use 'json' or 'csv'"})
        return
    }
    
    // Validate we have cards
    if len(cards) == 0 {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "No cards found in import data"})
        return
    }
    
    // Limit the number of cards per import
    maxCards := 10000
    if len(cards) > maxCards {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "error": fmt.Sprintf("Too many cards. Maximum %d cards per import", maxCards),
            "provided": len(cards),
            "maximum": maxCards,
        })
        return
    }
    
    // Process the import
    result := ut.processCardImport(importID, userID, cards, req)
    result.ProcessingTime = time.Since(startTime).String()
    
    // Log import completion
    ut.logAuditEvent(AuditEvent{
        UserID:       userID,
        Action:       "cards_import",
        ResourceType: "cards",
        ResourceID:   importID,
        IPAddress:    r.RemoteAddr,
        UserAgent:    r.UserAgent(),
        Details: map[string]interface{}{
            "total_records": result.TotalRecords,
            "successful_imports": result.SuccessfulImports,
            "failed_imports": result.FailedImports,
            "duplicates": result.Duplicates,
            "processing_time": result.ProcessingTime,
            "format": req.Format,
            "duplicate_handling": req.DuplicateHandling,
        },
    })
    
    // Return result
    if result.FailedImports > 0 && result.SuccessfulImports == 0 {
        w.WriteHeader(http.StatusBadRequest)
    } else if result.FailedImports > 0 {
        w.WriteHeader(http.StatusPartialContent)
    } else {
        w.WriteHeader(http.StatusOK)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(result)
}

// parseCSVCards parses CSV data into CardImportRecord slice
func (ut *UnifiedTokenizer) parseCSVCards(data []byte) ([]CardImportRecord, error) {
    lines := strings.Split(string(data), "\n")
    if len(lines) < 2 {
        return nil, fmt.Errorf("CSV must have at least a header and one data row")
    }
    
    // Parse header
    header := strings.Split(strings.TrimSpace(lines[0]), ",")
    headerMap := make(map[string]int)
    for i, col := range header {
        headerMap[strings.TrimSpace(strings.Trim(col, "\""))] = i
    }
    
    // Required columns
    required := []string{"card_number", "expiry_month", "expiry_year"}
    for _, req := range required {
        if _, exists := headerMap[req]; !exists {
            return nil, fmt.Errorf("missing required column: %s", req)
        }
    }
    
    var cards []CardImportRecord
    for i, line := range lines[1:] {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        
        cols := strings.Split(line, ",")
        if len(cols) < len(required) {
            return nil, fmt.Errorf("row %d: insufficient columns", i+2)
        }
        
        // Clean and parse columns
        for j := range cols {
            cols[j] = strings.TrimSpace(strings.Trim(cols[j], "\""))
        }
        
        card := CardImportRecord{}
        
        // Required fields
        card.CardNumber = cols[headerMap["card_number"]]
        
        if monthStr := cols[headerMap["expiry_month"]]; monthStr != "" {
            if month, err := strconv.Atoi(monthStr); err == nil {
                card.ExpiryMonth = month
            } else {
                return nil, fmt.Errorf("row %d: invalid expiry_month: %s", i+2, monthStr)
            }
        }
        
        if yearStr := cols[headerMap["expiry_year"]]; yearStr != "" {
            if year, err := strconv.Atoi(yearStr); err == nil {
                card.ExpiryYear = year
            } else {
                return nil, fmt.Errorf("row %d: invalid expiry_year: %s", i+2, yearStr)
            }
        }
        
        // Optional fields
        if idx, exists := headerMap["card_holder"]; exists && idx < len(cols) {
            card.CardHolder = cols[idx]
        }
        if idx, exists := headerMap["external_id"]; exists && idx < len(cols) {
            card.ExternalID = cols[idx]
        }
        if idx, exists := headerMap["metadata"]; exists && idx < len(cols) {
            card.Metadata = cols[idx]
        }
        
        cards = append(cards, card)
    }
    
    return cards, nil
}

// processCardImport processes a batch of cards for import
func (ut *UnifiedTokenizer) processCardImport(importID, userID string, cards []CardImportRecord, req CardImportRequest) CardImportResult {
    result := CardImportResult{
        TotalRecords:    len(cards),
        ImportID:        importID,
        Status:          "completed",
        TokensGenerated: make([]CardImportSuccess, 0),
        Errors:          make([]CardImportError, 0),
    }
    
    // Process in batches
    batchSize := req.BatchSize
    if batchSize > 1000 {
        batchSize = 1000
    }
    
    for i := 0; i < len(cards); i += batchSize {
        end := i + batchSize
        if end > len(cards) {
            end = len(cards)
        }
        
        batch := cards[i:end]
        ut.processBatch(batch, i, &result, req)
    }
    
    // Update final status
    if result.FailedImports > 0 && result.SuccessfulImports == 0 {
        result.Status = "failed"
    } else if result.FailedImports > 0 {
        result.Status = "partial"
    }
    
    return result
}

// processBatch processes a single batch of cards
func (ut *UnifiedTokenizer) processBatch(batch []CardImportRecord, startIndex int, result *CardImportResult, req CardImportRequest) {
    // Start transaction for batch
    tx, err := ut.db.Begin()
    if err != nil {
        for j, card := range batch {
            result.Errors = append(result.Errors, CardImportError{
                RecordIndex: startIndex + j,
                ExternalID:  card.ExternalID,
                CardNumber:  maskCardNumber(card.CardNumber),
                Error:       "Database transaction error",
                Reason:      err.Error(),
            })
            result.FailedImports++
        }
        return
    }
    
    batchSuccess := true
    
    for j, card := range batch {
        recordIndex := startIndex + j
        result.ProcessedRecords++
        
        // Validate card
        if err := ut.validateCardRecord(card); err != nil {
            result.Errors = append(result.Errors, CardImportError{
                RecordIndex: recordIndex,
                ExternalID:  card.ExternalID,
                CardNumber:  maskCardNumber(card.CardNumber),
                Error:       "Validation failed",
                Reason:      err.Error(),
            })
            result.FailedImports++
            batchSuccess = false
            continue
        }
        
        // Check for duplicates
        exists, existingToken, err := ut.checkCardExists(card.CardNumber)
        if err != nil {
            result.Errors = append(result.Errors, CardImportError{
                RecordIndex: recordIndex,
                ExternalID:  card.ExternalID,
                CardNumber:  maskCardNumber(card.CardNumber),
                Error:       "Duplicate check failed",
                Reason:      err.Error(),
            })
            result.FailedImports++
            batchSuccess = false
            continue
        }
        
        if exists {
            result.Duplicates++
            switch req.DuplicateHandling {
            case "skip":
                // Skip this card
                continue
            case "error":
                result.Errors = append(result.Errors, CardImportError{
                    RecordIndex: recordIndex,
                    ExternalID:  card.ExternalID,
                    CardNumber:  maskCardNumber(card.CardNumber),
                    Error:       "Duplicate card",
                    Reason:      fmt.Sprintf("Card already exists with token: %s", existingToken),
                })
                result.FailedImports++
                batchSuccess = false
                continue
            case "overwrite":
                // Continue with processing, will update existing record
            }
        }
        
        // Tokenize card
        token, cardType, err := ut.tokenizeCardForImport(card, tx)
        if err != nil {
            result.Errors = append(result.Errors, CardImportError{
                RecordIndex: recordIndex,
                ExternalID:  card.ExternalID,
                CardNumber:  maskCardNumber(card.CardNumber),
                Error:       "Tokenization failed",
                Reason:      err.Error(),
            })
            result.FailedImports++
            batchSuccess = false
            continue
        }
        
        result.SuccessfulImports++
        result.TokensGenerated = append(result.TokensGenerated, CardImportSuccess{
            RecordIndex: recordIndex,
            ExternalID:  card.ExternalID,
            Token:       token,
            CardType:    cardType,
            LastFour:    card.CardNumber[len(card.CardNumber)-4:],
        })
    }
    
    // Commit or rollback transaction
    if batchSuccess {
        if err := tx.Commit(); err != nil {
            // If commit fails, mark all cards in this batch as failed
            for j, card := range batch {
                result.Errors = append(result.Errors, CardImportError{
                    RecordIndex: startIndex + j,
                    ExternalID:  card.ExternalID,
                    CardNumber:  maskCardNumber(card.CardNumber),
                    Error:       "Transaction commit failed",
                    Reason:      err.Error(),
                })
                result.FailedImports++
            }
            // Remove successful imports from this batch
            result.SuccessfulImports -= len(batch)
            result.TokensGenerated = result.TokensGenerated[:len(result.TokensGenerated)-len(batch)]
        }
    } else {
        tx.Rollback()
    }
}

// Helper functions for card import

// maskCardNumber masks a credit card number for logging (shows only last 4 digits)
func maskCardNumber(cardNumber string) string {
    if len(cardNumber) < 4 {
        return "****"
    }
    return "****" + cardNumber[len(cardNumber)-4:]
}

// validateCardRecord validates a single card record
func (ut *UnifiedTokenizer) validateCardRecord(card CardImportRecord) error {
    // Validate card number
    if card.CardNumber == "" {
        return fmt.Errorf("card number is required")
    }
    
    // Remove spaces and dashes
    cleanCard := strings.ReplaceAll(strings.ReplaceAll(card.CardNumber, " ", ""), "-", "")
    if len(cleanCard) < 13 || len(cleanCard) > 19 {
        return fmt.Errorf("card number must be between 13 and 19 digits")
    }
    
    // Check if all characters are digits
    for _, char := range cleanCard {
        if char < '0' || char > '9' {
            return fmt.Errorf("card number must contain only digits")
        }
    }
    
    // Validate using Luhn algorithm
    if !isValidLuhn(cleanCard) {
        return fmt.Errorf("card number fails Luhn algorithm validation")
    }
    
    // Validate expiry
    if card.ExpiryMonth < 1 || card.ExpiryMonth > 12 {
        return fmt.Errorf("expiry month must be between 1 and 12")
    }
    
    currentYear := time.Now().Year()
    if card.ExpiryYear < currentYear || card.ExpiryYear > currentYear+50 {
        return fmt.Errorf("expiry year must be between %d and %d", currentYear, currentYear+50)
    }
    
    // Check if card is expired
    currentTime := time.Now()
    expiryTime := time.Date(card.ExpiryYear, time.Month(card.ExpiryMonth+1), 1, 0, 0, 0, 0, time.UTC).Add(-time.Second)
    if currentTime.After(expiryTime) {
        return fmt.Errorf("card is expired")
    }
    
    // Validate card holder name if provided
    if card.CardHolder != "" && len(card.CardHolder) > 100 {
        return fmt.Errorf("card holder name too long (max 100 characters)")
    }
    
    // Validate external ID if provided
    if card.ExternalID != "" && len(card.ExternalID) > 64 {
        return fmt.Errorf("external ID too long (max 64 characters)")
    }
    
    return nil
}

// checkCardExists checks if a card already exists in the database
func (ut *UnifiedTokenizer) checkCardExists(cardNumber string) (bool, string, error) {
    // Clean card number
    cleanCard := strings.ReplaceAll(strings.ReplaceAll(cardNumber, " ", ""), "-", "")
    
    // Get last 4 digits for lookup
    lastFour := cleanCard[len(cleanCard)-4:]
    
    var token string
    var encryptedCard []byte
    
    rows, err := ut.db.Query(`
        SELECT token, card_number_encrypted 
        FROM credit_cards 
        WHERE last_four_digits = ? AND is_active = TRUE
    `, lastFour)
    
    if err != nil {
        return false, "", err
    }
    defer rows.Close()
    
    // Check each card with matching last 4 digits
    for rows.Next() {
        if err := rows.Scan(&token, &encryptedCard); err != nil {
            continue
        }
        
        // Decrypt and compare
        decryptedCard, err := ut.decryptCardNumber(encryptedCard)
        if err != nil {
            continue
        }
        
        if decryptedCard == cleanCard {
            return true, token, nil
        }
    }
    
    return false, "", nil
}

// tokenizeCardForImport tokenizes a card during import process
func (ut *UnifiedTokenizer) tokenizeCardForImport(card CardImportRecord, tx *sql.Tx) (string, string, error) {
    // Clean card number
    cleanCard := strings.ReplaceAll(strings.ReplaceAll(card.CardNumber, " ", ""), "-", "")
    
    // Generate token
    token := ut.generateToken()
    
    // Detect card type
    cardType := detectCardType(cleanCard)
    
    // Encrypt card number
    encryptedCard, err := ut.encryptCardNumber(cleanCard)
    if err != nil {
        return "", "", fmt.Errorf("failed to encrypt card: %v", err)
    }
    
    // Encrypt card holder name if provided
    var encryptedHolder []byte
    if card.CardHolder != "" {
        encryptedHolder, err = ut.encryptCardNumber(card.CardHolder)
        if err != nil {
            return "", "", fmt.Errorf("failed to encrypt card holder: %v", err)
        }
    }
    
    // Get first 6 and last 4 digits
    firstSix := cleanCard[:6]
    lastFour := cleanCard[len(cleanCard)-4:]
    
    // Get encryption key ID if using KEK/DEK
    var keyID *string
    if ut.useKEKDEK && ut.keyManager != nil {
        if currentKeyID := ut.keyManager.getCurrentDEKID(); currentKeyID != "" {
            keyID = &currentKeyID
        }
    }
    
    // Insert into database using transaction
    _, err = tx.Exec(`
        INSERT INTO credit_cards (
            token, card_number_encrypted, card_holder_name_encrypted,
            expiry_month, expiry_year, card_type, last_four_digits, first_six_digits,
            encryption_key_id, created_at, is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), TRUE)
        ON DUPLICATE KEY UPDATE
            card_number_encrypted = VALUES(card_number_encrypted),
            card_holder_name_encrypted = VALUES(card_holder_name_encrypted),
            expiry_month = VALUES(expiry_month),
            expiry_year = VALUES(expiry_year),
            card_type = VALUES(card_type),
            encryption_key_id = VALUES(encryption_key_id),
            updated_at = NOW()
    `, token, encryptedCard, encryptedHolder, card.ExpiryMonth, card.ExpiryYear, 
       cardType, lastFour, firstSix, keyID)
    
    if err != nil {
        return "", "", fmt.Errorf("failed to store card: %v", err)
    }
    
    return token, cardType, nil
}

func (ut *UnifiedTokenizer) handleGetUser(w http.ResponseWriter, r *http.Request) {
    username := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
    
    var user User
    var permissionsJSON []byte
    var lastLoginAt sql.NullTime
    
    err := ut.db.QueryRow(`
        SELECT user_id, username, email, full_name, role, permissions,
               is_active, created_at, last_login_at
        FROM users
        WHERE username = ? OR user_id = ?
    `, username, username).Scan(
        &user.UserID, &user.Username, &user.Email, &user.FullName,
        &user.Role, &permissionsJSON, &user.IsActive, &user.CreatedAt, &lastLoginAt,
    )
    
    if err == sql.ErrNoRows {
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(map[string]string{"error": "User not found"})
        return
    } else if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
        return
    }
    
    json.Unmarshal(permissionsJSON, &user.Permissions)
    if lastLoginAt.Valid {
        user.LastLoginAt = &lastLoginAt.Time
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(user)
}

func (ut *UnifiedTokenizer) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
    username := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
    
    var req struct {
        Email       *string   `json:"email"`
        FullName    *string   `json:"full_name"`
        Role        *string   `json:"role"`
        Permissions *[]string `json:"permissions"`
        IsActive    *bool     `json:"is_active"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
        return
    }
    
    // Build update query dynamically
    updates := []string{}
    params := []interface{}{}
    
    if req.Email != nil {
        updates = append(updates, "email = ?")
        params = append(params, *req.Email)
    }
    if req.FullName != nil {
        updates = append(updates, "full_name = ?")
        params = append(params, *req.FullName)
    }
    if req.Role != nil {
        updates = append(updates, "role = ?")
        params = append(params, *req.Role)
    }
    if req.Permissions != nil {
        permissionsJSON, _ := json.Marshal(*req.Permissions)
        updates = append(updates, "permissions = ?")
        params = append(params, permissionsJSON)
    }
    if req.IsActive != nil {
        updates = append(updates, "is_active = ?")
        params = append(params, *req.IsActive)
    }
    
    if len(updates) == 0 {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "No fields to update"})
        return
    }
    
    updates = append(updates, "updated_at = NOW()")
    params = append(params, username, username) // for WHERE clause
    
    query := fmt.Sprintf("UPDATE users SET %s WHERE username = ? OR user_id = ?", strings.Join(updates, ", "))
    result, err := ut.db.Exec(query, params...)
    
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to update user"})
        return
    }
    
    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(map[string]string{"error": "User not found"})
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "User updated successfully"})
}

func (ut *UnifiedTokenizer) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
    username := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
    
    // Don't allow deleting the default admin
    if username == "admin" || username == "usr_admin_default" {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]string{"error": "Cannot delete default admin user"})
        return
    }
    
    // Check if user exists
    var userID string
    err := ut.db.QueryRow("SELECT user_id FROM users WHERE username = ? OR user_id = ?", username, username).Scan(&userID)
    if err == sql.ErrNoRows {
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(map[string]string{"error": "User not found"})
        return
    }
    
    // Delete user (cascades to sessions and api_keys)
    _, err = ut.db.Exec("DELETE FROM users WHERE user_id = ?", userID)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to delete user"})
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "User deleted successfully"})
}

func (ut *UnifiedTokenizer) startAPIServer() {
    mux := http.NewServeMux()
    
    // Health check and version (no auth required)
    mux.HandleFunc("/health", ut.handleAPIHealth)
    mux.HandleFunc("/api/v1/version", ut.handleGetVersion)
    
    // Authentication endpoints (no auth required, but rate limited and validated)
    mux.HandleFunc("/api/v1/auth/login", ut.rateLimitMiddleware(ut.validationMiddleware("/api/v1/auth/login")(ut.handleLogin)))
    mux.HandleFunc("/api/v1/auth/logout", ut.handleLogout)
    mux.HandleFunc("/api/v1/auth/me", ut.handleGetCurrentUser)
    mux.HandleFunc("/api/v1/auth/change-password", ut.rateLimitMiddleware(ut.validationMiddleware("/api/v1/auth/change-password")(ut.handleChangePassword)))
    
    // API Key management (requires permissions and validation)
    mux.HandleFunc("/api/v1/api-keys", func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case "GET":
            ut.requirePermission(ut.handleListAPIKeys, PermAPIKeysRead)(w, r)
        case "POST":
            ut.validationMiddleware("/api/v1/api-keys")(ut.requirePermission(ut.handleCreateAPIKey, PermAPIKeysWrite))(w, r)
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
    
    mux.HandleFunc("/api/v1/api-keys/", func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case "DELETE":
            ut.requirePermission(ut.handleRevokeAPIKey, PermAPIKeysDelete)(w, r)
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
    
    // Token management (requires permissions)
    mux.HandleFunc("/api/v1/tokens", func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case "GET":
            ut.requirePermission(ut.handleAPIListTokens, PermTokensRead)(w, r)
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
    
    mux.HandleFunc("/api/v1/tokens/search", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "POST" {
            ut.validationMiddleware("/api/v1/tokens/search")(ut.requirePermission(ut.handleSearchTokens, PermTokensRead))(w, r)
        } else {
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
    
    // Individual token operations
    mux.HandleFunc("/api/v1/tokens/", func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case "GET":
            ut.requirePermission(ut.handleAPIGetToken, PermTokensRead)(w, r)
        case "DELETE":
            ut.requirePermission(ut.handleAPIRevokeToken, PermTokensDelete)(w, r)
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
    
    // Activity monitoring
    mux.HandleFunc("/api/v1/activity", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "GET" {
            ut.requirePermission(ut.handleGetActivity, PermActivityRead)(w, r)
        } else {
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
    
    // Stats
    mux.HandleFunc("/api/v1/stats", ut.requirePermission(ut.handleAPIStats, PermStatsRead))
    
    // Card import endpoint (requires admin permissions and validation)
    mux.HandleFunc("/api/v1/cards/import", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "POST" {
            ut.validationMiddleware("/api/v1/cards/import")(ut.requirePermission(ut.handleCardImport, PermSystemAdmin))(w, r)
        } else {
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
    
    // User management endpoints (with validation)
    mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case "GET":
            ut.requirePermission(ut.handleListUsers, PermUsersRead)(w, r)
        case "POST":
            ut.validationMiddleware("/api/v1/users")(ut.requirePermission(ut.handleCreateUser, PermUsersWrite))(w, r)
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
    
    mux.HandleFunc("/api/v1/users/", func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case "GET":
            ut.requirePermission(ut.handleGetUser, PermUsersRead)(w, r)
        case "PUT":
            ut.requirePermission(ut.handleUpdateUser, PermUsersWrite)(w, r)
        case "DELETE":
            ut.requirePermission(ut.handleDeleteUser, PermUsersDelete)(w, r)
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
    
    // Key management endpoints (if KEK/DEK is enabled)
    if ut.useKEKDEK {
        mux.HandleFunc("/api/v1/keys/status", func(w http.ResponseWriter, r *http.Request) {
            if r.Method == "GET" {
                ut.handleKeyStatus(w, r)
            } else {
                w.WriteHeader(http.StatusMethodNotAllowed)
            }
        })
        
        mux.HandleFunc("/api/v1/keys/rotate", func(w http.ResponseWriter, r *http.Request) {
            if r.Method == "POST" {
                ut.handleKeyRotation(w, r)
            } else {
                w.WriteHeader(http.StatusMethodNotAllowed)
            }
        })
        
        mux.HandleFunc("/api/v1/keys/rotations", func(w http.ResponseWriter, r *http.Request) {
            if r.Method == "GET" {
                ut.handleKeyRotationHistory(w, r)
            } else {
                w.WriteHeader(http.StatusMethodNotAllowed)
            }
        })
    }
    
    log.Printf("Starting API server on port %s with CORS enabled", ut.apiPort)
    if err := http.ListenAndServe(":"+ut.apiPort, ut.corsMiddleware(mux)); err != nil {
        log.Fatalf("API server failed: %v", err)
    }
}

// Key management API handlers

func (ut *UnifiedTokenizer) handleKeyStatus(w http.ResponseWriter, r *http.Request) {
    // Permission check is handled by requirePermission middleware
    
    type KeyInfo struct {
        KeyID      string    `json:"key_id"`
        Version    int       `json:"version"`
        Status     string    `json:"status"`
        CreatedAt  time.Time `json:"created_at"`
        CardsCount int       `json:"cards_encrypted,omitempty"`
    }
    
    response := struct {
        KEK *KeyInfo `json:"kek,omitempty"`
        DEK *KeyInfo `json:"dek,omitempty"`
    }{}
    
    // Get KEK info
    var kekInfo KeyInfo
    err := ut.db.QueryRow(`
        SELECT key_id, key_version, key_status, created_at
        FROM encryption_keys
        WHERE key_type = 'KEK' AND key_status = 'active'
        ORDER BY key_version DESC LIMIT 1
    `).Scan(&kekInfo.KeyID, &kekInfo.Version, &kekInfo.Status, &kekInfo.CreatedAt)
    
    if err == nil {
        response.KEK = &kekInfo
    }
    
    // Get DEK info
    var dekInfo KeyInfo
    err = ut.db.QueryRow(`
        SELECT key_id, key_version, key_status, created_at
        FROM encryption_keys
        WHERE key_type = 'DEK' AND key_status = 'active'
        ORDER BY key_version DESC LIMIT 1
    `).Scan(&dekInfo.KeyID, &dekInfo.Version, &dekInfo.Status, &dekInfo.CreatedAt)
    
    if err == nil {
        response.DEK = &dekInfo
        
        // Count cards encrypted with this DEK
        ut.db.QueryRow(`
            SELECT COUNT(*) FROM credit_cards 
            WHERE encryption_key_id = ?
        `, dekInfo.KeyID).Scan(&dekInfo.CardsCount)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func (ut *UnifiedTokenizer) handleKeyRotation(w http.ResponseWriter, r *http.Request) {
    // Permission check is handled by requirePermission middleware
    
    // Check if KEK/DEK is enabled
    if !ut.useKEKDEK || ut.keyManager == nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "KEK/DEK encryption is not enabled",
        })
        return
    }
    
    // Parse request body for rotation type
    var request struct {
        KeyType string `json:"key_type"` // "KEK", "DEK", or "both"
    }
    
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        request.KeyType = "DEK" // Default to DEK rotation
    }
    
    rotationID := "rot_" + generateRandomID()
    
    // Log rotation attempt
    _, err := ut.db.Exec(`
        INSERT INTO key_rotation_log (rotation_id, key_type, status, started_at)
        VALUES (?, ?, 'in_progress', NOW())
    `, rotationID, request.KeyType)
    
    if err != nil {
        log.Printf("Failed to log rotation start: %v", err)
    }
    
    var rotatedKeys []string
    var errors []string
    
    // Perform rotation based on type
    switch request.KeyType {
    case "KEK":
        if err := ut.keyManager.RotateKEK(); err != nil {
            errors = append(errors, fmt.Sprintf("KEK rotation failed: %v", err))
        } else {
            rotatedKeys = append(rotatedKeys, "KEK")
        }
    case "both":
        if err := ut.keyManager.RotateKEK(); err != nil {
            errors = append(errors, fmt.Sprintf("KEK rotation failed: %v", err))
        } else {
            rotatedKeys = append(rotatedKeys, "KEK")
        }
        if err := ut.keyManager.RotateDEK(); err != nil {
            errors = append(errors, fmt.Sprintf("DEK rotation failed: %v", err))
        } else {
            rotatedKeys = append(rotatedKeys, "DEK")
        }
    default: // "DEK" or any other value
        if err := ut.keyManager.RotateDEK(); err != nil {
            errors = append(errors, fmt.Sprintf("DEK rotation failed: %v", err))
        } else {
            rotatedKeys = append(rotatedKeys, "DEK")
        }
    }
    
    // Update rotation log
    status := "completed"
    if len(errors) > 0 {
        status = "failed"
    }
    
    _, err = ut.db.Exec(`
        UPDATE key_rotation_log 
        SET status = ?, completed_at = NOW(), error_message = ?
        WHERE rotation_id = ?
    `, status, strings.Join(errors, "; "), rotationID)
    
    if err != nil {
        log.Printf("Failed to update rotation log: %v", err)
    }
    
    // Prepare response
    response := map[string]interface{}{
        "rotation_id":   rotationID,
        "status":        status,
        "rotated_keys":  rotatedKeys,
        "requested_type": request.KeyType,
    }
    
    if len(errors) > 0 {
        response["errors"] = errors
        w.WriteHeader(http.StatusInternalServerError)
    } else {
        response["message"] = "Key rotation completed successfully"
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func (ut *UnifiedTokenizer) handleKeyRotationHistory(w http.ResponseWriter, r *http.Request) {
    // Permission check is handled by requirePermission middleware
    
    // Get query parameters
    limit := 50
    if l := r.URL.Query().Get("limit"); l != "" {
        if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
            limit = parsed
        }
    }
    
    rows, err := ut.db.Query(`
        SELECT rotation_id, key_type, status, started_at, completed_at, error_message
        FROM key_rotation_log
        ORDER BY started_at DESC
        LIMIT ?
    `, limit)
    
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
        return
    }
    defer rows.Close()
    
    var rotations []map[string]interface{}
    
    for rows.Next() {
        var rotationID, keyType, status string
        var errorMessage sql.NullString
        var startedAt time.Time
        var completedAt sql.NullTime
        
        err := rows.Scan(&rotationID, &keyType, &status, &startedAt, &completedAt, &errorMessage)
        if err != nil {
            continue
        }
        
        rotation := map[string]interface{}{
            "rotation_id": rotationID,
            "key_type":    keyType,
            "status":      status,
            "started_at":  startedAt.Format(time.RFC3339),
        }
        
        if completedAt.Valid {
            rotation["completed_at"] = completedAt.Time.Format(time.RFC3339)
            rotation["duration_ms"] = completedAt.Time.Sub(startedAt).Milliseconds()
        }
        
        if errorMessage.Valid && errorMessage.String != "" {
            rotation["error_message"] = errorMessage.String
        }
        
        rotations = append(rotations, rotation)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "rotations": rotations,
        "total":     len(rotations),
    })
}

func (ut *UnifiedTokenizer) startICAPServer() {
    listener, err := net.Listen("tcp", ":"+ut.icapPort)
    if err != nil {
        log.Fatalf("Failed to start ICAP server: %v", err)
    }
    defer listener.Close()
    
    log.Printf("Starting ICAP detokenization server on port %s", ut.icapPort)
    
    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Failed to accept connection: %v", err)
            continue
        }
        
        go ut.handleICAP(conn)
    }
}

// KeyManager Implementation

func NewKeyManager(db *sql.DB) (*KeyManager, error) {
    km := &KeyManager{
        db:       db,
        kekCache: make(map[string][]byte),
        dekCache: make(map[string][]byte),
    }
    
    // Load or generate KEK
    if err := km.loadOrGenerateKEK(); err != nil {
        return nil, fmt.Errorf("failed to initialize KEK: %v", err)
    }
    
    // Load or generate DEK
    if err := km.loadOrGenerateDEK(); err != nil {
        return nil, fmt.Errorf("failed to initialize DEK: %v", err)
    }
    
    return km, nil
}

// getCurrentDEKID returns the current active DEK ID
func (km *KeyManager) getCurrentDEKID() string {
    km.mu.RLock()
    defer km.mu.RUnlock()
    return km.currentDEKID
}

func (km *KeyManager) loadOrGenerateKEK() error {
    var keyID string
    var key []byte
    
    err := km.db.QueryRow(`
        SELECT key_id, encrypted_key FROM encryption_keys
        WHERE key_type = 'KEK' AND key_status = 'active'
        ORDER BY key_version DESC LIMIT 1
    `).Scan(&keyID, &key)
    
    if err == sql.ErrNoRows {
        // Generate new KEK
        key = make([]byte, 32)
        if _, err := io.ReadFull(cryptorand.Reader, key); err != nil {
            return fmt.Errorf("failed to generate KEK: %v", err)
        }
        
        keyID = "kek_" + generateRandomID()
        
        _, err = km.db.Exec(`
            INSERT INTO encryption_keys 
            (key_id, key_type, key_version, encrypted_key, key_status, activated_at)
            VALUES (?, 'KEK', 1, ?, 'active', NOW())
        `, keyID, key)
        
        if err != nil {
            return fmt.Errorf("failed to store KEK: %v", err)
        }
        
        log.Printf("Generated new KEK: %s", keyID)
    } else if err != nil {
        return err
    }
    
    km.mu.Lock()
    km.kekCache[keyID] = key
    km.currentKEKID = keyID
    km.mu.Unlock()
    
    return nil
}

func (km *KeyManager) loadOrGenerateDEK() error {
    var keyID string
    var encryptedKey []byte
    var metadata json.RawMessage
    
    err := km.db.QueryRow(`
        SELECT key_id, encrypted_key, metadata FROM encryption_keys
        WHERE key_type = 'DEK' AND key_status = 'active'
        ORDER BY key_version DESC LIMIT 1
    `).Scan(&keyID, &encryptedKey, &metadata)
    
    if err == sql.ErrNoRows {
        // Generate new DEK
        return km.generateNewDEK()
    } else if err != nil {
        return err
    }
    
    // Decrypt DEK with KEK
    var kekID string
    km.mu.RLock()
    for kid := range km.kekCache {
        kekID = kid
        break
    }
    kek := km.kekCache[kekID]
    km.mu.RUnlock()
    
    dek, err := km.decryptWithKEK(encryptedKey, kek)
    if err != nil {
        return fmt.Errorf("failed to decrypt DEK: %v", err)
    }
    
    km.mu.Lock()
    km.dekCache[keyID] = dek
    km.currentDEKID = keyID
    km.mu.Unlock()
    
    return nil
}

func (km *KeyManager) generateNewDEK() error {
    // Get active KEK
    var kekID string
    var kek []byte
    
    km.mu.RLock()
    for kid, k := range km.kekCache {
        kekID = kid
        kek = k
        break
    }
    km.mu.RUnlock()
    
    if kek == nil {
        return errors.New("no active KEK found")
    }
    
    // Generate new DEK
    dek := make([]byte, 32)
    if _, err := io.ReadFull(cryptorand.Reader, dek); err != nil {
        return fmt.Errorf("failed to generate DEK: %v", err)
    }
    
    // Encrypt DEK with KEK
    encryptedDEK, err := km.encryptWithKEK(dek, kek)
    if err != nil {
        return fmt.Errorf("failed to encrypt DEK: %v", err)
    }
    
    dekID := "dek_" + generateRandomID()
    
    // Get next version
    var maxVersion int
    km.db.QueryRow("SELECT COALESCE(MAX(key_version), 0) FROM encryption_keys WHERE key_type = 'DEK'").Scan(&maxVersion)
    
    // Store encrypted DEK
    metadata := map[string]string{"kek_id": kekID}
    metadataJSON, _ := json.Marshal(metadata)
    
    _, err = km.db.Exec(`
        INSERT INTO encryption_keys 
        (key_id, key_type, key_version, encrypted_key, key_status, metadata, activated_at)
        VALUES (?, 'DEK', ?, ?, 'active', ?, NOW())
    `, dekID, maxVersion+1, encryptedDEK, metadataJSON)
    
    if err != nil {
        return fmt.Errorf("failed to store DEK: %v", err)
    }
    
    km.mu.Lock()
    km.dekCache[dekID] = dek
    km.currentDEKID = dekID
    km.mu.Unlock()
    
    log.Printf("Generated new DEK: %s", dekID)
    
    return nil
}

func (km *KeyManager) EncryptData(plaintext []byte) ([]byte, string, error) {
    km.mu.RLock()
    dekID := km.currentDEKID
    dek, exists := km.dekCache[dekID]
    km.mu.RUnlock()
    
    if !exists || len(dek) == 0 {
        return nil, "", errors.New("no active DEK available")
    }
    
    // AES-GCM encryption
    block, err := aes.NewCipher(dek)
    if err != nil {
        return nil, "", err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, "", err
    }
    
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
        return nil, "", err
    }
    
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return ciphertext, dekID, nil
}

func (km *KeyManager) DecryptData(ciphertext []byte, dekID string) ([]byte, error) {
    km.mu.RLock()
    dek, exists := km.dekCache[dekID]
    km.mu.RUnlock()
    
    if !exists {
        // Try to load from database
        if err := km.loadDEK(dekID); err != nil {
            return nil, fmt.Errorf("failed to load DEK: %v", err)
        }
        
        km.mu.RLock()
        dek, exists = km.dekCache[dekID]
        km.mu.RUnlock()
        
        if !exists {
            return nil, errors.New("DEK not found")
        }
    }
    
    // AES-GCM decryption
    block, err := aes.NewCipher(dek)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }
    
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

func (km *KeyManager) loadDEK(dekID string) error {
    var encryptedKey []byte
    var metadata json.RawMessage
    
    err := km.db.QueryRow(`
        SELECT encrypted_key, metadata FROM encryption_keys
        WHERE key_id = ? AND key_type = 'DEK'
    `, dekID).Scan(&encryptedKey, &metadata)
    
    if err != nil {
        return err
    }
    
    // Get KEK ID from metadata
    var meta map[string]string
    json.Unmarshal(metadata, &meta)
    kekID := meta["kek_id"]
    
    km.mu.RLock()
    kek, exists := km.kekCache[kekID]
    km.mu.RUnlock()
    
    if !exists {
        return errors.New("KEK not found")
    }
    
    // Decrypt DEK
    dek, err := km.decryptWithKEK(encryptedKey, kek)
    if err != nil {
        return err
    }
    
    km.mu.Lock()
    km.dekCache[dekID] = dek
    km.mu.Unlock()
    
    return nil
}

func (km *KeyManager) encryptWithKEK(plaintext, kek []byte) ([]byte, error) {
    block, err := aes.NewCipher(kek)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
        return nil, err
    }
    
    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (km *KeyManager) decryptWithKEK(ciphertext, kek []byte) ([]byte, error) {
    block, err := aes.NewCipher(kek)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }
    
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// Key rotation methods
func (km *KeyManager) RotateKEK() error {
    log.Printf("Starting KEK rotation...")
    
    // Generate new KEK
    newKEK := make([]byte, 32)
    if _, err := io.ReadFull(cryptorand.Reader, newKEK); err != nil {
        return fmt.Errorf("failed to generate new KEK: %v", err)
    }
    
    newKEKID := "kek_" + generateRandomID()
    
    // Get current KEK version
    var currentVersion int
    err := km.db.QueryRow(`
        SELECT COALESCE(MAX(key_version), 0) FROM encryption_keys 
        WHERE key_type = 'KEK'
    `).Scan(&currentVersion)
    
    if err != nil {
        return fmt.Errorf("failed to get current KEK version: %v", err)
    }
    
    newVersion := currentVersion + 1
    
    // Start transaction for atomic rotation
    tx, err := km.db.Begin()
    if err != nil {
        return fmt.Errorf("failed to start transaction: %v", err)
    }
    defer tx.Rollback()
    
    // Mark old KEK as retired
    _, err = tx.Exec(`
        UPDATE encryption_keys 
        SET key_status = 'retired', retired_at = NOW() 
        WHERE key_type = 'KEK' AND key_status = 'active'
    `)
    if err != nil {
        return fmt.Errorf("failed to mark old KEK as rotated: %v", err)
    }
    
    // Insert new KEK
    _, err = tx.Exec(`
        INSERT INTO encryption_keys 
        (key_id, key_type, key_version, encrypted_key, key_status, activated_at)
        VALUES (?, 'KEK', ?, ?, 'active', NOW())
    `, newKEKID, newVersion, newKEK)
    
    if err != nil {
        return fmt.Errorf("failed to store new KEK: %v", err)
    }
    
    // Commit transaction
    if err := tx.Commit(); err != nil {
        return fmt.Errorf("failed to commit KEK rotation: %v", err)
    }
    
    // Update cache
    km.mu.Lock()
    // Clear old KEKs from cache
    km.kekCache = make(map[string][]byte)
    km.kekCache[newKEKID] = newKEK
    km.currentKEKID = newKEKID
    km.mu.Unlock()
    
    log.Printf("KEK rotation completed successfully. New KEK ID: %s, Version: %d", newKEKID, newVersion)
    return nil
}

func (km *KeyManager) RotateDEK() error {
    log.Printf("Starting DEK rotation...")
    
    // Get current KEK for encrypting new DEK
    var kekID string
    var kek []byte
    
    km.mu.RLock()
    for kid, k := range km.kekCache {
        kekID = kid
        kek = k
        break
    }
    km.mu.RUnlock()
    
    if kek == nil {
        return errors.New("no active KEK available for DEK rotation")
    }
    
    // Generate new DEK
    newDEK := make([]byte, 32)
    if _, err := io.ReadFull(cryptorand.Reader, newDEK); err != nil {
        return fmt.Errorf("failed to generate new DEK: %v", err)
    }
    
    // Encrypt new DEK with KEK
    encryptedDEK, err := km.encryptWithKEK(newDEK, kek)
    if err != nil {
        return fmt.Errorf("failed to encrypt new DEK: %v", err)
    }
    
    newDEKID := "dek_" + generateRandomID()
    
    // Get current DEK version
    var currentVersion int
    err = km.db.QueryRow(`
        SELECT COALESCE(MAX(key_version), 0) FROM encryption_keys 
        WHERE key_type = 'DEK'
    `).Scan(&currentVersion)
    
    if err != nil {
        return fmt.Errorf("failed to get current DEK version: %v", err)
    }
    
    newVersion := currentVersion + 1
    
    // Prepare metadata
    metadata := map[string]interface{}{
        "kek_id": kekID,
        "algorithm": "AES-256-GCM",
        "rotated_at": time.Now().UTC(),
    }
    metadataJSON, _ := json.Marshal(metadata)
    
    // Start transaction for atomic rotation
    tx, err := km.db.Begin()
    if err != nil {
        return fmt.Errorf("failed to start transaction: %v", err)
    }
    defer tx.Rollback()
    
    // Mark old DEK as retired
    _, err = tx.Exec(`
        UPDATE encryption_keys 
        SET key_status = 'retired', retired_at = NOW() 
        WHERE key_type = 'DEK' AND key_status = 'active'
    `)
    if err != nil {
        return fmt.Errorf("failed to mark old DEK as rotated: %v", err)
    }
    
    // Insert new DEK
    _, err = tx.Exec(`
        INSERT INTO encryption_keys 
        (key_id, key_type, key_version, encrypted_key, key_status, activated_at, metadata)
        VALUES (?, 'DEK', ?, ?, 'active', NOW(), ?)
    `, newDEKID, newVersion, encryptedDEK, metadataJSON)
    
    if err != nil {
        return fmt.Errorf("failed to store new DEK: %v", err)
    }
    
    // Commit transaction
    if err := tx.Commit(); err != nil {
        return fmt.Errorf("failed to commit DEK rotation: %v", err)
    }
    
    // Update cache
    km.mu.Lock()
    // Clear old DEKs from cache (keep for decryption if needed)
    km.dekCache[newDEKID] = newDEK
    km.currentDEKID = newDEKID
    km.mu.Unlock()
    
    log.Printf("DEK rotation completed successfully. New DEK ID: %s, Version: %d", newDEKID, newVersion)
    return nil
}

func generateRandomID() string {
    b := make([]byte, 16)
    cryptorand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}

// User authentication methods

func generateSecurePassword(length int) string {
    const (
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lowercase = "abcdefghijklmnopqrstuvwxyz"
        digits    = "0123456789"
        special   = "!@#$%^&*"
    )
    
    allChars := uppercase + lowercase + digits + special
    password := make([]byte, length)
    
    // Ensure at least one of each type
    password[0] = uppercase[rand.Intn(len(uppercase))]
    password[1] = lowercase[rand.Intn(len(lowercase))]
    password[2] = digits[rand.Intn(len(digits))]
    password[3] = special[rand.Intn(len(special))]
    
    // Fill the rest
    for i := 4; i < length; i++ {
        password[i] = allChars[rand.Intn(len(allChars))]
    }
    
    // Shuffle the password
    for i := len(password) - 1; i > 0; i-- {
        j := rand.Intn(i + 1)
        password[i], password[j] = password[j], password[i]
    }
    
    return string(password)
}

func (ut *UnifiedTokenizer) createDefaultAdminUser() error {
    // Check if admin user already exists
    var count int
    err := ut.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'admin'").Scan(&count)
    if err != nil {
        return err
    }
    
    if count > 0 {
        return nil // Admin already exists
    }
    
    // Generate a secure random password
    randomPassword := generateSecurePassword(16)
    
    // Generate password hash
    passwordHash, err := bcrypt.GenerateFromPassword([]byte(randomPassword), bcrypt.DefaultCost)
    if err != nil {
        return err
    }
    
    userID := "usr_admin_default"
    permissions := []string{PermSystemAdmin}
    permissionsJSON, _ := json.Marshal(permissions)
    
    _, err = ut.db.Exec(`
        INSERT INTO users (
            user_id, username, email, password_hash, full_name, 
            role, permissions, is_active, is_email_verified,
            password_changed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
    `, userID, "admin", "admin@tokenshield.local", string(passwordHash), 
       "Default Administrator", RoleAdmin, permissionsJSON, true, true)
    
    if err != nil {
        return fmt.Errorf("failed to create default admin user: %v", err)
    }
    
    log.Printf("========================================")
    log.Printf("ADMIN USER CREATED - INITIAL CREDENTIALS:")
    log.Printf("Username: admin")
    log.Printf("Password: %s", randomPassword)
    log.Printf("========================================")
    log.Printf("WARNING: You must change this password on first login!")
    log.Printf("========================================")
    
    return nil
}

func (ut *UnifiedTokenizer) authenticateUser(username, password string) (*User, error) {
    var user User
    var passwordHash string
    var permissionsJSON []byte
    var lastLoginAt sql.NullTime
    var passwordChangedAt sql.NullTime
    
    err := ut.db.QueryRow(`
        SELECT user_id, username, email, password_hash, full_name, 
               role, permissions, is_active, created_at, last_login_at,
               password_changed_at
        FROM users 
        WHERE username = ? OR email = ?
    `, username, username).Scan(
        &user.UserID, &user.Username, &user.Email, &passwordHash,
        &user.FullName, &user.Role, &permissionsJSON, &user.IsActive,
        &user.CreatedAt, &lastLoginAt, &passwordChangedAt,
    )
    
    if err == sql.ErrNoRows {
        return nil, errors.New("invalid username or password")
    } else if err != nil {
        return nil, err
    }
    
    // Check if user is active
    if !user.IsActive {
        return nil, errors.New("user account is disabled")
    }
    
    // Verify password
    err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
    if err != nil {
        // Increment failed login attempts
        ut.db.Exec(`
            UPDATE users 
            SET failed_login_attempts = failed_login_attempts + 1 
            WHERE user_id = ?
        `, user.UserID)
        return nil, errors.New("invalid username or password")
    }
    
    // Parse permissions
    json.Unmarshal(permissionsJSON, &user.Permissions)
    
    if lastLoginAt.Valid {
        user.LastLoginAt = &lastLoginAt.Time
    }
    
    if passwordChangedAt.Valid {
        user.PasswordChangedAt = &passwordChangedAt.Time
    }
    
    // Update last login time and reset failed attempts
    ut.db.Exec(`
        UPDATE users 
        SET last_login_at = NOW(), failed_login_attempts = 0 
        WHERE user_id = ?
    `, user.UserID)
    
    return &user, nil
}

func (ut *UnifiedTokenizer) createSession(user *User, ipAddress, userAgent string) (*UserSession, error) {
    // Clean up expired sessions first
    ut.cleanupExpiredSessions()
    
    // Check concurrent session limits
    var activeSessionCount int
    err := ut.db.QueryRow(`
        SELECT COUNT(*) FROM user_sessions 
        WHERE user_id = ? AND is_active = TRUE AND expires_at > NOW()
    `, user.UserID).Scan(&activeSessionCount)
    
    if err != nil {
        log.Printf("Error checking active sessions for user %s: %v", user.UserID, err)
    }
    
    // Enforce concurrent session limits
    if activeSessionCount >= ut.maxConcurrentSessions {
        // Log security event for session limit exceeded
        ut.logSecurityEvent(SecurityEvent{
            EventType: "session_limit_exceeded",
            Severity:  "medium",
            UserID:    user.UserID,
            Username:  user.Username,
            IPAddress: ipAddress,
            UserAgent: userAgent,
            Details: map[string]interface{}{
                "active_sessions": activeSessionCount,
                "max_allowed": ut.maxConcurrentSessions,
                "action": "oldest_session_invalidated",
            },
        })
        
        // Invalidate oldest session for this user
        _, err = ut.db.Exec(`
            UPDATE user_sessions 
            SET is_active = FALSE 
            WHERE user_id = ? AND is_active = TRUE 
            ORDER BY created_at ASC 
            LIMIT 1
        `, user.UserID)
        
        if err != nil {
            log.Printf("Error invalidating oldest session for user %s: %v", user.UserID, err)
        }
    }
    
    // Generate session ID and calculate expiry times
    sessionID := "sess_" + generateRandomID()
    now := time.Now()
    expiresAt := now.Add(ut.sessionTimeout)        // Absolute session timeout
    idleExpiresAt := now.Add(ut.sessionIdleTimeout) // Idle timeout (will be updated on activity)
    
    // Use the shorter of absolute or idle timeout for initial expiry
    if idleExpiresAt.Before(expiresAt) {
        expiresAt = idleExpiresAt
    }
    
    // Create session in database
    _, err = ut.db.Exec(`
        INSERT INTO user_sessions (
            session_id, user_id, ip_address, user_agent, 
            created_at, expires_at, last_activity_at, is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, TRUE)
    `, sessionID, user.UserID, ipAddress, userAgent, now, expiresAt, now)
    
    if err != nil {
        return nil, fmt.Errorf("failed to create session: %v", err)
    }
    
    // Log successful session creation
    ut.logAuditEvent(AuditEvent{
        UserID:       user.UserID,
        Action:       "session_created",
        ResourceType: "session",
        ResourceID:   sessionID,
        IPAddress:    ipAddress,
        UserAgent:    userAgent,
        Details: map[string]interface{}{
            "session_timeout": ut.sessionTimeout.String(),
            "idle_timeout": ut.sessionIdleTimeout.String(),
            "max_concurrent": ut.maxConcurrentSessions,
        },
    })
    
    session := &UserSession{
        SessionID:    sessionID,
        UserID:       user.UserID,
        User:         user,
        IPAddress:    ipAddress,
        UserAgent:    userAgent,
        CreatedAt:    now,
        ExpiresAt:    expiresAt,
        LastActivity: now,
    }
    
    return session, nil
}

// cleanupExpiredSessions removes expired sessions from the database
func (ut *UnifiedTokenizer) cleanupExpiredSessions() {
    // Clean up expired sessions (both absolute and idle timeouts)
    result, err := ut.db.Exec(`
        UPDATE user_sessions 
        SET is_active = FALSE 
        WHERE is_active = TRUE 
          AND (expires_at <= NOW() 
               OR (last_activity_at <= DATE_SUB(NOW(), INTERVAL ? SECOND)))
    `, int(ut.sessionIdleTimeout.Seconds()))
    
    if err != nil {
        log.Printf("Error cleaning up expired sessions: %v", err)
        return
    }
    
    // Log cleanup activity if sessions were cleaned
    if rowsAffected, err := result.RowsAffected(); err == nil && rowsAffected > 0 {
        log.Printf("Cleaned up %d expired sessions", rowsAffected)
        
        // Log security event for session cleanup
        ut.logSecurityEvent(SecurityEvent{
            EventType: "session_cleanup",
            Severity:  "info",
            IPAddress: "system",
            Details: map[string]interface{}{
                "sessions_cleaned": rowsAffected,
                "cleanup_reason": "expired_or_idle",
                "idle_timeout": ut.sessionIdleTimeout.String(),
            },
        })
    }
}

// invalidateUserSessions invalidates all sessions for a specific user
func (ut *UnifiedTokenizer) invalidateUserSessions(userID string, reason string) error {
    result, err := ut.db.Exec(`
        UPDATE user_sessions 
        SET is_active = FALSE 
        WHERE user_id = ? AND is_active = TRUE
    `, userID)
    
    if err != nil {
        return fmt.Errorf("failed to invalidate sessions for user %s: %v", userID, err)
    }
    
    rowsAffected, _ := result.RowsAffected()
    if rowsAffected > 0 {
        log.Printf("Invalidated %d sessions for user %s (reason: %s)", rowsAffected, userID, reason)
        
        // Log security event for session invalidation
        ut.logSecurityEvent(SecurityEvent{
            EventType: "sessions_invalidated",
            Severity:  "medium",
            UserID:    userID,
            IPAddress: "system",
            Details: map[string]interface{}{
                "sessions_invalidated": rowsAffected,
                "reason": reason,
                "action": "bulk_session_invalidation",
            },
        })
    }
    
    return nil
}

// invalidateSession invalidates a specific session
func (ut *UnifiedTokenizer) invalidateSession(sessionID string, reason string) error {
    var userID string
    err := ut.db.QueryRow(`
        SELECT user_id FROM user_sessions WHERE session_id = ? AND is_active = TRUE
    `, sessionID).Scan(&userID)
    
    if err == sql.ErrNoRows {
        return nil // Session already invalid or doesn't exist
    } else if err != nil {
        return fmt.Errorf("failed to find session %s: %v", sessionID, err)
    }
    
    _, err = ut.db.Exec(`
        UPDATE user_sessions 
        SET is_active = FALSE 
        WHERE session_id = ?
    `, sessionID)
    
    if err != nil {
        return fmt.Errorf("failed to invalidate session %s: %v", sessionID, err)
    }
    
    log.Printf("Invalidated session %s (reason: %s)", sessionID, reason)
    
    // Log security event for single session invalidation
    ut.logSecurityEvent(SecurityEvent{
        EventType: "session_invalidated",
        Severity:  "info",
        UserID:    userID,
        IPAddress: "system",
        Details: map[string]interface{}{
            "session_id": sessionID,
            "reason": reason,
            "action": "single_session_invalidation",
        },
    })
    
    return nil
}

func (ut *UnifiedTokenizer) validateSession(sessionID string) (*UserSession, error) {
    var session UserSession
    var user User
    var permissionsJSON []byte
    var lastLoginAt sql.NullTime
    
    err := ut.db.QueryRow(`
        SELECT 
            s.session_id, s.user_id, s.ip_address, s.user_agent,
            s.created_at, s.expires_at, s.last_activity_at,
            u.username, u.email, u.full_name, u.role, u.permissions,
            u.is_active, u.created_at, u.last_login_at
        FROM user_sessions s
        JOIN users u ON s.user_id = u.user_id
        WHERE s.session_id = ? 
          AND s.is_active = TRUE 
          AND s.expires_at > NOW()
          AND u.is_active = TRUE
    `, sessionID).Scan(
        &session.SessionID, &session.UserID, &session.IPAddress, &session.UserAgent,
        &session.CreatedAt, &session.ExpiresAt, &session.LastActivity,
        &user.Username, &user.Email, &user.FullName, &user.Role, &permissionsJSON,
        &user.IsActive, &user.CreatedAt, &lastLoginAt,
    )
    
    if err == sql.ErrNoRows {
        return nil, errors.New("invalid or expired session")
    } else if err != nil {
        return nil, err
    }
    
    // Check idle timeout
    now := time.Now()
    if now.Sub(session.LastActivity) > ut.sessionIdleTimeout {
        // Session has been idle too long, invalidate it
        ut.db.Exec(`
            UPDATE user_sessions 
            SET is_active = FALSE 
            WHERE session_id = ?
        `, sessionID)
        
        // Log security event for idle session expiry
        ut.logSecurityEvent(SecurityEvent{
            EventType: "session_idle_expired",
            Severity:  "info",
            UserID:    session.UserID,
            Username:  user.Username,
            IPAddress: session.IPAddress,
            Details: map[string]interface{}{
                "session_id": sessionID,
                "idle_duration": now.Sub(session.LastActivity).String(),
                "idle_timeout": ut.sessionIdleTimeout.String(),
            },
        })
        
        return nil, errors.New("session expired due to inactivity")
    }
    
    // Calculate new expiry time based on idle timeout and absolute timeout
    absoluteExpiry := session.CreatedAt.Add(ut.sessionTimeout)
    idleExpiry := now.Add(ut.sessionIdleTimeout)
    
    // Use the earlier of the two expiry times
    newExpiresAt := idleExpiry
    if absoluteExpiry.Before(idleExpiry) {
        newExpiresAt = absoluteExpiry
    }
    
    // Update last activity and potentially extend expiry
    _, err = ut.db.Exec(`
        UPDATE user_sessions 
        SET last_activity_at = NOW(), expires_at = ?
        WHERE session_id = ?
    `, newExpiresAt, sessionID)
    
    if err != nil {
        log.Printf("Error updating session activity for %s: %v", sessionID, err)
    }
    
    // Parse user data
    user.UserID = session.UserID
    json.Unmarshal(permissionsJSON, &user.Permissions)
    if lastLoginAt.Valid {
        user.LastLoginAt = &lastLoginAt.Time
    }
    
    // Update session object with new values
    session.User = &user
    session.LastActivity = now
    session.ExpiresAt = newExpiresAt
    
    return &session, nil
}

func (ut *UnifiedTokenizer) hasPermission(user *User, permission string) bool {
    // System admin has all permissions
    for _, p := range user.Permissions {
        if p == PermSystemAdmin || p == permission {
            return true
        }
    }
    
    // Check role-based permissions
    switch user.Role {
    case RoleAdmin:
        return true // Admin has all permissions
    case RoleOperator:
        // Operators can read/write/delete tokens and view activity
        operatorPerms := []string{
            PermTokensRead, PermTokensWrite, PermTokensDelete,
            PermActivityRead, PermStatsRead,
        }
        for _, p := range operatorPerms {
            if p == permission {
                return true
            }
        }
    case RoleViewer:
        // Viewers have read-only access
        viewerPerms := []string{
            PermTokensRead, PermActivityRead, PermStatsRead,
        }
        for _, p := range viewerPerms {
            if p == permission {
                return true
            }
        }
    }
    
    return false
}

func (ut *UnifiedTokenizer) requirePermission(handler http.HandlerFunc, permission string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Check for API key first (backward compatibility)
        apiKey := r.Header.Get("X-API-Key")
        if apiKey != "" {
            // Validate API key
            var userID sql.NullString
            var isActive bool
            err := ut.db.QueryRow(`
                SELECT user_id, is_active FROM api_keys 
                WHERE api_key = ?
            `, apiKey).Scan(&userID, &isActive)
            
            if err == nil && isActive {
                // Update last used timestamp
                ut.db.Exec("UPDATE api_keys SET last_used_at = NOW() WHERE api_key = ?", apiKey)
                
                // If API key has associated user, check their permissions
                if userID.Valid && userID.String != "" {
                    var user User
                    var permissionsJSON []byte
                    err := ut.db.QueryRow(`
                        SELECT user_id, username, email, full_name, role, permissions, is_active
                        FROM users WHERE user_id = ? AND is_active = TRUE
                    `, userID.String).Scan(
                        &user.UserID, &user.Username, &user.Email, &user.FullName,
                        &user.Role, &permissionsJSON, &user.IsActive,
                    )
                    
                    if err == nil {
                        json.Unmarshal(permissionsJSON, &user.Permissions)
                        if ut.hasPermission(&user, permission) {
                            r.Header.Set("X-User-ID", user.UserID)
                            r.Header.Set("X-Username", user.Username)
                            handler(w, r)
                            return
                        }
                    }
                } else {
                    // Legacy API key without user - allow for backward compatibility
                    // but only for certain permissions
                    legacyAllowedPerms := []string{
                        PermTokensRead, PermTokensWrite, PermActivityRead, PermStatsRead,
                    }
                    for _, p := range legacyAllowedPerms {
                        if p == permission {
                            r.Header.Set("X-User-ID", "api_key_" + apiKey[:8])
                            r.Header.Set("X-Username", "API Key User")
                            handler(w, r)
                            return
                        }
                    }
                }
                
                w.WriteHeader(http.StatusForbidden)
                json.NewEncoder(w).Encode(map[string]string{"error": "Insufficient permissions"})
                return
            }
        }
        
        // Check for session cookie or Authorization header
        var sessionID string
        
        // Try cookie first
        cookie, err := r.Cookie("session_id")
        if err == nil {
            sessionID = cookie.Value
        }
        
        // Try Authorization header
        if sessionID == "" {
            auth := r.Header.Get("Authorization")
            if strings.HasPrefix(auth, "Bearer ") {
                sessionID = strings.TrimPrefix(auth, "Bearer ")
            }
        }
        
        if sessionID == "" {
            w.WriteHeader(http.StatusUnauthorized)
            json.NewEncoder(w).Encode(map[string]string{"error": "Authentication required"})
            return
        }
        
        // Validate session
        session, err := ut.validateSession(sessionID)
        if err != nil {
            w.WriteHeader(http.StatusUnauthorized)
            json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
            return
        }
        
        // Check permission
        if !ut.hasPermission(session.User, permission) {
            w.WriteHeader(http.StatusForbidden)
            json.NewEncoder(w).Encode(map[string]string{"error": "Insufficient permissions"})
            return
        }
        
        // Add user to request context
        r.Header.Set("X-User-ID", session.User.UserID)
        r.Header.Set("X-Username", session.User.Username)
        
        handler(w, r)
    }
}

// startSessionCleanupService runs a background cleanup service for expired sessions
func (ut *UnifiedTokenizer) startSessionCleanupService() {
    // Run cleanup immediately on startup
    ut.cleanupExpiredSessions()
    
    // Set up periodic cleanup every 15 minutes
    ticker := time.NewTicker(15 * time.Minute)
    defer ticker.Stop()
    
    log.Printf("Session cleanup service started (runs every 15 minutes)")
    
    for {
        select {
        case <-ticker.C:
            ut.cleanupExpiredSessions()
        }
    }
}

func main() {
    log.SetFlags(log.LstdFlags | log.Lshortfile)
    
    ut, err := NewUnifiedTokenizer()
    if err != nil {
        log.Fatalf("Failed to initialize tokenizer: %v", err)
    }
    defer ut.db.Close()
    
    log.Printf("TokenShield Unified Service starting...")
    log.Printf("HTTP Port: %s, ICAP Port: %s, API Port: %s", ut.httpPort, ut.icapPort, ut.apiPort)
    log.Printf("App Endpoint: %s", ut.appEndpoint)
    log.Printf("Token Format: %s", ut.tokenFormat)
    log.Printf("KEK/DEK Encryption: %v", ut.useKEKDEK)
    
    // Create default admin user if needed
    if err := ut.createDefaultAdminUser(); err != nil {
        log.Printf("Warning: Failed to create default admin user: %v", err)
    }
    
    // Start background session cleanup goroutine
    go ut.startSessionCleanupService()
    
    // Start all three servers
    go ut.startHTTPServer()
    go ut.startAPIServer()
    ut.startICAPServer()
}