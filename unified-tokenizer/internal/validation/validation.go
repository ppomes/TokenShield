package validation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"tokenshield-unified/internal/utils"
)

// ValidationRule defines validation criteria for a field
type ValidationRule struct {
	FieldName       string                    `json:"field_name"`
	Required        bool                      `json:"required"`
	MinLength       int                       `json:"min_length,omitempty"`
	MaxLength       int                       `json:"max_length,omitempty"`
	Pattern         *regexp.Regexp            `json:"-"`
	AllowedChars    string                    `json:"allowed_chars,omitempty"`
	Sanitize        bool                      `json:"sanitize"`
	CustomValidator func(interface{}) error   `json:"-"`
}

// ValidationConfig defines validation rules for an endpoint
type ValidationConfig struct {
	MaxRequestSize  int64                     `json:"max_request_size"`
	AllowedMethods  []string                  `json:"allowed_methods"`
	RequiredHeaders []string                  `json:"required_headers,omitempty"`
	Rules           map[string]ValidationRule `json:"rules"`
}

// ValidationError represents a validation failure
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   string `json:"value,omitempty"`
}

// ValidationResult contains the outcome of validation
type ValidationResult struct {
	Valid  bool                   `json:"valid"`
	Errors []ValidationError      `json:"errors,omitempty"`
	Data   map[string]interface{} `json:"data,omitempty"`
}

// Validator manages validation configurations and operations
type Validator struct {
	configs map[string]ValidationConfig
}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	return &Validator{
		configs: make(map[string]ValidationConfig),
	}
}

// SetConfig sets validation configuration for an endpoint
func (v *Validator) SetConfig(endpoint string, config ValidationConfig) {
	v.configs[endpoint] = config
}

// ValidateField validates a single field against its rules
func ValidateField(fieldName string, value interface{}, rule ValidationRule) []ValidationError {
	var errors []ValidationError
	
	// Convert value to string for most validations
	strValue := ""
	if value != nil {
		strValue = fmt.Sprintf("%v", value)
	}
	
	// Required field check
	if rule.Required && (value == nil || strValue == "") {
		errors = append(errors, ValidationError{
			Field:   fieldName,
			Message: "field is required",
		})
		return errors // If required and empty, no point in further validation
	}
	
	// Skip further validation if field is empty and not required
	if strValue == "" {
		return errors
	}
	
	// SQL injection check
	if utils.DetectSQLInjection(strValue) {
		errors = append(errors, ValidationError{
			Field:   fieldName,
			Message: "potentially dangerous content detected",
			Value:   strValue,
		})
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
			Value:   strValue[:min(50, len(strValue))] + "...", // Truncate for security
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

// ValidateRequest validates a complete request against endpoint configuration
func (v *Validator) ValidateRequest(endpoint string, data map[string]interface{}) ValidationResult {
	result := ValidationResult{
		Valid:  true,
		Errors: []ValidationError{},
		Data:   make(map[string]interface{}),
	}
	
	config, exists := v.configs[endpoint]
	if !exists {
		// No validation config means validation passes
		result.Data = data
		return result
	}
	
	// Validate each field according to rules
	for fieldName, rule := range config.Rules {
		value, exists := data[fieldName]
		
		// Check if required field is missing
		if !exists && rule.Required {
			result.Errors = append(result.Errors, ValidationError{
				Field:   fieldName,
				Message: "field is required",
			})
			continue
		}
		
		// Validate field if it exists
		if exists {
			fieldErrors := ValidateField(fieldName, value, rule)
			result.Errors = append(result.Errors, fieldErrors...)
			
			// Sanitize if requested and no validation errors
			if rule.Sanitize && len(fieldErrors) == 0 {
				if strValue, ok := value.(string); ok {
					result.Data[fieldName] = utils.SanitizeString(strValue)
				} else {
					result.Data[fieldName] = value
				}
			} else {
				result.Data[fieldName] = value
			}
		}
	}
	
	// Add fields not covered by validation rules
	for key, value := range data {
		if _, ruleExists := config.Rules[key]; !ruleExists {
			if strValue, ok := value.(string); ok {
				result.Data[key] = utils.SanitizeString(strValue)
			} else {
				result.Data[key] = value
			}
		}
	}
	
	result.Valid = len(result.Errors) == 0
	return result
}

// Middleware creates validation middleware for HTTP handlers
func (v *Validator) Middleware(endpoint string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			config, exists := v.configs[endpoint]
			if !exists {
				// No validation config, proceed normally
				next(w, r)
				return
			}
			
			// Check request size
			if config.MaxRequestSize > 0 && r.ContentLength > config.MaxRequestSize {
				http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
				return
			}
			
			// Check HTTP method
			if len(config.AllowedMethods) > 0 {
				methodAllowed := false
				for _, method := range config.AllowedMethods {
					if r.Method == method {
						methodAllowed = true
						break
					}
				}
				if !methodAllowed {
					http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
					return
				}
			}
			
			// Check required headers
			for _, header := range config.RequiredHeaders {
				if r.Header.Get(header) == "" {
					http.Error(w, fmt.Sprintf("Missing required header: %s", header), http.StatusBadRequest)
					return
				}
			}
			
			// For POST/PUT requests, validate JSON body
			if r.Method == "POST" || r.Method == "PUT" {
				if r.Header.Get("Content-Type") == "application/json" {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, "Failed to read request body", http.StatusBadRequest)
						return
					}
					
					var data map[string]interface{}
					if err := json.Unmarshal(body, &data); err != nil {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusBadRequest)
						json.NewEncoder(w).Encode(map[string]interface{}{
							"error": "Invalid JSON format",
							"details": err.Error(),
						})
						return
					}
					
					// Validate the data
					validationResult := v.ValidateRequest(endpoint, data)
					if !validationResult.Valid {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusBadRequest)
						json.NewEncoder(w).Encode(map[string]interface{}{
							"error": "Validation failed",
							"validation_errors": validationResult.Errors,
						})
						return
					}
					
					// Store validated data in request context or header for handler access
					// For now, we'll continue with the original request
				}
			}
			
			next(w, r)
		}
	}
}

// InitializeStandardConfigs sets up common validation configurations
func (v *Validator) InitializeStandardConfigs() {
	// Common regex patterns
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,50}$`)
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	
	// Login endpoint validation
	v.SetConfig("/api/v1/auth/login", ValidationConfig{
		MaxRequestSize: 1024, // 1KB
		AllowedMethods: []string{"POST"},
		RequiredHeaders: []string{"Content-Type"},
		Rules: map[string]ValidationRule{
			"username": {
				FieldName: "username",
				Required:  true,
				MinLength: 3,
				MaxLength: 50,
				Pattern:   usernameRegex,
				Sanitize:  true,
			},
			"password": {
				FieldName: "password", 
				Required:  true,
				MinLength: 12,
				MaxLength: 100,
				Sanitize:  false, // Don't sanitize passwords
			},
		},
	})
	
	// User creation endpoint
	v.SetConfig("/api/v1/users", ValidationConfig{
		MaxRequestSize: 2048, // 2KB
		AllowedMethods: []string{"POST"},
		RequiredHeaders: []string{"Content-Type"},
		Rules: map[string]ValidationRule{
			"username": {
				FieldName: "username",
				Required:  true,
				MinLength: 3,
				MaxLength: 50,
				Pattern:   usernameRegex,
				Sanitize:  true,
			},
			"email": {
				FieldName: "email",
				Required:  true,
				MaxLength: 100,
				Pattern:   emailRegex,
				Sanitize:  true,
			},
			"password": {
				FieldName: "password",
				Required:  true,
				MinLength: 12,
				MaxLength: 100,
				Sanitize:  false,
			},
			"full_name": {
				FieldName: "full_name",
				Required:  false,
				MaxLength: 100,
				Sanitize:  true,
			},
		},
	})
	
	// Password change endpoint
	v.SetConfig("/api/v1/auth/change-password", ValidationConfig{
		MaxRequestSize: 1024,
		AllowedMethods: []string{"POST"},
		RequiredHeaders: []string{"Content-Type"},
		Rules: map[string]ValidationRule{
			"current_password": {
				FieldName: "current_password",
				Required:  true,
				Sanitize:  false,
			},
			"new_password": {
				FieldName: "new_password",
				Required:  true,
				MinLength: 12,
				MaxLength: 100,
				Sanitize:  false,
			},
		},
	})
}

// Helper function for min operation
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}