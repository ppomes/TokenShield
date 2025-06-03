package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

// Global configuration
var (
	cfgFile     string
	apiURL      string
	apiKey      string
	adminSecret string
	sessionID   string
	verbose     bool
)

// API client
type TokenShieldClient struct {
	BaseURL     string
	APIKey      string
	AdminSecret string
	SessionID   string
	HTTPClient  *http.Client
}

// Auth structures
type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct {
	SessionID string    `json:"session_id"`
	User      User      `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
}

type User struct {
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	FullName    string   `json:"full_name"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	IsActive    bool     `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
}

func NewClient(baseURL, apiKey, adminSecret, sessionID string) *TokenShieldClient {
	return &TokenShieldClient{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		APIKey:      apiKey,
		AdminSecret: adminSecret,
		SessionID:   sessionID,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *TokenShieldClient) makeRequest(method, endpoint string, body io.Reader) (*http.Response, error) {
	url := c.BaseURL + endpoint
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	// Use session-based authentication (like GUI)
	if c.SessionID != "" {
		req.Header.Set("Authorization", "Bearer "+c.SessionID)
	}
	if c.AdminSecret != "" {
		req.Header.Set("X-Admin-Secret", c.AdminSecret)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.HTTPClient.Do(req)
}

// Root command
var rootCmd = &cobra.Command{
	Use:   "tokenshield",
	Short: "TokenShield CLI - Manage credit card tokenization",
	Long: `TokenShield CLI is a command-line tool for managing credit card tokenization.
	
It provides commands to:
- Manage tokens (list, search, revoke)
- Manage API keys (create, list, revoke)
- Monitor activity and statistics
- Manage encryption keys`,
}

// Version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		client := NewClient(apiURL, apiKey, adminSecret, sessionID)
		resp, err := client.makeRequest("GET", "/api/v1/version", nil)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			fmt.Printf("API Error: %s\n", resp.Status)
			os.Exit(1)
		}

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			fmt.Printf("Error parsing response: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("TokenShield CLI v1.0.0\n")
		fmt.Printf("Server Version: %s\n", result["version"])
		fmt.Printf("Token Format: %s\n", result["token_format"])
		fmt.Printf("KEK/DEK Enabled: %v\n", result["kek_dek_enabled"])
		fmt.Printf("Features: %v\n", result["features"])
	},
}

// Config commands
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage CLI configuration",
	Long:  "Commands for managing CLI configuration and security",
}

var configSecureCmd = &cobra.Command{
	Use:   "secure",
	Short: "Secure the configuration file permissions",
	Long:  "Set restrictive permissions (600) on the configuration file to protect credentials",
	Run: func(cmd *cobra.Command, args []string) {
		configFile := viper.ConfigFileUsed()
		if configFile == "" {
			fmt.Println("No configuration file found")
			return
		}
		
		// Check if config file contains sensitive data
		hasSensitiveData := viper.GetString("session_id") != ""
		
		if !hasSensitiveData {
			fmt.Printf("Configuration file %s contains no sensitive data\n", configFile)
			return
		}
		
		// Check current permissions
		fileInfo, err := os.Stat(configFile)
		if err != nil {
			fmt.Printf("Error checking file: %v\n", err)
			return
		}
		
		currentPerm := fileInfo.Mode().Perm()
		
		// Check if already secure
		if currentPerm&0077 == 0 {
			fmt.Printf("✅ Configuration file %s already has secure permissions (%o)\n", configFile, currentPerm)
			return
		}
		
		// Fix permissions
		if err := os.Chmod(configFile, 0600); err != nil {
			fmt.Printf("❌ Error setting permissions: %v\n", err)
			fmt.Printf("Please run manually: chmod 600 %s\n", configFile)
			return
		}
		
		fmt.Printf("✅ Successfully secured configuration file %s\n", configFile)
		fmt.Printf("   Previous permissions: %o\n", currentPerm)
		fmt.Printf("   New permissions: 600 (read/write for owner only)\n")
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Long:  "Display current configuration file location and security status",
	Run: func(cmd *cobra.Command, args []string) {
		configFile := viper.ConfigFileUsed()
		if configFile == "" {
			fmt.Println("No configuration file found")
			fmt.Println("Default locations:")
			home, _ := os.UserHomeDir()
			fmt.Printf("  - %s/.tokenshield.yaml\n", home)
			fmt.Printf("  - ./.tokenshield.yaml\n")
			return
		}
		
		fmt.Printf("Configuration file: %s\n", configFile)
		
		// Check permissions
		fileInfo, err := os.Stat(configFile)
		if err != nil {
			fmt.Printf("Error checking file: %v\n", err)
			return
		}
		
		perm := fileInfo.Mode().Perm()
		fmt.Printf("File permissions: %o\n", perm)
		
		// Check if secure
		if perm&0077 == 0 {
			fmt.Printf("Security status: ✅ Secure (owner access only)\n")
		} else {
			fmt.Printf("Security status: ⚠️  Insecure (readable by group/others)\n")
		}
		
		// Show configured values (without revealing secrets)
		fmt.Println("\nConfiguration:")
		fmt.Printf("  API URL: %s\n", viper.GetString("api_url"))
		
		// API keys removed - CLI now uses session-based authentication like GUI
		
		if viper.GetString("session_id") != "" {
			fmt.Printf("  Session: active (expires: %s)\n", viper.GetString("session_expires"))
		} else {
			fmt.Printf("  Session: not logged in\n")
		}
	},
}


// Token commands
var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage tokens",
	Long:  "Commands for managing credit card tokens",
}

var tokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tokens",
	Run: func(cmd *cobra.Command, args []string) {
		limit, _ := cmd.Flags().GetInt("limit")
		
		client := NewClient(apiURL, apiKey, adminSecret, sessionID)
		endpoint := fmt.Sprintf("/api/v1/tokens?limit=%d", limit)
		resp, err := client.makeRequest("GET", endpoint, nil)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			fmt.Printf("API Error: %s\n", resp.Status)
			os.Exit(1)
		}

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			fmt.Printf("Error parsing response: %v\n", err)
			os.Exit(1)
		}

		tokens := result["tokens"].([]interface{})
		
		fmt.Printf("Found %d tokens:\n\n", len(tokens))
		fmt.Printf("%-50s %-12s %-8s %-10s %-20s\n", "TOKEN", "CARD_TYPE", "LAST_4", "ACTIVE", "CREATED")
		fmt.Printf("%s\n", strings.Repeat("-", 100))
		
		for _, t := range tokens {
			token := t.(map[string]interface{})
			cardType := "Unknown"
			if token["card_type"] != nil {
				cardType = token["card_type"].(string)
			}
			
			fmt.Printf("%-50s %-12s %-8s %-10v %-20s\n",
				truncateString(token["token"].(string), 47),
				cardType,
				token["last_four"].(string),
				token["is_active"].(bool),
				formatTime(token["created_at"].(string)),
			)
		}
	},
}

var tokenSearchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search tokens with filters",
	Run: func(cmd *cobra.Command, args []string) {
		lastFour, _ := cmd.Flags().GetString("last-four")
		cardType, _ := cmd.Flags().GetString("card-type")
		limit, _ := cmd.Flags().GetInt("limit")
		active, _ := cmd.Flags().GetBool("active")
		
		searchReq := map[string]interface{}{
			"limit": limit,
		}
		
		if lastFour != "" {
			searchReq["last_four"] = lastFour
		}
		if cardType != "" {
			searchReq["card_type"] = cardType
		}
		if cmd.Flags().Changed("active") {
			searchReq["is_active"] = active
		}
		
		reqBody, _ := json.Marshal(searchReq)
		
		client := NewClient(apiURL, apiKey, adminSecret, sessionID)
		resp, err := client.makeRequest("POST", "/api/v1/tokens/search", strings.NewReader(string(reqBody)))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			fmt.Printf("API Error: %s\n", resp.Status)
			os.Exit(1)
		}

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			fmt.Printf("Error parsing response: %v\n", err)
			os.Exit(1)
		}

		tokens := result["tokens"].([]interface{})
		
		fmt.Printf("Search found %d tokens:\n\n", len(tokens))
		fmt.Printf("%-50s %-12s %-8s %-10s %-20s\n", "TOKEN", "CARD_TYPE", "LAST_4", "ACTIVE", "CREATED")
		fmt.Printf("%s\n", strings.Repeat("-", 100))
		
		for _, t := range tokens {
			token := t.(map[string]interface{})
			cardType := "Unknown"
			if token["card_type"] != nil {
				cardType = token["card_type"].(string)
			}
			
			fmt.Printf("%-50s %-12s %-8s %-10v %-20s\n",
				truncateString(token["token"].(string), 47),
				cardType,
				token["last_four"].(string),
				token["is_active"].(bool),
				formatTime(token["created_at"].(string)),
			)
		}
	},
}

var tokenRevokeCmd = &cobra.Command{
	Use:   "revoke [token]",
	Short: "Revoke a token",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		token := args[0]
		
		client := NewClient(apiURL, apiKey, adminSecret, sessionID)
		endpoint := fmt.Sprintf("/api/v1/tokens/%s", token)
		resp, err := client.makeRequest("DELETE", endpoint, nil)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			fmt.Printf("Token %s revoked successfully\n", token)
		} else if resp.StatusCode == 404 {
			fmt.Printf("Token not found: %s\n", token)
		} else {
			fmt.Printf("API Error: %s\n", resp.Status)
			os.Exit(1)
		}
	},
}

// API Key commands
var apiKeyCmd = &cobra.Command{
	Use:   "apikey",
	Short: "Manage API keys",
	Long:  "Commands for managing API keys (requires admin privileges)",
}

var apiKeyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all API keys",
	Run: func(cmd *cobra.Command, args []string) {
		client := NewClient(apiURL, apiKey, adminSecret, sessionID)
		resp, err := client.makeRequest("GET", "/api/v1/api-keys", nil)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			fmt.Printf("API Error: %s\n", resp.Status)
			os.Exit(1)
		}

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			fmt.Printf("Error parsing response: %v\n", err)
			os.Exit(1)
		}

		apiKeys := result["api_keys"].([]interface{})
		
		fmt.Printf("Found %d API keys:\n\n", len(apiKeys))
		fmt.Printf("%-30s %-20s %-10s %-20s\n", "API_KEY", "CLIENT_NAME", "ACTIVE", "CREATED")
		fmt.Printf("%s\n", strings.Repeat("-", 80))
		
		for _, k := range apiKeys {
			key := k.(map[string]interface{})
			
			fmt.Printf("%-30s %-20s %-10v %-20s\n",
				truncateString(key["api_key"].(string), 27),
				key["client_name"].(string),
				key["is_active"].(bool),
				formatTime(key["created_at"].(string)),
			)
		}
	},
}

var apiKeyCreateCmd = &cobra.Command{
	Use:   "create [client-name]",
	Short: "Create a new API key",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		clientName := args[0]
		permissions, _ := cmd.Flags().GetStringSlice("permissions")
		
		createReq := map[string]interface{}{
			"client_name": clientName,
			"permissions": permissions,
		}
		
		reqBody, _ := json.Marshal(createReq)
		
		client := NewClient(apiURL, apiKey, adminSecret, sessionID)
		resp, err := client.makeRequest("POST", "/api/v1/api-keys", strings.NewReader(string(reqBody)))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				fmt.Printf("Error parsing response: %v\n", err)
				os.Exit(1)
			}
			
			fmt.Printf("API key created successfully:\n")
			fmt.Printf("API Key: %s\n", result["api_key"])
			fmt.Printf("Client: %s\n", result["client_name"])
			fmt.Printf("Permissions: %v\n", result["permissions"])
		} else {
			fmt.Printf("API Error: %s\n", resp.Status)
			os.Exit(1)
		}
	},
}

// Activity command
var activityCmd = &cobra.Command{
	Use:   "activity",
	Short: "Show recent activity",
	Run: func(cmd *cobra.Command, args []string) {
		limit, _ := cmd.Flags().GetInt("limit")
		
		client := NewClient(apiURL, apiKey, adminSecret, sessionID)
		endpoint := fmt.Sprintf("/api/v1/activity?limit=%d", limit)
		resp, err := client.makeRequest("GET", endpoint, nil)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			fmt.Printf("API Error: %s\n", resp.Status)
			os.Exit(1)
		}

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			fmt.Printf("Error parsing response: %v\n", err)
			os.Exit(1)
		}

		activities := result["activities"].([]interface{})
		
		fmt.Printf("Recent activity (%d entries):\n\n", len(activities))
		fmt.Printf("%-20s %-12s %-8s %-15s %-20s\n", "TIMESTAMP", "TYPE", "LAST_4", "SOURCE_IP", "STATUS")
		fmt.Printf("%s\n", strings.Repeat("-", 80))
		
		for _, a := range activities {
			activity := a.(map[string]interface{})
			
			lastFour := "N/A"
			if activity["card_last_four"] != nil {
				lastFour = activity["card_last_four"].(string)
			}
			
			status := "N/A"
			if activity["status"] != nil {
				status = fmt.Sprintf("%.0f", activity["status"].(float64))
			}
			
			fmt.Printf("%-20s %-12s %-8s %-15s %-20s\n",
				formatTime(activity["timestamp"].(string)),
				activity["type"].(string),
				lastFour,
				activity["source_ip"].(string),
				status,
			)
		}
	},
}

// Stats command
var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show system statistics",
	Run: func(cmd *cobra.Command, args []string) {
		client := NewClient(apiURL, apiKey, adminSecret, sessionID)
		resp, err := client.makeRequest("GET", "/api/v1/stats", nil)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			fmt.Printf("API Error: %s\n", resp.Status)
			os.Exit(1)
		}

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			fmt.Printf("Error parsing response: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("TokenShield Statistics:\n\n")
		fmt.Printf("Active Tokens: %.0f\n", result["active_tokens"].(float64))
		
		if requests, ok := result["requests_24h"].(map[string]interface{}); ok {
			fmt.Printf("\nRequests (24h):\n")
			for reqType, count := range requests {
				fmt.Printf("  %s: %.0f\n", reqType, count.(float64))
			}
		}
	},
}

// Login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to TokenShield",
	Long:  `Authenticate with TokenShield using username and password`,
	Run: func(cmd *cobra.Command, args []string) {
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		
		if username == "" {
			fmt.Print("Username: ")
			fmt.Scanln(&username)
		}
		
		if password == "" {
			fmt.Print("Password: ")
			// Hide password input
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				fmt.Printf("Error reading password: %v\n", err)
				os.Exit(1)
			}
			password = string(bytePassword)
			fmt.Println() // New line after hidden input
		}
		
		client := NewClient(apiURL, "", "", "")
		
		authReq := AuthRequest{
			Username: username,
			Password: password,
		}
		
		body, _ := json.Marshal(authReq)
		resp, err := client.makeRequest("POST", "/api/v1/auth/login", strings.NewReader(string(body)))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != 200 {
			var errResp map[string]string
			json.NewDecoder(resp.Body).Decode(&errResp)
			fmt.Printf("Login failed: %s\n", errResp["error"])
			os.Exit(1)
		}
		
		var authResp AuthResponse
		if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
			fmt.Printf("Error parsing response: %v\n", err)
			os.Exit(1)
		}
		
		// Save session to config
		viper.Set("session_id", authResp.SessionID)
		viper.Set("session_expires", authResp.ExpiresAt.Format(time.RFC3339))
		viper.Set("username", authResp.User.Username)
		
		// Ensure API URL is saved if not already set
		if viper.GetString("api_url") == "" {
			viper.Set("api_url", apiURL)
		}
		
		// Write config file
		if err := viper.WriteConfig(); err != nil {
			// Config file doesn't exist, create it
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Printf("Error getting home directory: %v\n", err)
				os.Exit(1)
			}
			
			configPath := home + "/.tokenshield.yaml"
			viper.SetConfigFile(configPath)
			
			if err := viper.WriteConfigAs(configPath); err != nil {
				fmt.Printf("Error creating config file: %v\n", err)
				fmt.Printf("Session saved temporarily but won't persist\n")
			} else {
				fmt.Printf("Created config file: %s\n", configPath)
				// Set secure permissions on new config file
				os.Chmod(configPath, 0600)
			}
		}
		
		fmt.Printf("Successfully logged in as %s (%s)\n", authResp.User.Username, authResp.User.Role)
		fmt.Printf("Session expires: %s\n", authResp.ExpiresAt.Local().Format("2006-01-02 15:04:05"))
	},
}

// Logout command
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout from TokenShield",
	Long:  `Invalidate the current session`,
	Run: func(cmd *cobra.Command, args []string) {
		client := NewClient(apiURL, apiKey, adminSecret, sessionID)
		
		resp, err := client.makeRequest("POST", "/api/v1/auth/logout", nil)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		
		// Clear session from config
		viper.Set("session_id", "")
		viper.Set("session_expires", "")
		viper.Set("username", "")
		viper.WriteConfig()
		
		fmt.Println("Successfully logged out")
	},
}

// User management commands
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "User management commands",
	Long:  `Commands for managing TokenShield users`,
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users",
	Run: func(cmd *cobra.Command, args []string) {
		client := NewClient(apiURL, apiKey, adminSecret, sessionID)
		
		resp, err := client.makeRequest("GET", "/api/v1/users", nil)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != 200 {
			var errResp map[string]string
			json.NewDecoder(resp.Body).Decode(&errResp)
			fmt.Printf("Error: %s\n", errResp["error"])
			os.Exit(1)
		}
		
		var result struct {
			Users []User `json:"users"`
			Total int    `json:"total"`
		}
		
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			fmt.Printf("Error parsing response: %v\n", err)
			os.Exit(1)
		}
		
		fmt.Printf("Users (%d total):\n\n", result.Total)
		fmt.Printf("%-20s %-15s %-25s %-10s %-10s\n", "Username", "Role", "Email", "Active", "Created")
		fmt.Println(strings.Repeat("-", 85))
		
		for _, user := range result.Users {
			active := "Yes"
			if !user.IsActive {
				active = "No"
			}
			fmt.Printf("%-20s %-15s %-25s %-10s %-10s\n",
				truncateString(user.Username, 20),
				user.Role,
				truncateString(user.Email, 25),
				active,
				user.CreatedAt.Format("2006-01-02"),
			)
		}
	},
}

var userCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user",
	Run: func(cmd *cobra.Command, args []string) {
		username, _ := cmd.Flags().GetString("username")
		email, _ := cmd.Flags().GetString("email")
		password, _ := cmd.Flags().GetString("password")
		fullName, _ := cmd.Flags().GetString("full-name")
		role, _ := cmd.Flags().GetString("role")
		
		if username == "" || email == "" || password == "" {
			fmt.Println("Error: username, email, and password are required")
			os.Exit(1)
		}
		
		client := NewClient(apiURL, apiKey, adminSecret, sessionID)
		
		user := map[string]interface{}{
			"username":  username,
			"email":     email,
			"password":  password,
			"full_name": fullName,
			"role":      role,
		}
		
		body, _ := json.Marshal(user)
		resp, err := client.makeRequest("POST", "/api/v1/users", strings.NewReader(string(body)))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != 201 {
			var errResp map[string]string
			json.NewDecoder(resp.Body).Decode(&errResp)
			fmt.Printf("Error: %s\n", errResp["error"])
			os.Exit(1)
		}
		
		var newUser User
		if err := json.NewDecoder(resp.Body).Decode(&newUser); err != nil {
			fmt.Printf("Error parsing response: %v\n", err)
			os.Exit(1)
		}
		
		fmt.Printf("User created successfully:\n")
		fmt.Printf("  ID: %s\n", newUser.UserID)
		fmt.Printf("  Username: %s\n", newUser.Username)
		fmt.Printf("  Email: %s\n", newUser.Email)
		fmt.Printf("  Role: %s\n", newUser.Role)
	},
}

var userDeleteCmd = &cobra.Command{
	Use:   "delete [username]",
	Short: "Delete a user",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			fmt.Printf("Are you sure you want to delete user '%s'? (y/N): ", username)
			var confirm string
			fmt.Scanln(&confirm)
			if confirm != "y" && confirm != "Y" {
				fmt.Println("Cancelled")
				return
			}
		}
		
		client := NewClient(apiURL, apiKey, adminSecret, sessionID)
		
		resp, err := client.makeRequest("DELETE", "/api/v1/users/"+username, nil)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != 200 {
			var errResp map[string]string
			json.NewDecoder(resp.Body).Decode(&errResp)
			fmt.Printf("Error: %s\n", errResp["error"])
			os.Exit(1)
		}
		
		fmt.Printf("User '%s' deleted successfully\n", username)
	},
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show current user information",
	Run: func(cmd *cobra.Command, args []string) {
		client := NewClient(apiURL, apiKey, adminSecret, sessionID)
		
		resp, err := client.makeRequest("GET", "/api/v1/auth/me", nil)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != 200 {
			fmt.Println("Not logged in")
			os.Exit(1)
		}
		
		var user User
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			fmt.Printf("Error parsing response: %v\n", err)
			os.Exit(1)
		}
		
		fmt.Printf("Current user:\n")
		fmt.Printf("  Username: %s\n", user.Username)
		fmt.Printf("  Email: %s\n", user.Email)
		fmt.Printf("  Full Name: %s\n", user.FullName)
		fmt.Printf("  Role: %s\n", user.Role)
		fmt.Printf("  Permissions: %s\n", strings.Join(user.Permissions, ", "))
	},
}

// Utility functions
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatTime(timeStr string) string {
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return timeStr
	}
	return t.Format("2006-01-02 15:04:05")
}

func checkConfigFileSecurity() {
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		return // No config file in use
	}
	
	// Check if config file contains sensitive data
	hasSensitiveData := viper.GetString("session_id") != ""
	
	if !hasSensitiveData {
		return // No sensitive data to protect
	}
	
	// Check file permissions
	fileInfo, err := os.Stat(configFile)
	if err != nil {
		return // Can't check permissions
	}
	
	perm := fileInfo.Mode().Perm()
	
	// Check if file is readable by group or others (should be 600 or 400)
	if perm&0077 != 0 {
		fmt.Fprintf(os.Stderr, "\n⚠️  SECURITY WARNING: Config file has insecure permissions\n")
		fmt.Fprintf(os.Stderr, "   File: %s\n", configFile)
		fmt.Fprintf(os.Stderr, "   Current permissions: %o\n", perm)
		fmt.Fprintf(os.Stderr, "   Recommended: 600 (read/write for owner only)\n")
		fmt.Fprintf(os.Stderr, "   \n")
		fmt.Fprintf(os.Stderr, "   Your config file contains sensitive credentials (session tokens)\n")
		fmt.Fprintf(os.Stderr, "   that could be read by other users on this system.\n")
		fmt.Fprintf(os.Stderr, "   \n")
		fmt.Fprintf(os.Stderr, "   To fix this, run: chmod 600 %s\n", configFile)
		fmt.Fprintf(os.Stderr, "   \n")
	}
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".tokenshield")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	// Set defaults from config or environment
	if apiURL == "" {
		apiURL = viper.GetString("api_url")
		if apiURL == "" {
			apiURL = "http://localhost:8090"
		}
	}
	
	// API keys removed - using session-based authentication only
	// Admin secret only used as fallback for bootstrapping (e.g., creating initial user)
	if adminSecret == "" {
		adminSecret = viper.GetString("admin_secret")
	}
	
	// Load session from config
	if sessionID == "" {
		sessionID = viper.GetString("session_id")
		// Check if session is expired
		if expiresStr := viper.GetString("session_expires"); expiresStr != "" {
			if expires, err := time.Parse(time.RFC3339, expiresStr); err == nil {
				if time.Now().After(expires) {
					// Session expired, clear it
					sessionID = ""
					viper.Set("session_id", "")
					viper.Set("session_expires", "")
					viper.Set("username", "")
				}
			}
		}
	}
	
	// Check config file security after loading sensitive data
	checkConfigFileSecurity()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.tokenshield.yaml)")
	rootCmd.PersistentFlags().StringVar(&apiURL, "api-url", "", "TokenShield API URL (default: http://localhost:8090)")
	// API key flag removed - using session-based authentication only
	// Admin secret flag removed - using session-based authentication only
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	// Token command flags
	tokenListCmd.Flags().IntP("limit", "l", 100, "Maximum number of tokens to list")
	tokenSearchCmd.Flags().String("last-four", "", "Filter by last four digits")
	tokenSearchCmd.Flags().String("card-type", "", "Filter by card type (Visa, Mastercard, etc.)")
	tokenSearchCmd.Flags().IntP("limit", "l", 50, "Maximum number of tokens to return")
	tokenSearchCmd.Flags().Bool("active", true, "Filter by active status")

	// API key command flags
	apiKeyCreateCmd.Flags().StringSlice("permissions", []string{"read", "write"}, "Permissions for the API key")
	
	// Activity command flags
	activityCmd.Flags().IntP("limit", "l", 50, "Maximum number of activities to show")
	
	// Login command flags
	loginCmd.Flags().StringP("username", "u", "", "Username")
	loginCmd.Flags().StringP("password", "p", "", "Password")
	
	// User command flags
	userCreateCmd.Flags().String("username", "", "Username (required)")
	userCreateCmd.Flags().String("email", "", "Email address (required)")
	userCreateCmd.Flags().String("password", "", "Password (required)")
	userCreateCmd.Flags().String("full-name", "", "Full name")
	userCreateCmd.Flags().String("role", "viewer", "User role (admin, operator, viewer)")
	userCreateCmd.MarkFlagRequired("username")
	userCreateCmd.MarkFlagRequired("email")
	userCreateCmd.MarkFlagRequired("password")
	
	userDeleteCmd.Flags().BoolP("force", "f", false, "Skip confirmation prompt")

	// Add commands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(whoamiCmd)
	rootCmd.AddCommand(tokenCmd)
	rootCmd.AddCommand(apiKeyCmd)
	rootCmd.AddCommand(userCmd)
	rootCmd.AddCommand(activityCmd)
	rootCmd.AddCommand(statsCmd)

	tokenCmd.AddCommand(tokenListCmd)
	tokenCmd.AddCommand(tokenSearchCmd)
	tokenCmd.AddCommand(tokenRevokeCmd)

	apiKeyCmd.AddCommand(apiKeyListCmd)
	apiKeyCmd.AddCommand(apiKeyCreateCmd)
	
	userCmd.AddCommand(userListCmd)
	userCmd.AddCommand(userCreateCmd)
	userCmd.AddCommand(userDeleteCmd)
	
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configSecureCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}