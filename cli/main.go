package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Global configuration
var (
	cfgFile   string
	apiURL    string
	apiKey    string
	adminSecret string
	verbose   bool
)

// API client
type TokenShieldClient struct {
	BaseURL     string
	APIKey      string
	AdminSecret string
	HTTPClient  *http.Client
}

func NewClient(baseURL, apiKey, adminSecret string) *TokenShieldClient {
	return &TokenShieldClient{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		APIKey:      apiKey,
		AdminSecret: adminSecret,
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

	if c.APIKey != "" {
		req.Header.Set("X-API-Key", c.APIKey)
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
		client := NewClient(apiURL, apiKey, adminSecret)
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
		
		client := NewClient(apiURL, apiKey, adminSecret)
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
		
		client := NewClient(apiURL, apiKey, adminSecret)
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
		
		client := NewClient(apiURL, apiKey, adminSecret)
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
		client := NewClient(apiURL, apiKey, adminSecret)
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
		
		client := NewClient(apiURL, apiKey, adminSecret)
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
		
		client := NewClient(apiURL, apiKey, adminSecret)
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
		client := NewClient(apiURL, apiKey, adminSecret)
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
	
	if apiKey == "" {
		apiKey = viper.GetString("api_key")
	}
	
	if adminSecret == "" {
		adminSecret = viper.GetString("admin_secret")
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.tokenshield.yaml)")
	rootCmd.PersistentFlags().StringVar(&apiURL, "api-url", "", "TokenShield API URL (default: http://localhost:8090)")
	rootCmd.PersistentFlags().StringVar(&apiKey, "api-key", "", "API key for authentication")
	rootCmd.PersistentFlags().StringVar(&adminSecret, "admin-secret", "", "Admin secret for privileged operations")
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

	// Add commands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(tokenCmd)
	rootCmd.AddCommand(apiKeyCmd)
	rootCmd.AddCommand(activityCmd)
	rootCmd.AddCommand(statsCmd)

	tokenCmd.AddCommand(tokenListCmd)
	tokenCmd.AddCommand(tokenSearchCmd)
	tokenCmd.AddCommand(tokenRevokeCmd)

	apiKeyCmd.AddCommand(apiKeyListCmd)
	apiKeyCmd.AddCommand(apiKeyCreateCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}