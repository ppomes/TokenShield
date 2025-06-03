# TokenShield CLI

A command-line interface for managing TokenShield credit card tokenization.

## Installation

### Build from Source
```bash
./build.sh
sudo cp tokenshield /usr/local/bin/
```

### Using Docker
```bash
docker build -t tokenshield-cli .
```

## Getting Started

### First Time Setup

The CLI uses session-based authentication (like the GUI). Start by logging in:

```bash
# First time login - creates config file automatically
tokenshield login
Username: admin
Password: [hidden input]

Created config file: /Users/user/.tokenshield.yaml
Successfully logged in as admin (admin)
Session expires: 2024-01-15 10:30:00
```

This creates a secure configuration file at `~/.tokenshield.yaml`:
```yaml
api_url: http://localhost:8090
session_id: sess_abc123...
session_expires: 2024-01-15T10:30:00Z
username: admin
```

### Configuration Options

#### Option 1: Interactive Login (Recommended)
```bash
tokenshield login
# Prompts for username and secure password input
```

#### Option 2: Command Line Login
```bash
# Specify username, prompt for password
tokenshield login -u admin

# Specify both (not recommended - password visible in history)
tokenshield login -u admin -p mypassword
```

#### Option 3: Environment Variables
```bash
export TOKENSHIELD_API_URL="http://localhost:8090"
# Then login as usual
tokenshield login
```

#### Option 4: Custom Config File
```bash
tokenshield --config /path/to/config.yaml login
```

## Authentication

### Session-Based (Primary Method)
```bash
# Login once to get session
tokenshield login

# Use commands with active session
tokenshield token list
tokenshield stats

# Logout when done
tokenshield logout
```

### Admin Secret (Bootstrap Only)
For initial setup or emergency access:
```bash
tokenshield --admin-secret "change-this-admin-secret" user create ...
```

## Commands

### Authentication

#### Login
```bash
# Interactive login
tokenshield login

# With username
tokenshield login -u admin

# Check current session
tokenshield whoami
```

#### Logout
```bash
tokenshield logout
```

### Configuration Management

#### Show Configuration
```bash
# Display config file location and security status
tokenshield config show
```

#### Secure Configuration
```bash
# Fix file permissions automatically
tokenshield config secure
```

### System Information

#### Version
```bash
tokenshield version
```

### Token Management

#### List Tokens
```bash
# List all tokens (default limit: 100)
tokenshield token list

# Limit results
tokenshield token list --limit 50
```

#### Search Tokens
```bash
# Search by last four digits
tokenshield token search --last-four 1234

# Search by card type
tokenshield token search --card-type Visa

# Search active tokens only
tokenshield token search --active

# Combine filters
tokenshield token search --last-four 1234 --card-type Visa --limit 10
```

#### Revoke Token
```bash
tokenshield token revoke tok_abc123def456
```

### API Key Management

> **Note:** API key operations require admin session

#### List API Keys
```bash
tokenshield apikey list
```

#### Create API Key
```bash
# Basic API key
tokenshield apikey create "My Application"

# With specific permissions
tokenshield apikey create "Dashboard" --permissions read,write,admin
```

### User Management

> **Note:** User operations require admin session

#### List Users
```bash
tokenshield user list
```

#### Create User
```bash
tokenshield user create --username newuser --email user@example.com --password mypassword --role operator
```

#### Delete User
```bash
tokenshield user delete username
```

### Monitoring

#### Recent Activity
```bash
# Show recent activity (default: 50 entries)
tokenshield activity

# Limit results
tokenshield activity --limit 20
```

#### Statistics
```bash
tokenshield stats
```

## Examples

### Daily Operations
```bash
# Check session status
tokenshield whoami

# Check system status
tokenshield version
tokenshield stats

# Monitor recent activity
tokenshield activity --limit 10

# Search for specific tokens
tokenshield token search --last-four 1234 --active
```

### Administration
```bash
# Login as admin
tokenshield login -u admin

# Create new user
tokenshield user create --username operator1 --email op@company.com --password securepass --role operator

# Create API key for application
tokenshield apikey create "Payment Dashboard" --permissions read,write

# List all users and API keys
tokenshield user list
tokenshield apikey list

# Check system statistics
tokenshield stats
```

### Incident Response
```bash
# Login quickly
tokenshield login -u admin

# Search for potentially compromised cards
tokenshield token search --last-four 1234

# Revoke specific token
tokenshield token revoke tok_suspicious_token

# Monitor recent activity for anomalies
tokenshield activity --limit 100

# Check who has access
tokenshield user list
tokenshield apikey list
```

## Global Flags

- `--api-url`: TokenShield API URL (default: http://localhost:8090)
- `--admin-secret`: Admin secret for privileged operations (bootstrap only)
- `--config`: Configuration file path
- `--verbose, -v`: Verbose output

## Security Features

### Secure Configuration
The CLI automatically:
- ✅ Creates config files with secure permissions (600)
- ✅ Warns about insecure file permissions
- ✅ Hides password input during login
- ✅ Uses temporary session tokens (not persistent API keys)
- ✅ Supports automatic session expiration

### Configuration Security Check
```bash
# Check config file security
tokenshield config show
# Output:
# Configuration file: /Users/user/.tokenshield.yaml
# File permissions: 600
# Security status: ✅ Secure (owner access only)

# Fix insecure permissions
tokenshield config secure
```

## Docker Usage

### With Docker Network
```bash
# Run with specific network (for containerized TokenShield)
docker run --rm --network tokenshield_tokenshield-net tokenshield-cli \
  --api-url http://tokenshield-unified:8090 \
  login
```

### With Host Network
```bash
# Run with host network (for local TokenShield)
docker run --rm --network host tokenshield-cli \
  --api-url http://localhost:8090 \
  login
```

### With Volume for Config Persistence
```bash
# Mount home directory for config persistence
docker run --rm --network host \
  -v $HOME/.tokenshield.yaml:/root/.tokenshield.yaml \
  tokenshield-cli token list
```

## Error Handling

The CLI provides clear error messages:

```bash
# Not logged in
tokenshield token list
# Output: Not logged in

# Invalid credentials
tokenshield login
# Output: Login failed: Invalid username or password

# Session expired
tokenshield token list
# Output: Session expired, please login again

# Missing admin privileges
tokenshield user list
# Output: API Error: 403 Forbidden
```

## Session Management

### Session Lifecycle
```bash
# Login (creates session)
tokenshield login
# Session expires: 2024-01-15 10:30:00

# Check session status
tokenshield whoami
# Current user: admin (admin)

# Session expires automatically
tokenshield token list
# Session expired, please login again

# Manual logout
tokenshield logout
# Successfully logged out
```

### Multiple Environments
```bash
# Development environment
tokenshield --config ~/.tokenshield-dev.yaml --api-url http://localhost:8090 login

# Production environment  
tokenshield --config ~/.tokenshield-prod.yaml --api-url https://tokenshield.company.com login
```

## Output Formats

Currently supports table format. JSON and YAML formats planned for future releases.

## Troubleshooting

### Connection Issues
```bash
# Test connectivity
tokenshield version

# Check configuration
tokenshield config show

# Use verbose mode
tokenshield --verbose version
```

### Authentication Issues
```bash
# Check if logged in
tokenshield whoami

# Re-login if session expired
tokenshield login

# Check config file exists and has proper permissions
tokenshield config show
```

### Configuration Issues
```bash
# Check current configuration
tokenshield config show

# Fix file permissions
tokenshield config secure

# Use different config file
tokenshield --config /path/to/config.yaml whoami
```

### Debug Mode
```bash
# Enable verbose output
tokenshield --verbose token list

# Check config file location
tokenshield --verbose config show
```

## Integration

### Bash Scripts
```bash
#!/bin/bash
# Login and get token count
tokenshield login -u admin -p "$ADMIN_PASSWORD"
TOKENS=$(tokenshield stats | grep "Active Tokens" | awk '{print $3}')
echo "Current token count: $TOKENS"

# Alert if too many tokens
if [ "$TOKENS" -gt 1000 ]; then
    echo "WARNING: High token count detected"
fi

# Logout
tokenshield logout
```

### Cron Jobs
```bash
# Daily login and token monitoring
0 2 * * * /usr/local/bin/tokenshield login -u monitor -p "$MONITOR_PASSWORD" && \
          /usr/local/bin/tokenshield activity --limit 1000 > /var/log/tokenshield-daily.log && \
          /usr/local/bin/tokenshield logout

# Hourly activity check
0 * * * * /usr/local/bin/tokenshield login -u monitor -p "$MONITOR_PASSWORD" && \
          /usr/local/bin/tokenshield activity --limit 100 | grep -c "ERROR" > /var/log/tokenshield-errors.log && \
          /usr/local/bin/tokenshield logout
```

### CI/CD Integration
```bash
# In CI/CD pipeline
export TOKENSHIELD_API_URL="https://tokenshield.company.com"
echo "$TOKENSHIELD_PASSWORD" | tokenshield login -u ci-user
tokenshield stats
tokenshield logout
```

## Development

### Building
```bash
# Build for current platform
go build -o tokenshield .

# Build for all platforms
./build.sh
```

### Testing
```bash
# Test with local TokenShield
./tokenshield --api-url http://localhost:8090 login

# Test with Docker
docker run --rm tokenshield-cli version
```

### Configuration for Development
```bash
# Create development config
cat > ~/.tokenshield-dev.yaml << EOF
api_url: http://localhost:8090
EOF

# Use development config
tokenshield --config ~/.tokenshield-dev.yaml login
```

## Migration from API Key Authentication

If you have an existing config file with API keys, the CLI will continue to work but will show security warnings. To migrate to session-based authentication:

1. Login with your existing credentials:
   ```bash
   tokenshield login
   ```

2. The old API key will be ignored and session-based auth will be used going forward.

3. Your config file will be updated automatically with session information.