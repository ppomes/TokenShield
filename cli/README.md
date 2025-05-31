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

## Configuration

Create a configuration file at `~/.tokenshield.yaml`:

```yaml
api_url: "http://localhost:8090"
api_key: "ts_your-api-key-here"
admin_secret: "change-this-admin-secret"
```

Or use environment variables:
```bash
export TOKENSHIELD_API_URL="http://localhost:8090"
export TOKENSHIELD_API_KEY="ts_your-api-key-here"
export TOKENSHIELD_ADMIN_SECRET="change-this-admin-secret"
```

## Commands

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

> **Note:** API key operations require admin privileges

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
# Create API key for new application
tokenshield apikey create "New Dashboard" --permissions read,write

# List all API keys
tokenshield apikey list

# Check system statistics
tokenshield stats
```

### Incident Response
```bash
# Search for potentially compromised cards
tokenshield token search --last-four 1234

# Revoke specific token
tokenshield token revoke tok_suspicious_token

# Monitor recent activity for anomalies
tokenshield activity --limit 100
```

## Global Flags

- `--api-url`: TokenShield API URL (default: http://localhost:8090)
- `--api-key`: API key for authentication
- `--admin-secret`: Admin secret for privileged operations
- `--config`: Configuration file path
- `--verbose, -v`: Verbose output

## Authentication

### API Key
Most operations require an API key:
```bash
tokenshield --api-key "ts_your-key" token list
```

### Admin Operations
Admin operations require both API key and admin secret:
```bash
tokenshield --admin-secret "your-secret" apikey list
```

## Docker Usage

### With Docker Network
```bash
# Run with specific network (for containerized TokenShield)
docker run --rm --network tokenshield_tokenshield-net tokenshield-cli \\
  --api-url http://tokenshield-unified:8090 \\
  --api-key "ts_your-key" \\
  version
```

### With Host Network
```bash
# Run with host network (for local TokenShield)
docker run --rm --network host tokenshield-cli \\
  --api-url http://localhost:8090 \\
  --api-key "ts_your-key" \\
  token list
```

## Error Handling

The CLI provides clear error messages:

```bash
# Invalid API key
tokenshield token list
# Output: API Error: 401 Unauthorized

# Token not found
tokenshield token revoke invalid-token
# Output: Token not found: invalid-token

# Missing admin privileges
tokenshield apikey list
# Output: API Error: 403 Forbidden
```

## Output Formats

Currently supports table format. JSON and YAML formats planned for future releases.

## Troubleshooting

### Connection Issues
```bash
# Test connectivity
tokenshield version

# Check configuration
tokenshield version --verbose
```

### Authentication Issues
```bash
# Verify API key works
tokenshield stats

# Test admin privileges
tokenshield apikey list
```

### Debug Mode
```bash
# Enable verbose output
tokenshield --verbose token list
```

## Integration

### Bash Scripts
```bash
#!/bin/bash
# Get token count
TOKENS=$(tokenshield stats | grep "Active Tokens" | awk '{print $3}')
echo "Current token count: $TOKENS"

# Alert if too many tokens
if [ "$TOKENS" -gt 1000 ]; then
    echo "WARNING: High token count detected"
fi
```

### Cron Jobs
```bash
# Daily token cleanup (remove old tokens)
0 2 * * * /usr/local/bin/tokenshield token search --active false | grep -v "CREATED" | awk '{print $1}' | xargs -I {} /usr/local/bin/tokenshield token revoke {}

# Hourly activity monitoring
0 * * * * /usr/local/bin/tokenshield activity --limit 100 | grep -c "ERROR" > /var/log/tokenshield-errors.log
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
# Run with local TokenShield
./tokenshield --api-url http://localhost:8090 version

# Run with Docker
docker run --rm tokenshield-cli version
```