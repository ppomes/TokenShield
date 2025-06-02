# TokenShield - PCI Compliance Gateway

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ████████╗ ██████╗ ██╗  ██╗███████╗███╗   ██╗            ║
║   ╚══██╔══╝██╔═══██╗██║ ██╔╝██╔════╝████╗  ██║            ║
║      ██║   ██║   ██║█████╔╝ █████╗  ██╔██╗ ██║            ║
║      ██║   ██║   ██║██╔═██╗ ██╔══╝  ██║╚██╗██║            ║
║      ██║   ╚██████╔╝██║  ██╗███████╗██║ ╚████║            ║
║      ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝            ║
║                                                           ║
║   ███████╗██╗  ██╗██╗███████╗██╗     ██████╗              ║
║   ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗             ║
║   ███████╗███████║██║█████╗  ██║     ██║  ██║             ║
║   ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║             ║
║   ███████║██║  ██║██║███████╗███████╗██████╔╝             ║
║   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝              ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

## ⚠️ **PROTOTYPE - NOT PRODUCTION READY** ⚠️

**This is a prototype implementation for educational and demonstration purposes only.**

- 🚧 **Proof of Concept**: Demonstrates tokenization concepts but lacks production safeguards
- 🔒 **Security Gaps**: Missing critical security features required for production use
- 📋 **Not PCI Compliant**: Does not meet PCI DSS requirements as-is
- 🧪 **Educational Only**: Suitable for learning, testing concepts, and architectural exploration
- ⚡ **Prototype Quality**: Code quality and error handling not production-grade

---

**TokenShield** is a prototype PCI compliance gateway that demonstrates how to implement credit card tokenization using modern proxy technologies. This proof-of-concept shows how HAProxy and Squid can work together with a unified Go tokenization service to intercept and tokenize sensitive data transparently.

## Prototype Features

- **Unified Go Service**: Demonstrates multi-protocol tokenization in a single binary
- **Triple Protocol Support**: HTTP (tokenization), ICAP (detokenization), REST API (management)  
- **Web GUI Dashboard**: Modern browser-based interface for managing tokens and monitoring activity
- **CLI Management Tool**: Command-line interface for all tokenization operations
- **Transparent Interception**: Shows how proxies can intercept and modify traffic
- **Bidirectional Flow**: Tokenizes inbound requests, detokenizes outbound requests
- **Educational Architecture**: Illustrates concepts for reducing PCI compliance scope

## Architecture Overview

```
┌─────────────┐     ┌───────────┐     ┌────────────────────┐     ┌─────────────┐
│   Client    │────▶│  HAProxy  │────▶│ Unified Tokenizer  │────▶│  Your App   │
│  (Browser)  │     │ (Port 80) │     │  (HTTP: 8080)      │     │ (Port 8000) │
└─────────────┘     └───────────┘     └────────────────────┘     └─────────────┘
                                                 │
                                                 ▼
                                           ┌──────────┐
                                           │  MySQL   │
                                           │    DB    │
                                           └──────────┘
                                            
┌─────────────┐     ┌───────────┐     ┌────────────────────┐     ┌─────────────┐
│  Your App   │────▶│   Squid   │────▶│ Unified Tokenizer  │────▶│   Payment   │
│             │     │(Port 3128)│     │  (ICAP: 1344)      │     │   Gateway   │
└─────────────┘     └───────────┘     └────────────────────┘     └─────────────┘
                                                 │
                                      ┌──────────┴──────────┐
                                      │   Management API    │
                                      │    (Port 8090)      │
                                      └──────────┬──────────┘
                                                 │
                                      ┌──────────▼──────────┐
                                      │   Web GUI & CLI     │
                                      │  Dashboard & Tools  │
                                      │   (Port 8081)       │
                                      └─────────────────────┘
```

## Quick Start

### Option 1: Automated Setup (Recommended)
```bash
./start.sh
```
This script automatically:
- Creates `.env` file with a generated encryption key
- Generates SSL certificates
- Starts all services with default settings

### Option 2: Manual Setup

#### 1. Generate Encryption Key
```bash
# Using OpenSSL (recommended)
openssl rand -base64 32

# Or using Python if you prefer
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

#### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env and add the encryption key generated above
```

##### Token Format Options
TokenShield supports two token formats:

1. **Prefix Format (default)**: `tok_abc123...`
   - Clearly distinguishable as tokens
   - Won't pass credit card validation
   - Set `TOKEN_FORMAT=prefix` or leave unset

2. **Luhn-Valid Format**: `9999xxxxxxxxxxxx`
   - Looks like a valid credit card number
   - Passes Luhn algorithm validation
   - Uses prefix `9999` (not used by real issuers)
   - Set `TOKEN_FORMAT=luhn` in your `.env` file

#### 3. Generate SSL Certificates
```bash
cd certs
./generate-certs.sh
cd ..
```

#### 4. Start All Services
```bash
docker-compose up -d

# Or with environment variable override:
TOKEN_FORMAT=luhn docker-compose up -d
```

#### 5. Verify Services are Running
```bash
docker-compose ps
```

## Testing the System

### 1. Access the Web GUI Dashboard
Open your browser and go to: **http://localhost:8081**

The TokenShield dashboard provides:
- **System overview** with real-time statistics
- **Token management** - view, search, and revoke tokens
- **API key management** - create and manage API keys
- **Activity monitoring** - track all tokenization operations
- **Settings** - configure API connection and preferences

#### Initial Setup
1. Go to the **Settings** tab
2. Enter API configuration:
   - **API URL**: `http://localhost:8090`
   - **Admin Secret**: `change-this-admin-secret`
3. Click **"Test Connection"** and **"Save Settings"**
4. Navigate to **API Keys** tab and create your first API key
5. Use the new API key in Settings for full dashboard access

### 2. Access the Demo Application
You can also test the tokenization flow directly at: http://localhost

You'll see a checkout form where you can enter credit card details.

### 3. Test Credit Card Numbers
- Visa: 4532015112830366
- Mastercard: 5425233430109903
- Amex: 378282246310005
- Discover: 6011111111111117

### 4. What Happens During Testing

1. **Submit Payment**: Enter card details in the form at http://localhost
2. **HAProxy Intercepts**: The request goes through HAProxy which detects credit card data
3. **Tokenization**: The tokenizer replaces the card number with a secure token
4. **App Receives Token**: Your application only sees the token, not the real card
5. **Payment Processing**: When the app calls the payment gateway, Squid intercepts
6. **Detokenization**: Squid calls the tokenizer to replace the token with the real card
7. **Gateway Processing**: The payment gateway receives the real card number

### 5. Monitor the Flow

Watch the logs to see the tokenization in action:
```bash
# All logs
docker-compose logs -f

# Specific service logs
docker-compose logs -f unified-tokenizer
docker-compose logs -f dummy-app
docker-compose logs -f payment-gateway
```

### 6. Check HAProxy Stats
Visit: http://localhost:8404/stats

### 7. CLI Management Tool

TokenShield includes a powerful CLI tool for managing the system:

```bash
# Build the CLI tool
cd cli
./build.sh

# Or use Docker
docker build -t tokenshield-cli .

# Create API key
./tokenshield apikey create "My App" --admin-secret change-this-admin-secret

# List tokens
./tokenshield token list --api-key YOUR_API_KEY

# Search tokens
./tokenshield token search --last-four 1234 --api-key YOUR_API_KEY

# View activity
./tokenshield activity --limit 50 --api-key YOUR_API_KEY

# Get statistics
./tokenshield stats --api-key YOUR_API_KEY
```

See `cli/README.md` for complete CLI documentation.

### 8. Management API

Create an API key:
```bash
curl -X POST http://localhost:8090/api/v1/api-keys \
  -H "Content-Type: application/json" \
  -H "X-Admin-Secret: change-this-admin-secret" \
  -d '{"client_name": "Test Client"}'
```

List tokens (use the API key from above):
```bash
curl http://localhost:8090/api/v1/tokens \
  -H "X-API-Key: YOUR_API_KEY"
```

Get statistics:
```bash
curl http://localhost:8090/api/v1/stats \
  -H "X-API-Key: YOUR_API_KEY"
```

## Services and Ports

- **HAProxy**: 80 (HTTP), 443 (HTTPS), 8404 (Stats)
- **Unified Tokenizer**: 
  - 8080 (HTTP Tokenization)
  - 1344 (ICAP Detokenization)
  - 8090 (Management API)
- **GUI Dashboard**: 8081 (Web Interface)
- **MySQL**: 3306
- **Squid**: 3128 (HTTP), 3129 (HTTPS)
- **Dummy App**: 8000
- **Payment Gateway**: 9000

## Missing for Production

⚠️ **This prototype lacks many critical features required for production:**

1. **Security**: No authentication, authorization, or input validation
2. **Key Management**: Uses basic encryption, needs HSM/KMS integration
3. **Compliance**: Missing PCI DSS controls, logging, and audit requirements
4. **Error Handling**: Minimal error handling and recovery mechanisms
5. **Performance**: No load balancing, caching, or optimization
6. **Monitoring**: Basic logging only, no alerting or health checks
7. **Data Protection**: No secure key storage or rotation
8. **Network Security**: Uses self-signed certificates and basic networking

## Troubleshooting

### Services not starting
```bash
# Check logs
docker-compose logs mysql
docker-compose logs tokenizer

# Restart services
docker-compose restart
```

### Database connection issues
```bash
# Check if MySQL is healthy
docker-compose ps mysql

# Connect to MySQL
docker exec -it tokenshield-mysql mysql -u pciproxy -ppciproxy123 tokenshield

# Check unified tokenizer logs
docker-compose logs unified-tokenizer | grep -i error
```

### Certificate issues
```bash
# Regenerate certificates
cd certs
rm -f *.crt *.key *.pem
./generate-certs.sh
cd ..
docker-compose restart haproxy squid
```

## Development

### Adding New Payment Providers

Edit `squid/squid.conf` and add the domain:
```
acl payment_providers dstdomain .newprovider.com
```

### Customizing Tokenization Rules

Edit `unified-tokenizer/main.go` to modify the card detection patterns or tokenization logic. The unified service handles:
- Credit card pattern matching via regex
- Token generation and storage
- Encryption/decryption with Fernet
- Both HTTP and ICAP protocols

### Testing without Docker

The unified tokenizer can be run locally:
```bash
cd unified-tokenizer
go mod download
go run main.go
```

Make sure to set the required environment variables:
- `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
- `ENCRYPTION_KEY`
- `HTTP_PORT`, `ICAP_PORT`, `API_PORT`

## License

This is a prototype/demonstration project for educational purposes only. Not intended for production use.
