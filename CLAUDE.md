# TokenShield - Claude Development Context

## Project Overview

**TokenShield** is a prototype PCI compliance gateway demonstrating credit card tokenization using modern proxy technologies. This is an educational/demonstration project showing how HAProxy, Squid, and a unified Go tokenization service can work together to intercept and tokenize sensitive data transparently.

⚠️ **PROTOTYPE ONLY** - Not production ready, missing critical security features for real-world use.

## Architecture Summary

```
Client → HAProxy → Unified Tokenizer → Your App
                        ↓
                   MySQL Database
                        ↓
Your App → Squid → Unified Tokenizer → Payment Gateway
                        ↓
              Management API (REST)
                        ↓
           GUI Dashboard & CLI Tool
```

## Technology Stack

- **Go**: Unified tokenizer service (HTTP + ICAP + REST API)
- **HAProxy**: Incoming traffic interception and tokenization
- **Squid**: Outgoing traffic interception and detokenization  
- **MySQL**: Token and metadata storage
- **HTML/CSS/JS**: Web GUI dashboard
- **React + TypeScript**: Modern React GUI with Material-UI
- **Go + Cobra**: CLI management tool
- **Docker**: Complete containerization
- **Nginx**: Web server for GUI

## Current Implementation Status

### ✅ Completed Features

1. **Unified Tokenizer Service** (`unified-tokenizer/main.go`)
   - HTTP tokenization server (port 8080)
   - ICAP detokenization server (port 1344) 
   - REST management API (port 8090)
   - KEK/DEK encryption support with AES-GCM
   - Configurable token formats (prefix: `tok_` or Luhn-valid: `9999xxxx`)
   - CORS middleware for browser API access

2. **Database Schema** (`database/schema.sql`)
   - Credit card tokens storage
   - API keys management
   - Request activity logging
   - KEK/DEK encryption keys tables
   - Key rotation logging
   - User management and sessions
   - Two-tier audit logging (user actions + security events)

3. **Proxy Configuration**
   - HAProxy config with Lua tokenization script (`haproxy/`)
   - Squid proxy with ICAP integration (`squid/`)
   - SSL/TLS certificate generation (`certs/`)

4. **Demo Applications**
   - Dummy e-commerce app with HTTP tracing (`dummy-app/`)
   - Payment gateway simulator (`dummy-gateway/`)
   - Card distributor API (`card-distributor/`)

5. **REST API** (Management API on port 8090)
   - API key management (create, list, revoke)
   - Token management (list, search, revoke) 
   - Activity monitoring
   - System statistics
   - Version and health endpoints
   - KEK/DEK key management (when enabled)
   - User management and authentication

6. **CLI Tool** (`cli/`)
   - Complete Go CLI using Cobra framework
   - Token management commands
   - API key operations  
   - Activity monitoring
   - Statistics viewing
   - Docker support and cross-platform builds

7. **Web GUI Dashboard** (`gui/`)
   - Modern HTML/CSS/JavaScript interface
   - Real-time system statistics
   - Token management (view, search, revoke)
   - API key management (create, list, revoke)
   - Activity monitoring with filtering
   - Settings configuration
   - Responsive design for mobile/desktop
   - Docker deployment with Nginx

8. **React GUI Dashboard** (`gui-react/`)
   - Modern React 19 + TypeScript + Material-UI v5
   - Theme management with light/dark modes
   - Dynamic API configuration
   - Complete feature parity with legacy GUI
   - Docker deployment on port 8082
   - Modern development workflow with Vite

9. **Security Enhancements**
   - Rate limiting for authentication endpoints (5 attempts per 15 minutes)
   - Two-tier audit logging (user actions + security events)
   - Session security with configurable timeouts and concurrent limits
   - Automatic session cleanup and background monitoring
   - PCI DSS v4.0 compliant password requirements (12+ characters)

10. **Docker Integration**
    - Complete docker-compose.yml with all services
    - Multi-stage builds for Go applications
    - Health checks and service dependencies
    - Volume management for data persistence

## Key Configuration

### Environment Variables
- `TOKEN_FORMAT`: "prefix" (default) or "luhn" for Luhn-valid tokens
- `USE_KEK_DEK`: "true" to enable KEK/DEK encryption (default: false)
- `ENCRYPTION_KEY`: Base64 encoded encryption key
- `ADMIN_SECRET`: Admin secret for privileged operations (default: "change-this-admin-secret")
- `SESSION_TIMEOUT`: Absolute session timeout (default: 24h)
- `SESSION_IDLE_TIMEOUT`: Idle session timeout (default: 4h)
- `MAX_CONCURRENT_SESSIONS`: Maximum sessions per user (default: 5)

### Service Ports
- **80/443**: HAProxy (HTTP/HTTPS traffic)
- **8080**: Unified tokenizer HTTP service
- **1344**: Unified tokenizer ICAP service  
- **8090**: Management REST API
- **8081**: Legacy GUI web dashboard
- **8082**: React GUI web dashboard
- **3306**: MySQL database
- **3128/3129**: Squid proxy (HTTP/HTTPS)
- **8000**: Dummy app
- **9000**: Payment gateway
- **5001**: Card distributor
- **8404**: HAProxy stats

## Database Schema

### Core Tables
- `credit_cards`: Token storage with metadata
- `api_keys`: API key management
- `token_requests`: Activity logging
- `encryption_keys`: KEK/DEK keys (when enabled)
- `key_rotation_log`: Key rotation history
- `users`: User accounts and authentication
- `user_sessions`: Session management
- `user_audit_log`: User action logging
- `security_audit_log`: Security event logging

### Key Fields
- Tokens stored with card type, last 4 digits, creation time
- Activity includes source IP, request type, timestamps
- API keys have permissions and usage tracking
- Sessions include timeout, idle tracking, and concurrent limits
- Audit logs capture both user actions and security events

## Development Commands

### Start System
```bash
docker-compose up -d
```

### Build CLI Tool
```bash
cd cli && ./build.sh
```

### Create API Key
```bash
curl -X POST http://localhost:8090/api/v1/api-keys \
  -H "Content-Type: application/json" \
  -H "X-Admin-Secret: change-this-admin-secret" \
  -d '{"client_name":"Test","permissions":["read","write","admin"]}'
```

### Test Tokenization
- Legacy GUI Dashboard: http://localhost:8081
- React GUI Dashboard: http://localhost:8082
- Demo App: http://localhost
- API: http://localhost:8090

### View Logs
```bash
docker-compose logs -f unified-tokenizer
docker-compose logs -f dummy-app
```

## Code Structure

### Unified Tokenizer (`unified-tokenizer/main.go`)
- `UnifiedTokenizer` struct: Main service with HTTP, ICAP, and API servers
- `KeyManager`: KEK/DEK encryption management
- HTTP handlers: Tokenization endpoints
- ICAP handlers: Detokenization for Squid integration
- API handlers: Management REST endpoints
- CORS middleware: Browser compatibility
- Rate limiting: Authentication protection
- Session management: Security and timeouts
- Audit logging: User actions and security events

### React GUI Dashboard (`gui-react/`)
- `index.html`: Main interface structure
- `src/App.tsx`: Main React application with theme provider
- `src/contexts/ThemeContext.tsx`: Theme management system
- `src/components/`: Feature-specific React components
- `Dockerfile`: Nginx-based container with Vite build
- `nginx.conf`: Web server configuration

### CLI Tool (`cli/main.go`)
- Cobra-based command structure
- API client with authentication
- Commands for all major operations
- Configuration file support
- Cross-platform build support

## Recent Development History

1. **HTTP Tracing**: Added comprehensive request/response logging to dummy-app
2. **Token Formats**: Implemented configurable token formats (prefix vs Luhn-valid)
3. **KEK/DEK**: Added enterprise-grade key encryption with rotation
4. **REST API**: Built complete management API for GUI/CLI consumption
5. **CLI Tool**: Created full-featured command-line interface
6. **GUI Dashboard**: Developed modern web interface with all management features
7. **CORS Support**: Added browser compatibility for GUI-API communication
8. **React Migration**: Built modern React GUI with TypeScript and Material-UI
9. **Theme System**: Implemented comprehensive light/dark theme management
10. **Security Hardening**: Added rate limiting, audit logging, and session security
11. **Session Security**: Implemented configurable timeouts, concurrent limits, and cleanup

## Testing Data

### Test Credit Cards
- Visa: 4532015112830366
- Mastercard: 5425233430109903  
- Amex: 378282246310005
- Discover: 6011111111111117

### Default Credentials
- Admin Secret: `change-this-admin-secret`
- MySQL: pciproxy/pciproxy123
- Database: tokenshield

## Known Issues & Limitations

### Current State
- Prototype quality code
- Self-signed certificates
- Basic error handling
- No production security features
- Limited input validation

### Missing for Production
- HSM/KMS integration
- Comprehensive audit logging
- Rate limiting and DDoS protection
- Advanced monitoring and alerting
- PCI DSS compliance controls
- Production-grade authentication
- Network security hardening

## Security Features

### Implemented Security Controls
- **Rate Limiting**: 5 login attempts per 15 minutes per IP
- **Session Security**: Configurable timeouts (24h absolute, 4h idle)
- **Concurrent Sessions**: Maximum 5 sessions per user
- **Password Requirements**: PCI DSS v4.0 compliant (12+ characters)
- **Audit Logging**: Two-tier logging (user actions + security events)
- **Background Cleanup**: Automatic session cleanup every 15 minutes
- **Session Invalidation**: Manual session termination for security events

### Session Security Features
- Absolute session timeout (default: 24 hours)
- Idle session timeout (default: 4 hours)
- Concurrent session limits (default: 5 per user)
- Automatic cleanup of expired sessions
- Session invalidation on security events
- Detailed security event logging
- Background monitoring service

## Next Development Ideas

### Security Improvements
- Input validation middleware
- Health checks for dependencies
- Structured logging with security classification
- Database connection pooling optimization
- Multi-factor authentication
- Role-based access control refinements

### Advanced Features
- Multi-tenant support
- Token format customization
- Webhook notifications
- Backup and recovery procedures
- Performance monitoring
- Load balancing support

## Development Notes

### Build Requirements
- Go 1.21+
- Docker and Docker Compose
- Node.js 18+ (for React GUI)
- MySQL client (for direct DB access)
- Modern web browser (for GUI testing)

### Testing Approach
1. Start with React GUI dashboard for modern experience
2. Use CLI for automated operations
3. Direct API calls for integration testing
4. Log monitoring for debugging and security analysis

### Code Style
- Go: Standard Go formatting, error handling
- TypeScript: Modern ES6+, async/await patterns
- CSS: Custom properties, responsive design
- HTML: Semantic markup, accessibility considerations

## Claude Development Context

- **Last Updated**: 2024-06-04
- **Current Focus**: Session security enhancements completed
- **Recent Work**: 
  * Implemented session security with configurable timeouts
  * Added concurrent session limits and cleanup
  * Enhanced validateSession with idle timeout checks
  * Added background session cleanup service
  * Implemented session invalidation functions
- **Completed Security Features**:
  * Rate limiting for authentication endpoints
  * Two-tier audit logging system
  * Session security with timeouts and limits
  * Background session monitoring and cleanup