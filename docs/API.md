# TokenShield REST API Documentation

## Base URL
```
http://localhost:8090/api/v1
```

## Authentication

TokenShield uses session-based authentication for all clients (GUI and CLI).

### Session-Based Authentication
Users authenticate with username/password and receive a session token.

```
Authorization: Bearer sess_your-session-token
```

Sessions expire after 24 hours and must be renewed by logging in again.

**Note:** Admin operations require a user with admin role. The legacy X-Admin-Secret header is no longer used.

## Endpoints

### Authentication

#### POST /api/v1/auth/login
Authenticate user and create session.

**Request:**
```json
{
  "username": "admin",
  "password": "your-password"
}
```

**Response:**
```json
{
  "session_id": "sess_abc123...",
  "user": {
    "user_id": "usr_admin",
    "username": "admin",
    "email": "admin@example.com",
    "full_name": "Admin User",
    "role": "admin",
    "permissions": ["system.admin"],
    "is_active": true,
    "created_at": "2024-01-01T00:00:00Z",
    "last_login_at": "2024-01-02T10:00:00Z"
  },
  "expires_at": "2024-01-03T10:00:00Z",
  "require_password_change": false
}
```

#### POST /api/v1/auth/logout
End current session.

**Headers:**
- `Authorization: Bearer sess_your-session-token`

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

#### GET /api/v1/auth/me
Get current user information.

**Headers:**
- `Authorization: Bearer sess_your-session-token`

**Response:**
```json
{
  "user_id": "usr_admin",
  "username": "admin",
  "email": "admin@example.com",
  "full_name": "Admin User",
  "role": "admin",
  "permissions": ["system.admin"],
  "is_active": true,
  "created_at": "2024-01-01T00:00:00Z",
  "last_login_at": "2024-01-02T10:00:00Z"
}
```

#### POST /api/v1/auth/change-password
Change user password.

**Headers:**
- `Authorization: Bearer sess_your-session-token`

**Request:**
```json
{
  "current_password": "old-password",
  "new_password": "new-secure-password"
}
```

**Response:**
```json
{
  "message": "Password changed successfully"
}
```

**Password Requirements:**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

### User Management (Admin Only)

#### GET /api/v1/users
List all users. Requires admin role.

**Headers:**
- `Authorization: Bearer sess_your-session-token`

**Response:**
```json
{
  "users": [
    {
      "user_id": "usr_123",
      "username": "john",
      "email": "john@example.com",
      "full_name": "John Doe",
      "role": "operator",
      "permissions": ["tokens.read", "tokens.write"],
      "is_active": true,
      "created_at": "2024-01-01T00:00:00Z",
      "last_login_at": "2024-01-02T10:00:00Z"
    }
  ],
  "total": 1
}
```

#### POST /api/v1/users
Create a new user. Requires admin role.

**Headers:**
- `Authorization: Bearer sess_your-session-token`

**Request:**
```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "initial-password",
  "full_name": "New User",
  "role": "operator"
}
```

**Available Roles:**
- `admin`: Full system access
- `operator`: Can manage tokens and API keys
- `viewer`: Read-only access

**Response:**
```json
{
  "user_id": "usr_456",
  "username": "newuser",
  "email": "newuser@example.com",
  "message": "User created successfully"
}
```

#### DELETE /api/v1/users/{username}
Delete a user. Requires admin role.

**Headers:**
- `Authorization: Bearer sess_your-session-token`

**Response:**
```json
{
  "message": "User deleted successfully"
}
```

### System Information

#### GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "healthy"
}
```

#### GET /api/v1/version
Get system version and configuration.

**Response:**
```json
{
  "version": "1.0.0-prototype",
  "build_time": "2024-01-01T00:00:00Z",
  "token_format": "luhn",
  "kek_dek_enabled": true,
  "features": ["tokenization", "detokenization", "api", "icap"]
}
```

### API Key Management

**Note:** API key authentication is not currently used by any TokenShield clients. Both the GUI and CLI use session-based authentication. These endpoints are available for future extensibility.

#### POST /api/v1/api-keys
Create a new API key. Requires admin role.

**Headers:**
- `Authorization: Bearer sess_your-session-token` (with admin role)

**Request:**
```json
{
  "client_name": "Web Dashboard",
  "permissions": ["read", "write"]
}
```

**Response:**
```json
{
  "api_key": "ts_abc123def456",
  "client_name": "Web Dashboard",
  "permissions": ["read", "write"],
  "created_at": "2024-01-01T00:00:00Z"
}
```

#### GET /api/v1/api-keys
List all API keys. Requires admin role.

**Headers:**
- `Authorization: Bearer sess_your-session-token` (with admin role)

**Response:**
```json
{
  "api_keys": [
    {
      "api_key": "ts_abc123def456",
      "client_name": "Web Dashboard",
      "permissions": ["read", "write"],
      "is_active": true,
      "created_at": "2024-01-01T00:00:00Z",
      "last_used_at": "2024-01-01T12:00:00Z"
    }
  ],
  "total": 1
}
```

#### DELETE /api/v1/api-keys/{api_key}
Revoke an API key. Requires admin role.

**Headers:**
- `Authorization: Bearer sess_your-session-token` (with admin role)

**Response:**
```json
{
  "message": "API key revoked successfully"
}
```

### Token Management

#### GET /api/v1/tokens
List all tokens with pagination.

**Headers (one of):**
- `Authorization: Bearer sess_your-session-token`
- `X-API-Key: your-api-key`

**Query Parameters:**
- `limit` (optional): Number of tokens to return (default: 100, max: 1000)

**Response:**
```json
{
  "tokens": [
    {
      "token": "tok_abc123",
      "card_type": "Visa",
      "last_four": "1234",
      "first_six": "424242",
      "is_active": true,
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

#### GET /api/v1/tokens/{token}
Get details for a specific token.

**Headers:**
- `X-API-Key: your-api-key`

**Response:**
```json
{
  "token": "tok_abc123",
  "card_type": "Visa",
  "last_four": "1234",
  "first_six": "424242",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00Z"
}
```

#### DELETE /api/v1/tokens/{token}
Revoke a token.

**Headers:**
- `X-API-Key: your-api-key`

**Response:**
```json
{
  "message": "Token revoked successfully"
}
```

#### POST /api/v1/tokens/search
Search tokens with filters.

**Headers:**
- `X-API-Key: your-api-key`

**Request:**
```json
{
  "last_four": "1234",
  "card_type": "Visa",
  "date_from": "2024-01-01T00:00:00Z",
  "date_to": "2024-01-31T23:59:59Z",
  "is_active": true,
  "limit": 50
}
```

**Response:**
```json
{
  "tokens": [
    {
      "token": "tok_abc123",
      "card_type": "Visa",
      "last_four": "1234",
      "first_six": "424242",
      "is_active": true,
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

#### POST /api/v1/cards/import
Import cards in bulk for system migration (Admin only).

**Headers:**
- `Authorization: Bearer sess_your-session-token` (Admin role required)
- `Content-Type: application/json`

**Request:**
```json
{
  "format": "json",
  "duplicate_handling": "skip",
  "batch_size": 100,
  "data": "base64_encoded_card_data"
}
```

**Parameters:**
- `format`: Import format - "json" or "csv"
- `duplicate_handling`: How to handle duplicates - "skip", "error", or "overwrite"
- `batch_size`: Cards per batch (1-1000, default: 100)
- `data`: Base64 encoded card data

**JSON Format Example:**
```json
[
  {
    "card_number": "4532015112830366",
    "card_holder": "John Doe",
    "expiry_month": 12,
    "expiry_year": 2028,
    "external_id": "customer_123_card_1",
    "metadata": "{\"customer_id\": \"123\"}"
  }
]
```

**CSV Format Example:**
```csv
card_number,card_holder,expiry_month,expiry_year,external_id,metadata
4532015112830366,John Doe,12,2028,customer_123_card_1,"{""customer_id"": ""123""}"
5425233430109903,Jane Smith,6,2027,customer_456_card_1,""
```

**Response:**
```json
{
  "total_records": 2,
  "processed_records": 2,
  "successful_imports": 2,
  "failed_imports": 0,
  "duplicates": 0,
  "import_id": "imp_xyz123",
  "status": "completed",
  "processing_time": "1.23s",
  "tokens_generated": [
    {
      "record_index": 0,
      "external_id": "customer_123_card_1",
      "token": "tok_abcd1234",
      "card_type": "Visa",
      "last_four": "0366"
    },
    {
      "record_index": 1,
      "external_id": "customer_456_card_1",
      "token": "tok_efgh5678", 
      "card_type": "Mastercard",
      "last_four": "9903"
    }
  ],
  "errors": []
}
```

**Status Codes:**
- `200 OK`: Import completed successfully
- `206 Partial Content`: Import completed with some failures
- `400 Bad Request`: Import failed completely or validation errors
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Admin role required
- `413 Payload Too Large`: Request exceeds 50MB limit

**Validation Rules:**
- Maximum 10,000 cards per import
- Maximum 50MB request size
- Card numbers must pass Luhn algorithm validation
- Expiry dates must be future dates
- External IDs are optional but recommended for database mapping

**Error Response Example:**
```json
{
  "total_records": 1,
  "successful_imports": 0,
  "failed_imports": 1,
  "status": "failed",
  "errors": [
    {
      "record_index": 0,
      "external_id": "invalid_card",
      "card_number_masked": "****1234",
      "error": "Validation failed",
      "reason": "card number fails Luhn algorithm validation"
    }
  ]
}
```

### Activity Monitoring

#### GET /api/v1/activity
Get recent tokenization activity.

**Headers:**
- `X-API-Key: your-api-key`

**Query Parameters:**
- `limit` (optional): Number of activities to return (default: 50, max: 1000)

**Response:**
```json
{
  "activities": [
    {
      "token": "tok_abc123",
      "type": "tokenize",
      "source_ip": "192.168.1.1",
      "destination": "http://app.example.com",
      "timestamp": "2024-01-01T00:00:00Z",
      "status": 200,
      "card_last_four": "1234"
    }
  ],
  "total": 1
}
```

#### GET /api/v1/stats
Get system statistics.

**Headers:**
- `X-API-Key: your-api-key`

**Response:**
```json
{
  "active_tokens": 1250,
  "requests_24h": {
    "tokenize": 450,
    "detokenize": 320,
    "forward": 180
  }
}
```

### Key Management (KEK/DEK)

Available only when `USE_KEK_DEK=true`.

#### GET /api/v1/keys/status
Get current encryption key status.

**Headers:**
- `X-API-Key: your-api-key`

**Response:**
```json
{
  "kek": {
    "key_id": "kek_abc123",
    "version": 1,
    "status": "active",
    "created_at": "2024-01-01T00:00:00Z"
  },
  "dek": {
    "key_id": "dek_def456",
    "version": 5,
    "status": "active",
    "created_at": "2024-01-15T00:00:00Z",
    "cards_encrypted": 1250
  }
}
```

#### POST /api/v1/keys/rotate
Initiate key rotation. Requires admin role.

**Headers:**
- `Authorization: Bearer sess_your-session-token` (with admin role)

**Request:**
```json
{
  "rotation_type": "immediate"
}
```

**Response:**
```json
{
  "status": "accepted",
  "message": "Key rotation initiated",
  "rotation_id": "rot_abc123"
}
```

## Error Responses

All endpoints return consistent error responses:

```json
{
  "error": "Error description",
  "code": "ERROR_CODE",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Common Error Codes

- `401 Unauthorized`: Missing or invalid API key
- `403 Forbidden`: Insufficient privileges (admin required)
- `404 Not Found`: Resource not found
- `400 Bad Request`: Invalid request body or parameters
- `500 Internal Server Error`: Server error

## Rate Limiting

Rate limiting is not currently implemented in this prototype version. In a production deployment, rate limiting should be implemented based on:
- Session/user for authenticated requests
- IP address for unauthenticated endpoints (login)
- Stricter limits for sensitive operations

## Examples

### Authentication

#### Login
```bash
curl -X POST http://localhost:8090/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{
    "username": "admin",
    "password": "your-password"
  }'
```

#### Change Password
```bash
curl -X POST http://localhost:8090/api/v1/auth/change-password \\
  -H "Authorization: Bearer sess_your-session-token" \\
  -H "Content-Type: application/json" \\
  -d '{
    "current_password": "old-password",
    "new_password": "NewSecure123!"
  }'
```

### Create API Key (Admin Only)
```bash
curl -X POST http://localhost:8090/api/v1/api-keys \\
  -H "Authorization: Bearer sess_your-admin-session-token" \\
  -H "Content-Type: application/json" \\
  -d '{
    "client_name": "My CLI Tool",
    "permissions": ["read", "write"]
  }'
```

### List Tokens
```bash
curl http://localhost:8090/api/v1/tokens \\
  -H "Authorization: Bearer sess_your-session-token"
```

### Search Tokens
```bash
curl -X POST http://localhost:8090/api/v1/tokens/search \\
  -H "Authorization: Bearer sess_your-session-token" \\
  -H "Content-Type: application/json" \\
  -d '{
    "last_four": "1234",
    "limit": 10
  }'
```

### Get Activity
```bash
curl http://localhost:8090/api/v1/activity?limit=20 \\
  -H "Authorization: Bearer sess_your-session-token"
```

### Get Statistics
```bash
curl http://localhost:8090/api/v1/stats \\
  -H "Authorization: Bearer sess_your-session-token"
```

### Import Cards (Admin Only)
```bash
# Prepare card data
cat > cards.json << 'EOF'
[
  {
    "card_number": "4532015112830366",
    "card_holder": "John Doe",
    "expiry_month": 12,
    "expiry_year": 2028,
    "external_id": "customer_123_card_1"
  }
]
EOF

# Base64 encode and import
CARD_DATA=$(base64 -i cards.json)
curl -X POST http://localhost:8090/api/v1/cards/import \\
  -H "Authorization: Bearer sess_your-session-token" \\
  -H "Content-Type: application/json" \\
  -d "{
    \"format\": \"json\",
    \"duplicate_handling\": \"skip\",
    \"batch_size\": 100,
    \"data\": \"$CARD_DATA\"
  }"
```

## Integration Notes

### For All Clients (GUI, CLI, and Automation)
- Use session-based authentication with login endpoint
- Handle `require_password_change` flag on login
- Sessions expire after 24 hours - implement re-authentication logic
- Store session tokens securely (browser storage for GUI, config file with proper permissions for CLI)

### For GUI Applications
- Implement automatic session refresh before expiry
- Use the activity endpoint for real-time monitoring
- Implement pagination for large token lists
- Cache statistics and refresh periodically

### For CLI Tools
- Persist session token between commands in secure config file
- Implement interactive login with hidden password input
- Use search endpoint for filtered operations
- Implement progress indicators for long operations

### For Future Automation (When API Keys are Implemented)
- API key authentication is not currently available
- For now, automation scripts must use session-based auth
- Consider implementing service accounts with extended session lifetimes
- Use activity monitoring for audit trails
- Implement retry logic with exponential backoff