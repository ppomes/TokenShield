# TokenShield REST API Documentation

## Base URL
```
http://localhost:8090/api/v1
```

## Authentication

### API Key Authentication
Include the API key in the request header:
```
X-API-Key: your-api-key-here
```

### Admin Authentication
For admin operations, include both API key and admin secret:
```
X-API-Key: your-api-key-here
X-Admin-Secret: your-admin-secret
```

## Endpoints

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

#### POST /api/v1/api-keys
Create a new API key. Requires admin privileges.

**Headers:**
- `X-Admin-Secret: your-admin-secret`

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
List all API keys. Requires admin privileges.

**Headers:**
- `X-Admin-Secret: your-admin-secret`

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
Revoke an API key. Requires admin privileges.

**Headers:**
- `X-Admin-Secret: your-admin-secret`

**Response:**
```json
{
  "message": "API key revoked successfully"
}
```

### Token Management

#### GET /api/v1/tokens
List all tokens with pagination.

**Headers:**
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
Initiate key rotation. Requires admin privileges.

**Headers:**
- `X-API-Key: your-api-key`
- `X-Admin-Secret: your-admin-secret`

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

API requests are rate-limited per API key:
- 1000 requests per hour for regular operations
- 100 requests per hour for admin operations

## Examples

### Create API Key
```bash
curl -X POST http://localhost:8090/api/v1/api-keys \\
  -H "X-Admin-Secret: change-this-admin-secret" \\
  -H "Content-Type: application/json" \\
  -d '{
    "client_name": "Dashboard",
    "permissions": ["read", "write"]
  }'
```

### List Tokens
```bash
curl http://localhost:8090/api/v1/tokens \\
  -H "X-API-Key: ts_your-api-key"
```

### Search Tokens
```bash
curl -X POST http://localhost:8090/api/v1/tokens/search \\
  -H "X-API-Key: ts_your-api-key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "last_four": "1234",
    "limit": 10
  }'
```

### Get Activity
```bash
curl http://localhost:8090/api/v1/activity?limit=20 \\
  -H "X-API-Key: ts_your-api-key"
```

### Get Statistics
```bash
curl http://localhost:8090/api/v1/stats \\
  -H "X-API-Key: ts_your-api-key"
```

## Integration Notes

### For GUI Applications
- Use the activity endpoint for real-time monitoring
- Implement pagination for large token lists
- Cache statistics and refresh periodically

### For CLI Tools
- Store API key in config file or environment variable
- Use search endpoint for filtered operations
- Implement progress indicators for long operations

### For Automation
- Use activity monitoring for audit trails
- Implement retry logic with exponential backoff
- Monitor key rotation status for compliance