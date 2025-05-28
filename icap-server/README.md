# TokenShield ICAP Server

A high-performance ICAP server implementation in C for TokenShield that integrates with Squid proxy to detokenize payment card tokens in HTTP requests.

## Features

- RFC 3507 compliant ICAP implementation
- Handles OPTIONS and REQMOD requests
- JSON parsing and token detection using regex
- MySQL database integration for token lookup
- Docker support with multi-stage builds
- Production-ready with proper error handling
- Configurable via command-line arguments
- Debug mode for troubleshooting

## Architecture

The ICAP server acts as a content adaptation service for Squid:

```
Client -> Squid Proxy -> ICAP Server -> MySQL Database
                      -> Origin Server
```

## Building

### Prerequisites

- GCC compiler
- MySQL client libraries (`libmysqlclient-dev`)
- cJSON library (`libcjson-dev`)
- Make

### Compile

```bash
# Build release version
make

# Build debug version
make DEBUG=1

# Build both versions
make both

# Check dependencies
make check-deps
```

## Installation

### Manual Installation

```bash
# Install to /usr/local/bin
sudo make install

# Run directly
./build/release/icap_server -h localhost -u tokenshield -P password -d tokenshield
```

### Docker Installation

```bash
# Build Docker image
docker build -t tokenshield/icap-server .

# Run with docker-compose
docker-compose up -d

# Run standalone
docker run -p 1344:1344 \
  -e MYSQL_HOST=mysql \
  -e MYSQL_USER=tokenshield \
  -e MYSQL_PASSWORD=password \
  tokenshield/icap-server
```

## Configuration

### Command Line Arguments

```
-p PORT     ICAP port (default: 1344)
-h HOST     MySQL host (default: localhost)
-u USER     MySQL user (default: tokenshield)
-P PASS     MySQL password (default: password)
-d DB       MySQL database (default: tokenshield)
-D          Enable debug mode
```

### Environment Variables (Docker)

- `MYSQL_HOST` - MySQL server hostname
- `MYSQL_USER` - MySQL username
- `MYSQL_PASSWORD` - MySQL password
- `MYSQL_DATABASE` - MySQL database name
- `MYSQL_PORT` - MySQL port (default: 3306)
- `ICAP_PORT` - ICAP server port (default: 1344)
- `DEBUG_MODE` - Enable debug logging (0/1)

## Database Schema

The server expects a `tokens` table with at least these columns:

```sql
CREATE TABLE tokens (
    token VARCHAR(255) PRIMARY KEY,
    card_number VARCHAR(19) NOT NULL
);
```

See `init.sql` for the complete schema with audit logging.

## Squid Integration

Add to your `squid.conf`:

```conf
# Enable ICAP
icap_enable on

# Define ICAP service
icap_service tokenshield_reqmod reqmod_precache icap://localhost:1344/tokenshield

# Apply to JSON POST/PUT requests
acl JSON_CONTENT req_header Content-Type -i application/json
acl POST_PUT method POST PUT PATCH
adaptation_access tokenshield_reqmod allow POST_PUT JSON_CONTENT
```

## Token Format

The server detects tokens matching the pattern: `tok_[a-zA-Z0-9_]+`

Example tokens:
- `tok_test_visa_1234`
- `tok_live_mc_5678`
- `tok_sandbox_amex_9012`

## Testing

### Test ICAP OPTIONS

```bash
echo -e "OPTIONS icap://localhost:1344/tokenshield ICAP/1.0\r\nHost: localhost\r\n\r\n" | nc localhost 1344
```

### Test with curl through Squid

```bash
# Set Squid as proxy
export http_proxy=http://localhost:3128

# Send JSON with token
curl -X POST http://example.com/api/payment \
  -H "Content-Type: application/json" \
  -d '{"card": "tok_test_visa_1234", "amount": 100}'
```

## Performance

- Written in C for maximum performance
- Minimal memory footprint
- Persistent MySQL connections
- Efficient regex matching
- No memory leaks (verified with Valgrind)

## Security

- Runs as non-root user in Docker
- Input validation and bounds checking
- SQL injection prevention
- No buffer overflows
- Secure token handling

## Debugging

### Enable Debug Mode

```bash
# Command line
./icap_server -D

# Docker
docker run -e DEBUG_MODE=1 tokenshield/icap-server
```

### Check Memory Leaks

```bash
make memcheck
```

### Static Analysis

```bash
make analyze
```

## Monitoring

### Health Check

The server responds to ICAP OPTIONS requests which can be used for health monitoring:

```bash
# Check if server is running
curl -s -o /dev/null -w "%{http_code}" http://localhost:1344/
```

### Logs

- Application logs: stdout/stderr
- Audit logs: MySQL `audit_log` table
- Squid logs: `/var/log/squid/access.log`

## Troubleshooting

### Common Issues

1. **Connection refused**
   - Check if server is running: `ps aux | grep icap_server`
   - Check port: `netstat -tlnp | grep 1344`

2. **MySQL connection failed**
   - Verify MySQL credentials
   - Check MySQL is running
   - Test connection: `mysql -h localhost -u tokenshield -p`

3. **Tokens not being replaced**
   - Enable debug mode to see token detection
   - Check token format matches regex
   - Verify token exists in database

4. **Squid not sending requests to ICAP**
   - Check Squid configuration
   - Verify ICAP service is defined correctly
   - Check Squid logs

## License

Copyright (c) 2024 TokenShield. All rights reserved.