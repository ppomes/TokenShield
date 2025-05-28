#!/bin/bash

# Parse DATABASE_URL to extract components
if [ -n "$DATABASE_URL" ]; then
    # Remove mysql:// prefix
    DB_URL="${DATABASE_URL#mysql://}"
    
    # Extract user:pass@host:port/database
    USER_PASS="${DB_URL%%@*}"
    HOST_PORT_DB="${DB_URL#*@}"
    
    # Extract user and password
    DB_USER="${USER_PASS%%:*}"
    DB_PASS="${USER_PASS#*:}"
    
    # Extract host:port and database
    HOST_PORT="${HOST_PORT_DB%%/*}"
    DB_NAME="${HOST_PORT_DB#*/}"
    
    # Extract host and port
    DB_HOST="${HOST_PORT%%:*}"
    DB_PORT="${HOST_PORT#*:}"
    
    # Set default port if not specified
    if [ "$DB_HOST" = "$HOST_PORT" ]; then
        DB_PORT="3306"
    fi
else
    # Use individual environment variables
    DB_HOST="${DB_HOST:-mysql}"
    DB_PORT="${DB_PORT:-3306}"
    DB_USER="${DB_USER:-root}"
    DB_PASS="${DB_PASSWORD:-rootpassword}"
    DB_NAME="${DB_NAME:-tokenshield}"
fi

# Wait for MySQL to be ready
echo "Waiting for MySQL at $DB_HOST:$DB_PORT..."
while ! nc -z "$DB_HOST" "$DB_PORT"; do
    sleep 1
done
echo "MySQL is ready!"

# Start ICAP server
ARGS="-h $DB_HOST -u $DB_USER -P $DB_PASS -d $DB_NAME -p ${ICAP_PORT:-1344}"

if [ "$DEBUG_MODE" = "1" ]; then
    ARGS="$ARGS -D"
fi

echo "Starting ICAP server with: /app/icap-server $ARGS"
exec /app/icap-server $ARGS 2>&1