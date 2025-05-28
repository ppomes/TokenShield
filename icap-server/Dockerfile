# Multi-stage build for TokenShield ICAP Server
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    libmysqlclient-dev \
    libcjson-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create build directory
WORKDIR /build

# Copy source files
COPY icap_server.c Makefile ./

# Build the ICAP server
RUN make clean && make

# Runtime stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libmysqlclient21 \
    libcjson1 \
    netcat \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/build/release/icap_server /app/icap-server
RUN chmod +x /app/icap-server

# Copy entrypoint script
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

# Create non-root user
RUN useradd -m -s /bin/bash -u 1000 icapuser && \
    chown -R icapuser:icapuser /app

# Create log directory
RUN mkdir -p /var/log/tokenshield && \
    chown icapuser:icapuser /var/log/tokenshield

# Switch to non-root user
USER icapuser

# Expose ICAP port
EXPOSE 1344

# Set environment variables with defaults
ENV DATABASE_URL="" \
    DB_HOST=mysql \
    DB_PORT=3306 \
    DB_USER=root \
    DB_PASS=rootpassword \
    DB_NAME=tokenshield \
    ICAP_PORT=1344

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD echo -e "OPTIONS icap://localhost:1344/tokenshield ICAP/1.0\r\nHost: localhost\r\n\r\n" | \
        nc -w 2 localhost 1344 | grep -q "200 OK" || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]