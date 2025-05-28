FROM ubuntu:22.04

# Install Squid and dependencies
RUN apt-get update && apt-get install -y \
    squid-openssl \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /var/spool/squid /var/log/squid /etc/squid/certs

# Generate CA certificate for SSL bump
RUN openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
    -subj "/C=US/ST=State/L=City/O=TokenShield/CN=TokenShield CA" \
    -keyout /etc/squid/certs/squid-ca-key.pem \
    -out /etc/squid/certs/squid-ca-cert.pem && \
    cat /etc/squid/certs/squid-ca-cert.pem /etc/squid/certs/squid-ca-key.pem > /etc/squid/certs/squid-ca-cert-key.pem

# Initialize cache directory
RUN squid -N -z

# Copy configuration
COPY squid.conf /etc/squid/squid.conf

# Set permissions
RUN chown -R proxy:proxy /var/spool/squid /var/log/squid /etc/squid

# Expose ports
EXPOSE 3128 3129

# Run Squid
CMD ["squid", "-N", "-d", "1"]