FROM ubuntu:22.04

# Install Squid and dependencies
RUN apt-get update && apt-get install -y \
    squid \
    squid-openssl \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /var/spool/squid /var/log/squid /etc/squid/certs

# Generate self-signed certificate for SSL bump
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/squid/certs/squid.pem \
    -out /etc/squid/certs/squid.pem \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=pci-proxy"

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