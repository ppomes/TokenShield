FROM python:3.9-slim

WORKDIR /app

# Install OpenSSL for certificate generation
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .

# Create directory for certificates
RUN mkdir -p /app/certs

# Expose HTTPS port
EXPOSE 9000

# Run the application
CMD ["python", "app.py"]