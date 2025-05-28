FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .

# Create non-root user
RUN useradd -m -s /bin/bash api && chown -R api:api /app
USER api

# Expose port
EXPOSE 8090

# Run the application
CMD ["gunicorn", "--bind", "0.0.0.0:8090", "--workers", "4", "app:app"]