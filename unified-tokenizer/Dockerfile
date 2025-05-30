# Build stage
FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy all files first
COPY . .

# Download dependencies and build
RUN go mod tidy && \
    go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o unified-tokenizer .

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/unified-tokenizer .

# Expose HTTP, ICAP, and API ports
EXPOSE 8080 1344 8090

# Run the unified tokenizer
CMD ["./unified-tokenizer"]