# Build stage
FROM golang:1.19-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY main.go test_icap.go ./
RUN go build -o icap-server main.go
RUN go build -o test-icap test_icap.go

# Runtime stage  
FROM alpine:latest

RUN apk --no-cache add ca-certificates netcat-openbsd
WORKDIR /app

COPY --from=builder /app/icap-server .
COPY --from=builder /app/test-icap .
RUN chmod +x icap-server test-icap

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD echo -e "OPTIONS icap://localhost:1344/tokenshield ICAP/1.0\r\nHost: localhost\r\n\r\n" | \
        nc -w 2 localhost 1344 | grep -q "200 OK" || exit 1

EXPOSE 1344

CMD ["./icap-server"]