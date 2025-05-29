package main

import (
    "bufio"
    "bytes"
    "crypto/rand"
    "database/sql"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "os"
    "regexp"
    "strconv"
    "strings"
    "sync"
    "time"

    "github.com/fernet/fernet-go"
    _ "github.com/go-sql-driver/mysql"
)

type UnifiedTokenizer struct {
    db              *sql.DB
    encryptionKey   *fernet.Key
    appEndpoint     string
    tokenRegex      *regexp.Regexp
    cardRegex       *regexp.Regexp
    httpPort        string
    icapPort        string
    debug           bool
    mu              sync.RWMutex
}

func NewUnifiedTokenizer() (*UnifiedTokenizer, error) {
    // Database connection
    dbHost := getEnv("DB_HOST", "mysql")
    dbPort := getEnv("DB_PORT", "3306")
    dbUser := getEnv("DB_USER", "pciproxy")
    dbPassword := getEnv("DB_PASSWORD", "pciproxy123")
    dbName := getEnv("DB_NAME", "tokenshield")
    
    dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName)
    db, err := sql.Open("mysql", dsn)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to database: %v", err)
    }
    
    // Test connection
    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("failed to ping database: %v", err)
    }
    
    // Set connection pool settings
    db.SetMaxOpenConns(25)
    db.SetMaxIdleConns(5)
    db.SetConnMaxLifetime(5 * time.Minute)
    
    // Encryption key
    encKeyStr := getEnv("ENCRYPTION_KEY", "")
    if encKeyStr == "" {
        // Generate a key for development
        encKeyStr = base64.URLEncoding.EncodeToString(fernet.Generate().Encode())
        log.Printf("WARNING: Using generated encryption key. Set ENCRYPTION_KEY in production!")
    }
    
    keyBytes, err := base64.URLEncoding.DecodeString(encKeyStr)
    if err != nil {
        return nil, fmt.Errorf("invalid encryption key: %v", err)
    }
    
    encKey, err := fernet.DecodeKey(string(keyBytes))
    if err != nil {
        return nil, fmt.Errorf("failed to decode encryption key: %v", err)
    }
    
    return &UnifiedTokenizer{
        db:            db,
        encryptionKey: encKey,
        appEndpoint:   getEnv("APP_ENDPOINT", "http://dummy-app:8000"),
        tokenRegex:    regexp.MustCompile(`tok_[a-zA-Z0-9_\-]+`),
        cardRegex:     regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b`),
        httpPort:      getEnv("HTTP_PORT", "8080"),
        icapPort:      getEnv("ICAP_PORT", "1344"),
        debug:         getEnv("DEBUG_MODE", "0") == "1",
    }, nil
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

// HTTP Tokenization Handler
func (ut *UnifiedTokenizer) handleTokenize(w http.ResponseWriter, r *http.Request) {
    start := time.Now()
    path := r.URL.Path
    
    if ut.debug {
        log.Printf("=== INCOMING REQUEST: %s %s ===", r.Method, path)
        log.Printf("Headers: %v", r.Header)
    }
    
    // Read body
    body, err := io.ReadAll(r.Body)
    if err != nil {
        log.Printf("Error reading body: %v", err)
        http.Error(w, "Error reading request", http.StatusBadRequest)
        return
    }
    r.Body.Close()
    
    // Process body for tokenization
    var processedBody []byte
    contentType := r.Header.Get("Content-Type")
    
    if strings.Contains(contentType, "application/json") && len(body) > 0 {
        tokenized, modified, err := ut.tokenizeJSON(string(body))
        if err != nil {
            log.Printf("Error tokenizing JSON: %v", err)
            processedBody = body
        } else {
            processedBody = []byte(tokenized)
            if modified && ut.debug {
                log.Printf("Tokenized request body")
            }
        }
    } else {
        processedBody = body
    }
    
    // Build forward URL
    forwardURL := ut.appEndpoint
    if path != "" && path != "/" {
        forwardURL = strings.TrimRight(ut.appEndpoint, "/") + path
    }
    
    if r.URL.RawQuery != "" {
        forwardURL += "?" + r.URL.RawQuery
    }
    
    // Create new request
    req, err := http.NewRequest(r.Method, forwardURL, bytes.NewReader(processedBody))
    if err != nil {
        log.Printf("Error creating forward request: %v", err)
        http.Error(w, "Error creating request", http.StatusInternalServerError)
        return
    }
    
    // Copy headers
    for key, values := range r.Header {
        for _, value := range values {
            req.Header.Add(key, value)
        }
    }
    
    // Update Content-Length
    req.ContentLength = int64(len(processedBody))
    req.Header.Set("Content-Length", strconv.Itoa(len(processedBody)))
    
    // Forward request
    client := &http.Client{
        Timeout: 30 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }
    
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Error forwarding request: %v", err)
        http.Error(w, "Error forwarding request", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()
    
    // Copy response headers
    for key, values := range resp.Header {
        for _, value := range values {
            w.Header().Add(key, value)
        }
    }
    
    // Set status code
    w.WriteHeader(resp.StatusCode)
    
    // Copy response body
    io.Copy(w, resp.Body)
    
    duration := time.Since(start)
    log.Printf("Request %s %s completed in %v with status %d", r.Method, path, duration, resp.StatusCode)
}

// ICAP Detokenization Server
func (ut *UnifiedTokenizer) handleICAP(conn net.Conn) {
    defer conn.Close()
    
    reader := bufio.NewReader(conn)
    writer := bufio.NewWriter(conn)
    
    // Read request line
    requestLine, err := reader.ReadString('\n')
    if err != nil {
        if err != io.EOF {
            log.Printf("Error reading request line: %v", err)
        }
        return
    }
    
    requestLine = strings.TrimSpace(requestLine)
    parts := strings.Split(requestLine, " ")
    if len(parts) < 3 {
        log.Printf("Invalid request line: %s", requestLine)
        return
    }
    
    method := parts[0]
    icapURI := parts[1]
    version := parts[2]
    
    if ut.debug {
        log.Printf("ICAP Request: %s %s %s", method, icapURI, version)
    }
    
    // Read headers
    headers := make(map[string]string)
    for {
        line, err := reader.ReadString('\n')
        if err != nil {
            log.Printf("Error reading headers: %v", err)
            return
        }
        line = strings.TrimSpace(line)
        if line == "" {
            break
        }
        
        colonIndex := strings.Index(line, ":")
        if colonIndex > 0 {
            key := strings.TrimSpace(line[:colonIndex])
            value := strings.TrimSpace(line[colonIndex+1:])
            headers[key] = value
        }
    }
    
    switch method {
    case "OPTIONS":
        ut.handleICAPOptions(writer, icapURI)
    case "REQMOD":
        ut.handleICAPReqmod(reader, writer, headers)
    default:
        log.Printf("Unsupported ICAP method: %s", method)
    }
    
    writer.Flush()
}

func (ut *UnifiedTokenizer) handleICAPOptions(writer *bufio.Writer, icapURI string) {
    response := fmt.Sprintf("ICAP/1.0 200 OK\r\n")
    response += "Methods: REQMOD\r\n"
    response += "Service: TokenShield Unified 1.0\r\n"
    response += "ISTag: \"TS-001\"\r\n"
    response += "Max-Connections: 100\r\n"
    response += "Options-TTL: 3600\r\n"
    response += "Allow: 204\r\n"
    response += "Preview: 0\r\n"
    response += "Transfer-Complete: *\r\n"
    response += "\r\n"
    
    writer.WriteString(response)
    writer.Flush()
    
    if ut.debug {
        log.Printf("Sent OPTIONS response for %s", icapURI)
    }
}

func (ut *UnifiedTokenizer) handleICAPReqmod(reader *bufio.Reader, writer *bufio.Writer, icapHeaders map[string]string) {
    // Parse encapsulated header
    encapHeader := icapHeaders["Encapsulated"]
    if encapHeader == "" {
        log.Printf("Missing Encapsulated header")
        return
    }
    
    // Read HTTP request
    httpRequest, httpHeaders, body, err := ut.parseEncapsulated(reader, encapHeader)
    if err != nil {
        log.Printf("Error parsing encapsulated data: %v", err)
        return
    }
    
    if ut.debug {
        log.Printf("HTTP Request: %s", httpRequest)
        log.Printf("Body length: %d", len(body))
    }
    
    // Check if we need to modify
    modified := false
    modifiedBody := body
    
    if len(body) > 0 {
        detokenized, wasModified, err := ut.detokenizeJSON(string(body))
        if err == nil && wasModified {
            modifiedBody = []byte(detokenized)
            modified = true
            log.Printf("Detokenized request body")
        }
    }
    
    if !modified {
        // Send 204 No Content
        response := "ICAP/1.0 204 No Content\r\n\r\n"
        writer.WriteString(response)
        writer.Flush()
        return
    }
    
    // Send modified response
    response := "ICAP/1.0 200 OK\r\n"
    
    // Calculate positions
    reqHdrLen := len(httpRequest) + 2 // +2 for \r\n
    for _, hdr := range httpHeaders {
        reqHdrLen += len(hdr) + 2
    }
    reqHdrLen += 2 // empty line
    
    response += fmt.Sprintf("Encapsulated: req-hdr=0, req-body=%d\r\n", reqHdrLen)
    response += "\r\n"
    
    // Write HTTP request line
    response += httpRequest + "\r\n"
    
    // Write HTTP headers (update Content-Length)
    contentLengthUpdated := false
    for _, hdr := range httpHeaders {
        if strings.HasPrefix(strings.ToLower(hdr), "content-length:") {
            response += fmt.Sprintf("Content-Length: %d\r\n", len(modifiedBody))
            contentLengthUpdated = true
        } else {
            response += hdr + "\r\n"
        }
    }
    
    if !contentLengthUpdated {
        response += fmt.Sprintf("Content-Length: %d\r\n", len(modifiedBody))
    }
    
    response += "\r\n"
    
    // Write response
    writer.WriteString(response)
    
    // Write body in chunks
    ut.writeChunked(writer, modifiedBody)
    writer.Flush()
}

func (ut *UnifiedTokenizer) parseEncapsulated(reader *bufio.Reader, encapHeader string) (string, []string, []byte, error) {
    // Parse positions from Encapsulated header
    positions := make(map[string]int)
    parts := strings.Split(encapHeader, ",")
    for _, part := range parts {
        kv := strings.Split(strings.TrimSpace(part), "=")
        if len(kv) == 2 {
            pos, _ := strconv.Atoi(kv[1])
            positions[kv[0]] = pos
        }
    }
    
    // Read HTTP request line
    requestLine, err := reader.ReadString('\n')
    if err != nil {
        return "", nil, nil, err
    }
    requestLine = strings.TrimSpace(requestLine)
    
    // Read HTTP headers
    var httpHeaders []string
    for {
        line, err := reader.ReadString('\n')
        if err != nil {
            return "", nil, nil, err
        }
        line = strings.TrimSpace(line)
        if line == "" {
            break
        }
        httpHeaders = append(httpHeaders, line)
    }
    
    // Read body if present
    var body []byte
    if _, hasBody := positions["req-body"]; hasBody {
        body, err = ut.readChunked(reader)
        if err != nil {
            return "", nil, nil, err
        }
    }
    
    return requestLine, httpHeaders, body, nil
}

func (ut *UnifiedTokenizer) readChunked(reader *bufio.Reader) ([]byte, error) {
    var result []byte
    
    for {
        // Read chunk size
        sizeLine, err := reader.ReadString('\n')
        if err != nil {
            return nil, err
        }
        
        sizeLine = strings.TrimSpace(sizeLine)
        size, err := strconv.ParseInt(sizeLine, 16, 64)
        if err != nil {
            return nil, err
        }
        
        if size == 0 {
            // Read final CRLF
            reader.ReadString('\n')
            break
        }
        
        // Read chunk data
        chunk := make([]byte, size)
        _, err = io.ReadFull(reader, chunk)
        if err != nil {
            return nil, err
        }
        
        result = append(result, chunk...)
        
        // Read trailing CRLF
        reader.ReadString('\n')
    }
    
    return result, nil
}

func (ut *UnifiedTokenizer) writeChunked(writer *bufio.Writer, data []byte) {
    if len(data) > 0 {
        writer.WriteString(fmt.Sprintf("%x\r\n", len(data)))
        writer.Write(data)
        writer.WriteString("\r\n")
    }
    writer.WriteString("0\r\n\r\n")
}

// Tokenization logic
func (ut *UnifiedTokenizer) tokenizeJSON(jsonStr string) (string, bool, error) {
    var data interface{}
    if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
        return jsonStr, false, err
    }
    
    modified := false
    ut.processValue(&data, &modified, true) // true for tokenization
    
    result, err := json.Marshal(data)
    if err != nil {
        return jsonStr, false, err
    }
    
    return string(result), modified, nil
}

// Detokenization logic
func (ut *UnifiedTokenizer) detokenizeJSON(jsonStr string) (string, bool, error) {
    var data interface{}
    if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
        return jsonStr, false, err
    }
    
    modified := false
    ut.processValue(&data, &modified, false) // false for detokenization
    
    result, err := json.Marshal(data)
    if err != nil {
        return jsonStr, false, err
    }
    
    return string(result), modified, nil
}

func (ut *UnifiedTokenizer) processValue(v interface{}, modified *bool, tokenize bool) {
    switch val := v.(type) {
    case *interface{}:
        ut.processValue(*val, modified, tokenize)
    case map[string]interface{}:
        for k, v := range val {
            if tokenize && ut.isCreditCardField(k) {
                if str, ok := v.(string); ok && ut.cardRegex.MatchString(str) {
                    token := ut.generateToken()
                    if err := ut.storeCard(token, str); err == nil {
                        val[k] = token
                        *modified = true
                        log.Printf("Tokenized card ending in %s", str[len(str)-4:])
                    }
                }
            } else if !tokenize && ut.isCreditCardField(k) {
                if str, ok := v.(string); ok && ut.tokenRegex.MatchString(str) {
                    if card := ut.retrieveCard(str); card != "" {
                        val[k] = card
                        *modified = true
                        log.Printf("Detokenized token %s", str)
                    }
                }
            } else {
                ut.processValue(v, modified, tokenize)
            }
        }
    case []interface{}:
        for i := range val {
            ut.processValue(&val[i], modified, tokenize)
        }
    case string:
        // Handle string values that might contain tokens or card numbers
        if tokenize && ut.cardRegex.MatchString(val) {
            // This case is handled by the parent map processor
        } else if !tokenize && ut.tokenRegex.MatchString(val) {
            // This case is handled by the parent map processor  
        }
    }
}

func (ut *UnifiedTokenizer) isCreditCardField(fieldName string) bool {
    lowerField := strings.ToLower(fieldName)
    cardFields := []string{"card_number", "cardnumber", "card", "creditcard", "credit_card", "pan", "account_number"}
    for _, field := range cardFields {
        if strings.Contains(lowerField, field) {
            return true
        }
    }
    return false
}

func (ut *UnifiedTokenizer) generateToken() string {
    b := make([]byte, 32)
    rand.Read(b)
    return "tok_" + base64.URLEncoding.EncodeToString(b)
}

func (ut *UnifiedTokenizer) storeCard(token, cardNumber string) error {
    encrypted := ut.encryptionKey.EncryptAndSign([]byte(cardNumber))
    
    _, err := ut.db.Exec(`
        INSERT INTO credit_cards (token, card_number_encrypted, card_last_four, created_at, is_active)
        VALUES (?, ?, ?, NOW(), TRUE)
    `, token, encrypted, cardNumber[len(cardNumber)-4:], )
    
    if err == nil {
        _, _ = ut.db.Exec(`
            INSERT INTO token_requests (token, request_type, source_ip, destination_url, response_status, created_at)
            VALUES (?, 'tokenize', '127.0.0.1', '', 200, NOW())
        `, token)
    }
    
    return err
}

func (ut *UnifiedTokenizer) retrieveCard(token string) string {
    var encryptedCard []byte
    err := ut.db.QueryRow(`
        SELECT card_number_encrypted FROM credit_cards 
        WHERE token = ? AND is_active = TRUE
    `, token).Scan(&encryptedCard)
    
    if err != nil {
        if err != sql.ErrNoRows {
            log.Printf("Database error: %v", err)
        }
        return ""
    }
    
    cardBytes := ut.encryptionKey.DecryptAndVerify(encryptedCard)
    if cardBytes == nil {
        log.Printf("Failed to decrypt card for token %s", token)
        return ""
    }
    
    _, _ = ut.db.Exec(`
        INSERT INTO token_requests (token, request_type, source_ip, destination_url, response_status, created_at)
        VALUES (?, 'detokenize', '127.0.0.1', '', 200, NOW())
    `, token)
    
    return string(cardBytes)
}

func (ut *UnifiedTokenizer) startHTTPServer() {
    http.HandleFunc("/", ut.handleTokenize)
    
    log.Printf("Starting HTTP tokenization server on port %s", ut.httpPort)
    if err := http.ListenAndServe(":"+ut.httpPort, nil); err != nil {
        log.Fatalf("HTTP server failed: %v", err)
    }
}

func (ut *UnifiedTokenizer) startICAPServer() {
    listener, err := net.Listen("tcp", ":"+ut.icapPort)
    if err != nil {
        log.Fatalf("Failed to start ICAP server: %v", err)
    }
    defer listener.Close()
    
    log.Printf("Starting ICAP detokenization server on port %s", ut.icapPort)
    
    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Failed to accept connection: %v", err)
            continue
        }
        
        go ut.handleICAP(conn)
    }
}

func main() {
    log.SetFlags(log.LstdFlags | log.Lshortfile)
    
    ut, err := NewUnifiedTokenizer()
    if err != nil {
        log.Fatalf("Failed to initialize tokenizer: %v", err)
    }
    defer ut.db.Close()
    
    log.Printf("TokenShield Unified Service starting...")
    log.Printf("HTTP Port: %s, ICAP Port: %s", ut.httpPort, ut.icapPort)
    log.Printf("App Endpoint: %s", ut.appEndpoint)
    
    // Start both servers
    go ut.startHTTPServer()
    ut.startICAPServer()
}