package main

import (
    "bufio"
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    cryptorand "crypto/rand"
    "database/sql"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "log"
    "math/rand"
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
    encryptionKey   *fernet.Key  // Legacy, kept for migration
    keyManager      *KeyManager
    appEndpoint     string
    tokenRegex      *regexp.Regexp
    cardRegex       *regexp.Regexp
    httpPort        string
    icapPort        string
    apiPort         string
    debug           bool
    tokenFormat     string // "prefix" for tok_ format, "luhn" for Luhn-valid format
    useKEKDEK       bool   // Whether to use KEK/DEK encryption
    mu              sync.RWMutex
}

// KeyManager handles KEK/DEK encryption
type KeyManager struct {
    db           *sql.DB
    kekCache     map[string][]byte
    dekCache     map[string][]byte
    currentDEKID string
    mu           sync.RWMutex
}

func NewUnifiedTokenizer() (*UnifiedTokenizer, error) {
    // Database connection
    dbHost := getEnv("DB_HOST", "mysql")
    dbPort := getEnv("DB_PORT", "3306")
    dbUser := getEnv("DB_USER", "pciproxy")
    dbPassword := getEnv("DB_PASSWORD", "pciproxy123")
    dbName := getEnv("DB_NAME", "tokenshield")
    
    dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", dbUser, dbPassword, dbHost, dbPort, dbName)
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
        key := fernet.Key{} 
        key.Generate()
        encKeyStr = base64.URLEncoding.EncodeToString(key[:])
        log.Printf("WARNING: Using generated encryption key. Set ENCRYPTION_KEY in production!")
    }
    
    keyBytes, err := base64.URLEncoding.DecodeString(encKeyStr)
    if err != nil {
        return nil, fmt.Errorf("invalid encryption key: %v", err)
    }
    
    if len(keyBytes) != 32 {
        return nil, fmt.Errorf("encryption key must be 32 bytes")
    }
    
    encKey := new(fernet.Key)
    copy(encKey[:], keyBytes)
    
    tokenFormat := getEnv("TOKEN_FORMAT", "prefix")
    if tokenFormat != "prefix" && tokenFormat != "luhn" {
        tokenFormat = "prefix"
    }
    
    // Adjust token regex based on format
    var tokenRegex *regexp.Regexp
    if tokenFormat == "luhn" {
        // Match 16-digit numbers starting with our special prefix (9999)
        tokenRegex = regexp.MustCompile(`\b9999[0-9]{12}\b`)
    } else {
        tokenRegex = regexp.MustCompile(`tok_[a-zA-Z0-9_\-]+=*`)
    }
    
    // Check if KEK/DEK is enabled
    useKEKDEK := getEnv("USE_KEK_DEK", "false") == "true"
    
    ut := &UnifiedTokenizer{
        db:            db,
        encryptionKey: encKey,
        appEndpoint:   getEnv("APP_ENDPOINT", "http://dummy-app:8000"),
        tokenRegex:    tokenRegex,
        cardRegex:     regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b`),
        httpPort:      getEnv("HTTP_PORT", "8080"),
        icapPort:      getEnv("ICAP_PORT", "1344"),
        apiPort:       getEnv("API_PORT", "8090"),
        debug:         getEnv("DEBUG_MODE", "0") == "1",
        tokenFormat:   tokenFormat,
        useKEKDEK:     useKEKDEK,
    }
    
    // Initialize KeyManager if KEK/DEK is enabled
    if useKEKDEK {
        km, err := NewKeyManager(db)
        if err != nil {
            log.Printf("Warning: Failed to initialize KeyManager: %v. Falling back to legacy encryption.", err)
            ut.useKEKDEK = false
        } else {
            ut.keyManager = km
        }
    }
    
    return ut, nil
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
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
    
    // Read response body
    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Printf("Error reading response body: %v", err)
        http.Error(w, "Error reading response", http.StatusInternalServerError)
        return
    }
    
    // Check if this is an endpoint that needs response detokenization
    processedRespBody := respBody
    needsDetokenization := (path == "/api/cards" || path == "/my-cards") && resp.StatusCode == 200
    
    if needsDetokenization {
        respContentType := resp.Header.Get("Content-Type")
        if ut.debug {
            log.Printf("DEBUG: Response content type: %s", respContentType)
            log.Printf("DEBUG: Response body preview: %s", string(respBody[:min(200, len(respBody))]))
        }
        
        // Handle JSON responses (API)
        if strings.Contains(respContentType, "application/json") {
            detokenized, modified, err := ut.detokenizeJSON(string(respBody))
            if err != nil {
                log.Printf("Error detokenizing JSON response: %v", err)
            } else if modified {
                processedRespBody = []byte(detokenized)
                log.Printf("Detokenized JSON response body for %s", path)
            } else if ut.debug {
                log.Printf("DEBUG: No tokens found to detokenize in JSON response")
            }
        } else if strings.Contains(respContentType, "text/html") {
            // Handle HTML responses (web pages)
            detokenized, modified, err := ut.detokenizeHTML(string(respBody))
            if err != nil {
                log.Printf("Error detokenizing HTML response: %v", err)
            } else if modified {
                processedRespBody = []byte(detokenized)
                log.Printf("Detokenized HTML response body for %s", path)
            } else if ut.debug {
                log.Printf("DEBUG: No tokens found to detokenize in HTML response")
            }
        }
    }
    
    // Copy response headers
    for key, values := range resp.Header {
        if key != "Content-Length" {
            for _, value := range values {
                w.Header().Add(key, value)
            }
        }
    }
    
    // Set correct content length
    w.Header().Set("Content-Length", strconv.Itoa(len(processedRespBody)))
    
    // Set status code
    w.WriteHeader(resp.StatusCode)
    
    // Write response body
    w.Write(processedRespBody)
    
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
    case "RESPMOD":
        ut.handleICAPRespmod(reader, writer, headers)
    default:
        log.Printf("Unsupported ICAP method: %s", method)
    }
    
    writer.Flush()
}

func (ut *UnifiedTokenizer) handleICAPOptions(writer *bufio.Writer, icapURI string) {
    response := fmt.Sprintf("ICAP/1.0 200 OK\r\n")
    
    // Support both REQMOD and RESPMOD based on the URI
    if strings.Contains(icapURI, "/respmod") {
        response += "Methods: RESPMOD\r\n"
    } else {
        response += "Methods: REQMOD\r\n"
    }
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

func (ut *UnifiedTokenizer) handleICAPRespmod(reader *bufio.Reader, writer *bufio.Writer, icapHeaders map[string]string) {
    // Parse encapsulated header for response modification
    encapHeader := icapHeaders["Encapsulated"]
    if encapHeader == "" {
        log.Printf("Missing Encapsulated header in RESPMOD")
        return
    }
    
    if ut.debug {
        log.Printf("RESPMOD: Processing response for tokenization")
        log.Printf("Encapsulated: %s", encapHeader)
    }
    
    // Parse the response (request + response)
    httpRequest, httpHeaders, body, err := ut.parseEncapsulated(reader, encapHeader)
    if err != nil {
        log.Printf("RESPMOD Error parsing encapsulated response data: %v", err)
        return
    }
    
    if ut.debug {
        log.Printf("Response HTTP Request: %s", httpRequest)
        log.Printf("Response body length: %d", len(body))
    }
    
    // Check if we need to tokenize the response
    modified := false
    modifiedBody := body
    
    // Handle null-body case - send 204 No Content
    if len(body) == 0 {
        if ut.debug {
            log.Printf("RESPMOD: No body to process, sending 204 No Content")
        }
        response := "ICAP/1.0 204 No Content\r\n"
        response += "ISTag: \"TS-001\"\r\n"
        response += "\r\n"
        writer.WriteString(response)
        writer.Flush()
        return
    }
    
    // Look for JSON responses that might contain card data
    if len(body) > 0 {
        contentType := ""
        for _, header := range httpHeaders {
            if strings.HasPrefix(strings.ToLower(header), "content-type:") {
                contentType = strings.ToLower(header)
                break
            }
        }
        
        if strings.Contains(contentType, "application/json") {
            if ut.debug {
                log.Printf("RESPMOD: Found JSON response, checking for cards to tokenize")
            }
            
            tokenizedJSON, wasModified, err := ut.tokenizeJSON(string(body))
            if err != nil {
                log.Printf("Error tokenizing JSON response: %v", err)
            } else if wasModified {
                modifiedBody = []byte(tokenizedJSON)
                modified = true
                log.Printf("RESPMOD: Tokenized card numbers in response")
            }
        }
    }
    
    // Send response
    if !modified {
        // No modification - send 204 No Content
        response := "ICAP/1.0 204 No Content\r\n"
        response += "ISTag: \"TS-001\"\r\n"
        response += "\r\n"
        writer.WriteString(response)
    } else {
        // Modified - send 200 OK with new body
        
        // Build HTTP response first to calculate exact positions
        // Include HTTP status line + headers
        httpHeadersStr := httpRequest + "\r\n" // HTTP status line
        for _, header := range httpHeaders {
            if strings.HasPrefix(strings.ToLower(header), "content-length:") {
                // Update content length for modified body
                httpHeadersStr += fmt.Sprintf("Content-Length: %d\r\n", len(modifiedBody))
            } else {
                httpHeadersStr += header + "\r\n"
            }
        }
        httpHeadersStr += "\r\n" // End of headers
        
        // Calculate exact byte positions for Encapsulated header
        resBodyOffset := len(httpHeadersStr)
        
        // Build ICAP response
        response := "ICAP/1.0 200 OK\r\n"
        response += "ISTag: \"TS-001\"\r\n"
        response += fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n", resBodyOffset)
        response += "\r\n"
        
        // Write ICAP headers
        writer.WriteString(response)
        
        // Write HTTP response headers
        writer.WriteString(httpHeadersStr)
        
        // Write modified body in chunks
        ut.writeChunked(writer, modifiedBody)
    }
    
    writer.Flush()
}

func (ut *UnifiedTokenizer) parseEncapsulated(reader *bufio.Reader, encapHeader string) (string, []string, []byte, error) {
    log.Printf("DEBUG_FORCE: parseEncapsulated called with header: %s", encapHeader)
    
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
    
    if ut.debug {
        log.Printf("DEBUG: parseEncapsulated positions: %+v", positions)
    }
    
    // For RESPMOD: req-hdr=0, res-hdr=175, res-body=322
    // This means: request headers start at 0, response headers at 175, response body at 322
    
    var requestLine string
    var httpHeaders []string
    var body []byte
    var err error
    
    // Determine if this is REQMOD or RESPMOD
    isRespmod := false
    if _, hasResHdr := positions["res-hdr"]; hasResHdr {
        isRespmod = true
    }
    
    if isRespmod {
        // RESPMOD: Skip request headers section if present, then read response headers
        if _, hasReqHdr := positions["req-hdr"]; hasReqHdr {
            if ut.debug {
                log.Printf("DEBUG: Skipping request headers section for RESPMOD")
            }
            // Read and discard request headers
            for {
                line, err := reader.ReadString('\n')
                if err != nil {
                    return "", nil, nil, err
                }
                if strings.TrimSpace(line) == "" {
                    break // End of request headers
                }
            }
        }
        
        // Read response status line and headers  
        if ut.debug {
            log.Printf("DEBUG: Reading response headers section for RESPMOD")
        }
        requestLine, err = reader.ReadString('\n')
        if err != nil {
            return "", nil, nil, err
        }
        requestLine = strings.TrimSpace(requestLine)
        
        // Read HTTP response headers
        for {
            line, err := reader.ReadString('\n')
            if err != nil {
                return "", nil, nil, err
            }
            line = strings.TrimSpace(line)
            if line == "" {
                break // End of headers
            }
            httpHeaders = append(httpHeaders, line)
        }
    } else {
        // REQMOD: Read request line and headers
        if ut.debug {
            log.Printf("DEBUG: Reading request headers section for REQMOD")
        }
        requestLine, err = reader.ReadString('\n')
        if err != nil {
            return "", nil, nil, err
        }
        requestLine = strings.TrimSpace(requestLine)
        
        // Read HTTP request headers
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
    }
    
    // Read body if present
    if _, hasReqBody := positions["req-body"]; hasReqBody {
        if ut.debug {
            log.Printf("DEBUG: Reading req-body")
        }
        body, err = ut.readChunked(reader)
        if err != nil {
            return "", nil, nil, err
        }
    } else if _, hasResBody := positions["res-body"]; hasResBody {
        if ut.debug {
            log.Printf("DEBUG: Reading res-body at position %d", positions["res-body"])
        }
        body, err = ut.readChunked(reader)
        if err != nil {
            if ut.debug {
                log.Printf("DEBUG: Error reading res-body: %v", err)
            }
            return "", nil, nil, err
        }
        if ut.debug {
            log.Printf("DEBUG: Successfully read res-body: %d bytes", len(body))
        }
    } else {
        if ut.debug {
            log.Printf("DEBUG: No body found in positions: %+v", positions)
        }
        // For null-body cases, we still need to return a proper response
        // This typically means there's no body to process
    }
    
    if ut.debug {
        log.Printf("DEBUG: parseEncapsulated result - requestLine: '%s', headers: %d, body: %d bytes", 
            requestLine, len(httpHeaders), len(body))
    }
    
    return requestLine, httpHeaders, body, nil
}

func (ut *UnifiedTokenizer) readChunked(reader *bufio.Reader) ([]byte, error) {
    var result []byte
    
    if ut.debug {
        log.Printf("DEBUG: readChunked starting")
    }
    
    for {
        // Read chunk size
        sizeLine, err := reader.ReadString('\n')
        if err != nil {
            if ut.debug {
                log.Printf("DEBUG: readChunked error reading size line: %v", err)
            }
            return nil, err
        }
        
        sizeLine = strings.TrimSpace(sizeLine)
        if ut.debug {
            log.Printf("DEBUG: readChunked size line: '%s'", sizeLine)
        }
        
        size, err := strconv.ParseInt(sizeLine, 16, 64)
        if err != nil {
            if ut.debug {
                log.Printf("DEBUG: readChunked error parsing size: %v", err)
            }
            return nil, err
        }
        
        if ut.debug {
            log.Printf("DEBUG: readChunked chunk size: %d", size)
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
    if ut.debug {
        log.Printf("DEBUG: detokenizeJSON called with: %s", jsonStr[:min(200, len(jsonStr))])
    }
    
    var data interface{}
    if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
        return jsonStr, false, err
    }
    
    if ut.debug {
        log.Printf("DEBUG: Unmarshaled data type: %T", data)
    }
    
    modified := false
    ut.processValue(&data, &modified, false) // false for detokenization
    
    if ut.debug {
        log.Printf("DEBUG: detokenizeJSON modified=%v", modified)
    }
    
    result, err := json.Marshal(data)
    if err != nil {
        return jsonStr, false, err
    }
    
    return string(result), modified, nil
}

// Detokenize HTML content
func (ut *UnifiedTokenizer) detokenizeHTML(htmlStr string) (string, bool, error) {
    if ut.debug {
        log.Printf("DEBUG: detokenizeHTML called, length: %d", len(htmlStr))
    }
    
    modified := false
    result := htmlStr
    
    // Find all tokens in the HTML content
    matches := ut.tokenRegex.FindAllString(htmlStr, -1)
    if ut.debug {
        log.Printf("DEBUG: Found %d potential tokens in HTML", len(matches))
    }
    
    for _, token := range matches {
        if ut.debug {
            log.Printf("DEBUG: Attempting to detokenize token: %s", token)
        }
        if card := ut.retrieveCard(token); card != "" {
            result = strings.ReplaceAll(result, token, card)
            modified = true
            log.Printf("Detokenized token %s in HTML content", token)
        } else if ut.debug {
            log.Printf("DEBUG: Failed to retrieve card for token: %s", token)
        }
    }
    
    return result, modified, nil
}

func (ut *UnifiedTokenizer) processValue(v interface{}, modified *bool, tokenize bool) {
    switch val := v.(type) {
    case *interface{}:
        if ut.debug && !tokenize {
            log.Printf("DEBUG: Processing pointer to interface{}")
        }
        ut.processValue(*val, modified, tokenize)
    case map[string]interface{}:
        if ut.debug && !tokenize {
            log.Printf("DEBUG: Processing map with keys: %v", ut.getMapKeys(val))
        }
        for k, v := range val {
            if ut.debug && !tokenize {
                log.Printf("DEBUG: Processing map key '%s' with value type %T", k, v)
            }
            if tokenize && ut.isCreditCardField(k) {
                if str, ok := v.(string); ok && ut.cardRegex.MatchString(str) {
                    // Don't tokenize if it's already one of our tokens
                    if ut.tokenFormat == "luhn" && strings.HasPrefix(str, "9999") {
                        // This is already a token, skip it
                        continue
                    }
                    token := ut.generateToken()
                    if err := ut.storeCard(token, str); err == nil {
                        val[k] = token
                        *modified = true
                        log.Printf("Tokenized card ending in %s", str[len(str)-4:])
                    }
                }
            } else if !tokenize && ut.isCreditCardField(k) {
                if str, ok := v.(string); ok {
                    if ut.debug {
                        log.Printf("DEBUG: Checking field '%s' with value '%s' for detokenization", k, str)
                    }
                    if ut.tokenRegex.MatchString(str) {
                        if card := ut.retrieveCard(str); card != "" {
                            val[k] = card
                            *modified = true
                            log.Printf("Detokenized token %s in field %s", str, k)
                        } else if ut.debug {
                            log.Printf("DEBUG: Failed to retrieve card for token %s", str)
                        }
                    } else if ut.debug {
                        log.Printf("DEBUG: Value '%s' doesn't match token regex", str)
                    }
                }
            } else {
                if ut.debug && !tokenize {
                    log.Printf("DEBUG: Recursively processing non-card field '%s' with value type %T", k, v)
                }
                ut.processValue(v, modified, tokenize)
            }
        }
    case []interface{}:
        if ut.debug && !tokenize {
            log.Printf("DEBUG: Processing array with %d elements", len(val))
        }
        for i := range val {
            if ut.debug && !tokenize && i == 0 {
                log.Printf("DEBUG: First array element type: %T", val[i])
            }
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

func (ut *UnifiedTokenizer) getMapKeys(m map[string]interface{}) []string {
    keys := make([]string, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }
    return keys
}

func (ut *UnifiedTokenizer) isCreditCardField(fieldName string) bool {
    lowerField := strings.ToLower(fieldName)
    // Exact matches to avoid false positives like "cards" matching "card"
    exactMatches := []string{"card", "pan"}
    for _, field := range exactMatches {
        if lowerField == field {
            return true
        }
    }
    
    // Partial matches for compound names
    cardFields := []string{"card_number", "cardnumber", "creditcard", "credit_card", "account_number"}
    for _, field := range cardFields {
        if strings.Contains(lowerField, field) {
            return true
        }
    }
    return false
}

func (ut *UnifiedTokenizer) generateToken() string {
    if ut.tokenFormat == "luhn" {
        return ut.generateLuhnToken()
    }
    
    // Default prefix format
    b := make([]byte, 32)
    cryptorand.Read(b)
    return "tok_" + base64.URLEncoding.EncodeToString(b)
}

// calculateLuhnCheckDigit calculates the Luhn check digit for a given number
func calculateLuhnCheckDigit(number string) int {
    sum := 0
    alternate := false
    
    // Process from right to left
    for i := len(number) - 1; i >= 0; i-- {
        digit := int(number[i] - '0')
        
        if alternate {
            digit *= 2
            if digit > 9 {
                digit = (digit % 10) + 1
            }
        }
        
        sum += digit
        alternate = !alternate
    }
    
    return (10 - (sum % 10)) % 10
}

// generateLuhnToken generates a token that looks like a valid credit card number
func (ut *UnifiedTokenizer) generateLuhnToken() string {
    // Use prefix 9999 to distinguish tokens from real cards
    // This prefix is not used by any real card issuer
    prefix := "9999"
    
    // Generate 11 random digits
    randomPart := make([]byte, 11)
    for i := 0; i < 11; i++ {
        randomPart[i] = byte(rand.Intn(10)) + '0'
    }
    
    // Combine prefix and random part (15 digits total)
    partial := prefix + string(randomPart)
    
    // Calculate and append Luhn check digit
    checkDigit := calculateLuhnCheckDigit(partial)
    
    return partial + strconv.Itoa(checkDigit)
}

// Detect card type based on card number
func detectCardType(cardNumber string) string {
    if len(cardNumber) < 4 {
        return "Unknown"
    }
    
    // Remove any spaces or dashes
    cardNumber = strings.ReplaceAll(strings.ReplaceAll(cardNumber, " ", ""), "-", "")
    
    // Visa: starts with 4
    if strings.HasPrefix(cardNumber, "4") && (len(cardNumber) == 13 || len(cardNumber) == 16 || len(cardNumber) == 19) {
        return "Visa"
    }
    
    // Mastercard: starts with 5 (51-55) or 2 (2221-2720)
    if len(cardNumber) >= 2 {
        prefix2 := cardNumber[:2]
        if (prefix2 >= "51" && prefix2 <= "55") || (prefix2 >= "22" && prefix2 <= "27") {
            if len(cardNumber) == 16 {
                return "Mastercard"
            }
        }
    }
    
    // American Express: starts with 34 or 37
    if len(cardNumber) >= 2 {
        prefix2 := cardNumber[:2]
        if (prefix2 == "34" || prefix2 == "37") && len(cardNumber) == 15 {
            return "Amex"
        }
    }
    
    // Discover: starts with 6011, 622126-622925, 644-649, or 65
    if len(cardNumber) >= 4 {
        prefix4 := cardNumber[:4]
        prefix2 := cardNumber[:2]
        prefix3 := cardNumber[:3]
        
        if prefix4 == "6011" || prefix2 == "65" {
            if len(cardNumber) == 16 {
                return "Discover"
            }
        }
        
        if len(cardNumber) >= 6 {
            prefix6 := cardNumber[:6]
            if prefix6 >= "622126" && prefix6 <= "622925" {
                return "Discover"
            }
        }
        
        if prefix3 >= "644" && prefix3 <= "649" {
            if len(cardNumber) == 16 {
                return "Discover"
            }
        }
    }
    
    return "Unknown"
}

func (ut *UnifiedTokenizer) storeCard(token, cardNumber string) error {
    var encrypted []byte
    var keyID string
    var err error
    
    // Detect card type
    cardType := detectCardType(cardNumber)
    
    if ut.useKEKDEK && ut.keyManager != nil {
        // Use KEK/DEK encryption
        encrypted, keyID, err = ut.keyManager.EncryptData([]byte(cardNumber))
        if err != nil {
            return fmt.Errorf("KEK/DEK encryption failed: %v", err)
        }
    } else {
        // Use legacy Fernet encryption
        encrypted, err = fernet.EncryptAndSign([]byte(cardNumber), ut.encryptionKey)
        if err != nil {
            return fmt.Errorf("encryption failed: %v", err)
        }
    }
    
    if ut.useKEKDEK && keyID != "" {
        _, err = ut.db.Exec(`
            INSERT INTO credit_cards (token, card_number_encrypted, card_type, last_four_digits, first_six_digits, 
                                     expiry_month, expiry_year, created_at, is_active, encryption_key_id)
            VALUES (?, ?, ?, ?, ?, 12, 2025, NOW(), TRUE, ?)
        `, token, encrypted, cardType, cardNumber[len(cardNumber)-4:], cardNumber[:6], keyID)
    } else {
        _, err = ut.db.Exec(`
            INSERT INTO credit_cards (token, card_number_encrypted, card_type, last_four_digits, first_six_digits, 
                                     expiry_month, expiry_year, created_at, is_active)
            VALUES (?, ?, ?, ?, ?, 12, 2025, NOW(), TRUE)
        `, token, encrypted, cardType, cardNumber[len(cardNumber)-4:], cardNumber[:6])
    }
    
    if err == nil {
        _, _ = ut.db.Exec(`
            INSERT INTO token_requests (token, request_type, source_ip, destination_url, response_status)
            VALUES (?, 'tokenize', '127.0.0.1', '', 200)
        `, token)
    }
    
    return err
}

func (ut *UnifiedTokenizer) retrieveCard(token string) string {
    if ut.debug {
        log.Printf("DEBUG: retrieveCard called with token: %s", token)
    }
    
    var encryptedCard []byte
    var keyID sql.NullString
    
    err := ut.db.QueryRow(`
        SELECT card_number_encrypted, encryption_key_id FROM credit_cards 
        WHERE token = ? AND is_active = TRUE
    `, token).Scan(&encryptedCard, &keyID)
    
    if err != nil {
        if err == sql.ErrNoRows {
            if ut.debug {
                log.Printf("DEBUG: Token not found in database: %s", token)
            }
        } else {
            log.Printf("Database error: %v", err)
        }
        return ""
    }
    
    var cardBytes []byte
    
    if ut.useKEKDEK && ut.keyManager != nil && keyID.Valid && keyID.String != "" {
        // Use KEK/DEK decryption
        cardBytes, err = ut.keyManager.DecryptData(encryptedCard, keyID.String)
        if err != nil {
            log.Printf("Failed to decrypt card with KEK/DEK for token %s: %v", token, err)
            return ""
        }
    } else {
        // Use legacy Fernet decryption
        cardBytes = fernet.VerifyAndDecrypt(encryptedCard, 0, []*fernet.Key{ut.encryptionKey})
        if cardBytes == nil {
            log.Printf("Failed to decrypt card for token %s", token)
            return ""
        }
    }
    
    _, _ = ut.db.Exec(`
        INSERT INTO token_requests (token, request_type, source_ip, destination_url, response_status)
        VALUES (?, 'detokenize', '127.0.0.1', '', 200)
    `, token)
    
    return string(cardBytes)
}

// API Handlers
func (ut *UnifiedTokenizer) handleAPIHealth(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (ut *UnifiedTokenizer) authenticateAPIRequest(r *http.Request) bool {
    apiKey := r.Header.Get("X-API-Key")
    if apiKey == "" {
        return false
    }
    
    var count int
    err := ut.db.QueryRow(`
        SELECT COUNT(*) FROM api_keys 
        WHERE api_key = ? AND is_active = TRUE
    `, apiKey).Scan(&count)
    
    return err == nil && count > 0
}

func (ut *UnifiedTokenizer) handleAPIListTokens(w http.ResponseWriter, r *http.Request) {
    if !ut.authenticateAPIRequest(r) {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
        return
    }
    
    rows, err := ut.db.Query(`
        SELECT token, card_type, last_four_digits, first_six_digits, 
               created_at, is_active
        FROM credit_cards
        ORDER BY created_at DESC
        LIMIT 100
    `)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Internal server error"})
        return
    }
    defer rows.Close()
    
    tokens := []map[string]interface{}{}
    for rows.Next() {
        var token, cardType, lastFour, firstSix string
        var createdAt sql.NullTime
        var isActive bool
        
        var cardTypeNull sql.NullString
        if err := rows.Scan(&token, &cardTypeNull, &lastFour, &firstSix, &createdAt, &isActive); err != nil {
            log.Printf("Error scanning row: %v", err)
            continue
        }
        
        if cardTypeNull.Valid {
            cardType = cardTypeNull.String
        }
        
        tokenData := map[string]interface{}{
            "token":      token,
            "card_type":  cardType,
            "last_four":  lastFour,
            "first_six":  firstSix,
            "is_active":  isActive,
        }
        
        if createdAt.Valid {
            tokenData["created_at"] = createdAt.Time.Format(time.RFC3339)
        }
        
        tokens = append(tokens, tokenData)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{"tokens": tokens})
}

func (ut *UnifiedTokenizer) handleAPIGetToken(w http.ResponseWriter, r *http.Request) {
    if !ut.authenticateAPIRequest(r) {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
        return
    }
    
    // Extract token from URL path
    token := strings.TrimPrefix(r.URL.Path, "/api/v1/tokens/")
    if token == "" {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Token required"})
        return
    }
    
    var cardType, lastFour, firstSix string
    var createdAt sql.NullTime
    var isActive bool
    var cardTypeNull sql.NullString
    
    err := ut.db.QueryRow(`
        SELECT card_type, last_four_digits, first_six_digits, 
               created_at, is_active
        FROM credit_cards
        WHERE token = ?
    `, token).Scan(&cardTypeNull, &lastFour, &firstSix, &createdAt, &isActive)
    
    if err == sql.ErrNoRows {
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(map[string]string{"error": "Token not found"})
        return
    } else if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Internal server error"})
        return
    }
    
    if cardTypeNull.Valid {
        cardType = cardTypeNull.String
    }
    
    result := map[string]interface{}{
        "token":      token,
        "card_type":  cardType,
        "last_four":  lastFour,
        "first_six":  firstSix,
        "is_active":  isActive,
    }
    
    if createdAt.Valid {
        result["created_at"] = createdAt.Time.Format(time.RFC3339)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(result)
}

func (ut *UnifiedTokenizer) handleAPIRevokeToken(w http.ResponseWriter, r *http.Request) {
    if !ut.authenticateAPIRequest(r) {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
        return
    }
    
    token := strings.TrimPrefix(r.URL.Path, "/api/v1/tokens/")
    
    result, err := ut.db.Exec(`
        UPDATE credit_cards 
        SET is_active = FALSE 
        WHERE token = ?
    `, token)
    
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Internal server error"})
        return
    }
    
    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(map[string]string{"error": "Token not found"})
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "Token revoked successfully"})
}

func (ut *UnifiedTokenizer) handleAPIStats(w http.ResponseWriter, r *http.Request) {
    if !ut.authenticateAPIRequest(r) {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
        return
    }
    
    // Get active token count
    var activeTokens int
    ut.db.QueryRow("SELECT COUNT(*) FROM credit_cards WHERE is_active = TRUE").Scan(&activeTokens)
    
    // Get request stats
    rows, err := ut.db.Query(`
        SELECT request_type, COUNT(*) as count
        FROM token_requests
        WHERE request_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY request_type
    `)
    
    requestStats := make(map[string]int)
    if err == nil {
        defer rows.Close()
        for rows.Next() {
            var reqType string
            var count int
            if err := rows.Scan(&reqType, &count); err == nil {
                requestStats[reqType] = count
            }
        }
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "active_tokens": activeTokens,
        "requests_24h":  requestStats,
    })
}

// Additional API endpoints for GUI/CLI

func (ut *UnifiedTokenizer) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
    // Check admin privileges
    adminSecret := r.Header.Get("X-Admin-Secret")
    expectedSecret := getEnv("ADMIN_SECRET", "change-this-admin-secret")
    if adminSecret != expectedSecret {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]string{"error": "Admin privileges required"})
        return
    }
    
    var req struct {
        ClientName  string   `json:"client_name"`
        Permissions []string `json:"permissions,omitempty"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
        return
    }
    
    if req.ClientName == "" {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "client_name is required"})
        return
    }
    
    // Generate API key
    apiKey := "ts_" + generateRandomID()
    secretHash := "hash_" + generateRandomID() // In production, use proper hashing
    
    permissions, _ := json.Marshal(req.Permissions)
    
    _, err := ut.db.Exec(`
        INSERT INTO api_keys (api_key, api_secret_hash, client_name, permissions, is_active)
        VALUES (?, ?, ?, ?, TRUE)
    `, apiKey, secretHash, req.ClientName, permissions)
    
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create API key"})
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "api_key":     apiKey,
        "client_name": req.ClientName,
        "permissions": req.Permissions,
        "created_at":  time.Now().Format(time.RFC3339),
    })
}

func (ut *UnifiedTokenizer) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
    // Check admin privileges
    adminSecret := r.Header.Get("X-Admin-Secret")
    expectedSecret := getEnv("ADMIN_SECRET", "change-this-admin-secret")
    if adminSecret != expectedSecret {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]string{"error": "Admin privileges required"})
        return
    }
    
    rows, err := ut.db.Query(`
        SELECT api_key, client_name, permissions, is_active, created_at, last_used_at
        FROM api_keys
        ORDER BY created_at DESC
    `)
    
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
        return
    }
    defer rows.Close()
    
    var apiKeys []map[string]interface{}
    
    for rows.Next() {
        var apiKey, clientName string
        var permissions sql.NullString
        var isActive bool
        var createdAt time.Time
        var lastUsedAt sql.NullTime
        
        err := rows.Scan(&apiKey, &clientName, &permissions, &isActive, &createdAt, &lastUsedAt)
        if err != nil {
            continue
        }
        
        keyInfo := map[string]interface{}{
            "api_key":     apiKey,
            "client_name": clientName,
            "is_active":   isActive,
            "created_at":  createdAt.Format(time.RFC3339),
        }
        
        if permissions.Valid {
            var perms []string
            json.Unmarshal([]byte(permissions.String), &perms)
            keyInfo["permissions"] = perms
        }
        
        if lastUsedAt.Valid {
            keyInfo["last_used_at"] = lastUsedAt.Time.Format(time.RFC3339)
        }
        
        apiKeys = append(apiKeys, keyInfo)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "api_keys": apiKeys,
        "total":    len(apiKeys),
    })
}

func (ut *UnifiedTokenizer) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
    // Check admin privileges
    adminSecret := r.Header.Get("X-Admin-Secret")
    expectedSecret := getEnv("ADMIN_SECRET", "change-this-admin-secret")
    if adminSecret != expectedSecret {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]string{"error": "Admin privileges required"})
        return
    }
    
    apiKey := strings.TrimPrefix(r.URL.Path, "/api/v1/api-keys/")
    
    result, err := ut.db.Exec(`
        UPDATE api_keys SET is_active = FALSE WHERE api_key = ?
    `, apiKey)
    
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
        return
    }
    
    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(map[string]string{"error": "API key not found"})
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "API key revoked successfully"})
}

func (ut *UnifiedTokenizer) handleGetActivity(w http.ResponseWriter, r *http.Request) {
    if !ut.authenticateAPIRequest(r) {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
        return
    }
    
    // Get query parameters
    limit := 50
    if l := r.URL.Query().Get("limit"); l != "" {
        if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
            limit = parsed
        }
    }
    
    rows, err := ut.db.Query(`
        SELECT tr.token, tr.request_type, tr.source_ip, tr.destination_url, 
               tr.request_timestamp, tr.response_status, cc.last_four_digits
        FROM token_requests tr
        LEFT JOIN credit_cards cc ON tr.token = cc.token
        ORDER BY tr.request_timestamp DESC
        LIMIT ?
    `, limit)
    
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
        return
    }
    defer rows.Close()
    
    var activities []map[string]interface{}
    
    for rows.Next() {
        var token, requestType, sourceIP, destinationURL string
        var requestTimestamp time.Time
        var responseStatus sql.NullInt64
        var lastFour sql.NullString
        
        err := rows.Scan(&token, &requestType, &sourceIP, &destinationURL, 
                        &requestTimestamp, &responseStatus, &lastFour)
        if err != nil {
            continue
        }
        
        activity := map[string]interface{}{
            "token":       token,
            "type":        requestType,
            "source_ip":   sourceIP,
            "destination": destinationURL,
            "timestamp":   requestTimestamp.Format(time.RFC3339),
        }
        
        if responseStatus.Valid {
            activity["status"] = responseStatus.Int64
        }
        
        if lastFour.Valid {
            activity["card_last_four"] = lastFour.String
        }
        
        activities = append(activities, activity)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "activities": activities,
        "total":      len(activities),
    })
}

func (ut *UnifiedTokenizer) handleSearchTokens(w http.ResponseWriter, r *http.Request) {
    if !ut.authenticateAPIRequest(r) {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
        return
    }
    
    var req struct {
        LastFour  string `json:"last_four,omitempty"`
        CardType  string `json:"card_type,omitempty"`
        DateFrom  string `json:"date_from,omitempty"`
        DateTo    string `json:"date_to,omitempty"`
        IsActive  *bool  `json:"is_active,omitempty"`
        Limit     int    `json:"limit,omitempty"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
        return
    }
    
    if req.Limit <= 0 || req.Limit > 1000 {
        req.Limit = 100
    }
    
    // Build dynamic query
    query := `SELECT token, card_type, last_four_digits, first_six_digits, 
                     created_at, is_active FROM credit_cards WHERE 1=1`
    args := []interface{}{}
    
    if req.LastFour != "" {
        query += " AND last_four_digits = ?"
        args = append(args, req.LastFour)
    }
    
    if req.CardType != "" {
        query += " AND card_type = ?"
        args = append(args, req.CardType)
    }
    
    if req.DateFrom != "" {
        query += " AND created_at >= ?"
        args = append(args, req.DateFrom)
    }
    
    if req.DateTo != "" {
        query += " AND created_at <= ?"
        args = append(args, req.DateTo)
    }
    
    if req.IsActive != nil {
        query += " AND is_active = ?"
        args = append(args, *req.IsActive)
    }
    
    query += " ORDER BY created_at DESC LIMIT ?"
    args = append(args, req.Limit)
    
    rows, err := ut.db.Query(query, args...)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
        return
    }
    defer rows.Close()
    
    var tokens []map[string]interface{}
    
    for rows.Next() {
        var token, lastFour, firstSix string
        var cardType sql.NullString
        var createdAt time.Time
        var isActive bool
        
        err := rows.Scan(&token, &cardType, &lastFour, &firstSix, &createdAt, &isActive)
        if err != nil {
            continue
        }
        
        tokenInfo := map[string]interface{}{
            "token":      token,
            "last_four":  lastFour,
            "first_six":  firstSix,
            "created_at": createdAt.Format(time.RFC3339),
            "is_active":  isActive,
        }
        
        if cardType.Valid {
            tokenInfo["card_type"] = cardType.String
        }
        
        tokens = append(tokens, tokenInfo)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "tokens": tokens,
        "total":  len(tokens),
    })
}

func (ut *UnifiedTokenizer) handleGetVersion(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "version":     "1.0.0-prototype",
        "build_time":  time.Now().Format(time.RFC3339),
        "token_format": ut.tokenFormat,
        "kek_dek_enabled": ut.useKEKDEK,
        "features": []string{"tokenization", "detokenization", "api", "icap"},
    })
}

func (ut *UnifiedTokenizer) startHTTPServer() {
    http.HandleFunc("/", ut.handleTokenize)
    
    log.Printf("Starting HTTP tokenization server on port %s", ut.httpPort)
    if err := http.ListenAndServe(":"+ut.httpPort, nil); err != nil {
        log.Fatalf("HTTP server failed: %v", err)
    }
}

// CORS middleware
func (ut *UnifiedTokenizer) corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Set CORS headers
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key, X-Admin-Secret, Authorization")
        w.Header().Set("Access-Control-Max-Age", "3600")
        
        // Handle preflight OPTIONS requests
        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusOK)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}

func (ut *UnifiedTokenizer) startAPIServer() {
    mux := http.NewServeMux()
    
    // Health check and version
    mux.HandleFunc("/health", ut.handleAPIHealth)
    mux.HandleFunc("/api/v1/version", ut.handleGetVersion)
    
    // API Key management (admin only)
    mux.HandleFunc("/api/v1/api-keys", func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case "GET":
            ut.handleListAPIKeys(w, r)
        case "POST":
            ut.handleCreateAPIKey(w, r)
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
    
    mux.HandleFunc("/api/v1/api-keys/", func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case "DELETE":
            ut.handleRevokeAPIKey(w, r)
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
    
    // Token management
    mux.HandleFunc("/api/v1/tokens", func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case "GET":
            ut.handleAPIListTokens(w, r)
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
    
    mux.HandleFunc("/api/v1/tokens/search", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "POST" {
            ut.handleSearchTokens(w, r)
        } else {
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
    
    // Individual token operations
    mux.HandleFunc("/api/v1/tokens/", func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case "GET":
            ut.handleAPIGetToken(w, r)
        case "DELETE":
            ut.handleAPIRevokeToken(w, r)
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
    
    // Activity monitoring
    mux.HandleFunc("/api/v1/activity", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "GET" {
            ut.handleGetActivity(w, r)
        } else {
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
    
    // Stats
    mux.HandleFunc("/api/v1/stats", ut.handleAPIStats)
    
    // Key management endpoints (if KEK/DEK is enabled)
    if ut.useKEKDEK {
        mux.HandleFunc("/api/v1/keys/status", func(w http.ResponseWriter, r *http.Request) {
            if r.Method == "GET" {
                ut.handleKeyStatus(w, r)
            } else {
                w.WriteHeader(http.StatusMethodNotAllowed)
            }
        })
        
        mux.HandleFunc("/api/v1/keys/rotate", func(w http.ResponseWriter, r *http.Request) {
            if r.Method == "POST" {
                ut.handleKeyRotation(w, r)
            } else {
                w.WriteHeader(http.StatusMethodNotAllowed)
            }
        })
    }
    
    log.Printf("Starting API server on port %s with CORS enabled", ut.apiPort)
    if err := http.ListenAndServe(":"+ut.apiPort, ut.corsMiddleware(mux)); err != nil {
        log.Fatalf("API server failed: %v", err)
    }
}

// Key management API handlers

func (ut *UnifiedTokenizer) handleKeyStatus(w http.ResponseWriter, r *http.Request) {
    if !ut.authenticateAPIRequest(r) {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
        return
    }
    
    type KeyInfo struct {
        KeyID      string    `json:"key_id"`
        Version    int       `json:"version"`
        Status     string    `json:"status"`
        CreatedAt  time.Time `json:"created_at"`
        CardsCount int       `json:"cards_encrypted,omitempty"`
    }
    
    response := struct {
        KEK *KeyInfo `json:"kek,omitempty"`
        DEK *KeyInfo `json:"dek,omitempty"`
    }{}
    
    // Get KEK info
    var kekInfo KeyInfo
    err := ut.db.QueryRow(`
        SELECT key_id, key_version, key_status, created_at
        FROM encryption_keys
        WHERE key_type = 'KEK' AND key_status = 'active'
        ORDER BY key_version DESC LIMIT 1
    `).Scan(&kekInfo.KeyID, &kekInfo.Version, &kekInfo.Status, &kekInfo.CreatedAt)
    
    if err == nil {
        response.KEK = &kekInfo
    }
    
    // Get DEK info
    var dekInfo KeyInfo
    err = ut.db.QueryRow(`
        SELECT key_id, key_version, key_status, created_at
        FROM encryption_keys
        WHERE key_type = 'DEK' AND key_status = 'active'
        ORDER BY key_version DESC LIMIT 1
    `).Scan(&dekInfo.KeyID, &dekInfo.Version, &dekInfo.Status, &dekInfo.CreatedAt)
    
    if err == nil {
        response.DEK = &dekInfo
        
        // Count cards encrypted with this DEK
        ut.db.QueryRow(`
            SELECT COUNT(*) FROM credit_cards 
            WHERE encryption_key_id = ?
        `, dekInfo.KeyID).Scan(&dekInfo.CardsCount)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func (ut *UnifiedTokenizer) handleKeyRotation(w http.ResponseWriter, r *http.Request) {
    if !ut.authenticateAPIRequest(r) {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
        return
    }
    
    // For prototype, just return a message
    // In production, this would trigger the key rotation process
    response := map[string]interface{}{
        "status": "accepted",
        "message": "Key rotation initiated (prototype - not implemented)",
        "rotation_id": "rot_" + generateRandomID(),
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
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

// KeyManager Implementation

func NewKeyManager(db *sql.DB) (*KeyManager, error) {
    km := &KeyManager{
        db:       db,
        kekCache: make(map[string][]byte),
        dekCache: make(map[string][]byte),
    }
    
    // Load or generate KEK
    if err := km.loadOrGenerateKEK(); err != nil {
        return nil, fmt.Errorf("failed to initialize KEK: %v", err)
    }
    
    // Load or generate DEK
    if err := km.loadOrGenerateDEK(); err != nil {
        return nil, fmt.Errorf("failed to initialize DEK: %v", err)
    }
    
    return km, nil
}

func (km *KeyManager) loadOrGenerateKEK() error {
    var keyID string
    var key []byte
    
    err := km.db.QueryRow(`
        SELECT key_id, encrypted_key FROM encryption_keys
        WHERE key_type = 'KEK' AND key_status = 'active'
        ORDER BY key_version DESC LIMIT 1
    `).Scan(&keyID, &key)
    
    if err == sql.ErrNoRows {
        // Generate new KEK
        key = make([]byte, 32)
        if _, err := io.ReadFull(cryptorand.Reader, key); err != nil {
            return fmt.Errorf("failed to generate KEK: %v", err)
        }
        
        keyID = "kek_" + generateRandomID()
        
        _, err = km.db.Exec(`
            INSERT INTO encryption_keys 
            (key_id, key_type, key_version, encrypted_key, key_status, activated_at)
            VALUES (?, 'KEK', 1, ?, 'active', NOW())
        `, keyID, key)
        
        if err != nil {
            return fmt.Errorf("failed to store KEK: %v", err)
        }
        
        log.Printf("Generated new KEK: %s", keyID)
    } else if err != nil {
        return err
    }
    
    km.mu.Lock()
    km.kekCache[keyID] = key
    km.mu.Unlock()
    
    return nil
}

func (km *KeyManager) loadOrGenerateDEK() error {
    var keyID string
    var encryptedKey []byte
    var metadata json.RawMessage
    
    err := km.db.QueryRow(`
        SELECT key_id, encrypted_key, metadata FROM encryption_keys
        WHERE key_type = 'DEK' AND key_status = 'active'
        ORDER BY key_version DESC LIMIT 1
    `).Scan(&keyID, &encryptedKey, &metadata)
    
    if err == sql.ErrNoRows {
        // Generate new DEK
        return km.generateNewDEK()
    } else if err != nil {
        return err
    }
    
    // Decrypt DEK with KEK
    var kekID string
    km.mu.RLock()
    for kid := range km.kekCache {
        kekID = kid
        break
    }
    kek := km.kekCache[kekID]
    km.mu.RUnlock()
    
    dek, err := km.decryptWithKEK(encryptedKey, kek)
    if err != nil {
        return fmt.Errorf("failed to decrypt DEK: %v", err)
    }
    
    km.mu.Lock()
    km.dekCache[keyID] = dek
    km.currentDEKID = keyID
    km.mu.Unlock()
    
    return nil
}

func (km *KeyManager) generateNewDEK() error {
    // Get active KEK
    var kekID string
    var kek []byte
    
    km.mu.RLock()
    for kid, k := range km.kekCache {
        kekID = kid
        kek = k
        break
    }
    km.mu.RUnlock()
    
    if kek == nil {
        return errors.New("no active KEK found")
    }
    
    // Generate new DEK
    dek := make([]byte, 32)
    if _, err := io.ReadFull(cryptorand.Reader, dek); err != nil {
        return fmt.Errorf("failed to generate DEK: %v", err)
    }
    
    // Encrypt DEK with KEK
    encryptedDEK, err := km.encryptWithKEK(dek, kek)
    if err != nil {
        return fmt.Errorf("failed to encrypt DEK: %v", err)
    }
    
    dekID := "dek_" + generateRandomID()
    
    // Get next version
    var maxVersion int
    km.db.QueryRow("SELECT COALESCE(MAX(key_version), 0) FROM encryption_keys WHERE key_type = 'DEK'").Scan(&maxVersion)
    
    // Store encrypted DEK
    metadata := map[string]string{"kek_id": kekID}
    metadataJSON, _ := json.Marshal(metadata)
    
    _, err = km.db.Exec(`
        INSERT INTO encryption_keys 
        (key_id, key_type, key_version, encrypted_key, key_status, metadata, activated_at)
        VALUES (?, 'DEK', ?, ?, 'active', ?, NOW())
    `, dekID, maxVersion+1, encryptedDEK, metadataJSON)
    
    if err != nil {
        return fmt.Errorf("failed to store DEK: %v", err)
    }
    
    km.mu.Lock()
    km.dekCache[dekID] = dek
    km.currentDEKID = dekID
    km.mu.Unlock()
    
    log.Printf("Generated new DEK: %s", dekID)
    
    return nil
}

func (km *KeyManager) EncryptData(plaintext []byte) ([]byte, string, error) {
    km.mu.RLock()
    dekID := km.currentDEKID
    dek, exists := km.dekCache[dekID]
    km.mu.RUnlock()
    
    if !exists || len(dek) == 0 {
        return nil, "", errors.New("no active DEK available")
    }
    
    // AES-GCM encryption
    block, err := aes.NewCipher(dek)
    if err != nil {
        return nil, "", err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, "", err
    }
    
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
        return nil, "", err
    }
    
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return ciphertext, dekID, nil
}

func (km *KeyManager) DecryptData(ciphertext []byte, dekID string) ([]byte, error) {
    km.mu.RLock()
    dek, exists := km.dekCache[dekID]
    km.mu.RUnlock()
    
    if !exists {
        // Try to load from database
        if err := km.loadDEK(dekID); err != nil {
            return nil, fmt.Errorf("failed to load DEK: %v", err)
        }
        
        km.mu.RLock()
        dek, exists = km.dekCache[dekID]
        km.mu.RUnlock()
        
        if !exists {
            return nil, errors.New("DEK not found")
        }
    }
    
    // AES-GCM decryption
    block, err := aes.NewCipher(dek)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }
    
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

func (km *KeyManager) loadDEK(dekID string) error {
    var encryptedKey []byte
    var metadata json.RawMessage
    
    err := km.db.QueryRow(`
        SELECT encrypted_key, metadata FROM encryption_keys
        WHERE key_id = ? AND key_type = 'DEK'
    `, dekID).Scan(&encryptedKey, &metadata)
    
    if err != nil {
        return err
    }
    
    // Get KEK ID from metadata
    var meta map[string]string
    json.Unmarshal(metadata, &meta)
    kekID := meta["kek_id"]
    
    km.mu.RLock()
    kek, exists := km.kekCache[kekID]
    km.mu.RUnlock()
    
    if !exists {
        return errors.New("KEK not found")
    }
    
    // Decrypt DEK
    dek, err := km.decryptWithKEK(encryptedKey, kek)
    if err != nil {
        return err
    }
    
    km.mu.Lock()
    km.dekCache[dekID] = dek
    km.mu.Unlock()
    
    return nil
}

func (km *KeyManager) encryptWithKEK(plaintext, kek []byte) ([]byte, error) {
    block, err := aes.NewCipher(kek)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
        return nil, err
    }
    
    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (km *KeyManager) decryptWithKEK(ciphertext, kek []byte) ([]byte, error) {
    block, err := aes.NewCipher(kek)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }
    
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

func generateRandomID() string {
    b := make([]byte, 16)
    cryptorand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}

func main() {
    log.SetFlags(log.LstdFlags | log.Lshortfile)
    
    ut, err := NewUnifiedTokenizer()
    if err != nil {
        log.Fatalf("Failed to initialize tokenizer: %v", err)
    }
    defer ut.db.Close()
    
    log.Printf("TokenShield Unified Service starting...")
    log.Printf("HTTP Port: %s, ICAP Port: %s, API Port: %s", ut.httpPort, ut.icapPort, ut.apiPort)
    log.Printf("App Endpoint: %s", ut.appEndpoint)
    log.Printf("Token Format: %s", ut.tokenFormat)
    log.Printf("KEK/DEK Encryption: %v", ut.useKEKDEK)
    
    // Start all three servers
    go ut.startHTTPServer()
    go ut.startAPIServer()
    ut.startICAPServer()
}