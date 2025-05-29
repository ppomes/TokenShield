package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/fernet/fernet-go"
	_ "github.com/go-sql-driver/mysql"
)

type ICAPServer struct {
	db         *sql.DB
	tokenRegex *regexp.Regexp
	debug      bool
	fernetKey  *fernet.Key
}

type Config struct {
	Port          string
	DBHost        string
	DBUser        string
	DBPass        string
	DBName        string
	Debug         bool
	EncryptionKey string
}

func NewICAPServer(config Config) (*ICAPServer, error) {
	// Connect to MySQL
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s", config.DBUser, config.DBPass, config.DBHost, config.DBName)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	// Compile token regex - tokens can contain letters, numbers, underscores, and hyphens
	tokenRegex, err := regexp.Compile(`tok_[a-zA-Z0-9_\-]+`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile token regex: %v", err)
	}

	// Initialize Fernet key for decryption
	var fernetKey *fernet.Key
	if config.EncryptionKey != "" {
		keyBytes, err := base64.URLEncoding.DecodeString(config.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode encryption key: %v", err)
		}
		fernetKey = &fernet.Key{}
		copy(fernetKey[:], keyBytes)
	}

	return &ICAPServer{
		db:         db,
		tokenRegex: tokenRegex,
		debug:      config.Debug,
		fernetKey:  fernetKey,
	}, nil
}

func (s *ICAPServer) lookupToken(token string) (string, error) {
	if s.debug {
		log.Printf("DEBUG: Looking up token: %s", token)
	}
	var encryptedCardNumber []byte
	err := s.db.QueryRow("SELECT card_number_encrypted FROM credit_cards WHERE token = ? AND is_active = TRUE", token).Scan(&encryptedCardNumber)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil // Token not found
		}
		return "", err
	}
	
	// Decrypt the card number
	if s.fernetKey == nil {
		return "", fmt.Errorf("encryption key not configured")
	}
	
	decryptedBytes := fernet.VerifyAndDecrypt(encryptedCardNumber, 0, []*fernet.Key{s.fernetKey})
	if decryptedBytes == nil {
		return "", fmt.Errorf("failed to decrypt card number")
	}
	
	return string(decryptedBytes), nil
}

func (s *ICAPServer) detokenizeJSON(jsonStr string) (string, bool, error) {
	// Check if the string contains tokens
	tokens := s.tokenRegex.FindAllString(jsonStr, -1)
	if s.debug {
		log.Printf("DEBUG: Found %d tokens in JSON: %v", len(tokens), tokens)
	}
	if len(tokens) == 0 {
		if s.debug {
			log.Printf("DEBUG: No tokens found in JSON")
		}
		return jsonStr, false, nil // No tokens found
	}

	modified := false
	result := jsonStr

	// Replace each token with the actual card number
	for _, token := range tokens {
		cardNumber, err := s.lookupToken(token)
		if err != nil {
			return "", false, fmt.Errorf("failed to lookup token %s: %v", token, err)
		}
		if cardNumber != "" {
			result = strings.ReplaceAll(result, token, cardNumber)
			modified = true
			if s.debug {
				log.Printf("DEBUG: Replaced token %s with card number", token)
			}
		}
	}

	return result, modified, nil
}

func (s *ICAPServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	if s.debug {
		log.Printf("DEBUG: New connection from %s", conn.RemoteAddr())
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read ICAP request line
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("ERROR: Failed to read request line: %v", err)
		return
	}

	requestLine = strings.TrimSpace(requestLine)
	parts := strings.Split(requestLine, " ")
	if len(parts) != 3 {
		log.Printf("ERROR: Invalid request line: %s", requestLine)
		return
	}

	method, uri, version := parts[0], parts[1], parts[2]

	if s.debug {
		log.Printf("DEBUG: ICAP %s %s %s", method, uri, version)
	}

	// Read ICAP headers
	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("ERROR: Failed to read header: %v", err)
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			break // End of headers
		}

		colonIndex := strings.Index(line, ":")
		if colonIndex == -1 {
			continue
		}

		key := strings.TrimSpace(line[:colonIndex])
		value := strings.TrimSpace(line[colonIndex+1:])
		headers[key] = value

		if s.debug {
			log.Printf("DEBUG: Header: %s: %s", key, value)
		}
	}

	// Handle different ICAP methods
	switch method {
	case "OPTIONS":
		s.handleOptions(writer)
	case "REQMOD":
		s.handleReqmod(reader, writer, headers)
	default:
		s.sendErrorResponse(writer, 405, "Method Not Allowed")
	}
}

func (s *ICAPServer) handleOptions(writer *bufio.Writer) {
	response := "ICAP/1.0 200 OK\r\n" +
		"Service: TokenShield ICAP Server\r\n" +
		"ISTag: \"TS001\"\r\n" +
		"Encapsulated: null-body=0\r\n" +
		"Max-Connections: 100\r\n" +
		"Options-TTL: 3600\r\n" +
		"Allow: 204\r\n" +
		"Preview: 0\r\n" +
		"Methods: REQMOD\r\n" +
		"\r\n"

	writer.WriteString(response)
	writer.Flush()

	if s.debug {
		log.Printf("DEBUG: Sent OPTIONS response")
	}
}

func (s *ICAPServer) handleReqmod(reader *bufio.Reader, writer *bufio.Writer, headers map[string]string) {
	encapsulated := headers["Encapsulated"]
	if encapsulated == "" {
		if s.debug {
			log.Printf("DEBUG: No Encapsulated header, sending 204")
		}
		s.send204Response(writer)
		return
	}

	if s.debug {
		log.Printf("DEBUG: Encapsulated header: %s", encapsulated)
	}

	// Parse encapsulated header
	reqHdrStart, reqBodyStart, hasNullBody, err := s.parseEncapsulated(encapsulated)
	if err != nil {
		log.Printf("ERROR: Failed to parse Encapsulated header: %v", err)
		s.sendErrorResponse(writer, 400, "Bad Request")
		return
	}

	if s.debug {
		log.Printf("DEBUG: Parsed - req-hdr=%d, req-body=%d, null-body=%v", reqHdrStart, reqBodyStart, hasNullBody)
	}

	// Read the HTTP request
	var httpReq *http.Request
	if reqHdrStart >= 0 && reqBodyStart > reqHdrStart {
		// Read HTTP headers
		headerBytes := make([]byte, reqBodyStart-reqHdrStart)
		_, err := io.ReadFull(reader, headerBytes)
		if err != nil {
			log.Printf("ERROR: Failed to read HTTP headers: %v", err)
			s.sendErrorResponse(writer, 500, "Internal Server Error")
			return
		}

		if s.debug {
			log.Printf("DEBUG: Read %d bytes of HTTP headers", len(headerBytes))
		}

		// Parse HTTP request from headers
		httpReq, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(headerBytes)))
		if err != nil {
			log.Printf("ERROR: Failed to parse HTTP request: %v", err)
			s.sendErrorResponse(writer, 500, "Internal Server Error")
			return
		}

		// Read HTTP body if present
		if !hasNullBody {
			// Read chunked body
			bodyBytes, err := s.readChunkedBody(reader)
			if err != nil {
				log.Printf("ERROR: Failed to read HTTP body: %v", err)
				s.sendErrorResponse(writer, 500, "Internal Server Error")
				return
			}

			if s.debug {
				log.Printf("DEBUG: Read %d bytes of HTTP body", len(bodyBytes))
				log.Printf("DEBUG: Body content: %s", string(bodyBytes))
			}

			// Set the body
			httpReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			// Check if body contains tokens and detokenize
			contentType := httpReq.Header.Get("Content-Type")
			if s.debug {
				log.Printf("DEBUG: Content-Type: %s, Body length: %d", contentType, len(bodyBytes))
			}
			// Always try to detokenize if we have body content
			if len(bodyBytes) > 0 {
				if s.debug {
					log.Printf("DEBUG: Calling detokenizeJSON with: %s", string(bodyBytes))
				}
				detokenized, modified, err := s.detokenizeJSON(string(bodyBytes))
				if err != nil {
					log.Printf("ERROR: Failed to detokenize JSON: %v", err)
					s.sendErrorResponse(writer, 500, "Internal Server Error")
					return
				}

				if modified {
					if s.debug {
						log.Printf("DEBUG: Body was modified, sending 200 with new content")
						log.Printf("DEBUG: Modified body content: %s", detokenized)
					}
					s.sendModifiedResponse(writer, httpReq, []byte(detokenized))
					return
				}
			}
		}
	}

	if s.debug {
		log.Printf("DEBUG: No modification needed, sending 204")
	}
	s.send204Response(writer)
}

func (s *ICAPServer) parseEncapsulated(encapsulated string) (reqHdrStart, reqBodyStart int, hasNullBody bool, err error) {
	reqHdrStart = -1
	reqBodyStart = -1
	hasNullBody = false

	parts := strings.Split(encapsulated, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "req-hdr=") {
			_, err := fmt.Sscanf(part, "req-hdr=%d", &reqHdrStart)
			if err != nil {
				return -1, -1, false, err
			}
		} else if strings.HasPrefix(part, "req-body=") {
			_, err := fmt.Sscanf(part, "req-body=%d", &reqBodyStart)
			if err != nil {
				return -1, -1, false, err
			}
		} else if strings.HasPrefix(part, "null-body=") {
			hasNullBody = true
		}
	}

	return reqHdrStart, reqBodyStart, hasNullBody, nil
}

func (s *ICAPServer) readChunkedBody(reader *bufio.Reader) ([]byte, error) {
	var body bytes.Buffer

	for {
		// Read chunk size line
		sizeLine, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		sizeLine = strings.TrimSpace(sizeLine)
		if s.debug {
			log.Printf("DEBUG: Chunk size line: %s", sizeLine)
		}

		// Parse chunk size (hex)
		var chunkSize int
		_, err = fmt.Sscanf(sizeLine, "%x", &chunkSize)
		if err != nil {
			return nil, fmt.Errorf("failed to parse chunk size: %v", err)
		}

		if s.debug {
			log.Printf("DEBUG: Chunk size: %d", chunkSize)
		}

		if chunkSize == 0 {
			// Read final \r\n
			reader.ReadString('\n')
			break
		}

		// Read chunk data
		chunkData := make([]byte, chunkSize)
		_, err = io.ReadFull(reader, chunkData)
		if err != nil {
			return nil, err
		}

		body.Write(chunkData)

		// Read trailing \r\n
		reader.ReadString('\n')
	}

	return body.Bytes(), nil
}

func (s *ICAPServer) send204Response(writer *bufio.Writer) {
	response := "ICAP/1.0 204 No Content\r\n" +
		"ISTag: \"TS001\"\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n"

	writer.WriteString(response)
	writer.Flush()
}

func (s *ICAPServer) sendModifiedResponse(writer *bufio.Writer, req *http.Request, modifiedBody []byte) {
	// Update Content-Length header
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(modifiedBody)))

	// Reconstruct HTTP request
	var httpBuf bytes.Buffer
	fmt.Fprintf(&httpBuf, "%s %s %s\r\n", req.Method, req.URL.String(), req.Proto)

	// Write headers
	for name, values := range req.Header {
		for _, value := range values {
			fmt.Fprintf(&httpBuf, "%s: %s\r\n", name, value)
		}
	}
	httpBuf.WriteString("\r\n")
	httpBuf.Write(modifiedBody)

	// Calculate where the body starts (after HTTP headers)
	bodyStart := httpBuf.Len() - len(modifiedBody)
	
	// Send ICAP response
	response := fmt.Sprintf("ICAP/1.0 200 OK\r\n"+
		"ISTag: \"TS001\"\r\n"+
		"Connection: keep-alive\r\n"+
		"Encapsulated: req-hdr=0, req-body=%d\r\n"+
		"\r\n", bodyStart)

	writer.WriteString(response)
	
	// Write HTTP headers
	httpHeadersOnly := httpBuf.Bytes()[:bodyStart]
	writer.Write(httpHeadersOnly)
	
	// Write body in chunked encoding
	writer.WriteString(fmt.Sprintf("%x\r\n", len(modifiedBody)))
	writer.Write(modifiedBody)
	writer.WriteString("\r\n0\r\n\r\n")
	
	writer.Flush()
}

func (s *ICAPServer) sendErrorResponse(writer *bufio.Writer, code int, message string) {
	response := fmt.Sprintf("ICAP/1.0 %d %s\r\n\r\n", code, message)
	writer.WriteString(response)
	writer.Flush()
}

func (s *ICAPServer) Start(port string) error {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("failed to listen on port %s: %v", port, err)
	}
	defer listener.Close()

	log.Printf("TokenShield ICAP server listening on port %s", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("ERROR: Failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func main() {
	config := Config{
		Port:          os.Getenv("ICAP_PORT"),
		DBHost:        os.Getenv("DB_HOST"),
		DBUser:        os.Getenv("DB_USER"),
		DBPass:        os.Getenv("DB_PASSWORD"),
		DBName:        os.Getenv("DB_NAME"),
		Debug:         os.Getenv("DEBUG_MODE") == "1",
		EncryptionKey: os.Getenv("ENCRYPTION_KEY"),
	}
	
	// Set defaults if environment variables are not set
	if config.Port == "" {
		config.Port = "1344"
	}
	if config.DBHost == "" {
		config.DBHost = "mysql"
	}
	if config.DBUser == "" {
		config.DBUser = "pciproxy"
	}
	if config.DBPass == "" {
		config.DBPass = "pciproxy123"
	}
	if config.DBName == "" {
		config.DBName = "pci_proxy"
	}

	server, err := NewICAPServer(config)
	if err != nil {
		log.Fatalf("Failed to create ICAP server: %v", err)
	}

	if err := server.Start(config.Port); err != nil {
		log.Fatalf("Failed to start ICAP server: %v", err)
	}
}