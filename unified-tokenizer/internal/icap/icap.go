package icap

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
)

// Handler interface defines the methods needed for ICAP operations
type Handler interface {
	TokenizeJSON(jsonStr string) (string, bool, error)
	DetokenizeJSON(jsonStr string) (string, bool, error)
	DetokenizeHTML(htmlStr string) (string, bool, error)
}

// Server handles ICAP protocol operations
type Server struct {
	handler Handler
	debug   bool
}

// NewServer creates a new ICAP server instance
func NewServer(handler Handler, debug bool) *Server {
	return &Server{
		handler: handler,
		debug:   debug,
	}
}

// HandleConnection processes an ICAP connection
func (s *Server) HandleConnection(conn net.Conn) {
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
	
	if s.debug {
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
		s.handleICAPOptions(writer, icapURI)
	case "REQMOD":
		s.handleICAPReqmod(reader, writer, headers)
	case "RESPMOD":
		s.handleICAPRespmod(reader, writer, headers)
	default:
		log.Printf("Unsupported ICAP method: %s", method)
	}
	
	writer.Flush()
}

func (s *Server) handleICAPOptions(writer *bufio.Writer, icapURI string) {
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
	
	if s.debug {
		log.Printf("Sent OPTIONS response for %s", icapURI)
	}
}

func (s *Server) handleICAPReqmod(reader *bufio.Reader, writer *bufio.Writer, icapHeaders map[string]string) {
	// Parse encapsulated header
	encapHeader := icapHeaders["Encapsulated"]
	if encapHeader == "" {
		log.Printf("Missing Encapsulated header")
		return
	}
	
	// Read HTTP request
	httpRequest, httpHeaders, body, err := s.parseEncapsulated(reader, encapHeader)
	if err != nil {
		log.Printf("Error parsing encapsulated data: %v", err)
		return
	}
	
	if s.debug {
		log.Printf("HTTP Request: %s", httpRequest)
		log.Printf("Body length: %d", len(body))
	}
	
	// Check if we need to modify
	modified := false
	modifiedBody := body
	
	if len(body) > 0 {
		detokenized, wasModified, err := s.handler.DetokenizeJSON(string(body))
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
	s.writeChunked(writer, modifiedBody)
	writer.Flush()
}

func (s *Server) handleICAPRespmod(reader *bufio.Reader, writer *bufio.Writer, icapHeaders map[string]string) {
	// Parse encapsulated header for response modification
	encapHeader := icapHeaders["Encapsulated"]
	if encapHeader == "" {
		log.Printf("Missing Encapsulated header in RESPMOD")
		return
	}
	
	if s.debug {
		log.Printf("RESPMOD: Processing response for tokenization")
		log.Printf("Encapsulated: %s", encapHeader)
	}
	
	// Parse the response (request + response)
	_, _, body, err := s.parseEncapsulated(reader, encapHeader)
	if err != nil {
		log.Printf("RESPMOD Error parsing encapsulated response data: %v", err)
		return
	}
	
	if s.debug {
		log.Printf("RESPMOD Body length: %d", len(body))
		if len(body) > 0 && len(body) < 1000 {
			log.Printf("RESPMOD Body content: %s", string(body))
		}
	}
	
	// Check if we need to modify the body
	modified := false
	modifiedBody := body
	
	if len(body) > 0 {
		bodyStr := string(body)
		
		// Try JSON tokenization first (for card import responses)
		if tokenized, wasModified, err := s.handler.TokenizeJSON(bodyStr); err == nil && wasModified {
			modifiedBody = []byte(tokenized)
			modified = true
			if s.debug {
				log.Printf("RESPMOD: Tokenized JSON response")
			}
		}
	}
	
	if !modified {
		// Send 204 No Content - no modification needed
		response := "ICAP/1.0 204 No Content\r\n\r\n"
		writer.WriteString(response)
		if s.debug {
			log.Printf("RESPMOD: No modifications needed, sending 204")
		}
		return
	}
	
	if s.debug {
		log.Printf("RESPMOD: Sending modified response, original size: %d, modified size: %d", len(body), len(modifiedBody))
	}
	
	// Build ICAP response
	response := "ICAP/1.0 200 OK\r\n"
	response += "Encapsulated: res-hdr=0, res-body=\r\n"
	response += "\r\n"
	
	// Write ICAP headers
	writer.WriteString(response)
	
	// Write HTTP response line
	writer.WriteString("HTTP/1.1 200 OK\r\n")
	
	// Write response headers with updated Content-Length
	writer.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(modifiedBody)))
	writer.WriteString("Content-Type: application/json\r\n")
	writer.WriteString("\r\n")
	
	// Write body using chunked encoding
	s.writeChunked(writer, modifiedBody)
	
	writer.Flush()
}

func (s *Server) parseEncapsulated(reader *bufio.Reader, encapHeader string) (string, []string, []byte, error) {
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
	
	if s.debug {
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
			if s.debug {
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
		if s.debug {
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
		if s.debug {
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
		if s.debug {
			log.Printf("DEBUG: Reading req-body")
		}
		body, err = s.readChunked(reader)
		if err != nil {
			return "", nil, nil, err
		}
	} else if _, hasResBody := positions["res-body"]; hasResBody {
		if s.debug {
			log.Printf("DEBUG: Reading res-body at position %d", positions["res-body"])
		}
		body, err = s.readChunked(reader)
		if err != nil {
			if s.debug {
				log.Printf("DEBUG: Error reading res-body: %v", err)
			}
			return "", nil, nil, err
		}
		if s.debug {
			log.Printf("DEBUG: Successfully read res-body: %d bytes", len(body))
		}
	} else {
		if s.debug {
			log.Printf("DEBUG: No body found in positions: %+v", positions)
		}
		// For null-body cases, we still need to return a proper response
		// This typically means there's no body to process
	}
	
	if s.debug {
		log.Printf("DEBUG: parseEncapsulated result - requestLine: '%s', headers: %d, body: %d bytes", 
			requestLine, len(httpHeaders), len(body))
	}
	
	return requestLine, httpHeaders, body, nil
}

func (s *Server) readChunked(reader *bufio.Reader) ([]byte, error) {
	var result []byte
	
	if s.debug {
		log.Printf("DEBUG: readChunked starting")
	}
	
	for {
		// Read chunk size
		sizeLine, err := reader.ReadString('\n')
		if err != nil {
			if s.debug {
				log.Printf("DEBUG: readChunked error reading size line: %v", err)
			}
			return nil, err
		}
		
		sizeLine = strings.TrimSpace(sizeLine)
		if s.debug {
			log.Printf("DEBUG: readChunked size line: '%s'", sizeLine)
		}
		
		size, err := strconv.ParseInt(sizeLine, 16, 64)
		if err != nil {
			if s.debug {
				log.Printf("DEBUG: readChunked error parsing size: %v", err)
			}
			return nil, err
		}
		
		if s.debug {
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

func (s *Server) writeChunked(writer *bufio.Writer, data []byte) {
	if len(data) > 0 {
		writer.WriteString(fmt.Sprintf("%x\r\n", len(data)))
		writer.Write(data)
		writer.WriteString("\r\n")
	}
	writer.WriteString("0\r\n\r\n")
}