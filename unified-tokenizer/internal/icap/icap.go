package icap

import (
	"bufio"
	"bytes"
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
	defer writer.Flush()

	// Read request line
	requestLine, _, err := reader.ReadLine()
	if err != nil {
		log.Printf("Error reading ICAP request line: %v", err)
		return
	}

	// Parse request line
	parts := strings.Split(string(requestLine), " ")
	if len(parts) < 3 {
		log.Printf("Invalid ICAP request line: %s", string(requestLine))
		return
	}

	method, icapURI, version := parts[0], parts[1], parts[2]
	if s.debug {
		log.Printf("ICAP Request: %s %s %s", method, icapURI, version)
	}

	// Read headers
	headers := make(map[string]string)
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			log.Printf("Error reading ICAP headers: %v", err)
			return
		}
		if len(line) == 0 {
			break
		}
		headerStr := string(line)
		if colonIndex := strings.Index(headerStr, ":"); colonIndex > 0 {
			key := strings.TrimSpace(headerStr[:colonIndex])
			value := strings.TrimSpace(headerStr[colonIndex+1:])
			headers[key] = value
		}
	}

	// Route to appropriate handler
	switch method {
	case "OPTIONS":
		s.handleOptions(writer, icapURI)
	case "REQMOD":
		s.handleReqmod(reader, writer, headers)
	case "RESPMOD":
		s.handleRespmod(reader, writer, headers)
	default:
		log.Printf("Unsupported ICAP method: %s", method)
		s.writeErrorResponse(writer, 405, "Method Not Allowed")
	}
}

// handleOptions responds to ICAP OPTIONS requests
func (s *Server) handleOptions(writer *bufio.Writer, icapURI string) {
	response := fmt.Sprintf("ICAP/1.0 200 OK\r\n"+
		"Methods: REQMOD, RESPMOD\r\n"+
		"Service: TokenShield ICAP Detokenization Service\r\n"+
		"ISTag: TokenShield-1.0\r\n"+
		"Encapsulated: null-body=0\r\n"+
		"Max-Connections: 100\r\n"+
		"Preview: 0\r\n"+
		"Transfer-Preview: *\r\n"+
		"Transfer-Ignore: jpg,gif,png,exe,zip\r\n"+
		"Transfer-Complete: \r\n"+
		"\r\n")

	writer.WriteString(response)
}

// handleReqmod processes ICAP REQMOD requests (request modification)
func (s *Server) handleReqmod(reader *bufio.Reader, writer *bufio.Writer, icapHeaders map[string]string) {
	// Parse encapsulated header
	httpRequest, httpHeaders, httpBody, err := s.parseEncapsulated(reader, icapHeaders["Encapsulated"])
	if err != nil {
		log.Printf("Error parsing REQMOD encapsulated data: %v", err)
		s.writeErrorResponse(writer, 400, "Bad Request")
		return
	}

	if s.debug {
		log.Printf("DEBUG: REQMOD HTTP Request: %s", httpRequest)
		log.Printf("DEBUG: REQMOD HTTP Headers: %v", httpHeaders)
		log.Printf("DEBUG: REQMOD HTTP Body length: %d", len(httpBody))
	}

	// Process tokenization on the request body
	modifiedBody := httpBody
	var modified bool

	if len(httpBody) > 0 {
		// Try to tokenize JSON content
		if modifiedJSON, wasModified, err := s.handler.TokenizeJSON(string(httpBody)); err == nil && wasModified {
			modifiedBody = []byte(modifiedJSON)
			modified = true
			if s.debug {
				log.Printf("DEBUG: REQMOD tokenized JSON body")
			}
		}
	}

	// Send response
	if modified {
		s.sendModifiedResponse(writer, httpRequest, httpHeaders, modifiedBody)
	} else {
		s.sendUnmodifiedResponse(writer)
	}
}

// handleRespmod processes ICAP RESPMOD requests (response modification)
func (s *Server) handleRespmod(reader *bufio.Reader, writer *bufio.Writer, icapHeaders map[string]string) {
	// Parse encapsulated header
	httpRequest, httpHeaders, httpBody, err := s.parseEncapsulated(reader, icapHeaders["Encapsulated"])
	if err != nil {
		log.Printf("Error parsing RESPMOD encapsulated data: %v", err)
		s.writeErrorResponse(writer, 400, "Bad Request")
		return
	}

	if s.debug {
		log.Printf("DEBUG: RESPMOD HTTP Request: %s", httpRequest)
		log.Printf("DEBUG: RESPMOD HTTP Headers: %v", httpHeaders)
		log.Printf("DEBUG: RESPMOD HTTP Body length: %d", len(httpBody))
	}

	// Process detokenization on the response body
	modifiedBody := httpBody
	var modified bool

	if len(httpBody) > 0 {
		bodyStr := string(httpBody)

		// Determine content type for appropriate detokenization
		contentType := ""
		for _, header := range httpHeaders {
			if strings.HasPrefix(strings.ToLower(header), "content-type:") {
				contentType = strings.ToLower(strings.TrimSpace(header[13:]))
				break
			}
		}

		// Try different detokenization strategies based on content type
		if strings.Contains(contentType, "application/json") {
			if modifiedJSON, wasModified, err := s.handler.DetokenizeJSON(bodyStr); err == nil && wasModified {
				modifiedBody = []byte(modifiedJSON)
				modified = true
				if s.debug {
					log.Printf("DEBUG: RESPMOD detokenized JSON body")
				}
			}
		} else if strings.Contains(contentType, "text/html") {
			if modifiedHTML, wasModified, err := s.handler.DetokenizeHTML(bodyStr); err == nil && wasModified {
				modifiedBody = []byte(modifiedHTML)
				modified = true
				if s.debug {
					log.Printf("DEBUG: RESPMOD detokenized HTML body")
				}
			}
		} else {
			// Try JSON detokenization as fallback
			if modifiedJSON, wasModified, err := s.handler.DetokenizeJSON(bodyStr); err == nil && wasModified {
				modifiedBody = []byte(modifiedJSON)
				modified = true
				if s.debug {
					log.Printf("DEBUG: RESPMOD detokenized as JSON fallback")
				}
			}
		}
	}

	// Send response
	if modified {
		s.sendModifiedResponse(writer, httpRequest, httpHeaders, modifiedBody)
	} else {
		s.sendUnmodifiedResponse(writer)
	}
}

// parseEncapsulated parses ICAP encapsulated HTTP message
func (s *Server) parseEncapsulated(reader *bufio.Reader, encapHeader string) (string, []string, []byte, error) {
	if encapHeader == "" {
		return "", nil, nil, fmt.Errorf("missing Encapsulated header")
	}

	// Parse encapsulated header to find section offsets
	sections := make(map[string]int)
	parts := strings.Split(encapHeader, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if eqIndex := strings.Index(part, "="); eqIndex > 0 {
			key := strings.TrimSpace(part[:eqIndex])
			value := strings.TrimSpace(part[eqIndex+1:])
			if offset, err := strconv.Atoi(value); err == nil {
				sections[key] = offset
			}
		}
	}

	// Read all remaining data
	var buffer bytes.Buffer
	_, err := io.Copy(&buffer, reader)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error reading encapsulated data: %v", err)
	}
	data := buffer.Bytes()

	var httpRequest string
	var httpHeaders []string
	var httpBody []byte

	// Extract HTTP request line if present
	if reqOffset, exists := sections["req-hdr"]; exists {
		if reqOffset < len(data) {
			// Find end of request line
			if nlIndex := bytes.Index(data[reqOffset:], []byte("\r\n")); nlIndex > 0 {
				httpRequest = string(data[reqOffset : reqOffset+nlIndex])
			}
		}
	}

	// Extract HTTP headers if present
	if hdrOffset, exists := sections["req-hdr"]; exists {
		var endOffset int
		if bodyOffset, hasBody := sections["req-body"]; hasBody {
			endOffset = bodyOffset
		} else if resOffset, hasRes := sections["res-hdr"]; hasRes {
			endOffset = resOffset
		} else {
			endOffset = len(data)
		}

		if hdrOffset < endOffset && hdrOffset < len(data) {
			headerData := data[hdrOffset:min(endOffset, len(data))]
			headerLines := strings.Split(string(headerData), "\r\n")
			for _, line := range headerLines {
				if strings.TrimSpace(line) != "" && strings.Contains(line, ":") {
					httpHeaders = append(httpHeaders, line)
				}
			}
		}
	}

	// Extract HTTP body if present
	if bodyOffset, exists := sections["req-body"]; exists {
		if bodyOffset < len(data) {
			// Check if it's chunked encoding
			if s.isChunkedEncoding(httpHeaders) {
				httpBody, err = s.readChunked(bytes.NewReader(data[bodyOffset:]))
				if err != nil {
					return httpRequest, httpHeaders, nil, fmt.Errorf("error reading chunked body: %v", err)
				}
			} else {
				httpBody = data[bodyOffset:]
			}
		}
	}

	return httpRequest, httpHeaders, httpBody, nil
}

// isChunkedEncoding checks if the transfer encoding is chunked
func (s *Server) isChunkedEncoding(headers []string) bool {
	for _, header := range headers {
		if strings.HasPrefix(strings.ToLower(header), "transfer-encoding:") {
			value := strings.ToLower(strings.TrimSpace(header[18:]))
			return strings.Contains(value, "chunked")
		}
	}
	return false
}

// readChunked reads chunked HTTP body
func (s *Server) readChunked(reader io.Reader) ([]byte, error) {
	bufReader := bufio.NewReader(reader)
	var result bytes.Buffer

	for {
		// Read chunk size line
		sizeLine, err := bufReader.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("error reading chunk size: %v", err)
		}

		// Parse chunk size (hex)
		sizeStr := strings.TrimSpace(string(sizeLine))
		if semiIndex := strings.Index(sizeStr, ";"); semiIndex > 0 {
			sizeStr = sizeStr[:semiIndex] // Remove chunk extensions
		}

		size, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid chunk size: %s", sizeStr)
		}

		if size == 0 {
			// Last chunk, read trailing headers if any
			for {
				line, err := bufReader.ReadBytes('\n')
				if err != nil || len(bytes.TrimSpace(line)) == 0 {
					break
				}
			}
			break
		}

		// Read chunk data
		chunkData := make([]byte, size)
		_, err = io.ReadFull(bufReader, chunkData)
		if err != nil {
			return nil, fmt.Errorf("error reading chunk data: %v", err)
		}

		result.Write(chunkData)

		// Read trailing CRLF
		bufReader.ReadBytes('\n')
	}

	return result.Bytes(), nil
}

// sendModifiedResponse sends an ICAP response with modified content
func (s *Server) sendModifiedResponse(writer *bufio.Writer, httpRequest string, httpHeaders []string, body []byte) {
	response := "ICAP/1.0 200 OK\r\n" +
		"Encapsulated: res-hdr=0, res-body=" + strconv.Itoa(len(httpRequest)+2) + "\r\n" +
		"\r\n"

	// Write HTTP response headers
	response += "HTTP/1.1 200 OK\r\n"
	response += "Content-Length: " + strconv.Itoa(len(body)) + "\r\n"
	response += "Content-Type: application/json\r\n"
	response += "\r\n"

	writer.WriteString(response)

	// Write body in chunked format
	s.writeChunked(writer, body)
}

// sendUnmodifiedResponse sends an ICAP response indicating no modification
func (s *Server) sendUnmodifiedResponse(writer *bufio.Writer) {
	response := "ICAP/1.0 204 No Content\r\n" +
		"Encapsulated: null-body=0\r\n" +
		"\r\n"

	writer.WriteString(response)
}

// writeErrorResponse sends an ICAP error response
func (s *Server) writeErrorResponse(writer *bufio.Writer, code int, message string) {
	response := fmt.Sprintf("ICAP/1.0 %d %s\r\n"+
		"Encapsulated: null-body=0\r\n"+
		"\r\n", code, message)

	writer.WriteString(response)
}

// writeChunked writes data in HTTP chunked encoding
func (s *Server) writeChunked(writer *bufio.Writer, data []byte) {
	if len(data) > 0 {
		// Write chunk size in hex
		writer.WriteString(fmt.Sprintf("%X\r\n", len(data)))
		// Write chunk data
		writer.Write(data)
		writer.WriteString("\r\n")
	}
	// Write final chunk
	writer.WriteString("0\r\n\r\n")
}

// Helper function for min operation
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}