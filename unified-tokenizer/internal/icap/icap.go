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
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		if err != io.EOF {
			log.Printf("Error reading ICAP request line: %v", err)
		}
		return
	}

	// Parse request line
	requestLine = strings.TrimSpace(requestLine)
	parts := strings.Split(requestLine, " ")
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
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Error reading ICAP headers: %v", err)
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
	writer.Flush()
}

// handleReqmod processes ICAP REQMOD requests (request modification)
func (s *Server) handleReqmod(reader *bufio.Reader, writer *bufio.Writer, icapHeaders map[string]string) {
	log.Printf("DEBUG: handleReqmod called with Encapsulated: %s", icapHeaders["Encapsulated"])
	
	// Parse encapsulated header
	httpRequest, httpHeaders, httpBody, err := s.parseEncapsulated(reader, icapHeaders["Encapsulated"])
	if err != nil {
		log.Printf("Error parsing REQMOD encapsulated data: %v", err)
		s.writeErrorResponse(writer, 400, "Bad Request")
		return
	}
	
	log.Printf("DEBUG: parseEncapsulated returned successfully")

	if s.debug {
		log.Printf("DEBUG: REQMOD HTTP Request: %s", httpRequest)
		log.Printf("DEBUG: REQMOD HTTP Headers: %v", httpHeaders)
		log.Printf("DEBUG: REQMOD HTTP Body length: %d", len(httpBody))
	}

	// Process tokenization on the request body
	modifiedBody := httpBody
	var modified bool

	if len(httpBody) > 0 {
		// Try to detokenize JSON content (REQMOD is for outgoing requests)
		if modifiedJSON, wasModified, err := s.handler.DetokenizeJSON(string(httpBody)); err == nil && wasModified {
			modifiedBody = []byte(modifiedJSON)
			modified = true
			if s.debug {
				log.Printf("DEBUG: REQMOD detokenized JSON body")
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
func (s *Server) readChunked(reader *bufio.Reader) ([]byte, error) {
	var result bytes.Buffer

	for {
		// Read chunk size line
		sizeLine, err := reader.ReadBytes('\n')
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
				line, err := reader.ReadBytes('\n')
				if err != nil || len(bytes.TrimSpace(line)) == 0 {
					break
				}
			}
			break
		}

		// Read chunk data
		chunkData := make([]byte, size)
		_, err = io.ReadFull(reader, chunkData)
		if err != nil {
			return nil, fmt.Errorf("error reading chunk data: %v", err)
		}

		result.Write(chunkData)

		// Read trailing CRLF
		reader.ReadBytes('\n')
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
	writer.Flush()
}

// sendUnmodifiedResponse sends an ICAP response indicating no modification
func (s *Server) sendUnmodifiedResponse(writer *bufio.Writer) {
	response := "ICAP/1.0 204 No Content\r\n" +
		"Encapsulated: null-body=0\r\n" +
		"\r\n"

	writer.WriteString(response)
	writer.Flush()
}

// writeErrorResponse sends an ICAP error response
func (s *Server) writeErrorResponse(writer *bufio.Writer, code int, message string) {
	response := fmt.Sprintf("ICAP/1.0 %d %s\r\n"+
		"Encapsulated: null-body=0\r\n"+
		"\r\n", code, message)

	writer.WriteString(response)
	writer.Flush()
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