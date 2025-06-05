package icap

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
)

// parseEncapsulated parses ICAP encapsulated HTTP message
func (s *Server) parseEncapsulated(reader *bufio.Reader, encapHeader string) (string, []string, []byte, error) {
	log.Printf("DEBUG: parseEncapsulated called with header: %s", encapHeader)
	
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

	// Determine what sections we have
	hasReqHdr := false
	hasReqBody := false
	
	if _, ok := sections["req-hdr"]; ok {
		hasReqHdr = true
	}
	if _, ok := sections["req-body"]; ok {
		hasReqBody = true
	}
	
	log.Printf("DEBUG: Sections - req-hdr:%v, req-body:%v", hasReqHdr, hasReqBody)

	var httpRequest string
	var httpHeaders []string
	var httpBody []byte

	// For REQMOD, we need to read the request headers and body
	if hasReqHdr {
		// Read HTTP request line
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", nil, nil, fmt.Errorf("error reading request line: %v", err)
		}
		httpRequest = strings.TrimSpace(line)
		log.Printf("DEBUG: HTTP Request line: %s", httpRequest)
		
		// Read HTTP headers
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return "", nil, nil, fmt.Errorf("error reading headers: %v", err)
			}
			line = strings.TrimSpace(line)
			if line == "" {
				break // End of headers
			}
			httpHeaders = append(httpHeaders, line)
		}
		log.Printf("DEBUG: Read %d headers", len(httpHeaders))
	}

	// Read HTTP body if present
	if hasReqBody {
		// Check for chunked encoding
		isChunked := false
		for _, hdr := range httpHeaders {
			if strings.HasPrefix(strings.ToLower(hdr), "transfer-encoding:") && 
			   strings.Contains(strings.ToLower(hdr), "chunked") {
				isChunked = true
				break
			}
		}
		
		if isChunked {
			// Read chunked body
			body, err := s.readChunked(reader)
			if err != nil {
				return httpRequest, httpHeaders, nil, fmt.Errorf("error reading chunked body: %v", err)
			}
			httpBody = body
			log.Printf("DEBUG: Read chunked body of %d bytes", len(httpBody))
		} else {
			// Find Content-Length header
			contentLength := 0
			for _, hdr := range httpHeaders {
				if strings.HasPrefix(strings.ToLower(hdr), "content-length:") {
					parts := strings.Split(hdr, ":")
					if len(parts) >= 2 {
						contentLength, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
						break
					}
				}
			}
			
			log.Printf("DEBUG: Content-Length: %d", contentLength)
			
			if contentLength > 0 {
				httpBody = make([]byte, contentLength)
				_, err := io.ReadFull(reader, httpBody)
				if err != nil {
					return httpRequest, httpHeaders, nil, fmt.Errorf("error reading body: %v", err)
				}
				log.Printf("DEBUG: Read body of %d bytes", len(httpBody))
			}
		}
	}

	return httpRequest, httpHeaders, httpBody, nil
}