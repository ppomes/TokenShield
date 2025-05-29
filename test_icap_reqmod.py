#!/usr/bin/env python3
import socket

def test_reqmod():
    # Test 1: OPTIONS request
    icap_options = "OPTIONS icap://unified-tokenizer:1344/reqmod ICAP/1.0\r\nHost: unified-tokenizer:1344\r\n\r\n"
    
    print("=== Test 1: ICAP OPTIONS ===")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(('localhost', 1344))
        sock.send(icap_options.encode())
        response = sock.recv(4096).decode()
        print("OPTIONS Response:", response[:200])
        print("✓ OPTIONS working")
    except Exception as e:
        print(f"✗ OPTIONS failed: {e}")
        return
    finally:
        sock.close()
    
    # Test 2: Simple REQMOD with tokenized card
    print("\n=== Test 2: REQMOD with token ===")
    
    # HTTP request with tokenized card
    test_token = "tok_D8UzD2HYe26z-0jy9xXibdjL8lBAghtMGIcEi5u266w="
    http_body = f'{{"card_number": "{test_token}", "amount": "99.99"}}'
    
    # HTTP headers only (body will be sent chunked)
    http_headers = f"""POST /process HTTP/1.1\r
Host: payment-gateway:9000\r
Content-Type: application/json\r
Content-Length: {len(http_body)}\r
\r
"""
    
    # Convert body to chunked encoding format
    body_chunk_size = hex(len(http_body))[2:]  # Remove '0x' prefix
    chunked_body = f"{body_chunk_size}\r\n{http_body}\r\n0\r\n\r\n"
    
    # ICAP REQMOD request  
    icap_reqmod = f"""REQMOD icap://unified-tokenizer:1344/reqmod ICAP/1.0\r
Host: unified-tokenizer:1344\r
Encapsulated: req-hdr=0, req-body={len(http_headers)}\r
\r
{http_headers}{chunked_body}"""
    
    print("Sending REQMOD request...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(10)  # 10 second timeout
        sock.connect(('localhost', 1344))
        sock.send(icap_reqmod.encode())
        response = sock.recv(4096).decode()
        print("REQMOD Response length:", len(response))
        print("Response preview:", response[:300])
        if "4532015112830366" in response:
            print("✓ Token was detokenized!")
        else:
            print("✗ Token not detokenized")
    except Exception as e:
        print(f"✗ REQMOD failed: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    test_reqmod()