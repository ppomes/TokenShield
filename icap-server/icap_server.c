#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <regex.h>
#include <mysql/mysql.h>
#include <cjson/cJSON.h>
#include <time.h>

#define ICAP_PORT 1344
#define BUFFER_SIZE 65536
#define MAX_HEADERS 100
#define TOKEN_PATTERN "tok_[a-zA-Z0-9_]+"

// ICAP server configuration
typedef struct {
    int port;
    char mysql_host[256];
    char mysql_user[256];
    char mysql_pass[256];
    char mysql_db[256];
    int mysql_port;
    int debug;
} icap_config_t;

// HTTP request structure
typedef struct {
    char method[16];
    char uri[2048];
    char version[16];
    char headers[MAX_HEADERS][4096];
    int header_count;
    char *body;
    size_t body_length;
    char host[256];
    char content_type[256];
} http_request_t;

// ICAP request structure
typedef struct {
    char method[16];
    char uri[2048];
    char version[16];
    char headers[MAX_HEADERS][4096];
    int header_count;
    int preview_size;
    char encapsulated[256];
    http_request_t *http_req;
} icap_request_t;

// Global variables
icap_config_t g_config;
MYSQL *g_mysql = NULL;
regex_t g_token_regex;
int g_running = 1;

// Function prototypes
void signal_handler(int sig);
int init_mysql_connection(void);
void close_mysql_connection(void);
char* lookup_token(const char *token);
int parse_icap_request(int client_fd, icap_request_t *req);
int parse_http_request(const char *data, size_t length, http_request_t *req);
int handle_options_request(int client_fd, icap_request_t *req);
int handle_reqmod_request(int client_fd, icap_request_t *req);
char* detokenize_json(const char *json_str);
void free_icap_request(icap_request_t *req);
void free_http_request(http_request_t *req);

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        printf("Received signal %d, shutting down...\n", sig);
        g_running = 0;
    }
}

// Initialize MySQL connection
int init_mysql_connection(void) {
    g_mysql = mysql_init(NULL);
    if (!g_mysql) {
        fprintf(stderr, "Failed to initialize MySQL\n");
        return -1;
    }

    if (!mysql_real_connect(g_mysql, g_config.mysql_host, g_config.mysql_user,
                           g_config.mysql_pass, g_config.mysql_db, 
                           g_config.mysql_port, NULL, 0)) {
        fprintf(stderr, "Failed to connect to MySQL: %s\n", mysql_error(g_mysql));
        mysql_close(g_mysql);
        g_mysql = NULL;
        return -1;
    }

    return 0;
}

// Close MySQL connection
void close_mysql_connection(void) {
    if (g_mysql) {
        mysql_close(g_mysql);
        g_mysql = NULL;
    }
}

// Lookup token in database
char* lookup_token(const char *token) {
    static char card_number[32];
    char query[512];
    MYSQL_RES *result;
    MYSQL_ROW row;

    if (!g_mysql) {
        if (init_mysql_connection() < 0) {
            return NULL;
        }
    }

    // Escape the token for safety
    char escaped_token[256];
    mysql_real_escape_string(g_mysql, escaped_token, token, strlen(token));

    snprintf(query, sizeof(query), 
             "SELECT card_number FROM tokens WHERE token = '%s'", escaped_token);

    if (mysql_query(g_mysql, query) != 0) {
        fprintf(stderr, "MySQL query failed: %s\n", mysql_error(g_mysql));
        return NULL;
    }

    result = mysql_store_result(g_mysql);
    if (!result) {
        fprintf(stderr, "Failed to store result: %s\n", mysql_error(g_mysql));
        return NULL;
    }

    row = mysql_fetch_row(result);
    if (row && row[0]) {
        strncpy(card_number, row[0], sizeof(card_number) - 1);
        card_number[sizeof(card_number) - 1] = '\0';
        mysql_free_result(result);
        return card_number;
    }

    mysql_free_result(result);
    return NULL;
}

// Read line from socket
int read_line(int fd, char *buffer, int max_len) {
    int i = 0;
    char c;

    while (i < max_len - 1) {
        int n = recv(fd, &c, 1, 0);
        if (n <= 0) {
            if (n < 0) perror("recv");
            return -1;
        }

        buffer[i++] = c;
        if (c == '\n') {
            break;
        }
    }

    buffer[i] = '\0';
    return i;
}

// Parse ICAP request
int parse_icap_request(int client_fd, icap_request_t *req) {
    char line[4096];
    
    // Parse request line
    if (read_line(client_fd, line, sizeof(line)) <= 0) {
        return -1;
    }

    if (sscanf(line, "%15s %2047s %15s", req->method, req->uri, req->version) != 3) {
        fprintf(stderr, "Invalid ICAP request line: %s", line);
        return -1;
    }

    // Parse headers
    req->header_count = 0;
    while (req->header_count < MAX_HEADERS) {
        if (read_line(client_fd, line, sizeof(line)) <= 0) {
            return -1;
        }

        // Empty line indicates end of headers
        if (line[0] == '\r' || line[0] == '\n') {
            break;
        }

        strcpy(req->headers[req->header_count], line);

        // Parse specific headers
        if (strncasecmp(line, "Preview:", 8) == 0) {
            req->preview_size = atoi(line + 8);
        } else if (strncasecmp(line, "Encapsulated:", 13) == 0) {
            strcpy(req->encapsulated, line + 13);
        }

        req->header_count++;
    }

    return 0;
}

// Parse HTTP request from ICAP body
int parse_http_request(const char *data, size_t length, http_request_t *req) {
    const char *p = data;
    const char *end = data + length;
    char line[4096];
    int line_len;

    // Parse request line
    const char *line_end = strstr(p, "\r\n");
    if (!line_end || line_end > end) {
        return -1;
    }

    line_len = line_end - p;
    if (line_len >= sizeof(line)) {
        return -1;
    }

    memcpy(line, p, line_len);
    line[line_len] = '\0';

    if (sscanf(line, "%15s %2047s %15s", req->method, req->uri, req->version) != 3) {
        return -1;
    }

    p = line_end + 2;

    // Parse headers
    req->header_count = 0;
    while (p < end && req->header_count < MAX_HEADERS) {
        line_end = strstr(p, "\r\n");
        if (!line_end || line_end > end) {
            break;
        }

        line_len = line_end - p;
        if (line_len == 0) {
            // Empty line - end of headers
            p += 2;
            break;
        }

        if (line_len >= sizeof(req->headers[0])) {
            return -1;
        }

        memcpy(req->headers[req->header_count], p, line_len);
        req->headers[req->header_count][line_len] = '\0';

        // Extract specific headers
        if (strncasecmp(p, "Host:", 5) == 0) {
            sscanf(p + 5, "%255s", req->host);
        } else if (strncasecmp(p, "Content-Type:", 13) == 0) {
            sscanf(p + 13, "%255s", req->content_type);
        }

        req->header_count++;
        p = line_end + 2;
    }

    // Get body
    if (p < end) {
        req->body_length = end - p;
        req->body = malloc(req->body_length + 1);
        if (req->body) {
            memcpy(req->body, p, req->body_length);
            req->body[req->body_length] = '\0';
        }
    } else {
        req->body = NULL;
        req->body_length = 0;
    }

    return 0;
}

// Detokenize JSON content
char* detokenize_json(const char *json_str) {
    cJSON *json = cJSON_Parse(json_str);
    if (!json) {
        return strdup(json_str);
    }

    int modified = 0;
    regmatch_t matches[1];
    
    // Function to recursively process JSON
    void process_json_item(cJSON *item) {
        if (cJSON_IsString(item)) {
            char *value = cJSON_GetStringValue(item);
            if (value && regexec(&g_token_regex, value, 1, matches, 0) == 0) {
                // Found a token
                char token[256];
                int len = matches[0].rm_eo - matches[0].rm_so;
                if (len < sizeof(token)) {
                    strncpy(token, value + matches[0].rm_so, len);
                    token[len] = '\0';
                    
                    char *card_number = lookup_token(token);
                    if (card_number) {
                        cJSON_SetValuestring(item, card_number);
                        modified = 1;
                        if (g_config.debug) {
                            printf("Replaced token %s with card number\n", token);
                        }
                    }
                }
            }
        } else if (cJSON_IsObject(item) || cJSON_IsArray(item)) {
            cJSON *child = NULL;
            cJSON_ArrayForEach(child, item) {
                process_json_item(child);
            }
        }
    }

    process_json_item(json);

    char *result;
    if (modified) {
        result = cJSON_Print(json);
    } else {
        result = strdup(json_str);
    }

    cJSON_Delete(json);
    return result;
}

// Handle OPTIONS request
int handle_options_request(int client_fd, icap_request_t *req) {
    char response[4096];
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    char date[64];
    
    strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", tm);

    snprintf(response, sizeof(response),
        "ICAP/1.0 200 OK\r\n"
        "Date: %s\r\n"
        "Service: TokenShield ICAP Server\r\n"
        "ISTag: \"TS001\"\r\n"
        "Encapsulated: null-body=0\r\n"
        "Max-Connections: 100\r\n"
        "Options-TTL: 3600\r\n"
        "Allow: 204\r\n"
        "Preview: 0\r\n"
        "Transfer-Complete: *\r\n"
        "Methods: REQMOD\r\n"
        "\r\n",
        date);

    if (send(client_fd, response, strlen(response), 0) < 0) {
        perror("send");
        return -1;
    }

    return 0;
}

// Handle REQMOD request
int handle_reqmod_request(int client_fd, icap_request_t *req) {
    char buffer[BUFFER_SIZE];
    int total_read = 0;
    int n;

    // Read the encapsulated HTTP request
    while ((n = recv(client_fd, buffer + total_read, 
                    sizeof(buffer) - total_read - 1, 0)) > 0) {
        total_read += n;
        if (total_read >= sizeof(buffer) - 1) {
            break;
        }
    }

    if (total_read <= 0) {
        return -1;
    }

    buffer[total_read] = '\0';

    // Parse the encapsulated HTTP request
    http_request_t http_req;
    memset(&http_req, 0, sizeof(http_req));

    if (parse_http_request(buffer, total_read, &http_req) < 0) {
        fprintf(stderr, "Failed to parse HTTP request\n");
        return -1;
    }

    // Check if we need to process this request
    int need_modification = 0;
    char *modified_body = NULL;

    if (http_req.body && http_req.body_length > 0 && 
        strstr(http_req.content_type, "json") != NULL) {
        // Check if body contains tokens
        regmatch_t matches[1];
        if (regexec(&g_token_regex, http_req.body, 1, matches, 0) == 0) {
            // Detokenize JSON
            modified_body = detokenize_json(http_req.body);
            if (modified_body && strcmp(modified_body, http_req.body) != 0) {
                need_modification = 1;
            }
        }
    }

    // Send ICAP response
    char response[BUFFER_SIZE];
    int response_len = 0;

    if (!need_modification) {
        // No modification needed - send 204
        response_len = snprintf(response, sizeof(response),
            "ICAP/1.0 204 No Content\r\n"
            "Date: %s\r\n"
            "ISTag: \"TS001\"\r\n"
            "Connection: keep-alive\r\n"
            "\r\n",
            "Thu, 01 Jan 2020 00:00:00 GMT");
    } else {
        // Send modified request
        char modified_request[BUFFER_SIZE];
        int modified_len = 0;

        // Reconstruct HTTP request with modified body
        modified_len += snprintf(modified_request + modified_len, 
                                sizeof(modified_request) - modified_len,
                                "%s %s %s\r\n", 
                                http_req.method, http_req.uri, http_req.version);

        // Copy headers, updating Content-Length
        for (int i = 0; i < http_req.header_count; i++) {
            if (strncasecmp(http_req.headers[i], "Content-Length:", 15) == 0) {
                modified_len += snprintf(modified_request + modified_len,
                                       sizeof(modified_request) - modified_len,
                                       "Content-Length: %zu\r\n",
                                       strlen(modified_body));
            } else {
                modified_len += snprintf(modified_request + modified_len,
                                       sizeof(modified_request) - modified_len,
                                       "%s", http_req.headers[i]);
            }
        }

        modified_len += snprintf(modified_request + modified_len,
                               sizeof(modified_request) - modified_len,
                               "\r\n%s", modified_body);

        // Send ICAP response with modified request
        response_len = snprintf(response, sizeof(response),
            "ICAP/1.0 200 OK\r\n"
            "Date: %s\r\n"
            "ISTag: \"TS001\"\r\n"
            "Connection: keep-alive\r\n"
            "Encapsulated: req-hdr=0, req-body=%d\r\n"
            "\r\n",
            "Thu, 01 Jan 2020 00:00:00 GMT",
            modified_len - strlen(modified_body));

        // Send ICAP headers
        if (send(client_fd, response, response_len, 0) < 0) {
            perror("send");
            free(modified_body);
            free_http_request(&http_req);
            return -1;
        }

        // Send modified HTTP request
        if (send(client_fd, modified_request, modified_len, 0) < 0) {
            perror("send");
            free(modified_body);
            free_http_request(&http_req);
            return -1;
        }
    }

    if (!need_modification && send(client_fd, response, response_len, 0) < 0) {
        perror("send");
        free_http_request(&http_req);
        return -1;
    }

    if (modified_body) {
        free(modified_body);
    }
    free_http_request(&http_req);
    return 0;
}

// Free ICAP request resources
void free_icap_request(icap_request_t *req) {
    if (req->http_req) {
        free_http_request(req->http_req);
        free(req->http_req);
        req->http_req = NULL;
    }
}

// Free HTTP request resources
void free_http_request(http_request_t *req) {
    if (req->body) {
        free(req->body);
        req->body = NULL;
    }
}

// Handle client connection
void handle_client(int client_fd) {
    icap_request_t req;
    memset(&req, 0, sizeof(req));

    if (parse_icap_request(client_fd, &req) < 0) {
        close(client_fd);
        return;
    }

    if (g_config.debug) {
        printf("ICAP %s request for %s\n", req.method, req.uri);
    }

    if (strcmp(req.method, "OPTIONS") == 0) {
        handle_options_request(client_fd, &req);
    } else if (strcmp(req.method, "REQMOD") == 0) {
        handle_reqmod_request(client_fd, &req);
    } else {
        // Unsupported method
        char response[] = "ICAP/1.0 405 Method Not Allowed\r\n\r\n";
        send(client_fd, response, strlen(response), 0);
    }

    free_icap_request(&req);
    close(client_fd);
}

// Main function
int main(int argc, char *argv[]) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int opt = 1;

    printf("TokenShield ICAP server starting...\n");
    fflush(stdout);

    // Initialize configuration with defaults
    g_config.port = ICAP_PORT;
    strcpy(g_config.mysql_host, "localhost");
    strcpy(g_config.mysql_user, "tokenshield");
    strcpy(g_config.mysql_pass, "password");
    strcpy(g_config.mysql_db, "tokenshield");
    g_config.mysql_port = 3306;
    g_config.debug = 0;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            g_config.port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
            strncpy(g_config.mysql_host, argv[++i], sizeof(g_config.mysql_host) - 1);
        } else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
            strncpy(g_config.mysql_user, argv[++i], sizeof(g_config.mysql_user) - 1);
        } else if (strcmp(argv[i], "-P") == 0 && i + 1 < argc) {
            strncpy(g_config.mysql_pass, argv[++i], sizeof(g_config.mysql_pass) - 1);
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            strncpy(g_config.mysql_db, argv[++i], sizeof(g_config.mysql_db) - 1);
        } else if (strcmp(argv[i], "-D") == 0) {
            g_config.debug = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  -p PORT     ICAP port (default: 1344)\n");
            printf("  -h HOST     MySQL host (default: localhost)\n");
            printf("  -u USER     MySQL user (default: tokenshield)\n");
            printf("  -P PASS     MySQL password (default: password)\n");
            printf("  -d DB       MySQL database (default: tokenshield)\n");
            printf("  -D          Enable debug mode\n");
            return 0;
        }
    }

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Compile regex for token matching
    if (regcomp(&g_token_regex, TOKEN_PATTERN, REG_EXTENDED) != 0) {
        fprintf(stderr, "Failed to compile token regex\n");
        return 1;
    }

    // Initialize MySQL connection
    if (init_mysql_connection() < 0) {
        fprintf(stderr, "Warning: Failed to connect to MySQL\n");
    }

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_fd);
        return 1;
    }

    // Bind socket
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(g_config.port);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    // Listen for connections
    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("ICAP server listening on 0.0.0.0:%d\n", g_config.port);
    fflush(stdout);
    if (g_config.debug) {
        printf("Debug mode enabled\n");
        printf("MySQL: %s@%s:%s\n", g_config.mysql_user, g_config.mysql_host, g_config.mysql_db);
        fflush(stdout);
    }

    // Accept connections loop
    printf("Waiting for connections...\n");
    fflush(stdout);
    while (g_running) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            continue;
        }

        if (g_config.debug) {
            printf("Client connected from %s:%d\n", 
                   inet_ntoa(client_addr.sin_addr), 
                   ntohs(client_addr.sin_port));
        }

        // Handle client in same thread (can be improved with threading)
        handle_client(client_fd);
    }

    // Cleanup
    close(server_fd);
    close_mysql_connection();
    regfree(&g_token_regex);

    printf("Server shutdown complete\n");
    return 0;
}