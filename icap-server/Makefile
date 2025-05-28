# TokenShield ICAP Server Makefile

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -D_GNU_SOURCE
LDFLAGS = -lmysqlclient -lcjson -lpthread

# Debug/Release configuration
ifdef DEBUG
    CFLAGS += -g -O0 -DDEBUG
    BUILD_DIR = build/debug
else
    CFLAGS += -O3 -DNDEBUG
    BUILD_DIR = build/release
endif

# MySQL configuration (adjust paths as needed)
MYSQL_CFLAGS = $(shell mysql_config --cflags 2>/dev/null || echo "-I/usr/include/mysql")
MYSQL_LDFLAGS = $(shell mysql_config --libs 2>/dev/null || echo "-L/usr/lib/mysql -lmysqlclient")

# Source files
SRCS = icap_server.c
OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)
TARGET = $(BUILD_DIR)/icap_server

# Default target
all: $(TARGET)

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Compile object files
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	@echo "CC  $<"
	@$(CC) $(CFLAGS) $(MYSQL_CFLAGS) -c $< -o $@

# Link executable
$(TARGET): $(OBJS)
	@echo "LD  $@"
	@$(CC) $(OBJS) -o $@ $(LDFLAGS) $(MYSQL_LDFLAGS)

# Install target
install: $(TARGET)
	@echo "Installing $(TARGET) to /usr/local/bin"
	@install -m 755 $(TARGET) /usr/local/bin/tokenshield-icap

# Clean build files
clean:
	@echo "Cleaning build files..."
	@rm -rf build/

# Run the server (debug mode)
run: all
	./$(TARGET) -D

# Run with custom MySQL settings
run-mysql: all
	./$(TARGET) -h localhost -u tokenshield -P password -d tokenshield -D

# Debug with gdb
debug: DEBUG=1
debug: all
	gdb ./$(TARGET)

# Check dependencies
check-deps:
	@echo "Checking dependencies..."
	@which mysql_config >/dev/null 2>&1 || (echo "ERROR: mysql_config not found. Install MySQL development libraries." && exit 1)
	@pkg-config --exists libcjson || (echo "ERROR: cJSON not found. Install cJSON library." && exit 1)
	@echo "All dependencies found."

# Format code
format:
	@which clang-format >/dev/null 2>&1 && clang-format -i *.c *.h || echo "clang-format not found"

# Static analysis
analyze:
	@which clang-tidy >/dev/null 2>&1 && clang-tidy *.c -- $(CFLAGS) $(MYSQL_CFLAGS) || echo "clang-tidy not found"
	@which cppcheck >/dev/null 2>&1 && cppcheck --enable=all --suppress=missingIncludeSystem *.c || echo "cppcheck not found"

# Memory leak check with valgrind
memcheck: DEBUG=1
memcheck: all
	valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET) -D

# Performance profiling
profile: CFLAGS += -pg
profile: LDFLAGS += -pg
profile: clean all
	@echo "Run the server and use gprof for analysis"

# Build both debug and release
both:
	@$(MAKE) clean
	@echo "Building debug version..."
	@$(MAKE) DEBUG=1
	@echo "Building release version..."
	@$(MAKE)

# Help
help:
	@echo "TokenShield ICAP Server Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build the ICAP server (default)"
	@echo "  clean        - Remove build files"
	@echo "  install      - Install to /usr/local/bin"
	@echo "  run          - Run the server in debug mode"
	@echo "  debug        - Build debug version and run with gdb"
	@echo "  check-deps   - Check for required dependencies"
	@echo "  format       - Format code with clang-format"
	@echo "  analyze      - Run static analysis"
	@echo "  memcheck     - Check for memory leaks with valgrind"
	@echo "  profile      - Build with profiling support"
	@echo "  both         - Build both debug and release versions"
	@echo ""
	@echo "Variables:"
	@echo "  DEBUG=1      - Build with debug symbols"
	@echo ""
	@echo "Example:"
	@echo "  make DEBUG=1 run"

.PHONY: all clean install run run-mysql debug check-deps format analyze memcheck profile both help