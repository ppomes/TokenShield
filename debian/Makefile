# Makefile for TokenShield Debian packages

.PHONY: all clean build install unified-build cli-build unified-install cli-install check

# Package versions
UNIFIED_VERSION := 1.0.0-1
CLI_VERSION := 1.0.0-1

# Build directories
BUILD_DIR := build
UNIFIED_BUILD := $(BUILD_DIR)/tokenshield-unified
CLI_BUILD := $(BUILD_DIR)/tokenshield-cli

# Package names
UNIFIED_DEB := tokenshield-unified_$(UNIFIED_VERSION)_amd64.deb
CLI_DEB := tokenshield-cli_$(CLI_VERSION)_amd64.deb

all: build

clean:
	@echo "Cleaning build directories..."
	rm -rf $(BUILD_DIR)

build: unified-build cli-build

unified-build: $(BUILD_DIR)/$(UNIFIED_DEB)

cli-build: $(BUILD_DIR)/$(CLI_DEB)

$(BUILD_DIR)/$(UNIFIED_DEB):
	@echo "Building tokenshield-unified package..."
	@mkdir -p $(UNIFIED_BUILD)
	@cp -r ../unified-tokenizer $(UNIFIED_BUILD)/
	@cp -r tokenshield-unified $(UNIFIED_BUILD)/debian
	@cp tokenshield-unified.service $(UNIFIED_BUILD)/debian/
	@cp tokenshield-unified.default $(UNIFIED_BUILD)/debian/
	@cd $(UNIFIED_BUILD) && dpkg-buildpackage -us -uc -b
	@echo "Package built: $(BUILD_DIR)/$(UNIFIED_DEB)"

$(BUILD_DIR)/$(CLI_DEB):
	@echo "Building tokenshield-cli package..."
	@mkdir -p $(CLI_BUILD)
	@cp -r ../cli $(CLI_BUILD)/
	@cp -r tokenshield-cli $(CLI_BUILD)/debian
	@cp tokenshield.bash-completion $(CLI_BUILD)/debian/
	@cp tokenshield.zsh-completion $(CLI_BUILD)/debian/
	@cp tokenshield.1 $(CLI_BUILD)/debian/
	@cp tokenshield.conf.example $(CLI_BUILD)/debian/
	@cd $(CLI_BUILD) && dpkg-buildpackage -us -uc -b
	@echo "Package built: $(BUILD_DIR)/$(CLI_DEB)"

install: unified-install cli-install

unified-install: unified-build
	@echo "Installing tokenshield-unified..."
	sudo dpkg -i $(BUILD_DIR)/$(UNIFIED_DEB) || sudo apt-get install -f -y

cli-install: cli-build
	@echo "Installing tokenshield-cli..."
	sudo dpkg -i $(BUILD_DIR)/$(CLI_DEB) || sudo apt-get install -f -y

check: build
	@echo "Running lintian checks..."
	@lintian $(BUILD_DIR)/$(UNIFIED_DEB) || true
	@lintian $(BUILD_DIR)/$(CLI_DEB) || true

help:
	@echo "TokenShield Debian Package Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build all packages (default)"
	@echo "  clean        - Remove build directories"
	@echo "  build        - Build all packages"
	@echo "  install      - Build and install all packages"
	@echo "  unified-build - Build only tokenshield-unified"
	@echo "  cli-build    - Build only tokenshield-cli"
	@echo "  unified-install - Build and install tokenshield-unified"
	@echo "  cli-install  - Build and install tokenshield-cli"
	@echo "  check        - Run lintian checks on built packages"
	@echo "  help         - Show this help message"