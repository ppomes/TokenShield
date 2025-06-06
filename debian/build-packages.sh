#!/bin/bash
# Build script for TokenShield Debian packages

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ] || [ ! -d "unified-tokenizer" ] || [ ! -d "cli" ]; then
    print_error "This script must be run from the TokenShield root directory"
    exit 1
fi

# Check for required tools
for tool in dpkg-buildpackage debuild lintian; do
    if ! command -v $tool &> /dev/null; then
        print_error "$tool is required but not installed"
        print_info "Install with: sudo apt-get install build-essential devscripts lintian"
        exit 1
    fi
done

# Create build directories
print_info "Creating build directories..."
mkdir -p build/tokenshield-unified
mkdir -p build/tokenshield-cli

# Build tokenshield-unified package
print_info "Building tokenshield-unified package..."
cd build/tokenshield-unified

# Copy source files
cp -r ../../unified-tokenizer .
cp -r ../../debian/tokenshield-unified debian
cp ../../debian/tokenshield-unified.service debian/
cp ../../debian/tokenshield-unified.default debian/

# Build the package
dpkg-buildpackage -us -uc -b

# Run lintian
print_info "Running lintian checks on tokenshield-unified..."
lintian ../tokenshield-unified_*.deb || print_warning "Lintian found issues"

cd ../..

# Build tokenshield-cli package
print_info "Building tokenshield-cli package..."
cd build/tokenshield-cli

# Copy source files
cp -r ../../cli .
cp -r ../../debian/tokenshield-cli debian
cp ../../debian/tokenshield.bash-completion debian/
cp ../../debian/tokenshield.zsh-completion debian/
cp ../../debian/tokenshield.1 debian/
cp ../../debian/tokenshield.conf.example debian/

# Build the package
dpkg-buildpackage -us -uc -b

# Run lintian
print_info "Running lintian checks on tokenshield-cli..."
lintian ../tokenshield-cli_*.deb || print_warning "Lintian found issues"

cd ../..

# Summary
print_info "Build complete! Packages are in build/"
ls -la build/*.deb

print_info "To install the packages:"
echo "  sudo dpkg -i build/tokenshield-unified_*.deb"
echo "  sudo dpkg -i build/tokenshield-cli_*.deb"
echo ""
print_info "To fix any dependency issues:"
echo "  sudo apt-get install -f"