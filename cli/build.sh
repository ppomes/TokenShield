#!/bin/bash

# Build script for TokenShield CLI

echo "Building TokenShield CLI..."

# Clean previous builds
rm -f tokenshield tokenshield-linux tokenshield-darwin tokenshield-windows.exe

# Download dependencies
go mod tidy
go mod download

# Build for current platform
echo "Building for current platform..."
go build -o tokenshield .

# Build for multiple platforms
echo "Building for Linux..."
GOOS=linux GOARCH=amd64 go build -o tokenshield-linux .

echo "Building for macOS..."
GOOS=darwin GOARCH=amd64 go build -o tokenshield-darwin .

echo "Building for Windows..."
GOOS=windows GOARCH=amd64 go build -o tokenshield-windows.exe .

echo "Build complete!"
echo "Files created:"
ls -la tokenshield*

echo ""
echo "To install locally:"
echo "  sudo cp tokenshield /usr/local/bin/"
echo ""
echo "To test:"
echo "  ./tokenshield version"