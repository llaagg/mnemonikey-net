#!/bin/bash

# Script to download and set up the Go mnemonikey binary for compatibility testing

set -e

# Configuration
REPO_URL="https://github.com/kklash/mnemonikey.git"
GO_VERSION="1.20"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ARTIFACTS_DIR="$PROJECT_ROOT/artifacts"
GO_BINARY_DIR="$ARTIFACTS_DIR/go-binary"
GO_SOURCE_DIR="$ARTIFACTS_DIR/go-source"

echo "Setting up Go mnemonikey binary for compatibility testing..."

# Create directories
mkdir -p "$ARTIFACTS_DIR"
mkdir -p "$GO_BINARY_DIR" 
mkdir -p "$GO_SOURCE_DIR"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go $GO_VERSION or later."
    echo "Visit https://golang.org/dl/ to download Go."
    exit 1
fi

# Check Go version
GO_VERSION_INSTALLED=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | sed 's/go//')
echo "Go version installed: $GO_VERSION_INSTALLED"

# Clone the original mnemonikey repository if not already cloned
if [ ! -d "$GO_SOURCE_DIR/mnemonikey" ]; then
    echo "Cloning mnemonikey repository..."
    git clone "$REPO_URL" "$GO_SOURCE_DIR/mnemonikey"
else
    echo "Updating mnemonikey repository..."
    cd "$GO_SOURCE_DIR/mnemonikey"
    git pull origin main
fi

cd "$GO_SOURCE_DIR/mnemonikey"

# Download dependencies
echo "Downloading Go dependencies..."
go mod download
go mod vendor

# Build the binary
echo "Building mnemonikey binary..."
CGO_ENABLED=0 go build -o "$GO_BINARY_DIR/mnemonikey" ./cmd/mnemonikey

# Make it executable
chmod +x "$GO_BINARY_DIR/mnemonikey"

# Verify the binary works
echo "Verifying binary..."
if "$GO_BINARY_DIR/mnemonikey" --help > /dev/null 2>&1; then
    echo "Go mnemonikey binary is ready at: $GO_BINARY_DIR/mnemonikey"
else
    echo "Binary verification failed"
    exit 1
fi

# Create a version info file
"$GO_BINARY_DIR/mnemonikey" --version > "$GO_BINARY_DIR/version.txt" 2>&1 || echo "Version command not available" > "$GO_BINARY_DIR/version.txt"

# Create test vectors directory structure
mkdir -p "$ARTIFACTS_DIR/test-vectors"
mkdir -p "$ARTIFACTS_DIR/compatibility-results"
mkdir -p "$ARTIFACTS_DIR/performance-benchmarks"

# Generate some basic test vectors for development
echo "Generating basic test vectors..."
cat > "$ARTIFACTS_DIR/test-vectors/basic-vectors.json" << 'EOF'
{
  "version": "1.0.0",
  "description": "Basic test vectors for mnemonikey compatibility testing",
  "vectors": [
    {
      "name": "Basic test case",
      "seed": "0123456789abcdef0123456789abcdef01234567",
      "creationTime": "2023-06-15T12:30:45Z",
      "userName": "Test User",
      "userEmail": "test@example.com",
      "ttl": null,
      "expectedPhraseLength": 14,
      "notes": "Standard test case for basic functionality"
    },
    {
      "name": "With TTL",
      "seed": "fedcba9876543210fedcba9876543210ba987654",
      "creationTime": "2023-07-01T00:00:00Z",
      "userName": "TTL User",
      "userEmail": "ttl@example.com", 
      "ttl": "2y",
      "expectedPhraseLength": 14,
      "notes": "Test case with 2-year TTL"
    },
    {
      "name": "Minimal case",
      "seed": "0000000000000000000000000000000000000001",
      "creationTime": "2023-01-01T00:00:01Z",
      "userName": null,
      "userEmail": null,
      "ttl": null,
      "expectedPhraseLength": 14,
      "notes": "Minimal test case with edge values"
    }
  ]
}
EOF

echo ""
echo "Setup complete!"
echo ""
echo "Artifacts directory structure:"
echo "  $ARTIFACTS_DIR/"
echo "  ├── go-binary/"
echo "  │   ├── mnemonikey          # The Go binary for testing"
echo "  │   └── version.txt         # Version information"
echo "  ├── go-source/"
echo "  │   └── mnemonikey/         # Go source code"
echo "  ├── test-vectors/"
echo "  │   └── basic-vectors.json  # Basic test vectors"
echo "  ├── compatibility-results/  # For storing test results"
echo "  └── performance-benchmarks/ # For performance comparisons"
echo ""
echo "To run compatibility tests:"
echo "  cd $PROJECT_ROOT"
echo "  dotnet test --filter Category=GoCompatibility"
echo ""
echo "Note: The artifacts/ directory is gitignored to avoid committing binaries and test data."