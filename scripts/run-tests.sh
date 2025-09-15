#!/bin/bash

# Script to run different categories of tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "MnemonikeyCs Test Runner"
echo "=========================="

# Function to run tests with specific filter
run_tests() {
    local filter="$1"
    local description="$2"
    
    echo ""
    echo "Running $description..."
    echo "Filter: $filter"
    
    cd "$PROJECT_ROOT"
    dotnet test --configuration Release --verbosity normal --filter "$filter"
}

# Function to check if Go binary is available
check_go_binary() {
    local go_binary="$PROJECT_ROOT/artifacts/go-binary/mnemonikey"
    
    if [ -x "$go_binary" ]; then
        echo "✅ Go binary available: $go_binary"
        return 0
    else
        echo "❌ Go binary not found: $go_binary"
        echo "Run 'scripts/setup-go-binary.sh' to set up the Go binary."
        return 1
    fi
}

# Default is to run all tests
TEST_CATEGORY="${1:-all}"

case "$TEST_CATEGORY" in
    "unit")
        run_tests "Category!=Integration&Category!=GoCompatibility" "Unit Tests"
        ;;
    
    "integration")
        run_tests "Category=Integration" "Integration Tests"
        ;;
    
    "go-compat")
        if check_go_binary; then
            run_tests "Category=GoCompatibility" "Go Compatibility Tests"
        else
            echo "Skipping Go compatibility tests - binary not available"
            exit 1
        fi
        ;;
    
    "fast")
        run_tests "Category!=Integration&Category!=GoCompatibility&Category!=Performance" "Fast Tests"
        ;;
    
    "all")
        echo "Running all test categories..."
        
        # Unit tests
        run_tests "Category!=Integration&Category!=GoCompatibility" "Unit Tests"
        
        # Integration tests  
        run_tests "Category=Integration&Category!=GoCompatibility" "Integration Tests (no Go)"
        
        # Go compatibility tests (if available)
        if check_go_binary; then
            run_tests "Category=GoCompatibility" "Go Compatibility Tests"
        else
            echo "⚠️  Skipping Go compatibility tests - binary not available"
            echo "   Run 'scripts/setup-go-binary.sh' to enable Go compatibility testing"
        fi
        ;;
    
    "coverage")
        echo "Running tests with coverage..."
        cd "$PROJECT_ROOT"
        dotnet test --configuration Release \
                   --collect:"XPlat Code Coverage" \
                   --settings coverlet.runsettings \
                   --filter "Category!=GoCompatibility"
        
        # Generate coverage report if reportgenerator is available
        if command -v reportgenerator &> /dev/null; then
            echo "Generating coverage report..."
            reportgenerator \
                -reports:"**/coverage.cobertura.xml" \
                -targetdir:"coverage-report" \
                -reporttypes:"Html;TextSummary"
            echo "Coverage report generated: coverage-report/index.html"
        else
            echo "Install 'dotnet tool install -g dotnet-reportgenerator-globaltool' for HTML coverage reports"
        fi
        ;;
    
    "help"|"-h"|"--help")
        echo "Usage: $0 [CATEGORY]"
        echo ""
        echo "Categories:"
        echo "  unit       - Run unit tests only"
        echo "  integration- Run integration tests (no Go required)"
        echo "  go-compat  - Run Go compatibility tests (requires Go binary)"
        echo "  fast       - Run fast tests (excludes slow integration/performance tests)"
        echo "  all        - Run all tests (default)"
        echo "  coverage   - Run tests with code coverage"
        echo "  help       - Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0                 # Run all tests"
        echo "  $0 unit            # Run only unit tests"
        echo "  $0 go-compat       # Run Go compatibility tests"
        echo "  $0 coverage        # Run with coverage reporting"
        ;;
    
    *)
        echo "Unknown test category: $TEST_CATEGORY"
        echo "Run '$0 help' for available options."
        exit 1
        ;;
esac

echo ""
echo "✅ Test run completed!"