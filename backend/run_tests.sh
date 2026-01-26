#!/bin/bash
# Test Runner Script for VRAgent
# This script runs the test suite with various options

echo "🧪 VRAgent Test Suite Runner"
echo "=============================="
echo ""

# Check if pytest is installed
if ! python -m pytest --version &> /dev/null; then
    echo "❌ pytest not found. Installing test dependencies..."
    pip install pytest pytest-asyncio pytest-cov pytest-mock
fi

# Parse command line arguments
COVERAGE=false
VERBOSE=false
SPECIFIC_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --coverage|-c)
            COVERAGE=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --file|-f)
            SPECIFIC_FILE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: ./run_tests.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -c, --coverage    Run with coverage report"
            echo "  -v, --verbose     Run with verbose output"
            echo "  -f, --file FILE   Run specific test file"
            echo "  -h, --help        Show this help message"
            echo ""
            echo "Examples:"
            echo "  ./run_tests.sh                           # Run all tests"
            echo "  ./run_tests.sh -v                        # Run with verbose output"
            echo "  ./run_tests.sh -c                        # Run with coverage"
            echo "  ./run_tests.sh -f test_binary_analysis   # Run specific file"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Build pytest command
PYTEST_CMD="python -m pytest tests/"

if [ -n "$SPECIFIC_FILE" ]; then
    PYTEST_CMD="python -m pytest tests/test_${SPECIFIC_FILE}.py"
fi

if [ "$VERBOSE" = true ]; then
    PYTEST_CMD="$PYTEST_CMD -v"
fi

if [ "$COVERAGE" = true ]; then
    PYTEST_CMD="$PYTEST_CMD --cov=backend --cov-report=html --cov-report=term"
    echo "📊 Running tests with coverage analysis..."
else
    echo "🧪 Running tests..."
fi

echo ""
echo "Command: $PYTEST_CMD"
echo ""

# Run the tests
$PYTEST_CMD

# Check exit code
EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ All tests passed!"
    if [ "$COVERAGE" = true ]; then
        echo "📊 Coverage report generated in htmlcov/index.html"
    fi
else
    echo "❌ Some tests failed (exit code: $EXIT_CODE)"
fi

exit $EXIT_CODE
