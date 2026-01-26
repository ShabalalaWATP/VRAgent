@echo off
REM Test Runner Script for VRAgent (Windows)
REM This script runs the test suite with various options

echo.
echo 🧪 VRAgent Test Suite Runner
echo ==============================
echo.

REM Check if pytest is installed
python -m pytest --version >nul 2>&1
if errorlevel 1 (
    echo ❌ pytest not found. Installing test dependencies...
    pip install pytest pytest-asyncio pytest-cov pytest-mock
)

REM Default values
set COVERAGE=0
set VERBOSE=0
set SPECIFIC_FILE=

REM Parse command line arguments
:parse_args
if "%1"=="" goto end_parse
if "%1"=="--coverage" set COVERAGE=1
if "%1"=="-c" set COVERAGE=1
if "%1"=="--verbose" set VERBOSE=1
if "%1"=="-v" set VERBOSE=1
if "%1"=="--file" (
    set SPECIFIC_FILE=%2
    shift
)
if "%1"=="-f" (
    set SPECIFIC_FILE=%2
    shift
)
if "%1"=="--help" goto show_help
if "%1"=="-h" goto show_help
shift
goto parse_args

:show_help
echo Usage: run_tests.bat [OPTIONS]
echo.
echo Options:
echo   -c, --coverage    Run with coverage report
echo   -v, --verbose     Run with verbose output
echo   -f, --file FILE   Run specific test file
echo   -h, --help        Show this help message
echo.
echo Examples:
echo   run_tests.bat                           # Run all tests
echo   run_tests.bat -v                        # Run with verbose output
echo   run_tests.bat -c                        # Run with coverage
echo   run_tests.bat -f test_binary_analysis   # Run specific file
exit /b 0

:end_parse

REM Build pytest command
set PYTEST_CMD=python -m pytest tests/

if not "%SPECIFIC_FILE%"=="" (
    set PYTEST_CMD=python -m pytest tests/test_%SPECIFIC_FILE%.py
)

if %VERBOSE%==1 (
    set PYTEST_CMD=%PYTEST_CMD% -v
)

if %COVERAGE%==1 (
    set PYTEST_CMD=%PYTEST_CMD% --cov=backend --cov-report=html --cov-report=term
    echo 📊 Running tests with coverage analysis...
) else (
    echo 🧪 Running tests...
)

echo.
echo Command: %PYTEST_CMD%
echo.

REM Run the tests
%PYTEST_CMD%

REM Check exit code
if errorlevel 1 (
    echo.
    echo ❌ Some tests failed
    exit /b 1
) else (
    echo.
    echo ✅ All tests passed!
    if %COVERAGE%==1 (
        echo 📊 Coverage report generated in htmlcov\index.html
    )
    exit /b 0
)
