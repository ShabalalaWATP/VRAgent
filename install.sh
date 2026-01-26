#!/bin/bash
set -e

# VRAgent Binary Analyzer - Installation Script
# Supports: Linux, macOS, Windows (Git Bash/WSL)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║          🔬 VRAgent Binary Analyzer - Installer 🔬           ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root (not recommended)
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}⚠️  Warning: Running as root is not recommended${NC}"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    OS="windows"
fi

echo -e "${BLUE}📍 Detected OS: $OS${NC}"
echo

# Function to check command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python() {
    if command_exists python3; then
        PYTHON_CMD="python3"
    elif command_exists python; then
        PYTHON_CMD="python"
    else
        echo -e "${RED}❌ Python not found${NC}"
        echo -e "${YELLOW}💡 Install Python 3.9+ from: https://www.python.org/downloads/${NC}"
        exit 1
    fi

    # Check version
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | grep -oP '\d+\.\d+')
    REQUIRED_VERSION="3.9"

    if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
        echo -e "${RED}❌ Python $REQUIRED_VERSION+ required (found $PYTHON_VERSION)${NC}"
        exit 1
    fi

    echo -e "${GREEN}✅ Python $PYTHON_VERSION${NC}"
}

# Function to check Docker
check_docker() {
    if command_exists docker; then
        DOCKER_VERSION=$(docker --version | grep -oP '\d+\.\d+\.\d+' | head -1)
        echo -e "${GREEN}✅ Docker $DOCKER_VERSION${NC}"
        HAS_DOCKER=true
    else
        echo -e "${YELLOW}⚠️  Docker not found (optional but recommended)${NC}"
        HAS_DOCKER=false
    fi

    if command_exists docker-compose || docker compose version >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Docker Compose${NC}"
        HAS_DOCKER_COMPOSE=true
    else
        echo -e "${YELLOW}⚠️  Docker Compose not found${NC}"
        HAS_DOCKER_COMPOSE=false
    fi
}

# Check prerequisites
echo -e "${BLUE}🔍 Checking prerequisites...${NC}"
echo

check_python
check_docker

echo

# Ask installation method
if [ "$HAS_DOCKER" = true ] && [ "$HAS_DOCKER_COMPOSE" = true ]; then
    echo -e "${BLUE}📦 Choose installation method:${NC}"
    echo "  1) Docker (Recommended - Easy setup, isolated environment)"
    echo "  2) Manual (Install dependencies locally)"
    echo
    read -p "Select option (1/2) [1]: " -n 1 -r INSTALL_METHOD
    echo
    INSTALL_METHOD=${INSTALL_METHOD:-1}
else
    echo -e "${YELLOW}⚠️  Docker not available, using manual installation${NC}"
    INSTALL_METHOD=2
fi

# Docker installation
if [ "$INSTALL_METHOD" = "1" ]; then
    echo
    echo -e "${BLUE}🐳 Docker installation selected${NC}"
    echo

    # Check if .env exists
    if [ ! -f .env ]; then
        echo -e "${YELLOW}📝 Creating .env file...${NC}"
        cat > .env << 'EOF'
# VRAgent Configuration

# AI Services (Optional - add your keys)
GEMINI_API_KEY=
OPENAI_API_KEY=

# Security
SECRET_KEY=vragent-dev-secret-change-in-production

# Ghidra (Optional - for decompilation)
# GHIDRA_HOME=/path/to/ghidra

# Environment
ENVIRONMENT=development
EOF
        echo -e "${GREEN}✅ Created .env file${NC}"
    fi

    # Start Docker Compose
    echo -e "${BLUE}🚀 Starting VRAgent with Docker Compose...${NC}"
    echo

    if command_exists docker-compose; then
        docker-compose -f docker-compose.quick-start.yml up -d
    else
        docker compose -f docker-compose.quick-start.yml up -d
    fi

    echo
    echo -e "${GREEN}✅ VRAgent is starting!${NC}"
    echo
    echo -e "${BLUE}📍 Services:${NC}"
    echo "   🌐 API:    http://localhost:8000"
    echo "   📖 Docs:   http://localhost:8000/docs"
    echo "   💚 Health: http://localhost:8000/health"
    echo
    echo -e "${YELLOW}⏳ Waiting for services to be ready (this may take 30-60 seconds)...${NC}"

    # Wait for health check
    for i in {1..60}; do
        if curl -s http://localhost:8000/health >/dev/null 2>&1; then
            echo
            echo -e "${GREEN}✨ VRAgent is ready!${NC}"
            echo
            echo -e "${BLUE}🎯 Quick commands:${NC}"
            echo "   View logs:    docker-compose -f docker-compose.quick-start.yml logs -f"
            echo "   Stop:         docker-compose -f docker-compose.quick-start.yml down"
            echo "   Restart:      docker-compose -f docker-compose.quick-start.yml restart"
            echo
            break
        fi
        sleep 1
        echo -n "."
    done

# Manual installation
elif [ "$INSTALL_METHOD" = "2" ]; then
    echo
    echo -e "${BLUE}📦 Manual installation selected${NC}"
    echo

    # Check if virtual environment should be created
    read -p "Create Python virtual environment? (Y/n): " -n 1 -r CREATE_VENV
    echo
    CREATE_VENV=${CREATE_VENV:-Y}

    if [[ $CREATE_VENV =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}🐍 Creating virtual environment...${NC}"
        $PYTHON_CMD -m venv venv

        if [ "$OS" = "windows" ]; then
            source venv/Scripts/activate
        else
            source venv/bin/activate
        fi

        echo -e "${GREEN}✅ Virtual environment activated${NC}"
    fi

    # Install Python dependencies
    echo -e "${BLUE}📦 Installing Python dependencies...${NC}"
    pip install --upgrade pip
    pip install -r backend/requirements.txt

    echo -e "${GREEN}✅ Dependencies installed${NC}"

    # Check for PostgreSQL
    echo
    echo -e "${YELLOW}⚠️  PostgreSQL Required${NC}"
    echo "   You need PostgreSQL running for VRAgent to work."
    echo
    read -p "Do you have PostgreSQL installed and running? (y/N): " -n 1 -r HAS_POSTGRES
    echo

    if [[ ! $HAS_POSTGRES =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}📖 Install PostgreSQL:${NC}"
        if [ "$OS" = "linux" ]; then
            echo "   sudo apt-get install postgresql postgresql-contrib"
        elif [ "$OS" = "macos" ]; then
            echo "   brew install postgresql@16"
        else
            echo "   Download from: https://www.postgresql.org/download/"
        fi
        echo
        echo -e "${YELLOW}After installing PostgreSQL, run this script again.${NC}"
        exit 1
    fi

    # Check for Redis
    echo
    echo -e "${YELLOW}⚠️  Redis Required${NC}"
    echo "   You need Redis running for VRAgent to work."
    echo
    read -p "Do you have Redis installed and running? (y/N): " -n 1 -r HAS_REDIS
    echo

    if [[ ! $HAS_REDIS =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}📖 Install Redis:${NC}"
        if [ "$OS" = "linux" ]; then
            echo "   sudo apt-get install redis-server"
        elif [ "$OS" = "macos" ]; then
            echo "   brew install redis"
        else
            echo "   Download from: https://redis.io/download"
        fi
        echo
        echo -e "${YELLOW}After installing Redis, run this script again.${NC}"
        exit 1
    fi

    # Create .env if not exists
    if [ ! -f backend/.env ]; then
        echo
        echo -e "${BLUE}📝 Creating configuration file...${NC}"

        read -p "PostgreSQL connection string [postgresql://localhost/vragent]: " DB_URL
        DB_URL=${DB_URL:-postgresql://localhost/vragent}

        read -p "Redis connection string [redis://localhost:6379/0]: " REDIS_URL
        REDIS_URL=${REDIS_URL:-redis://localhost:6379/0}

        cat > backend/.env << EOF
DATABASE_URL=$DB_URL
REDIS_URL=$REDIS_URL
GEMINI_API_KEY=
OPENAI_API_KEY=
SECRET_KEY=vragent-dev-secret-$(openssl rand -hex 32 2>/dev/null || echo "change-this")
ENVIRONMENT=development
EOF
        echo -e "${GREEN}✅ Configuration created${NC}"
    fi

    # Run database migrations
    echo
    echo -e "${BLUE}📦 Running database migrations...${NC}"
    cd backend
    alembic upgrade head
    cd ..
    echo -e "${GREEN}✅ Database ready${NC}"

    # Done
    echo
    echo -e "${GREEN}✨ Installation complete!${NC}"
    echo
    echo -e "${BLUE}🚀 To start VRAgent:${NC}"
    if [[ $CREATE_VENV =~ ^[Yy]$ ]]; then
        echo "   source venv/bin/activate  # Activate virtual environment"
    fi
    echo "   cd backend"
    echo "   uvicorn main:app --reload"
    echo
    echo -e "${BLUE}📍 Then visit:${NC}"
    echo "   http://localhost:8000"
    echo

fi

# Run verification
echo
read -p "Run setup verification? (Y/n): " -n 1 -r RUN_VERIFY
echo
RUN_VERIFY=${RUN_VERIFY:-Y}

if [[ $RUN_VERIFY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}🔍 Verifying installation...${NC}"
    $PYTHON_CMD verify_setup.py
fi

echo
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ Installation complete! Welcome to VRAgent! 🎉${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo
echo -e "${BLUE}📚 Next steps:${NC}"
echo "   1. Read the Quick Start guide: docs/QUICK_START.md"
echo "   2. Try the GUI: python backend/tools/binary_analyzer_tui.py"
echo "   3. Explore API docs: http://localhost:8000/docs"
echo
echo -e "${BLUE}💬 Need help?${NC}"
echo "   Troubleshooting: docs/TROUBLESHOOTING.md"
echo "   GitHub Issues: https://github.com/org/vragent/issues"
echo
