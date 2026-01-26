# VRAgent Quick Start Guide

Get started with VRAgent Binary Analyzer in under 5 minutes!

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Docker Installation (Recommended)](#docker-installation-recommended)
3. [Manual Installation](#manual-installation)
4. [First Analysis](#first-analysis)
5. [Configuration](#configuration)
6. [Next Steps](#next-steps)

---

## Prerequisites

### Minimum Requirements

- **OS:** Linux, macOS, or Windows (WSL/Git Bash)
- **RAM:** 8GB minimum, 16GB recommended
- **Disk:** 20GB free space
- **Internet:** For pulling Docker images or dependencies

### Required Software

Choose one installation method:

**Option A: Docker (Recommended)**
- Docker 20.10+
- Docker Compose 2.0+

**Option B: Manual**
- Python 3.9+
- PostgreSQL 12+
- Redis 6+

---

## Docker Installation (Recommended)

### One-Command Start

```bash
# Clone repository
git clone https://github.com/your-org/vragent.git
cd vragent

# Start VRAgent (pulls images, creates database, starts services)
docker-compose -f docker-compose.quick-start.yml up -d
```

That's it! VRAgent is now running.

### Verify Installation

```bash
# Check service health
curl http://localhost:8000/health

# Expected response:
# {
#   "status": "healthy",
#   "services": {...},
#   "resources": {...}
# }
```

### Access VRAgent

- **API:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs
- **Health Check:** http://localhost:8000/health

### Common Docker Commands

```bash
# View logs
docker-compose -f docker-compose.quick-start.yml logs -f

# Stop services
docker-compose -f docker-compose.quick-start.yml down

# Restart services
docker-compose -f docker-compose.quick-start.yml restart

# Rebuild after code changes
docker-compose -f docker-compose.quick-start.yml up -d --build
```

---

## Manual Installation

### Step 1: Run Installation Script

```bash
# Make script executable
chmod +x install.sh

# Run installer
./install.sh
```

The installer will:
1. Check prerequisites
2. Detect your OS
3. Offer Docker or manual installation
4. Install dependencies
5. Configure database
6. Run migrations
7. Verify setup

### Step 2: Start VRAgent

```bash
# Activate virtual environment
source venv/bin/activate

# Start backend
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Step 3: Verify Installation

```bash
# In another terminal
curl http://localhost:8000/health
```

---

## First Analysis

### Using the API

```bash
# Upload and analyze a binary
curl -X POST http://localhost:8000/reverse-engineering/analyze \
  -F "file=@/path/to/binary.exe" \
  -F "deep_analysis=true"
```

### Using the Terminal UI

```bash
# Activate virtual environment
source venv/bin/activate

# Run TUI
python backend/tools/binary_analyzer_tui.py
```

**TUI Features:**
- File browser for binary selection
- Three analysis modes (Standard/Deep/Exploit)
- Real-time progress display
- Beautiful formatted results
- Export to JSON/Markdown

### Using the Desktop GUI

```bash
# Activate virtual environment
source venv/bin/activate

# Run GUI
python backend/tools/binary_analyzer_gui.py
```

**GUI Features:**
- Visual file selection
- Tabbed result display
- Copy to clipboard
- Save results to file

---

## Configuration

### Environment Variables

Create `.env` file in project root (or `backend/.env`):

```bash
# Database
DATABASE_URL=postgresql://localhost/vragent

# Redis
REDIS_URL=redis://localhost:6379/0

# AI Services (Optional)
GEMINI_API_KEY=your_gemini_key_here
OPENAI_API_KEY=your_openai_key_here

# Security
SECRET_KEY=your_secret_key_here

# Ghidra (Optional - for decompilation)
GHIDRA_HOME=/path/to/ghidra_10.4

# Environment
ENVIRONMENT=development

# Resource Limits
MAX_UPLOAD_SIZE=2147483648  # 2GB
```

### Docker Configuration

Edit `docker-compose.quick-start.yml` to customize:

```yaml
environment:
  # Add your API keys
  GEMINI_API_KEY: "your_key_here"
  OPENAI_API_KEY: "your_key_here"

  # Adjust resource limits
  MAX_UPLOAD_SIZE: 5368709120  # 5GB
```

Then restart:
```bash
docker-compose -f docker-compose.quick-start.yml restart
```

### Resource Limits

Adjust resource limits in configuration:

```python
# backend/core/config.py
max_upload_size: int = 2 * 1024 * 1024 * 1024  # 2GB
max_memory_gb: float = 8.0  # 8GB per operation
max_timeout_seconds: int = 3600  # 1 hour
```

---

## Example Workflows

### 1. Quick Malware Scan

```bash
curl -X POST http://localhost:8000/reverse-engineering/analyze \
  -F "file=@suspicious.exe" \
  -F "quick_scan=true"
```

Returns: YARA matches, packer detection, basic metadata in <30 seconds.

### 2. Deep Binary Analysis

```bash
curl -X POST http://localhost:8000/reverse-engineering/analyze \
  -F "file=@target.bin" \
  -F "deep_analysis=true" \
  -F "enable_ghidra=true"
```

Returns: Full disassembly, decompilation, CFG, strings, imports, exports, anti-analysis detection.

### 3. Exploit Generation

```bash
curl -X POST http://localhost:8000/agentic-binary/request-exploit \
  -H "Content-Type: application/json" \
  -d '{
    "binary_name": "vulnerable_app",
    "vulnerability_type": "buffer_overflow",
    "offset": 256
  }'
```

Returns: Complete pwntools exploit script with ROP chains.

### 4. Android APK Analysis

```bash
curl -X POST http://localhost:8000/reverse-engineering/analyze-apk \
  -F "file=@app.apk"
```

Returns: Manifest analysis, permissions, components, native libraries, FRIDA scripts.

### 5. Fuzzing Campaign

```bash
curl -X POST http://localhost:8000/agentic-binary/start-fuzzing \
  -H "Content-Type: application/json" \
  -d '{
    "binary_path": "/path/to/target",
    "input_dir": "/path/to/seeds",
    "duration_hours": 24
  }'
```

Returns: Campaign ID for monitoring progress via WebSocket.

---

## Monitoring

### Health Checks

```bash
# Overall health
curl http://localhost:8000/health

# Readiness (for load balancers)
curl http://localhost:8000/health/ready

# Liveness (for Kubernetes)
curl http://localhost:8000/health/live

# Resource usage
curl http://localhost:8000/health/resources

# Version info
curl http://localhost:8000/health/version
```

### Logs

**Docker:**
```bash
docker-compose -f docker-compose.quick-start.yml logs -f backend
```

**Manual:**
```bash
tail -f backend/logs/vragent.log
```

---

## Troubleshooting

### Docker Issues

**Problem:** Services won't start
```bash
# Check logs
docker-compose -f docker-compose.quick-start.yml logs

# Common fix: Remove old containers
docker-compose -f docker-compose.quick-start.yml down -v
docker-compose -f docker-compose.quick-start.yml up -d
```

**Problem:** Database migration errors
```bash
# Run migrations manually
docker exec -it vragent-backend sh
cd backend && alembic upgrade head
```

### Manual Installation Issues

**Problem:** Database connection failed
```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Test connection
psql -U vragent -d vragent -c "SELECT 1"
```

**Problem:** Redis connection failed
```bash
# Check Redis is running
redis-cli ping

# Should return: PONG
```

**Problem:** Module not found
```bash
# Reinstall dependencies
pip install -r backend/requirements.txt
```

### Memory Issues

**Problem:** Out of memory errors
```bash
# Reduce resource limits
export MAX_UPLOAD_SIZE=1073741824  # 1GB
export MAX_MEMORY_GB=4.0  # 4GB
```

**Problem:** Large file upload fails
```bash
# Increase limits
export MAX_UPLOAD_SIZE=5368709120  # 5GB
```

---

## Next Steps

### 1. Explore the API

Visit the interactive API documentation:
- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

### 2. Try Advanced Features

- **Binary Fuzzing:** See `docs/FUZZING.md`
- **Exploit Synthesis:** See `docs/EXPLOITATION.md`
- **Android Analysis:** See `docs/ANDROID.md`
- **Malware Triage:** See `docs/MALWARE.md`

### 3. Integrate with Your Workflow

- **CI/CD Integration:** See `docs/CI_CD.md`
- **API Client Examples:** See `examples/`
- **WebSocket Monitoring:** See `docs/WEBSOCKET.md`

### 4. Configure AI Services

Add AI analysis capabilities:
1. Get API key from Google AI Studio or OpenAI
2. Add to `.env` file
3. Restart services
4. Enable AI analysis in API calls

### 5. Setup Ghidra (Optional)

For decompilation support:
1. Download Ghidra from https://ghidra-sre.org
2. Extract to `/opt/ghidra` or `C:\ghidra`
3. Set `GHIDRA_HOME` in `.env`
4. Restart services

### 6. Production Deployment

For production deployment:
- Use Kubernetes manifests in `k8s/`
- Setup TLS/SSL certificates
- Configure authentication
- Enable monitoring (Prometheus)
- Setup log aggregation
- Configure backups

---

## Getting Help

### Documentation

- **Full Documentation:** `docs/`
- **Troubleshooting:** `docs/TROUBLESHOOTING.md`
- **Architecture:** `docs/ARCHITECTURE.md`
- **API Reference:** http://localhost:8000/docs

### Community

- **GitHub Issues:** https://github.com/your-org/vragent/issues
- **Discussions:** https://github.com/your-org/vragent/discussions
- **Discord:** https://discord.gg/vragent

### Support

For enterprise support and custom deployments:
- **Email:** support@vragent.com
- **Website:** https://vragent.com

---

## Security

### Reporting Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Email: security@vragent.com

We'll respond within 24 hours.

### Best Practices

1. **Never commit API keys** to version control
2. **Use strong SECRET_KEY** in production
3. **Enable authentication** for production
4. **Use TLS/SSL** for all connections
5. **Keep dependencies updated** regularly
6. **Monitor resource usage** to prevent abuse
7. **Backup database** regularly

---

## License

VRAgent is licensed under [LICENSE]. See LICENSE file for details.

---

## Acknowledgments

VRAgent uses these amazing open-source projects:
- FastAPI - Web framework
- LIEF - Binary parser
- Capstone - Disassembler
- Ghidra - Decompiler
- AFL++ - Fuzzer
- YARA - Pattern matching
- PostgreSQL - Database
- Redis - Cache
- And many more!

---

**Happy Analyzing! 🔬**
