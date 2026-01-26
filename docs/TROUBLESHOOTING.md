# VRAgent Troubleshooting Guide

Common issues and solutions for VRAgent Binary Analyzer.

---

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Docker Issues](#docker-issues)
3. [Database Issues](#database-issues)
4. [Redis Issues](#redis-issues)
5. [Memory & Performance](#memory--performance)
6. [File Upload Issues](#file-upload-issues)
7. [Analysis Errors](#analysis-errors)
8. [Ghidra Issues](#ghidra-issues)
9. [AI Service Issues](#ai-service-issues)
10. [Network & API Issues](#network--api-issues)
11. [Advanced Debugging](#advanced-debugging)

---

## Installation Issues

### Error: Python version too old

**Symptom:**
```
❌ Python 3.9+ required (found 3.7)
```

**Solution:**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3.9 python3.9-venv

# macOS
brew install python@3.9

# Windows
# Download from python.org
```

---

### Error: Docker not found

**Symptom:**
```
⚠️ Docker not found (optional but recommended)
```

**Solution:**

**Linux:**
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt install docker-compose-plugin
```

**macOS:**
```bash
brew install --cask docker
```

**Windows:**
Download Docker Desktop from https://docker.com

---

### Error: Permission denied (Docker)

**Symptom:**
```
ERROR: permission denied while trying to connect to the Docker daemon socket
```

**Solution:**
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Log out and back in, or run:
newgrp docker

# Test
docker ps
```

---

### Error: Module not found

**Symptom:**
```python
ModuleNotFoundError: No module named 'fastapi'
```

**Solution:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install --upgrade pip
pip install -r backend/requirements.txt
```

---

## Docker Issues

### Error: Port already in use

**Symptom:**
```
Error: bind: address already in use
```

**Solution:**

**Check what's using the port:**
```bash
# Linux/macOS
sudo lsof -i :8000  # Backend
sudo lsof -i :5432  # PostgreSQL
sudo lsof -i :6379  # Redis

# Windows
netstat -ano | findstr :8000
```

**Stop conflicting service:**
```bash
# Kill process by PID
kill -9 <PID>

# Or change VRAgent ports in docker-compose.yml
ports:
  - "8001:8000"  # Use 8001 instead
```

---

### Error: Container exits immediately

**Symptom:**
```
vragent-backend exited with code 1
```

**Solution:**

**Check logs:**
```bash
docker-compose -f docker-compose.quick-start.yml logs backend
```

**Common causes:**

1. **Database not ready:**
```bash
# Wait for database to be healthy
docker-compose -f docker-compose.quick-start.yml ps
# Status should show "healthy"
```

2. **Migration failed:**
```bash
# Run migrations manually
docker exec -it vragent-backend sh
cd backend && alembic upgrade head
```

3. **Configuration error:**
```bash
# Check environment variables
docker exec vragent-backend env
```

---

### Error: Cannot pull images

**Symptom:**
```
Error: Get "https://registry-1.docker.io": context deadline exceeded
```

**Solution:**

**Configure Docker proxy (corporate networks):**
```bash
# Create/edit ~/.docker/config.json
{
  "proxies": {
    "default": {
      "httpProxy": "http://proxy.corp.com:8080",
      "httpsProxy": "http://proxy.corp.com:8080"
    }
  }
}
```

**Or use mirror:**
```bash
# Edit /etc/docker/daemon.json
{
  "registry-mirrors": ["https://mirror.gcr.io"]
}

sudo systemctl restart docker
```

---

### Error: Volume permission denied

**Symptom:**
```
Permission denied: '/var/lib/postgresql/data'
```

**Solution:**
```bash
# Fix volume permissions
sudo chown -R $(id -u):$(id -g) postgres_data/

# Or remove volumes and recreate
docker-compose -f docker-compose.quick-start.yml down -v
docker-compose -f docker-compose.quick-start.yml up -d
```

---

## Database Issues

### Error: Could not connect to database

**Symptom:**
```
❌ Database connection failed
💡 Solution: Check PostgreSQL is running
```

**Diagnosis:**
```bash
# Check PostgreSQL status
# Docker:
docker ps | grep postgres

# Manual:
sudo systemctl status postgresql  # Linux
brew services list | grep postgres  # macOS
```

**Solution:**

**Docker:**
```bash
# Restart database
docker-compose -f docker-compose.quick-start.yml restart postgres

# Check logs
docker logs vragent-postgres
```

**Manual:**
```bash
# Start PostgreSQL
sudo systemctl start postgresql  # Linux
brew services start postgresql@16  # macOS

# Test connection
psql -U vragent -d vragent -c "SELECT 1"
```

---

### Error: Database does not exist

**Symptom:**
```
FATAL: database "vragent" does not exist
```

**Solution:**
```bash
# Create database
# Docker:
docker exec -it vragent-postgres psql -U vragent -c "CREATE DATABASE vragent;"

# Manual:
psql -U postgres -c "CREATE DATABASE vragent;"
psql -U postgres -c "CREATE USER vragent WITH PASSWORD 'password';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE vragent TO vragent;"
```

---

### Error: Migration failed

**Symptom:**
```
ERROR: relation "projects" already exists
```

**Solution:**

**Reset database (CAUTION: Deletes all data):**
```bash
# Docker:
docker-compose -f docker-compose.quick-start.yml down -v
docker-compose -f docker-compose.quick-start.yml up -d

# Manual:
dropdb vragent
createdb vragent
cd backend && alembic upgrade head
```

**Or skip failed migration:**
```bash
# Mark migration as applied without running
cd backend
alembic stamp head
```

---

### Error: pgvector extension not available

**Symptom:**
```
ERROR: extension "vector" is not available
```

**Solution:**

**Docker:** Use `pgvector/pgvector` image (already in docker-compose.quick-start.yml)

**Manual:**
```bash
# Ubuntu/Debian
sudo apt install postgresql-16-pgvector

# macOS
brew install pgvector

# Then enable extension
psql -U vragent -d vragent -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

---

## Redis Issues

### Error: Redis connection refused

**Symptom:**
```
❌ Redis connection failed
Error: Connection refused (localhost:6379)
```

**Solution:**

**Docker:**
```bash
# Check Redis container
docker ps | grep redis

# Restart Redis
docker-compose -f docker-compose.quick-start.yml restart redis
```

**Manual:**
```bash
# Start Redis
sudo systemctl start redis  # Linux
brew services start redis   # macOS

# Test connection
redis-cli ping
# Should return: PONG
```

---

### Error: Redis out of memory

**Symptom:**
```
OOM command not allowed when used memory > 'maxmemory'
```

**Solution:**

**Increase Redis memory:**
```yaml
# docker-compose.quick-start.yml
redis:
  command: redis-server --maxmemory 2gb --maxmemory-policy allkeys-lru
```

**Or clear cache:**
```bash
# Clear all cache
curl -X DELETE http://localhost:8000/cache/osv
curl -X DELETE http://localhost:8000/cache/nvd

# Or flush all
redis-cli FLUSHALL
```

---

## Memory & Performance

### Error: Out of memory

**Symptom:**
```
❌ Memory limit exceeded: 9.50GB (limit: 8.00GB)
💡 Solution: Try analyzing a smaller file or reduce analysis scope
```

**Solutions:**

**1. Increase memory limit:**
```python
# backend/core/config.py
max_memory_gb: float = 16.0  # Increase to 16GB
```

**2. Reduce file size:**
```bash
# Only analyze main sections
curl -X POST http://localhost:8000/reverse-engineering/analyze \
  -F "file=@large.bin" \
  -F "quick_scan=true"  # Skip deep analysis
```

**3. Use streaming analysis:**
```python
# Processes file in chunks, never loads full file
from backend.core.file_validator import binary_validator

async for chunk in binary_validator.stream_file_chunks(file_path):
    # Process chunk
    ...
```

**4. Adjust Docker memory:**
```bash
# Give Docker more memory
docker update --memory=16g vragent-backend
```

---

### Error: Operation timeout

**Symptom:**
```
❌ Operation timeout: analyze_binary (timeout: 3600s)
💡 Solution: Try again or contact support if issue persists
```

**Solutions:**

**1. Increase timeout:**
```python
# backend/core/resource_limits.py
timeout_seconds: int = 7200  # 2 hours
```

**2. Use quick scan mode:**
```bash
curl -X POST http://localhost:8000/reverse-engineering/analyze \
  -F "file=@slow.bin" \
  -F "quick_scan=true"
```

**3. Disable slow analyses:**
```bash
# Skip Ghidra decompilation (slow)
curl -X POST http://localhost:8000/reverse-engineering/analyze \
  -F "file=@target.bin" \
  -F "enable_ghidra=false"
```

---

### Slow performance

**Symptoms:**
- API requests take >10 seconds
- High CPU usage
- High memory usage

**Diagnosis:**
```bash
# Check resource usage
curl http://localhost:8000/health/resources

# Check system resources
htop  # Linux/macOS
```

**Solutions:**

**1. Enable Redis caching:**
```bash
# Verify Redis is running
curl http://localhost:8000/health | jq '.services.redis'
```

**2. Add database indexes:**
```sql
-- Already included in migrations, but verify:
psql -U vragent -d vragent -c "\d+ scans"  # Check indexes
```

**3. Limit concurrent operations:**
```python
# backend/core/config.py
max_concurrent_scans: int = 5  # Reduce from 10
```

**4. Upgrade hardware:**
- More RAM (16GB+ recommended)
- SSD for database
- More CPU cores

---

## File Upload Issues

### Error: File too large

**Symptom:**
```
❌ File too large: 6.50GB (maximum: 5.00GB)
💡 Solution: Upload a smaller file or contact support for enterprise limits
```

**Solution:**

**Increase upload limit:**
```python
# backend/core/config.py
max_upload_size: int = 10 * 1024 * 1024 * 1024  # 10GB
```

**Or via environment variable:**
```bash
export MAX_UPLOAD_SIZE=10737418240  # 10GB
```

**Docker:**
```yaml
# docker-compose.quick-start.yml
environment:
  MAX_UPLOAD_SIZE: 10737418240  # 10GB
```

---

### Error: Invalid file format

**Symptom:**
```
❌ Unsupported file format: .txt
💡 Solution: Supported formats: .exe, .elf, .apk, .bin, ...
```

**Solution:**

**Check file is actually binary:**
```bash
file suspicious.txt
# If says "ELF executable", rename:
mv suspicious.txt suspicious.elf
```

**Bypass format check (advanced):**
```bash
# Force binary analysis
curl -X POST http://localhost:8000/reverse-engineering/analyze \
  -F "file=@unknown.bin" \
  -F "force_analyze=true"
```

---

### Error: Upload interrupted

**Symptom:**
```
nginx: upstream prematurely closed connection
```

**Solution:**

**Increase timeouts:**

**Nginx:**
```nginx
# /etc/nginx/sites-available/vragent
location / {
    proxy_read_timeout 300s;
    proxy_connect_timeout 300s;
    proxy_send_timeout 300s;
    client_max_body_size 10G;
}
```

**Docker:**
```yaml
# docker-compose.quick-start.yml
backend:
  deploy:
    resources:
      limits:
        memory: 16G
```

---

## Analysis Errors

### Error: Binary parsing failed

**Symptom:**
```
❌ Failed to parse binary: Invalid PE header
💡 Solution: Ensure the file is a valid PE/ELF/Mach-O binary
```

**Diagnosis:**
```bash
# Check file type
file suspicious.exe

# Check if corrupted
hexdump -C suspicious.exe | head -20
```

**Solutions:**

1. **File is packed/obfuscated:**
```bash
# Use quick scan to detect packer first
curl -X POST http://localhost:8000/reverse-engineering/analyze \
  -F "file=@packed.exe" \
  -F "quick_scan=true"

# Then manually unpack and re-analyze
```

2. **File is corrupted:**
```bash
# Try to repair
objdump -x corrupted.elf  # See what sections are readable
```

3. **Unsupported format:**
```bash
# Check if file is actually supported
file exotic.bin
# If not, may need custom parser
```

---

### Error: Decompilation failed

**Symptom:**
```
❌ Decompilation failed: Ghidra analysis error
💡 Solution: Try standard analysis mode or check if Ghidra is properly configured
```

**Solutions:**

**1. Check Ghidra installation:**
```bash
# Verify GHIDRA_HOME
echo $GHIDRA_HOME

# Test Ghidra manually
$GHIDRA_HOME/support/analyzeHeadless --help
```

**2. Use without Ghidra:**
```bash
# Disable decompilation
curl -X POST http://localhost:8000/reverse-engineering/analyze \
  -F "file=@target.bin" \
  -F "enable_ghidra=false"
```

**3. Check Ghidra logs:**
```bash
# Docker
docker exec vragent-backend cat /tmp/ghidra_*.log

# Manual
cat /tmp/ghidra_*.log
```

---

### Error: YARA scan failed

**Symptom:**
```
❌ YARA scan failed: Invalid rule syntax
💡 Solution: YARA rules may be corrupted. Contact support if issue persists.
```

**Solutions:**

**1. Validate YARA rules:**
```bash
# Test rules manually
yara-cli backend/yara_rules/malware_detection.yar test.exe
```

**2. Rebuild YARA rules:**
```bash
# Re-compile rules
cd backend/yara_rules
yara-compile malware_detection.yar malware_detection.yarc
```

**3. Check YARA version:**
```bash
yara --version
# Should be 4.0+
```

---

## Ghidra Issues

### Error: GHIDRA_HOME not set

**Symptom:**
```
⚠️ GHIDRA_HOME not configured
```

**Solution:**

**1. Download Ghidra:**
```bash
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip
unzip ghidra_10.4_PUBLIC_20230928.zip
sudo mv ghidra_10.4_PUBLIC /opt/ghidra
```

**2. Set environment variable:**
```bash
# .env file
GHIDRA_HOME=/opt/ghidra

# Or export
export GHIDRA_HOME=/opt/ghidra
```

**3. Verify:**
```bash
$GHIDRA_HOME/support/analyzeHeadless --help
```

---

### Error: Java not found (Ghidra requires Java)

**Symptom:**
```
ERROR: JAVA_HOME is not set
```

**Solution:**
```bash
# Install Java 17+
# Ubuntu/Debian
sudo apt install openjdk-17-jdk

# macOS
brew install openjdk@17

# Set JAVA_HOME
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64  # Linux
export JAVA_HOME=/opt/homebrew/opt/openjdk@17        # macOS
```

---

## AI Service Issues

### Error: AI service unavailable

**Symptom:**
```
❌ AI service error (gemini): API key not configured
💡 Solution: The AI service is temporarily unavailable. Results may be limited.
```

**Solution:**

**1. Configure API key:**
```bash
# Get key from https://ai.google.dev
# Add to .env
GEMINI_API_KEY=your_key_here
```

**2. Restart service:**
```bash
# Docker
docker-compose -f docker-compose.quick-start.yml restart backend

# Manual
# Restart uvicorn
```

**3. Verify configuration:**
```bash
curl http://localhost:8000/health | jq '.services.ai_services'
```

---

### Error: AI rate limit exceeded

**Symptom:**
```
429 Too Many Requests: Rate limit exceeded
```

**Solution:**

**1. Wait and retry:**
```bash
# Exponential backoff is automatic
# Just retry after a few minutes
```

**2. Upgrade API tier:**
- Google AI Studio: Upgrade to paid tier
- OpenAI: Increase rate limits

**3. Use caching:**
```bash
# Results are cached automatically
# Check cache stats
curl http://localhost:8000/cache/stats
```

---

## Network & API Issues

### Error: Connection refused

**Symptom:**
```
curl: (7) Failed to connect to localhost port 8000: Connection refused
```

**Solution:**

**1. Check service is running:**
```bash
# Docker
docker ps | grep vragent-backend

# Manual
ps aux | grep uvicorn
```

**2. Check correct port:**
```bash
# Default is 8000
curl http://localhost:8000/health

# If changed, use correct port
curl http://localhost:8001/health
```

**3. Check firewall:**
```bash
# Linux
sudo ufw status
sudo ufw allow 8000

# macOS
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add uvicorn
```

---

### Error: CORS blocked

**Symptom:**
```
Access to XMLHttpRequest blocked by CORS policy
```

**Solution:**

**Add allowed origin:**
```python
# backend/main.py
allowed_origins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "https://your-frontend.com",  # Add your frontend
]
```

---

### Error: 429 Rate limit exceeded

**Symptom:**
```
HTTP 429: Too many requests
```

**Solution:**

**1. Check rate limits:**
```python
# backend/core/config.py
rate_limit_requests: int = 100
rate_limit_window_seconds: int = 60
```

**2. Increase limits:**
```bash
export RATE_LIMIT_REQUESTS=1000
```

**3. Disable rate limiting (development only):**
```bash
export ENABLE_RATE_LIMITING=false
```

---

## Advanced Debugging

### Enable debug logging

**Docker:**
```yaml
# docker-compose.quick-start.yml
environment:
  LOG_LEVEL: DEBUG
```

**Manual:**
```python
# backend/core/logging.py
LOG_LEVEL = "DEBUG"
```

### Database query logging

```python
# backend/core/database.py
engine = create_engine(
    DATABASE_URL,
    echo=True,  # Enable SQL logging
)
```

### Profile slow endpoints

```python
# Add to route
from time import time

@router.post("/analyze")
async def analyze(file: UploadFile):
    start = time()

    # ... analysis code ...

    logger.info(f"Analysis took {time() - start:.2f}s")
```

### Check container resources

```bash
# Docker stats
docker stats vragent-backend

# Process info
docker exec vragent-backend ps aux
```

### Access container shell

```bash
# Docker
docker exec -it vragent-backend sh

# Then run commands
cd backend
python -c "import fastapi; print(fastapi.__version__)"
```

---

## Getting More Help

### Collect diagnostic information

```bash
# System info
uname -a
python3 --version
docker --version

# Service health
curl http://localhost:8000/health > health.json

# Logs
docker-compose -f docker-compose.quick-start.yml logs > logs.txt

# Resource usage
curl http://localhost:8000/health/resources > resources.json
```

### Report issues

Include in bug reports:
1. VRAgent version (`curl http://localhost:8000/health/version`)
2. OS and version
3. Docker version (if using Docker)
4. Complete error message
5. Steps to reproduce
6. Health check output
7. Relevant logs

### Contact support

- **GitHub Issues:** https://github.com/your-org/vragent/issues
- **Email:** support@vragent.com
- **Discord:** https://discord.gg/vragent

---

## Common Error Codes

| Code | Meaning | Solution |
|------|---------|----------|
| FILE_NOT_FOUND | File doesn't exist | Check path |
| FILE_TOO_LARGE | File exceeds limit | Increase MAX_UPLOAD_SIZE |
| INVALID_FILE_FORMAT | Unsupported format | Use supported format |
| BINARY_PARSING_ERROR | Can't parse binary | Check if file is valid |
| DECOMPILATION_ERROR | Ghidra failed | Check Ghidra config |
| YARA_SCAN_ERROR | YARA rule error | Validate rules |
| DEPENDENCY_MISSING | Tool not installed | Install dependency |
| SERVICE_UNAVAILABLE | Service down | Check service status |
| RESOURCE_LIMIT_EXCEEDED | Out of resources | Increase limits |
| TIMEOUT | Operation too slow | Increase timeout |
| AUTHENTICATION_FAILED | Bad credentials | Check auth token |
| INTERNAL_ERROR | Unexpected error | Check logs, report bug |

---

**Still stuck? We're here to help!**

Open an issue with diagnostic info and we'll get you sorted out.
