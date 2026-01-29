# Security Documentation

This document outlines security practices, configuration, and considerations for VRAgent.

## Authentication & Authorization

### JWT Tokens

VRAgent uses JWT (JSON Web Tokens) for authentication:

- **Access Token**: Short-lived (30 minutes default), used for API requests
- **Refresh Token**: Longer-lived (1 day default), used to obtain new access tokens
- **Algorithm**: HS256 (HMAC-SHA256)

Token lifetimes can be configured via environment variables:
```bash
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=1
```

### Token Blacklist

Tokens can be invalidated before expiry via the `/auth/logout` endpoint. The blacklist is stored in Redis with automatic expiration.

### Password Security

- Passwords are hashed using bcrypt with automatic salting
- Minimum password requirements should be enforced at the application level

## Environment Variables

### Required Secrets

| Variable | Description | How to Generate |
|----------|-------------|-----------------|
| `SECRET_KEY` | JWT signing key | `python -c "import secrets; print(secrets.token_urlsafe(64))"` |
| `POSTGRES_PASSWORD` | Database password | `python -c "import secrets; print(secrets.token_urlsafe(24))"` |

### Optional API Keys

| Variable | Purpose | Where to Get |
|----------|---------|--------------|
| `GEMINI_API_KEY` | AI-powered analysis | https://aistudio.google.com/app/apikey |
| `NVD_API_KEY` | Enhanced CVE lookups | https://nvd.nist.gov/developers/request-an-api-key |

## Security Headers

VRAgent sets the following security headers:

| Header | Value | Purpose |
|--------|-------|---------|
| X-Frame-Options | SAMEORIGIN | Clickjacking protection |
| X-Content-Type-Options | nosniff | MIME sniffing prevention |
| Referrer-Policy | strict-origin-when-cross-origin | Referrer leakage prevention |
| Permissions-Policy | Restrictive | Disable sensitive browser APIs |
| Content-Security-Policy | Strict (API) / Standard (other) | XSS prevention |
| Strict-Transport-Security | max-age=31536000 (prod only) | Force HTTPS |
| Cross-Origin-Opener-Policy | same-origin | Process isolation |
| Cross-Origin-Resource-Policy | same-origin | Resource isolation |

## CORS Configuration

### Development (localhost)

By default, only localhost origins are allowed:
- `http://localhost:3000`
- `http://localhost:5173`
- `http://localhost:8080`
- `http://127.0.0.1:3000/5173/8080`

### LAN/Custom Origins

Set `CORS_ORIGINS` in `.env` for additional origins:
```bash
CORS_ORIGINS=http://192.168.1.100:3000,http://192.168.1.100:5173
```

### Production

Always set explicit `CORS_ORIGINS` in production:
```bash
CORS_ORIGINS=https://yourdomain.com
```

## Rate Limiting

Rate limiting is **enabled by default in production** to prevent:
- Brute force attacks
- Denial of service
- Resource exhaustion

### Limits

| Endpoint Type | Limit |
|---------------|-------|
| General (authenticated) | 100 requests/minute |
| General (unauthenticated) | 20 requests/minute |
| Scan endpoints | 5 requests/minute |
| Project endpoints | 20 requests/minute |
| Fuzzing endpoints | 5 requests/minute |

### Configuration

```bash
# Disable rate limiting (development only)
ENABLE_RATE_LIMITING=false
```

## Input Validation

### File Uploads

- Maximum file size: 2GB (configurable via `MAX_UPLOAD_SIZE`)
- MIME type validation on upload
- Files stored with UUID filenames (prevents overwrites)
- Separate directories per project

### Path Traversal Prevention

- All file paths are validated using `Path.resolve()` and `relative_to()`
- Folder names are validated with regex: `^[a-zA-Z0-9_\-/]+$`
- Path traversal patterns (`..`) are explicitly rejected

## Database Security

### SQL Injection Prevention

- All database queries use SQLAlchemy ORM with parameterized queries
- No raw SQL string interpolation

### Connection Security

- Connection pooling with automatic reconnection
- Stale connection recycling (30 minute default)
- Pool size limits to prevent resource exhaustion

## Docker Security

### Credentials

Docker service credentials must be set in `.env`:
```bash
POSTGRES_PASSWORD=<secure-password>
OPENVAS_PASSWORD=<secure-password>
GRAFANA_PASSWORD=<secure-password>
```

Docker Compose will fail to start if required passwords are not set.

### Network Isolation

- Services communicate via internal Docker network
- Only necessary ports are exposed to host
- Database ports should not be exposed in production

### Container Capabilities

Some containers require elevated capabilities for security scanning:
- `NET_RAW`: Required for nmap network scanning
- `NET_ADMIN`: Required for packet capture

These should be reviewed and minimized for production deployments.

## Vulnerability Scanning Safety

### SSRF Prevention

By default, scanning localhost and private IPs is disabled:
```bash
ALLOW_LOCALHOST_SCANS=false
ALLOW_PRIVATE_IP_SCANS=false
```

Enable only for controlled testing environments.

## Security Checklist for Production

- [ ] Generate strong `SECRET_KEY` (64+ characters)
- [ ] Set unique passwords for all services
- [ ] Configure `CORS_ORIGINS` with production domain
- [ ] Enable HTTPS with valid certificate
- [ ] Remove default Docker port exposures
- [ ] Review container capabilities
- [ ] Enable rate limiting (`ENABLE_RATE_LIMITING=true`)
- [ ] Disable localhost/private IP scanning
- [ ] Set `ENVIRONMENT=production`
- [ ] Remove `/docs` and `/redoc` endpoints (automatic in production)

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly by:
1. Not publicly disclosing the issue until it's fixed
2. Providing sufficient detail to reproduce the issue
3. Allowing reasonable time for a fix before disclosure

## Security Updates

Keep dependencies updated regularly:
```bash
# Python dependencies
pip install --upgrade -r requirements.txt
pip-audit

# Node.js dependencies
npm audit
npm update
```
