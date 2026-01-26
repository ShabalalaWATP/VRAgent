# VRAgent Architecture Documentation

Technical architecture overview for VRAgent Binary Analyzer platform.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture Diagram](#architecture-diagram)
3. [Component Architecture](#component-architecture)
4. [Data Flow](#data-flow)
5. [Database Schema](#database-schema)
6. [API Architecture](#api-architecture)
7. [Security Model](#security-model)
8. [Resource Management](#resource-management)
9. [Scalability](#scalability)
10. [Deployment](#deployment)

---

## System Overview

VRAgent is a **multi-user hosted service** for advanced binary analysis, fuzzing, and exploit development. It combines static analysis, dynamic analysis, AI-guided vulnerability research, and automated fuzzing in a unified platform.

### Key Characteristics

- **Deployment Model:** Hosted multi-tenant SaaS
- **Architecture Style:** Microservices-ready monolith
- **API Pattern:** RESTful + WebSocket
- **Database:** PostgreSQL with pgvector extension
- **Cache:** Redis for performance and pub/sub
- **Queue:** Redis-based task queue (future: Celery)
- **Storage:** File system + PostgreSQL BLOB

### Technology Stack

**Backend:**
- FastAPI (Python 3.9+)
- SQLAlchemy (async ORM)
- Alembic (migrations)
- Pydantic (validation)

**Analysis Tools:**
- LIEF (binary parsing)
- Capstone (disassembly)
- Ghidra (decompilation)
- AFL++ (fuzzing)
- YARA (pattern matching)
- Androguard (Android)
- FRIDA (instrumentation)

**AI/ML:**
- Google Gemini
- OpenAI GPT
- Local embeddings

**Infrastructure:**
- Docker + Docker Compose
- PostgreSQL 16 + pgvector
- Redis 7
- Nginx (reverse proxy)

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Frontend Layer                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │   Web UI     │  │   CLI Tool   │  │  External    │             │
│  │  (React)     │  │  (Python)    │  │  Integrations│             │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘             │
│         │                 │                  │                      │
└─────────┼─────────────────┼──────────────────┼──────────────────────┘
          │                 │                  │
          └─────────────────┴──────────────────┘
                            │
                   ┌────────▼─────────┐
                   │   Load Balancer  │
                   │   (Nginx/HAProxy)│
                   └────────┬─────────┘
                            │
┌───────────────────────────┼─────────────────────────────────────────┐
│                  API Gateway Layer                                   │
│                   ┌───────▼───────┐                                 │
│                   │  FastAPI App  │                                 │
│                   │  (main.py)    │                                 │
│                   │               │                                 │
│                   │ - CORS        │                                 │
│                   │ - Auth        │                                 │
│                   │ - Rate Limit  │                                 │
│                   │ - Health      │                                 │
│                   └───────┬───────┘                                 │
│                           │                                         │
└───────────────────────────┼─────────────────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
    ┌─────────▼──────────┐    ┌──────────▼─────────┐
    │   Router Layer     │    │  WebSocket Layer   │
    │                    │    │                    │
    │ - Auth             │    │ - Real-time        │
    │ - Projects         │    │   progress         │
    │ - Scans            │    │ - Chat             │
    │ - Reports          │    │ - Notifications    │
    │ - Binary Analysis  │    │                    │
    │ - Fuzzing          │    └──────────┬─────────┘
    │ - Android          │               │
    │ - Network          │               │
    │ - Health           │               │
    └─────────┬──────────┘               │
              │                          │
┌─────────────┼──────────────────────────┼──────────────────────────┐
│             │     Service Layer        │                          │
│             │                          │                          │
│  ┌──────────▼──────────┐  ┌───────────▼────────┐                │
│  │  Core Services      │  │  Analysis Services  │                │
│  │                     │  │                     │                │
│  │ - Auth Service      │  │ - Binary Analysis   │                │
│  │ - Project Service   │  │ - Reverse Eng       │                │
│  │ - Scan Service      │  │ - Malware Analysis  │                │
│  │ - Report Service    │  │ - Exploit Synthesis │                │
│  │ - User Service      │  │ - Crash Triage      │                │
│  │ - Cache Service     │  │ - YARA Scanning     │                │
│  │ - File Service      │  │ - Decompilation     │                │
│  │ - WebSocket Service │  │                     │                │
│  └──────────┬──────────┘  └───────────┬─────────┘                │
│             │                         │                           │
│  ┌──────────▼──────────┐  ┌───────────▼─────────┐                │
│  │  Fuzzing Services   │  │  Network Services   │                │
│  │                     │  │                     │                │
│  │ - AFL++ Integration │  │ - PCAP Analysis     │                │
│  │ - Binary Fuzzer     │  │ - DNS Recon         │                │
│  │ - Android Fuzzer    │  │ - Network Fuzzing   │                │
│  │ - Protocol Fuzzer   │  │ - MITM Workbench    │                │
│  │ - Agentic Fuzzer    │  │ - API Testing       │                │
│  │ - Crash Analysis    │  │                     │                │
│  └──────────┬──────────┘  └───────────┬─────────┘                │
│             │                         │                           │
│  ┌──────────▼──────────┐  ┌───────────▼─────────┐                │
│  │  AI Services        │  │  Android Services   │                │
│  │                     │  │                     │                │
│  │ - AI Analysis       │  │ - APK Analysis      │                │
│  │ - AI Fuzzer         │  │ - Device Manager    │                │
│  │ - Exploit Gen       │  │ - Native Fuzzer     │                │
│  │ - Vulnerability     │  │ - Intent Fuzzer     │                │
│  │   Detection         │  │ - Emulator Manager  │                │
│  │ - Code Embeddings   │  │ - FRIDA Integration │                │
│  └──────────┬──────────┘  └───────────┬─────────┘                │
│             │                         │                           │
└─────────────┼─────────────────────────┼───────────────────────────┘
              │                         │
┌─────────────┼─────────────────────────┼───────────────────────────┐
│             │    Data Layer           │                           │
│             │                         │                           │
│  ┌──────────▼──────────┐  ┌───────────▼─────────┐                │
│  │  PostgreSQL 16      │  │  Redis 7            │                │
│  │  + pgvector         │  │                     │                │
│  │                     │  │ - Cache             │                │
│  │ - Users             │  │ - Sessions          │                │
│  │ - Projects          │  │ - Pub/Sub           │                │
│  │ - Scans             │  │ - Task Queue        │                │
│  │ - Reports           │  │ - Rate Limiting     │                │
│  │ - Findings          │  │                     │                │
│  │ - Crashes           │  │                     │                │
│  │ - Binary Metadata   │  │                     │                │
│  │ - Android Data      │  │                     │                │
│  │ - Vectors           │  │                     │                │
│  └──────────┬──────────┘  └───────────┬─────────┘                │
│             │                         │                           │
└─────────────┼─────────────────────────┼───────────────────────────┘
              │                         │
┌─────────────┼─────────────────────────┼───────────────────────────┐
│             │  External Layer         │                           │
│             │                         │                           │
│  ┌──────────▼──────────┐  ┌───────────▼─────────┐                │
│  │  File Storage       │  │  External Tools     │                │
│  │                     │  │                     │                │
│  │ - Uploaded Binaries │  │ - Ghidra            │                │
│  │ - Analysis Results  │  │ - AFL++             │                │
│  │ - Crash Artifacts   │  │ - QEMU              │                │
│  │ - Fuzzing Corpus    │  │ - Android SDK       │                │
│  │ - YARA Rules        │  │ - ADB               │                │
│  │ - Project Files     │  │ - FRIDA Server      │                │
│  └─────────────────────┘  └─────────────────────┘                │
│                                                                   │
│  ┌───────────────────────────────────────────────────┐           │
│  │  External APIs                                    │           │
│  │                                                   │           │
│  │ - Google Gemini (AI analysis)                    │           │
│  │ - OpenAI GPT (AI generation)                     │           │
│  │ - OSV.dev (Vulnerability DB)                     │           │
│  │ - NVD (CVE enrichment)                           │           │
│  │ - EPSS (Exploit prediction)                      │           │
│  └───────────────────────────────────────────────────┘           │
└───────────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### 1. API Gateway Layer

**Responsibilities:**
- Request routing
- Authentication/authorization
- Rate limiting
- CORS handling
- Request validation
- Error handling
- Health monitoring

**Key Files:**
- `backend/main.py` - Application entry point
- `backend/core/config.py` - Configuration
- `backend/core/exceptions.py` - Exception handling
- `backend/core/error_handler.py` - User-friendly errors

### 2. Router Layer

**Structure:**
```
backend/routers/
├── auth.py                 # Authentication endpoints
├── projects.py             # Project management
├── scans.py                # Scan management
├── reports.py              # Report generation
├── reverse_engineering.py  # Binary analysis (43k lines)
├── binary_fuzzer.py        # Fuzzing endpoints
├── android_fuzzer.py       # Android fuzzing
├── malware_analysis.py     # Malware triage
├── agentic_binary.py       # AI-guided analysis
├── network.py              # Network analysis
├── health.py               # Health monitoring
└── ... (30+ routers)
```

**Responsibilities:**
- HTTP endpoint definition
- Request/response models (Pydantic)
- Input validation
- Dependency injection
- File upload handling
- WebSocket endpoints

### 3. Service Layer

**Core Services:**

**Auth Service** (`backend/services/auth_service.py`)
- User authentication (JWT)
- User authorization
- Session management
- Role-based access control

**Project Service** (`backend/services/project_service.py`)
- Project CRUD operations
- Project file management
- User-project associations

**Scan Service** (`backend/services/scan_service.py`)
- Scan lifecycle management
- Progress tracking
- Result aggregation

**WebSocket Service** (`backend/services/websocket_service.py`)
- Real-time progress updates
- Redis pub/sub integration
- Connection management

**Analysis Services:**

**Reverse Engineering Service** (`backend/services/reverse_engineering_service.py`)
- 43,755 lines (needs refactoring)
- Binary parsing (LIEF)
- Disassembly (Capstone)
- Decompilation (Ghidra)
- YARA scanning
- APK analysis (Androguard)
- Supports 20+ architectures

**Binary Fuzzer Service** (`backend/services/binary_fuzzer_service.py`)
- AFL++ integration
- Crash triage
- Corpus management
- Coverage tracking

**Crash Triage Service** (`backend/services/crash_triage_service.py`)
- Crash deduplication
- Exploitability assessment
- Root cause analysis
- PoC generation

**Exploit Synthesis Service** (`backend/services/exploit_synthesis_service.py`)
- ROP chain generation
- Shellcode generation
- Exploit templates
- pwntools integration

**AI Services:**

**AI Analysis Service** (`backend/services/ai_analysis_service.py`)
- Gemini/GPT integration
- Code analysis
- Vulnerability detection
- Report generation

**AI Fuzzer Service** (`backend/services/ai_fuzzer_service.py`)
- AI-guided test case generation
- Mutation strategies
- Coverage optimization

### 4. Data Layer

**Database Models** (`backend/models/models.py`):

```python
# Core entities
User
Project
Scan
Report
Finding

# Binary analysis
BinaryMetadata
BinaryFunction
BinaryImport
BinaryExport
YARARuleMatch

# Fuzzing
FuzzCampaign
FuzzCrash
CoverageData
TestCase

# Android
AndroidDevice
AndroidAPK
AndroidCrash

# Network
NetworkScan
DNSRecord
PCAPAnalysis
```

**Database Features:**
- PostgreSQL 16 with pgvector extension
- Vector similarity search for code
- JSONB for flexible metadata
- Full-text search for findings
- Partitioning for large tables (crashes, logs)

**Cache Layer** (`backend/core/cache.py`):
- Redis-based caching
- Namespace-based organization
- TTL management
- Cache invalidation
- Statistics tracking

### 5. Resource Management

**File Validator** (`backend/core/file_validator.py`):
- Streaming validation
- Format detection
- Size enforcement
- Hash calculation

**Resource Limiter** (`backend/core/resource_limits.py`):
- Memory limits (per-operation)
- Timeout enforcement
- CPU monitoring
- System-wide protection

**Error Handler** (`backend/core/error_handler.py`):
- Custom exception hierarchy
- User-friendly messages
- Solution suggestions
- Documentation links

---

## Data Flow

### Binary Analysis Flow

```
1. User uploads binary via API
   │
   ▼
2. File Validator
   - Check size (< 5GB)
   - Verify format
   - Calculate SHA256
   │
   ▼
3. Save to disk + database
   - /uploads/binaries/{sha256}
   - Insert BinaryMetadata row
   │
   ▼
4. Create Scan record
   - Status: "queued"
   - User ID, Project ID
   │
   ▼
5. Start analysis (async)
   - Resource Limiter applied
   - Progress via Redis pub/sub
   │
   ├──▶ LIEF Parser
   │    - Extract metadata
   │    - Parse sections, headers
   │    - Find imports/exports
   │    │
   ├──▶ YARA Scanner
   │    - Match against rules
   │    - Detect packers, malware
   │    │
   ├──▶ Capstone Disassembler
   │    - Disassemble functions
   │    - Build CFG
   │    - Find gadgets
   │    │
   ├──▶ Ghidra Decompiler (optional)
   │    - Decompile functions
   │    - Generate C pseudocode
   │    │
   └──▶ AI Analysis (optional)
        - Vulnerability detection
        - Behavior analysis
        - Risk scoring
   │
   ▼
6. Generate Report
   - Aggregate results
   - Calculate scores
   - Create findings
   │
   ▼
7. Update Scan record
   - Status: "completed"
   - Store results
   │
   ▼
8. Notify user
   - WebSocket event
   - Email (optional)
```

### Fuzzing Campaign Flow

```
1. User creates fuzzing campaign
   │
   ▼
2. Validate target binary
   - Check format
   - Test execution
   │
   ▼
3. Setup fuzzing environment
   - Create AFL++ config
   - Prepare corpus
   - Setup QEMU (if needed)
   │
   ▼
4. Start AFL++ instances
   - Master + N workers
   - Monitor via AFL whatsup
   │
   ▼
5. Monitor progress (real-time)
   - Parse AFL stats
   - Stream via WebSocket
   - Update database
   │
   ▼
6. Crash detection
   - AFL finds crash
   - Save crash artifact
   - Run crash triage
   │
   ├──▶ Deduplication
   │    - Stack hash
   │    - Exploitability score
   │    │
   ├──▶ Root cause analysis
   │    - GDB backtrace
   │    - Register state
   │    - Memory dump
   │    │
   └──▶ Exploit generation
        - ROP chain if exploitable
        - PoC generation
   │
   ▼
7. Generate fuzzing report
   - Coverage stats
   - Unique crashes
   - Recommendations
   │
   ▼
8. User reviews results
   - Download crashes
   - View exploits
   - Download corpus
```

### AI Analysis Flow

```
1. User requests AI analysis
   │
   ▼
2. Extract code snippets
   - Decompiled code
   - Assembly
   - Strings
   │
   ▼
3. Generate embeddings
   - Cache in Redis
   - Store vectors in pgvector
   │
   ▼
4. Vector similarity search
   - Find similar vulnerable code
   - Retrieve historical findings
   │
   ▼
5. Send to AI service
   - Gemini or GPT
   - Context window optimization
   - Rate limit handling
   │
   ▼
6. Parse AI response
   - Extract vulnerabilities
   - Generate CWE mappings
   - Calculate severity
   │
   ▼
7. Create findings
   - Link to AI analysis
   - Store confidence scores
   - Generate recommendations
   │
   ▼
8. Return to user
   - Structured response
   - Markdown report
```

---

## Database Schema

### Core Tables

**users**
```sql
id              SERIAL PRIMARY KEY
username        VARCHAR(255) UNIQUE NOT NULL
email           VARCHAR(255) UNIQUE NOT NULL
hashed_password VARCHAR(255) NOT NULL
is_active       BOOLEAN DEFAULT TRUE
is_admin        BOOLEAN DEFAULT FALSE
created_at      TIMESTAMP DEFAULT NOW()
```

**projects**
```sql
id          SERIAL PRIMARY KEY
name        VARCHAR(255) NOT NULL
description TEXT
user_id     INTEGER REFERENCES users(id)
created_at  TIMESTAMP DEFAULT NOW()
updated_at  TIMESTAMP DEFAULT NOW()
```

**scans**
```sql
id           SERIAL PRIMARY KEY
project_id   INTEGER REFERENCES projects(id)
user_id      INTEGER REFERENCES users(id)
scan_type    VARCHAR(50) NOT NULL  -- 'binary', 'android', 'network'
status       VARCHAR(50) NOT NULL  -- 'queued', 'running', 'completed'
progress     INTEGER DEFAULT 0
results      JSONB
error        TEXT
created_at   TIMESTAMP DEFAULT NOW()
completed_at TIMESTAMP
```

### Binary Analysis Tables

**binary_metadata**
```sql
id              SERIAL PRIMARY KEY
scan_id         INTEGER REFERENCES scans(id)
filename        VARCHAR(255)
sha256          VARCHAR(64) UNIQUE
file_size       BIGINT
file_type       VARCHAR(100)
architecture    VARCHAR(50)
entry_point     BIGINT
is_stripped     BOOLEAN
is_packed       BOOLEAN
compiler        VARCHAR(100)
created_at      TIMESTAMP DEFAULT NOW()
```

**binary_functions**
```sql
id            SERIAL PRIMARY KEY
binary_id     INTEGER REFERENCES binary_metadata(id)
address       BIGINT NOT NULL
name          VARCHAR(255)
size          INTEGER
is_imported   BOOLEAN DEFAULT FALSE
is_exported   BOOLEAN DEFAULT FALSE
decompiled    TEXT
risk_score    INTEGER
```

**yara_matches**
```sql
id          SERIAL PRIMARY KEY
scan_id     INTEGER REFERENCES scans(id)
rule_name   VARCHAR(255)
category    VARCHAR(100)  -- 'malware', 'packer', 'exploit'
severity    VARCHAR(50)
matched_at  TIMESTAMP DEFAULT NOW()
```

### Fuzzing Tables

**fuzz_campaigns**
```sql
id              SERIAL PRIMARY KEY
campaign_id     VARCHAR(64) UNIQUE
name            VARCHAR(255)
user_id         INTEGER REFERENCES users(id)
binary_id       INTEGER REFERENCES binary_metadata(id)
status          VARCHAR(50)
config          JSONB
stats           JSONB
started_at      TIMESTAMP
ended_at        TIMESTAMP
created_at      TIMESTAMP DEFAULT NOW()
```

**fuzz_crashes**
```sql
id              SERIAL PRIMARY KEY
campaign_id     VARCHAR(64) REFERENCES fuzz_campaigns(campaign_id)
crash_hash      VARCHAR(64)
input_hash      VARCHAR(64)
crash_type      VARCHAR(100)  -- 'segfault', 'abort', 'timeout'
exploitability  VARCHAR(50)   -- 'high', 'medium', 'low', 'none'
stack_trace     TEXT
registers       JSONB
memory_dump     BYTEA
is_unique       BOOLEAN DEFAULT TRUE
severity        INTEGER
created_at      TIMESTAMP DEFAULT NOW()
```

### Android Tables

**android_apks**
```sql
id              SERIAL PRIMARY KEY
scan_id         INTEGER REFERENCES scans(id)
package_name    VARCHAR(255)
version_name    VARCHAR(100)
version_code    INTEGER
min_sdk         INTEGER
target_sdk      INTEGER
permissions     JSONB
components      JSONB  -- activities, services, receivers, providers
native_libs     JSONB
created_at      TIMESTAMP DEFAULT NOW()
```

### Vector Storage (pgvector)

**code_embeddings**
```sql
id              SERIAL PRIMARY KEY
binary_id       INTEGER REFERENCES binary_metadata(id)
function_id     INTEGER REFERENCES binary_functions(id)
code_snippet    TEXT
embedding       VECTOR(1536)  -- pgvector type
created_at      TIMESTAMP DEFAULT NOW()

INDEX idx_embeddings_vector USING ivfflat (embedding vector_cosine_ops);
```

---

## API Architecture

### REST API Design

**Base URL:** `http://api.vragent.com/api/v1`

**Authentication:**
```
Authorization: Bearer <JWT_TOKEN>
```

**Standard Response:**
```json
{
  "success": true,
  "data": {...},
  "error": null,
  "timestamp": "2024-01-20T12:00:00Z"
}
```

**Error Response:**
```json
{
  "success": false,
  "error": {
    "code": "FILE_TOO_LARGE",
    "message": "File too large: 6.50GB (maximum: 5.00GB)",
    "solution": "Upload a smaller file or contact support",
    "docs_url": "https://docs.vragent.com/limits"
  },
  "timestamp": "2024-01-20T12:00:00Z"
}
```

### WebSocket API

**Connection:** `ws://api.vragent.com/ws/{scan_id}`

**Message Types:**
```json
// Progress update
{
  "type": "progress",
  "scan_id": "abc123",
  "progress": 45,
  "stage": "disassembly",
  "message": "Disassembling functions..."
}

// Status change
{
  "type": "status",
  "scan_id": "abc123",
  "status": "completed",
  "results_url": "/api/v1/scans/abc123"
}

// Error
{
  "type": "error",
  "scan_id": "abc123",
  "error": "Analysis failed: timeout"
}
```

### Rate Limiting

**Strategy:** Token bucket per user

**Limits:**
- API: 100 requests/minute
- WebSocket: 1000 messages/minute
- Upload: 10 files/hour

**Headers:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1234567890
```

---

## Security Model

### Authentication

**Method:** JWT (JSON Web Tokens)

**Flow:**
```
1. User logs in with username/password
2. Server validates credentials
3. Server generates JWT with claims:
   - user_id
   - username
   - roles
   - exp (expiration)
4. Client includes JWT in Authorization header
5. Server validates JWT on each request
```

**JWT Claims:**
```json
{
  "sub": "user_123",
  "username": "analyst",
  "roles": ["user", "analyst"],
  "exp": 1234567890,
  "iat": 1234567800
}
```

### Authorization

**Model:** Role-Based Access Control (RBAC)

**Roles:**
- `user` - Basic access, own projects only
- `analyst` - Advanced features, collaboration
- `admin` - Full system access, user management

**Permissions:**
```python
PERMISSIONS = {
    "user": [
        "projects:read:own",
        "projects:create",
        "scans:create",
        "scans:read:own",
    ],
    "analyst": [
        "projects:read:own",
        "projects:read:shared",
        "scans:create",
        "scans:read:own",
        "scans:read:shared",
        "fuzzing:start",
        "exploits:generate",
    ],
    "admin": [
        "*:*:*",  # All permissions
    ]
}
```

### Data Isolation

**Multi-tenancy Strategy:**
- Database-level: Row-level security via user_id
- File-level: Separate directories per user
- Cache-level: Namespace per user

**Implementation:**
```python
# All queries automatically filtered by user_id
@app.get("/scans")
def list_scans(user: User = Depends(get_current_user)):
    return db.query(Scan).filter(Scan.user_id == user.id).all()
```

### Input Validation

**Layers:**
1. **Pydantic models** - Type validation, constraints
2. **File validator** - Format, size, content validation
3. **SQL injection** - Parameterized queries (SQLAlchemy)
4. **XSS prevention** - Content Security Policy headers

### Secrets Management

**Current:** Environment variables + .env files

**Production:** HashiCorp Vault or AWS Secrets Manager

**Secrets:**
- Database credentials
- Redis URL
- JWT secret key
- AI API keys
- Encryption keys

### API Security

**Measures:**
- TLS/SSL for all connections
- CORS policy enforcement
- Rate limiting per user
- Request size limits (5GB max)
- Timeout enforcement
- SQL injection prevention (ORM)
- XSS prevention (CSP headers)
- CSRF tokens for state-changing operations

---

## Resource Management

### Memory Management

**Strategy:** Per-operation limits with graceful degradation

**Implementation:**
```python
from backend.core.resource_limits import limit_large

@limit_large  # 8GB, 1 hour
async def analyze_binary(file_path: str):
    # Protected by resource limiter
    # Raises ResourceLimitExceeded if exceeded
    ...
```

**Limits:**
- Small operations: 2GB, 5 minutes
- Medium operations: 4GB, 15 minutes
- Large operations: 8GB, 1 hour
- XLarge operations: 16GB, 2 hours

**Monitoring:**
- Real-time memory tracking
- Periodic logging
- Automatic cleanup on limit exceeded

### Disk Management

**Upload Storage:**
```
/uploads/
├── binaries/{sha256}       # Uploaded binaries
├── crashes/{campaign_id}/   # Fuzzing crashes
├── corpus/{campaign_id}/    # Fuzzing corpus
├── reports/{scan_id}/       # Generated reports
└── temp/                    # Temporary files (cleaned daily)
```

**Retention Policy:**
- User files: Unlimited (until deleted)
- Temp files: 24 hours
- Crash artifacts: 90 days
- Logs: 30 days

**Cleanup:**
```python
# Daily cron job
@scheduler.scheduled_job('cron', hour=2)
def cleanup_old_files():
    delete_files_older_than('/uploads/temp/', days=1)
    delete_files_older_than('/uploads/crashes/', days=90)
    delete_files_older_than('/logs/', days=30)
```

### Database Connection Pooling

**Configuration:**
```python
engine = create_async_engine(
    DATABASE_URL,
    pool_size=20,          # 20 connections
    max_overflow=40,       # Up to 60 total
    pool_timeout=30,       # Wait 30s for connection
    pool_recycle=3600,     # Recycle after 1 hour
)
```

### Redis Connection Management

**Pattern:** Connection pool per service

```python
redis_pool = redis.ConnectionPool.from_url(
    settings.redis_url,
    max_connections=50,
    decode_responses=True
)

redis_client = redis.Redis(connection_pool=redis_pool)
```

---

## Scalability

### Horizontal Scaling

**Current Architecture:** Stateless backend (scales easily)

**Scaling Strategy:**
```
                   ┌───────────────┐
                   │ Load Balancer │
                   └───────┬───────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
      ┌────▼────┐     ┌────▼────┐    ┌────▼────┐
      │ Backend │     │ Backend │    │ Backend │
      │ Node 1  │     │ Node 2  │    │ Node 3  │
      └────┬────┘     └────┬────┘    └────┬────┘
           │               │               │
           └───────────────┴───────────────┘
                           │
                ┌──────────┴──────────┐
                │                     │
         ┌──────▼──────┐       ┌─────▼─────┐
         │ PostgreSQL  │       │   Redis   │
         │  (Primary)  │       │ (Cluster) │
         └─────────────┘       └───────────┘
```

**Session Management:** Redis-backed (no sticky sessions needed)

**File Storage:** Shared volume or S3-compatible storage

### Database Scaling

**Read Replicas:**
```
Primary (writes) ──────┐
                       │
                       ├──▶ Replica 1 (reads)
                       │
                       └──▶ Replica 2 (reads)
```

**Partitioning:** Large tables partitioned by date
```sql
-- Partition crashes table by month
CREATE TABLE crashes_2024_01 PARTITION OF crashes
FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
```

### Caching Strategy

**Levels:**
1. **Application cache** - In-memory (5 min TTL)
2. **Redis cache** - Shared (1 hour TTL)
3. **Database** - Persistent

**Cache Keys:**
```
binary:{sha256}:metadata
scan:{scan_id}:results
user:{user_id}:projects
ai:embedding:{code_hash}
```

### Async Processing

**Current:** Inline async/await

**Future:** Celery task queue
```python
# Heavy operations moved to background
@celery.task
def run_fuzzing_campaign(campaign_id: str):
    # Long-running fuzzing
    # Updates progress via Redis pub/sub
    ...
```

---

## Deployment

### Docker Deployment (Current)

**Single Server:**
```bash
docker-compose -f docker-compose.quick-start.yml up -d
```

**Components:**
- PostgreSQL container
- Redis container
- Backend container
- (Optional) Nginx container for TLS

### Kubernetes Deployment (Future)

**Manifests:**
```yaml
# backend-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vragent-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vragent-backend
  template:
    spec:
      containers:
      - name: backend
        image: vragent/backend:latest
        resources:
          limits:
            memory: "16Gi"
            cpu: "4"
          requests:
            memory: "8Gi"
            cpu: "2"
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8000
          initialDelaySeconds: 30
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8000
          initialDelaySeconds: 10
```

### Monitoring & Observability

**Health Checks:**
- `/health` - Comprehensive health
- `/health/ready` - Readiness probe
- `/health/live` - Liveness probe
- `/health/resources` - Resource metrics

**Metrics (Future):**
- Prometheus exporter
- Grafana dashboards
- Alert rules for resource exhaustion

**Logging:**
- Structured JSON logs
- Log aggregation (ELK/Loki)
- Request ID tracking

**Tracing (Future):**
- OpenTelemetry integration
- Distributed tracing
- Performance profiling

---

## Performance Optimization

### Database Optimization

**Indexes:**
```sql
-- Query optimization
CREATE INDEX idx_scans_user_status ON scans(user_id, status);
CREATE INDEX idx_crashes_campaign ON fuzz_crashes(campaign_id);
CREATE INDEX idx_functions_binary ON binary_functions(binary_id);

-- Full-text search
CREATE INDEX idx_findings_description ON findings USING GIN(to_tsvector('english', description));

-- Vector similarity (pgvector)
CREATE INDEX idx_embeddings_vector ON code_embeddings USING ivfflat (embedding vector_cosine_ops);
```

**Query Optimization:**
- Eager loading for relationships
- Pagination for large result sets
- Query result caching
- Database connection pooling

### Caching Strategy

**What to cache:**
- Binary metadata (SHA256 lookups)
- Analysis results (1 hour)
- User sessions (Redis)
- AI embeddings (persistent)
- API responses (5 minutes)

**What NOT to cache:**
- Real-time progress updates
- Authentication checks
- File uploads
- Crash artifacts

### File Processing

**Streaming:**
- Never load full file into memory
- Process in 8KB chunks
- Use async I/O for better throughput

**Parallelization:**
- Multiple disassembly threads
- Parallel YARA rule matching
- Concurrent function analysis

---

## Future Architecture

### Microservices Migration

**Candidate Services:**
1. **Analysis Service** - Binary/malware analysis
2. **Fuzzing Service** - AFL++ orchestration
3. **Android Service** - APK/device management
4. **AI Service** - AI/ML operations
5. **Report Service** - Report generation

**Benefits:**
- Independent scaling
- Technology diversity
- Fault isolation
- Easier deployment

### Event-Driven Architecture

**Event Bus:** Kafka or RabbitMQ

**Events:**
- `BinaryUploaded`
- `ScanStarted`
- `ScanCompleted`
- `CrashFound`
- `ExploitGenerated`

**Consumers:**
- Notification service
- Analytics service
- Audit logging service

---

## Conclusion

VRAgent's architecture balances **simplicity** with **scalability**. The current monolithic design is appropriate for the initial deployment but is structured to evolve into microservices as demand grows.

**Key Strengths:**
- ✅ Stateless backend (easy horizontal scaling)
- ✅ Resource management (prevents abuse)
- ✅ Comprehensive monitoring (health checks)
- ✅ Security model (RBAC, isolation)
- ✅ Modern stack (FastAPI, async, PostgreSQL)

**Areas for Improvement:**
- 🔄 Split 43k line file into modules
- 🔄 Add comprehensive test coverage
- 🔄 Implement Celery for background tasks
- 🔄 Add Prometheus metrics
- 🔄 Migrate to microservices (future)

For technical questions, see:
- **Troubleshooting:** `docs/TROUBLESHOOTING.md`
- **Quick Start:** `docs/QUICK_START.md`
- **API Docs:** http://localhost:8000/docs
