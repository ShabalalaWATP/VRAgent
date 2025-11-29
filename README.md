# AI Agent Vulnerability Research (VRAgent)

An end-to-end platform for automated security vulnerability scanning of code projects. Upload your code, run scans, and get detailed reports with AI-powered exploitability analysis.

## 🎯 Features

- **Multiple Code Sources**: Upload zip archives, folders, or clone directly from GitHub, GitLab, Bitbucket, or Azure DevOps
- **Multi-Language Support**: Scans Python, JavaScript/TypeScript, Java, Go, Ruby, Rust, PHP, and Kotlin projects
- **Dependency Vulnerability Detection**: Parses manifests for 7 ecosystems against OSV database:
  - **Python**: `requirements.txt`, `Pipfile`, `pyproject.toml` (PyPI)
  - **JavaScript/Node**: `package.json` (npm)
  - **Java/Kotlin**: `pom.xml`, `build.gradle`, `build.gradle.kts` (Maven)
  - **Go**: `go.mod` (Go)
  - **Ruby**: `Gemfile`, `Gemfile.lock` (RubyGems)
  - **Rust**: `Cargo.toml`, `Cargo.lock` (crates.io)
  - **PHP**: `composer.json`, `composer.lock` (Packagist)
- **EPSS Vulnerability Prioritization**: Integrates EPSS scores to prioritize vulnerabilities by likelihood of exploitation
- **Secret Detection**: Scans for hardcoded API keys, tokens, passwords, and credentials
- **Semgrep Security Analysis**: Deep static analysis with 2000+ security rules (optional)
- **ESLint Security Analysis**: Runs ESLint with security plugins for JavaScript/TypeScript projects
- **Static Code Analysis**: Pattern-based detection of common security issues (eval, exec, shell injection, etc.)
- **AI-Powered Analysis**: Uses Google Gemini for code embeddings and exploitability narratives
- **Interactive Codebase Map**: Visual tree view of analyzed files with per-file vulnerability counts
- **Expandable Code Snippets**: View vulnerable code directly in findings with syntax highlighting
- **Sortable Findings Table**: Sort vulnerabilities by severity, type, file, or line number
- **Report Management**: Delete reports, view detailed findings, and manage scan history
- **Report Generation**: Export reports in Markdown, PDF, or DOCX formats
- **SBOM Export**: Generate Software Bill of Materials in CycloneDX 1.5 and SPDX 2.3 formats
- **Real-time Progress**: WebSocket-based live scan progress updates via Redis pub/sub
- **Webhook Notifications**: Send scan results to Slack, Teams, Discord, or custom endpoints
- **Background Processing**: Long-running scans run asynchronously via Redis Queue
- **Modern Glassmorphism UI**: React-based frontend with Material UI, dark/light mode, and animated components

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   React + Vite  │────▶│  FastAPI Backend │────▶│   PostgreSQL    │
│    Frontend     │     │       API        │     │   + pgvector    │
└─────────────────┘     └────────┬─────────┘     └─────────────────┘
                                 │
                                 ▼
                        ┌─────────────────┐     ┌─────────────────┐
                        │      Redis      │◀───▶│   RQ Worker     │
                        │     Queue       │     │  (Background)   │
                        └─────────────────┘     └─────────────────┘
```

## 🚀 Quick Start with Docker (Recommended)

The easiest way to run VRAgent is with Docker Compose:

```bash
# Clone the repository
git clone https://github.com/your-org/vragent.git
cd vragent

# Copy environment template
cp .env.sample .env
# Edit .env with your settings (optional: add GEMINI_API_KEY for AI features)

# Start all services
docker-compose up -d

# Run database migrations
docker-compose exec backend alembic upgrade head
```

The application will be available at:
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

### Docker Services

| Service | Port | Description |
|---------|------|-------------|
| `frontend` | 3000 | React application (nginx) |
| `backend` | 8000 | FastAPI REST API |
| `worker` | - | Background job processor |
| `db` | 5432 | PostgreSQL with pgvector |
| `redis` | 6379 | Redis for job queuing & WebSocket pub/sub |

## 🪟 Complete Windows 11 Setup Guide (Beginner-Friendly)

This section walks you through setting up VRAgent on Windows 11 from scratch, assuming you have **never used Docker or Git before**. Follow each step carefully.

**Docker is the recommended approach** because it handles all dependencies (PostgreSQL, Redis, pgvector) automatically - you don't need to install anything else!

---

### Step 1: Install Docker Desktop

Docker is a tool that runs the application in isolated "containers" - think of it like a virtual machine but much lighter.

1. **Download Docker Desktop** 
   - Go to https://www.docker.com/products/docker-desktop/
   - Click the **"Download for Windows"** button
   - Save the file to your Downloads folder

2. **Run the installer**
   - Double-click `Docker Desktop Installer.exe`
   - Click **"Yes"** if Windows asks for permission
   - ✅ Make sure **"Use WSL 2 instead of Hyper-V"** is checked
   - Click **"Ok"** and wait for installation to complete

3. **Restart your computer** when prompted

4. **Start Docker Desktop**
   - After restart, Docker Desktop should start automatically
   - Look for the whale icon 🐳 in your system tray (bottom right)
   - Wait until it says **"Docker Desktop is running"** (may take 1-2 minutes)
   - You might see a tutorial - you can skip it

> 💡 **Common Issue**: If you see "WSL 2 installation is incomplete":
> 1. Click the link in the error message
> 2. Download and run the "WSL2 Linux kernel update package"
> 3. Restart Docker Desktop

---

### Step 2: Install Git

Git is a tool for downloading and managing code. We need it to download VRAgent.

1. **Download Git**
   - Go to https://git-scm.com/download/win
   - The download should start automatically
   - If not, click **"Click here to download manually"**

2. **Run the installer**
   - Double-click the downloaded file
   - Click **"Next"** through all the screens (default settings are fine)
   - Click **"Install"**
   - Click **"Finish"**

3. **Verify installation**
   - Open **PowerShell** (press `Win + X`, then click "Windows PowerShell")
   - Type `git --version` and press Enter
   - You should see something like `git version 2.43.0`

---

### Step 3: Download VRAgent

Now let's download the VRAgent code to your computer.

1. **Open PowerShell** (if not already open)
   - Press `Win + X`, then click **"Windows PowerShell"**

2. **Navigate to your Documents folder**
   ```powershell
   cd $HOME\Documents
   ```

3. **Download (clone) VRAgent**
   ```powershell
   git clone https://github.com/your-org/vragent.git
   ```
   > 📝 Replace `your-org` with the actual GitHub username/organization

4. **Enter the project folder**
   ```powershell
   cd vragent
   ```

5. **Verify you're in the right place**
   ```powershell
   dir
   ```
   You should see files like `docker-compose.yml`, `README.md`, `backend/`, `frontend/`

---

### Step 4: Create the Configuration File

VRAgent needs a `.env` file to store settings. This file tells the app how to connect to the database and (optionally) enables AI features.

1. **Create the .env file using PowerShell**
   ```powershell
   # Create the file with required settings
   @"
   # Database connection (Docker handles this)
   DATABASE_URL=postgresql://postgres:postgres@db:5432/vragent
   REDIS_URL=redis://redis:6379/0

   # Optional: Add your Gemini API key for AI features
   # Get one free at: https://makersuite.google.com/app/apikey
   # GEMINI_API_KEY=your_key_here
   "@ | Out-File -FilePath .env -Encoding utf8
   ```

2. **Verify the file was created**
   ```powershell
   Get-Content .env
   ```

#### (Optional) Get a Free Gemini API Key for AI Features

The AI features (exploit analysis) are optional but recommended. Here's how to get a free API key:

1. Go to https://makersuite.google.com/app/apikey
2. Sign in with your Google account
3. Click **"Create API key"**
4. Copy the key
5. Edit the `.env` file:
   ```powershell
   notepad .env
   ```
6. Uncomment the `GEMINI_API_KEY` line and paste your key
7. Save and close Notepad

---

### Step 5: Start VRAgent

Now let's start all the services!

1. **Make sure Docker Desktop is running**
   - Look for the whale icon 🐳 in your system tray
   - It should show "Docker Desktop is running"

2. **Start all services**
   ```powershell
   docker-compose up -d
   ```
   
   **What you'll see:**
   - First time: Docker downloads images (5-10 minutes depending on internet)
   - You'll see "Creating vragent-db ... done", "Creating vragent-redis ... done", etc.
   - Wait until you're back at the command prompt

3. **Wait for services to be ready** (about 30 seconds)
   ```powershell
   # Check that all services are running
   docker-compose ps
   ```
   You should see all services with "Up" status:
   ```
   NAME               STATUS
   vragent-backend    Up (healthy)
   vragent-db         Up (healthy)
   vragent-frontend   Up
   vragent-redis      Up (healthy)
   vragent-worker     Up
   ```

4. **Initialize the database**
   ```powershell
   docker-compose exec backend alembic upgrade head
   ```
   You should see: "INFO  [alembic.runtime.migration] Running upgrade..."

---

### Step 6: Open VRAgent in Your Browser

🎉 **You're done with setup!**

Open your web browser (Chrome, Firefox, Edge) and go to:

| What | URL |
|------|-----|
| **VRAgent App** | http://localhost:3000 |
| **API Documentation** | http://localhost:8000/docs |

---

### Step 7: How to Use VRAgent

Now that VRAgent is running, here's how to scan your first project:

#### Creating a Project

1. Open http://localhost:3000 in your browser
2. Click **"New Project"**
3. Enter a name for your project (e.g., "My Web App")
4. Optionally add a description
5. Click **"Create"**

#### Uploading Code

You have two options:

**Option A: Upload a ZIP file**
1. Click on your project
2. In the "Upload Code" tab, click **"Choose File"**
3. Select a ZIP file containing your source code
4. Click **"Upload"**

**Option B: Clone from GitHub**
1. Click on your project
2. Click the **"Clone Repo"** tab
3. Enter the repository URL (e.g., `https://github.com/username/repo`)
4. Optionally specify a branch
5. Click **"Clone"**

#### Running a Scan

1. After uploading code, click **"Start New Scan"**
2. Watch the real-time progress bar as VRAgent:
   - Extracts and parses your code
   - Detects hardcoded secrets
   - Runs static analysis (ESLint, Semgrep)
   - Parses dependencies
   - Looks up known CVEs
   - Calculates risk scores
3. When complete, you'll see the scan report

#### Viewing Results

1. Click on a report to see details
2. Use the **tabs** to switch between:
   - **Findings**: Table of all vulnerabilities (click headers to sort)
   - **Codebase Map**: Visual tree of analyzed files
   - **Exploitability**: AI-generated attack scenarios (if enabled)
3. Click **"View Code"** on any finding to see the vulnerable code
4. Export reports as Markdown, PDF, or Word documents

---

### Common PowerShell Commands

Here are commands you'll use frequently:

```powershell
# Start VRAgent (if stopped)
docker-compose up -d

# Stop VRAgent
docker-compose down

# View logs (helpful for debugging)
docker-compose logs

# View logs for a specific service
docker-compose logs backend
docker-compose logs worker

# Restart everything (after code changes)
docker-compose down
docker-compose up -d --build

# Check service status
docker-compose ps

# Complete reset (deletes all data!)
docker-compose down -v
docker-compose up -d
docker-compose exec backend alembic upgrade head
```

---

### Troubleshooting

| Problem | Solution |
|---------|----------|
| **"Docker daemon not running"** | Open Docker Desktop and wait for the whale icon to stop animating |
| **"Port 3000 already in use"** | Another app is using port 3000. Either close it or edit `docker-compose.yml` to change the port |
| **"Cannot connect to database"** | Wait 30 seconds after `docker-compose up`, then run the migration command again |
| **Containers keep restarting** | Run `docker-compose logs` to see error messages |
| **"GEMINI_API_KEY not set" warning** | This is fine - AI features are optional |
| **Scans stuck at 0%** | Check worker logs: `docker-compose logs worker` |
| **WebSocket not connecting** | Make sure Redis is healthy: `docker-compose ps` |
| **Page shows "Failed to fetch"** | Backend might not be ready. Wait 30 seconds and refresh |
| **"alembic: command not found"** | Make sure you're using `docker-compose exec backend alembic` (not just `alembic`) |

---

### Updating VRAgent

When new versions are released:

```powershell
# Pull latest code
git pull

# Rebuild and restart
docker-compose down
docker-compose up -d --build

# Run any new database migrations
docker-compose exec backend alembic upgrade head
```

---

### Uninstalling VRAgent

If you want to completely remove VRAgent:

```powershell
# Stop and remove all containers and data
docker-compose down -v

# Remove the project folder
cd ..
Remove-Item -Recurse -Force vragent

# (Optional) Uninstall Docker Desktop from Windows Settings > Apps
```

## 🛠️ Local Development Setup

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 15+ with pgvector extension
- Redis 7+

### Backend Setup

```bash
cd backend

# Create and activate virtual environment
python -m venv .venv

# Windows
.\.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create environment file
cp .env.sample .env
# Edit .env with your database and Redis URLs

# Set PYTHONPATH (Windows)
set PYTHONPATH=..

# Set PYTHONPATH (Linux/macOS)
export PYTHONPATH=..

# Run database migrations
alembic upgrade head

# Start the API server
uvicorn backend.main:app --reload --port 8000
```

### Worker Setup (separate terminal)

```bash
cd backend
# Activate virtual environment (same as above)

# Set PYTHONPATH
set PYTHONPATH=..  # Windows
export PYTHONPATH=..  # Linux/macOS

# Start the worker
python -m backend.worker
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Create environment file (optional)
cp .env.sample .env
# Edit .env if your backend is not on localhost:8000

# Start development server
npm run dev
```

The frontend will be available at http://localhost:5173

## 📖 API Reference

### Projects

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/projects` | List all projects |
| `POST` | `/projects` | Create a new project |
| `GET` | `/projects/{id}` | Get project details |
| `POST` | `/projects/{id}/upload` | Upload code archive |
| `POST` | `/projects/{id}/clone` | Clone a Git repository |
| `POST` | `/projects/{id}/scan` | Trigger a scan |
| `GET` | `/projects/{id}/reports` | List project reports |

### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/reports/{id}` | Get report details |
| `DELETE` | `/reports/{id}` | Delete a report |
| `GET` | `/reports/{id}/findings` | List report findings |
| `GET` | `/reports/{id}/findings/{fid}/snippet` | Get code snippet for finding |
| `GET` | `/reports/{id}/codebase` | Get codebase structure tree |
| `GET` | `/reports/{id}/export/markdown` | Export as Markdown |
| `GET` | `/reports/{id}/export/pdf` | Export as PDF |
| `GET` | `/reports/{id}/export/docx` | Export as DOCX |
| `GET` | `/reports/{id}/export/sbom/cyclonedx` | Export SBOM (CycloneDX) |
| `GET` | `/reports/{id}/export/sbom/spdx` | Export SBOM (SPDX) |

### Webhooks

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/projects/{id}/webhooks` | Register webhook |
| `GET` | `/projects/{id}/webhooks` | List project webhooks |
| `DELETE` | `/projects/{id}/webhooks` | Remove all webhooks |

### WebSocket

| Endpoint | Description |
|----------|-------------|
| `WS /ws/scans/{scan_run_id}` | Real-time scan progress |
| `WS /ws/projects/{project_id}` | All scans for a project |

### Exploitability

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/reports/{id}/exploitability` | Trigger AI analysis |
| `GET` | `/reports/{id}/exploitability` | Get exploit scenarios |

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |

Full interactive documentation available at `/docs` when running the backend.

## 🧪 Testing

```bash
cd backend

# Run all tests
pytest

# Run with coverage
pytest --cov=backend --cov-report=html

# Run specific test file
pytest tests/test_api.py

# Run specific test class
pytest tests/test_services/test_codebase_service.py::TestUnpackZipToTemp
```

## 📁 Project Structure

```
VRAgent/
├── docker-compose.yml       # Full stack orchestration
├── .env.sample              # Environment template
├── README.md
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── pytest.ini           # Test configuration
│   ├── alembic.ini          # Migration configuration
│   │
│   ├── core/
│   │   ├── config.py        # Settings management
│   │   ├── database.py      # Database connection
│   │   ├── exceptions.py    # Custom exceptions
│   │   └── logging.py       # Logging configuration
│   │
│   ├── models/
│   │   └── models.py        # SQLAlchemy models
│   │
│   ├── routers/
│   │   ├── projects.py      # Project endpoints
│   │   ├── scans.py         # Scan endpoints
│   │   ├── reports.py       # Report endpoints
│   │   ├── exports.py       # Export endpoints
│   │   └── exploitability.py
│   │
│   ├── services/
│   │   ├── codebase_service.py   # Code extraction & parsing
│   │   ├── cve_service.py        # OSV vulnerability lookup
│   │   ├── dependency_service.py # Multi-language dependency parsing
│   │   ├── embedding_service.py  # Gemini embeddings
│   │   ├── epss_service.py       # EPSS vulnerability scoring
│   │   ├── eslint_service.py     # ESLint security scanning
│   │   ├── exploit_service.py    # AI exploitability
│   │   ├── export_service.py     # Report generation
│   │   ├── git_service.py        # Repository cloning
│   │   ├── report_service.py     # Report creation
│   │   ├── scan_service.py       # Scan orchestration
│   │   ├── secret_service.py     # Secret detection
│   │   └── semgrep_service.py    # Semgrep static analysis
│   │
│   ├── tasks/
│   │   └── jobs.py          # Background job definitions
│   │
│   ├── migrations/
│   │   └── versions/        # Alembic migrations
│   │
│   └── tests/
│       ├── conftest.py      # Test fixtures
│       ├── test_api.py      # API tests
│       └── test_services/   # Service unit tests
│
└── frontend/
    ├── Dockerfile
    ├── nginx.conf           # Production nginx config
    ├── package.json
    │
    └── src/
        ├── App.tsx
        ├── main.tsx
        ├── api/
        │   └── client.ts    # API client
        ├── components/
        │   ├── CloneRepoForm.tsx    # Git clone interface
        │   ├── NewProjectForm.tsx   # Project creation form
        │   └── UploadCodeForm.tsx   # Zip upload form
        └── pages/
            ├── ProjectListPage.tsx
            ├── ProjectDetailPage.tsx
            └── ReportDetailPage.tsx
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `REDIS_URL` | Redis connection string | Required |
| `GEMINI_API_KEY` | Google Gemini API key | Optional |
| `GEMINI_MODEL_ID` | Gemini model to use | `gemini-pro` |
| `ENVIRONMENT` | `development`, `test`, or `production` | `development` |

### LLM Cost Optimization

VRAgent includes several features to minimize LLM API costs when scanning large codebases:

| Variable | Description | Default |
|----------|-------------|---------|
| `MAX_EMBEDDING_CHUNKS` | Max code chunks to send for embedding | `500` |
| `MAX_LLM_EXPLOIT_CALLS` | Max LLM calls for exploit analysis | `20` |
| `ENABLE_EMBEDDING_CACHE` | Cache embeddings to disk | `true` |
| `SKIP_EMBEDDINGS` | Skip embeddings entirely (free mode) | `false` |

**Cost-saving strategies:**

1. **Smart Prioritization**: Only security-relevant code is sent for embedding (auth, crypto, input handling, etc.)
2. **Disk Caching**: Identical code chunks are cached - re-scans are nearly free
3. **Pre-built Templates**: Common vulnerabilities (eval, SQL injection, XSS) use templates instead of LLM
4. **Truncation**: Code snippets are truncated to reduce token usage
5. **Batch Processing**: Multiple embeddings per API call

**Estimated costs for a 100k LOC codebase:**
| Mode | Embeddings | Exploit Analysis | Est. Cost |
|------|------------|------------------|-----------|
| Full | All chunks | All findings | ~$2-5 |
| Optimized (default) | 500 priority | 20 unique + templates | ~$0.10-0.30 |
| Free mode | None | Templates only | $0 |

To run completely free (no LLM):
```bash
SKIP_EMBEDDINGS=true GEMINI_API_KEY= docker-compose up
```

### Database Setup (Manual)

If not using Docker, you'll need to set up PostgreSQL with pgvector:

```sql
-- Create database
CREATE DATABASE vragent;

-- Connect to database
\c vragent

-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;
```

## 🔒 Security Features

### Vulnerability Detection

- **Dependency Scanning**: Parses manifests for 7 ecosystems:
  | Language | Manifest Files | Ecosystem |
  |----------|---------------|-----------|
  | Python | `requirements.txt`, `Pipfile`, `pyproject.toml` | PyPI |
  | JavaScript | `package.json` | npm |
  | Java/Kotlin | `pom.xml`, `build.gradle`, `build.gradle.kts` | Maven |
  | Go | `go.mod` | Go |
  | Ruby | `Gemfile`, `Gemfile.lock` | RubyGems |
  | Rust | `Cargo.toml`, `Cargo.lock` | crates.io |
  | PHP | `composer.json`, `composer.lock` | Packagist |

- **CVE Database Lookup**: Queries OSV.dev for known vulnerabilities in dependencies
- **EPSS Prioritization**: Uses FIRST's EPSS API to score vulnerabilities by exploitation probability

### Secret Detection

Scans for over 40 types of secrets including:
- AWS, Azure, GCP credentials
- GitHub, GitLab tokens
- Slack, Discord webhooks
- Stripe, Twilio API keys
- Private keys and certificates
- Database connection strings
- JWT secrets

### Static Analysis

- **Semgrep Integration**: Deep semantic analysis with 2000+ security rules covering OWASP Top 10 and CWE Top 25
- **Code Pattern Matching**: Detects dangerous patterns like `eval()`, `exec()`, shell injection
- **ESLint Security Plugins**: Runs `eslint-plugin-security` for JavaScript/TypeScript projects

### Semgrep (Optional but Recommended)

For enhanced static analysis, install Semgrep:

```bash
# Using pip
pip install semgrep

# Using Homebrew (macOS)
brew install semgrep
```

When installed, VRAgent automatically runs Semgrep's security audit providing:
- AST-aware semantic code analysis (not just regex)
- 2000+ community-maintained security rules
- OWASP Top 10 and CWE coverage
- Taint tracking for data flow analysis
- Support for 30+ programming languages

### Infrastructure Security

- **Path Traversal Protection**: Zip extraction validates all paths to prevent directory escape attacks
- **File Size Limits**: Per-file limit of 200MB, total archive limit of 2GB with streaming extraction
- **Intelligent File Skipping**: Automatically skips binaries, generated files, and common non-source folders
- **Structured Error Handling**: Custom exceptions prevent information leakage
- **CORS Configuration**: Restricted origins in production mode
- **Input Validation**: Pydantic schemas validate all API inputs

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [React](https://react.dev/) - UI library
- [Material UI](https://mui.com/) - React component library
- [pgvector](https://github.com/pgvector/pgvector) - Vector similarity for PostgreSQL
- [OSV](https://osv.dev/) - Open Source Vulnerability database
- [Google Gemini](https://ai.google.dev/) - AI embeddings and analysis
