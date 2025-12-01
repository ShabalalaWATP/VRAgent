# AI Agent Vulnerability Research (VRAgent)

An end-to-end platform for automated security vulnerability scanning of code projects. Upload your code, run scans, and get detailed reports with AI-powered exploitability analysis.

## 🎯 Features

### Code Analysis
- **Multiple Code Sources**: Upload zip archives, folders, or clone directly from GitHub, GitLab, Bitbucket, or Azure DevOps
- **Multi-Language Support**: Comprehensive security scanning for Python, JavaScript/TypeScript, Java, Go, Ruby, Rust, PHP, C/C++, and Kotlin projects

### Security Scanners

VRAgent integrates **7 specialized security scanners** for comprehensive vulnerability detection:

| Scanner | Languages | What It Detects |
|---------|-----------|-----------------|
| **Semgrep** | 30+ languages | 30+ rulesets: OWASP Top 10, CWE Top 25, language & framework-specific |
| **ESLint Security** | JavaScript/TypeScript | XSS, eval injection, prototype pollution, regex DoS, logic errors |
| **Bandit** | Python | SQL injection, shell injection, hardcoded passwords, weak crypto (medium+ confidence) |
| **gosec** | Go | SQL injection, command injection, file path traversal, crypto issues |
| **SpotBugs + FindSecBugs** | Java/Kotlin | SQL injection, XXE, LDAP injection, weak crypto, Spring security |
| **clang-tidy** | C/C++ | Buffer overflows, format strings, insecure functions, memory safety |
| **Secret Scanner** | All files | 50+ secret types: AWS, GCP, Azure, OpenAI, Anthropic, Hugging Face, and more |

### Dependency Security
- **7 Ecosystem Support**: Parses manifests for comprehensive dependency analysis:
  - **Python**: `requirements.txt`, `Pipfile`, `pyproject.toml` (PyPI)
  - **JavaScript/Node**: `package.json`, `package-lock.json` (npm)
  - **Java/Kotlin**: `pom.xml`, `build.gradle`, `build.gradle.kts` (Maven)
  - **Go**: `go.mod`, `go.sum` (Go)
  - **Ruby**: `Gemfile`, `Gemfile.lock` (RubyGems)
  - **Rust**: `Cargo.toml`, `Cargo.lock` (crates.io)
  - **PHP**: `composer.json`, `composer.lock` (Packagist)
- **CVE Database Lookup**: Queries OSV.dev for known vulnerabilities (aggregates CVE, GHSA, and ecosystem advisories)
- **NVD Enrichment**: Full CVSS vectors, CWE mappings, and reference links from NIST
- **EPSS Prioritization**: Score vulnerabilities by real-world exploitation probability

### AI-Powered Analysis
- **Google Gemini Integration**: AI-powered code analysis and exploitability narratives
- **Dual AI Summaries**: 
  - Application overview explaining what the code does
  - Security analysis summarizing risk posture and top concerns
- **Smart Caching**: AI summaries are generated once and cached in the database - subsequent exports are instant
- **Exploit Scenario Generation**: AI-generated attack narratives with:
  - **Smart Grouping**: Findings grouped by vulnerability category (injection, XSS, crypto, etc.) to avoid repetition
  - Step-by-step attack descriptions
  - Preconditions for exploitation
  - Potential impact assessment
  - Proof-of-concept outlines
  - Recommended mitigations
  - **30+ Built-in Templates**: Pre-defined exploit templates for common vulnerability types

### Risk Scoring
- **Intelligent 0-100 Scale**: Risk scores use a weighted formula with diminishing returns:
  - Critical findings contribute up to 40 points
  - High findings contribute up to 30 points
  - Medium findings contribute up to 20 points  
  - Low findings contribute up to 10 points
- **Minimum Thresholds**: Any critical finding guarantees at least 50/100; any high finding guarantees at least 25/100
- **Realistic Scores**: A project with 28 critical and 52 high vulnerabilities scores ~88/100, not just an average

### User Interface
- **Modern Glassmorphism UI**: React-based frontend with Material UI, dark/light mode
- **Real-time Progress**: WebSocket-based live scan progress with phase indicators
- **Interactive Findings Table**: Sort by severity, type, file, or line number
- **Expandable Code Snippets**: View vulnerable code with syntax highlighting
- **Interactive Codebase Map**: Visual tree view with per-file vulnerability counts
- **Improved Exploitability Display**: Clean card-based layout with colored sections for attack narrative, impact, PoC, and mitigations

### Reports & Exports
- **Multiple Export Formats**: Generate professional reports in:
  - **Markdown**: Well-structured with tables, links, and severity breakdown
  - **PDF**: Formatted report with title page, tables, and page breaks
  - **DOCX**: Word document with proper headings and styling
- **AI Content in Exports**: All exports include:
  - AI-generated application overview
  - AI security analysis
  - Exploit scenarios with PoC outlines
  - CVSS ratings and EPSS scores
  - CWE and CVE links
- **SBOM Generation**: Software Bill of Materials in:
  - CycloneDX 1.5 format
  - SPDX 2.3 format

### Integration & Automation
- **Webhook Notifications**: Send scan results to Slack, Teams, Discord, or custom endpoints
- **Background Processing**: Asynchronous scans via Redis Queue
- **REST API**: Full API for programmatic access
- **Project Management**: Create, view, and delete projects with history

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
git clone https://github.com/ShabalalaWATP/VRAgent.git
cd VRAgent

# Copy environment template
cp .env.example .env
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
| `frontend` | 3000 | React application (nginx) - healthcheck enabled |
| `backend` | 8000 | FastAPI REST API - healthcheck enabled |
| `worker` | - | Background job processor - healthcheck enabled |
| `db` | 5432 | PostgreSQL with pgvector - healthcheck enabled |
| `redis` | 6379 | Redis for job queuing & WebSocket pub/sub - healthcheck enabled |

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
   git clone https://github.com/ShabalalaWATP/VRAgent.git
   ```

4. **Enter the project folder**
   ```powershell
   cd VRAgent
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
   - Detects hardcoded secrets (40+ secret types)
   - Runs static analysis scanners based on detected languages:
     - ESLint for JavaScript/TypeScript
     - Semgrep for all supported languages
     - Bandit for Python
     - gosec for Go
     - SpotBugs for Java/Kotlin
     - clang-tidy for C/C++
   - Parses dependencies from manifest files
   - Looks up known CVEs in OSV database
   - Enriches findings with NVD data and EPSS scores
   - Generates AI summaries and exploitability analysis
3. When complete, you'll see the scan report

#### Viewing Results

1. Click on a report to see details
2. Use the **tabs** to switch between:
   - **Findings**: Table of all vulnerabilities (click headers to sort)
   - **Codebase Map**: Visual tree of analyzed files with vulnerability counts
   - **Exploitability**: AI-generated attack scenarios with step-by-step narratives, impact analysis, PoC outlines, and mitigations
3. Click **"View Code"** on any finding to see the vulnerable code
4. Export reports as **Markdown**, **PDF**, or **Word** documents with:
   - AI-generated application overview and security analysis
   - Severity breakdown with priority ratings
   - Detailed findings tables with CVE/CWE links
   - CVSS scores and EPSS exploitation probabilities
5. Generate **SBOM** exports in CycloneDX or SPDX format

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
Remove-Item -Recurse -Force VRAgent

# (Optional) Uninstall Docker Desktop from Windows Settings > Apps
```

---

## 🐧 Complete Linux Setup Guide (Ubuntu/Debian - Beginner-Friendly)

This section walks you through setting up VRAgent on Ubuntu 22.04+ or Debian 12+ from scratch. Follow each step carefully.

**Docker is the recommended approach** because it handles all dependencies (PostgreSQL, Redis, pgvector) automatically!

---

### Step 1: Update Your System

First, let's make sure your system is up to date.

1. **Open a terminal**
   - Press `Ctrl + Alt + T` or search for "Terminal" in your applications

2. **Update package lists and upgrade existing packages**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```
   > 💡 Enter your password when prompted. You won't see characters as you type - this is normal!

---

### Step 2: Install Docker

Docker runs the application in isolated containers. We'll install Docker Engine (the command-line version).

1. **Install prerequisites**
   ```bash
   sudo apt install -y ca-certificates curl gnupg
   ```

2. **Add Docker's official GPG key**
   ```bash
   sudo install -m 0755 -d /etc/apt/keyrings
   curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
   sudo chmod a+r /etc/apt/keyrings/docker.gpg
   ```
   > 📝 **For Debian**: Replace `ubuntu` with `debian` in the URL above

3. **Add the Docker repository**
   ```bash
   echo \
     "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
     $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
     sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
   ```
   > 📝 **For Debian**: Replace `ubuntu` with `debian` in the URL above

4. **Install Docker Engine**
   ```bash
   sudo apt update
   sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   ```

5. **Add your user to the docker group** (so you don't need `sudo` for docker commands)
   ```bash
   sudo usermod -aG docker $USER
   ```

6. **Apply the group change**
   ```bash
   newgrp docker
   ```
   > ⚠️ Alternatively, log out and log back in for this to take effect permanently

7. **Verify Docker is working**
   ```bash
   docker run hello-world
   ```
   You should see "Hello from Docker!" message

---

### Step 3: Install Git

Git is used to download VRAgent's source code.

1. **Install Git**
   ```bash
   sudo apt install -y git
   ```

2. **Verify installation**
   ```bash
   git --version
   ```
   You should see something like `git version 2.40.1`

---

### Step 4: Download VRAgent

Now let's download VRAgent to your computer.

1. **Navigate to your home directory** (or wherever you want to store projects)
   ```bash
   cd ~
   ```

2. **Clone the repository**
   ```bash
   git clone https://github.com/ShabalalaWATP/VRAgent.git
   ```

3. **Enter the project directory**
   ```bash
   cd VRAgent
   ```

4. **Verify you're in the right place**
   ```bash
   ls
   ```
   You should see: `docker-compose.yml`, `README.md`, `backend/`, `frontend/`, etc.

---

### Step 5: Create the Configuration File

VRAgent needs a `.env` file for settings.

1. **Create the .env file**
   ```bash
   cat > .env << 'EOF'
   # Database connection (Docker handles this)
   DATABASE_URL=postgresql://postgres:postgres@db:5432/vragent
   REDIS_URL=redis://redis:6379/0

   # Optional: Add your Gemini API key for AI features
   # Get one free at: https://makersuite.google.com/app/apikey
   # GEMINI_API_KEY=your_key_here
   EOF
   ```

2. **Verify the file was created**
   ```bash
   cat .env
   ```

#### (Optional) Get a Free Gemini API Key for AI Features

The AI features (codebase summary, exploit analysis) are optional but recommended:

1. Go to https://makersuite.google.com/app/apikey
2. Sign in with your Google account
3. Click **"Create API key"**
4. Copy the key
5. Edit the `.env` file:
   ```bash
   nano .env
   ```
6. Uncomment the `GEMINI_API_KEY` line and paste your key
7. Press `Ctrl + O` to save, then `Ctrl + X` to exit

---

### Step 6: Start VRAgent

Now let's start all the services!

1. **Start all services**
   ```bash
   docker compose up -d
   ```
   
   **What you'll see:**
   - First time: Docker downloads images (5-10 minutes depending on internet)
   - Progress bars for each layer being downloaded
   - "Container vragent-xxx Started" messages

2. **Wait for services to be healthy** (about 30-60 seconds)
   ```bash
   docker compose ps
   ```
   
   You should see all services with "Up" or "Up (healthy)" status:
   ```
   NAME               STATUS              PORTS
   vragent-backend    Up (healthy)        0.0.0.0:8000->8000/tcp
   vragent-db         Up (healthy)        0.0.0.0:5432->5432/tcp
   vragent-frontend   Up                  0.0.0.0:3000->80/tcp
   vragent-redis      Up (healthy)        0.0.0.0:6379->6379/tcp
   vragent-worker     Up
   ```

3. **Initialize the database**
   ```bash
   docker compose exec backend alembic upgrade head
   ```
   You should see: "INFO  [alembic.runtime.migration] Running upgrade..."

---

### Step 7: Open VRAgent in Your Browser

🎉 **You're done with setup!**

Open your web browser and go to:

| What | URL |
|------|-----|
| **VRAgent App** | http://localhost:3000 |
| **API Documentation** | http://localhost:8000/docs |

---

### Common Linux Commands

Here are commands you'll use frequently:

```bash
# Start VRAgent (if stopped)
docker compose up -d

# Stop VRAgent
docker compose down

# View logs (all services)
docker compose logs

# View logs for a specific service (with live follow)
docker compose logs -f backend
docker compose logs -f worker

# Restart everything (after code changes)
docker compose down && docker compose up -d --build

# Check service status
docker compose ps

# Complete reset (deletes all data!)
docker compose down -v
docker compose up -d
docker compose exec backend alembic upgrade head

# Check disk space used by Docker
docker system df

# Clean up unused Docker resources
docker system prune -a
```

---

### Linux Troubleshooting

| Problem | Solution |
|---------|----------|
| **"permission denied" for docker** | Run `sudo usermod -aG docker $USER` then log out and back in |
| **"Cannot connect to Docker daemon"** | Run `sudo systemctl start docker` |
| **Port 3000 already in use** | Find what's using it: `sudo lsof -i :3000` and kill it, or change port in `docker-compose.yml` |
| **"No space left on device"** | Run `docker system prune -a` to clean up unused images |
| **Containers keep restarting** | Check logs: `docker compose logs backend` |
| **Database connection refused** | Wait 30 seconds for PostgreSQL to initialize |
| **Slow first startup** | Normal - Docker needs to download ~2GB of images |
| **"docker compose" not found** | You have old Docker. Try `docker-compose` (with hyphen) or reinstall Docker |

---

### Updating VRAgent on Linux

When new versions are released:

```bash
# Navigate to project directory
cd ~/VRAgent

# Pull latest code
git pull

# Rebuild and restart
docker compose down
docker compose up -d --build

# Run any new database migrations
docker compose exec backend alembic upgrade head
```

---

### Uninstalling VRAgent on Linux

To completely remove VRAgent:

```bash
# Navigate to project directory
cd ~/VRAgent

# Stop and remove all containers and data
docker compose down -v

# Remove the project folder
cd ~
rm -rf VRAgent

# (Optional) Remove Docker images to free disk space
docker image prune -a
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
cp .env.example .env
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
cp .env.example .env
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
| `DELETE` | `/projects/{id}` | Delete a project and all associated data |
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
| `GET` | `/reports/{id}/codebase/summary` | Get AI-generated codebase summaries |
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
├── .env.example             # Environment template
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
│   │   ├── bandit_service.py     # Python security scanning (Bandit)
│   │   ├── clangtidy_service.py  # C/C++ security scanning (clang-tidy)
│   │   ├── codebase_service.py   # Code extraction & parsing
│   │   ├── cve_service.py        # OSV vulnerability lookup
│   │   ├── dependency_service.py # Multi-language dependency parsing
│   │   ├── embedding_service.py  # Gemini embeddings
│   │   ├── epss_service.py       # EPSS vulnerability scoring
│   │   ├── eslint_service.py     # JavaScript/TypeScript scanning (ESLint)
│   │   ├── exploit_service.py    # AI exploitability analysis
│   │   ├── export_service.py     # Report generation (MD/PDF/DOCX)
│   │   ├── git_service.py        # Repository cloning
│   │   ├── gosec_service.py      # Go security scanning (gosec)
│   │   ├── nvd_service.py        # NVD CVE enrichment
│   │   ├── report_service.py     # Report creation
│   │   ├── sbom_service.py       # SBOM generation (CycloneDX/SPDX)
│   │   ├── scan_service.py       # Scan orchestration
│   │   ├── secret_service.py     # Secret detection
│   │   ├── semgrep_service.py    # Multi-language SAST (Semgrep)
│   │   ├── spotbugs_service.py   # Java/Kotlin scanning (SpotBugs)
│   │   └── webhook_service.py    # Webhook notifications
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
| `GEMINI_API_KEY` | Google Gemini API key for AI features | Optional |
| `GEMINI_MODEL_ID` | Gemini model to use | `gemini-2.0-flash` |
| `NVD_API_KEY` | NIST NVD API key (50 vs 5 req/30s) | Optional |
| `ENVIRONMENT` | `development`, `test`, or `production` | `development` |

### NVD API Key (Recommended)

VRAgent enriches CVEs with detailed information from the NIST National Vulnerability Database. While no API key is required, getting a free key increases your rate limit from 5 to 50 requests per 30 seconds.

1. Request a free API key at: https://nvd.nist.gov/developers/request-an-api-key
2. Add to your `.env` file: `NVD_API_KEY=your-key-here`

The NVD enrichment adds:
- Full CVSS v3/v4 vector strings and breakdowns
- CWE weakness classifications
- Reference links to advisories and patches
- Detailed vulnerability descriptions

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
  | Go | `go.mod`, `go.sum` | Go |
  | Ruby | `Gemfile`, `Gemfile.lock` | RubyGems |
  | Rust | `Cargo.toml`, `Cargo.lock` | crates.io |
  | PHP | `composer.json`, `composer.lock` | Packagist |

- **Smart Deduplication**: When both manifest and lock files exist, lock file versions are preferred for precision
- **CVE Database Lookup**: Queries OSV.dev for known vulnerabilities in dependencies (aggregates CVE, GHSA, and ecosystem-specific advisories)
- **NVD Enrichment**: Enhances CVE data with detailed information from NIST's National Vulnerability Database including full CVSS vectors, CWE mappings, and reference links
- **EPSS Prioritization**: Uses FIRST's EPSS API to score vulnerabilities by exploitation probability (chance of being exploited in next 30 days)

### Vulnerability Lookup Efficiency

VRAgent uses optimized batch APIs and caching to minimize API calls:

| Data Source | Method | Rate Limit Handling |
|-------------|--------|---------------------|
| **OSV.dev** | Batch API (100 deps/request) | 5 concurrent batches |
| **EPSS** | Batch API (100 CVEs/request) | Single request for all |
| **NVD** | Concurrent requests + caching | 3 concurrent (with key) or rate-limited |

- **24-hour caching** for NVD and EPSS responses reduces repeat lookups
- **Lock file preference** ensures precise version matching for vulnerability detection
- **Automatic deduplication** prevents redundant database queries

### Secret Detection

Scans for over 50 types of secrets including:
- **Cloud providers**: AWS, Azure, GCP, DigitalOcean, Heroku, Cloudflare, Vercel
- **AI/ML platforms**: OpenAI, Anthropic, Hugging Face
- **Code hosting**: GitHub (PAT, OAuth, fine-grained), GitLab
- **Communication**: Slack tokens & webhooks, Discord
- **Payments**: Stripe (live/test keys), Twilio
- **Backend services**: Supabase, Firebase, Datadog, Sentry
- **Package registries**: NPM, PyPI tokens
- **Infrastructure**: Private keys (RSA, DSA, EC, PGP), SSH keys
- **Databases**: MongoDB, MySQL, PostgreSQL, Redis connection strings
- **Authentication**: JWT secrets, bearer tokens, generic API keys

### Static Analysis Scanners

VRAgent runs **7 specialized security scanners** automatically based on the languages detected in your project:

#### Semgrep (Multi-Language SAST)
Deep semantic analysis with 30+ security rulesets:
- AST-aware analysis (not just regex)
- **Core rulesets**: `p/security-audit`, `p/owasp-top-ten`, `p/cwe-top-25`, `p/secrets`
- **Language-specific**: `p/python`, `p/javascript`, `p/typescript`, `p/java`, `p/go`, `p/c`, `p/php`, `p/ruby`, `p/rust`
- **Framework-specific**: `p/django`, `p/flask`, `p/react`, `p/nodejs`, `p/express`, `p/spring`
- **Vulnerability-specific**: `p/sql-injection`, `p/xss`, `p/command-injection`, `p/jwt`, `p/crypto`, `p/deserialization`
- Taint tracking for data flow analysis

#### ESLint Security (JavaScript/TypeScript)
Security-focused linting for JS/TS projects:
- Uses `@eslint/js`, `typescript-eslint`, `eslint-plugin-security`
- Detects XSS, eval injection, prototype pollution, regex DoS
- **Additional checks**: Logic errors (`eqeqeq`), prototype manipulation, unsafe patterns
- Runs automatically when `.js`, `.ts`, `.jsx`, `.tsx` files detected

#### Bandit (Python)
Python-specific security scanner:
- Detects SQL injection, shell injection, hardcoded passwords
- Weak cryptographic usage (MD5, DES, weak random)
- **Confidence filtering**: Only reports medium+ confidence findings to reduce false positives
- **Smart exclusions**: Automatically skips test directories, `.tox`, `.eggs`, `__pycache__`
- Runs automatically when `.py` files detected

#### gosec (Go)
Go security scanner:
- SQL injection, command injection, path traversal
- Crypto issues, file permissions, tainted data
- Runs automatically when `.go` files detected

#### SpotBugs + FindSecBugs (Java/Kotlin)
Enterprise Java security scanner:
- SQL injection, XXE, LDAP injection, XSS
- Weak cryptography, insecure deserialization
- Spring Security issues, CSRF vulnerabilities
- Runs automatically when `.java` or `.kt` files detected (compiles with Maven/Gradle)

#### clang-tidy (C/C++)
C/C++ security analyzer:
- Buffer overflows, format string vulnerabilities
- Use of insecure functions (`strcpy`, `sprintf`, etc.)
- Memory safety issues, null pointer dereferences
- Runs automatically when `.c`, `.cpp`, `.h`, `.hpp` files detected

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
- [Semgrep](https://semgrep.dev/) - Multi-language SAST engine
- [Bandit](https://bandit.readthedocs.io/) - Python security linter
- [gosec](https://securego.io/) - Go security checker
- [SpotBugs](https://spotbugs.github.io/) - Java static analysis
- [ESLint](https://eslint.org/) - JavaScript/TypeScript linting
