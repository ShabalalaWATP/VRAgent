# AI Agent Vulnerability Research (VRAgent)

An end-to-end platform for automated security vulnerability scanning and analysis. VRAgent provides:
- **Code Security Scanning**: Upload code or clone repositories for comprehensive vulnerability detection with 10+ specialized scanners
- **Network Security Analysis**: Run Nmap scans and analyze PCAP files with AI-powered insights
- **AI-Powered Reports**: Google Gemini generates detailed exploitability narratives, attack scenarios, and remediation guidance
- **Interactive Learning Hub**: Educational content covering security fundamentals, attack frameworks, and pentesting methodologies

## 🎯 Features

### Code Analysis
- **Multiple Code Sources**: Upload zip archives, folders, or clone directly from GitHub, GitLab, Bitbucket, or Azure DevOps
- **Multi-Language Support**: Comprehensive security scanning for Python, JavaScript/TypeScript, Java, Go, Ruby, Rust, PHP, C/C++, and Kotlin projects

### Security Scanners

VRAgent integrates **10+ specialized security scanners** for comprehensive vulnerability detection:

| Scanner | Languages | What It Detects |
|---------|-----------|-----------------|
| **Semgrep** | 30+ languages | 30+ rulesets: OWASP Top 10, CWE Top 25, language & framework-specific |
| **ESLint Security** | JavaScript/TypeScript | XSS, eval injection, prototype pollution, regex DoS, logic errors |
| **Bandit** | Python | SQL injection, shell injection, hardcoded passwords, weak crypto (medium+ confidence) |
| **gosec** | Go | SQL injection, command injection, file path traversal, crypto issues |
| **SpotBugs + FindSecBugs** | Java/Kotlin | SQL injection, XXE, LDAP injection, weak crypto, Spring security |
| **clang-tidy** | C/C++ | Buffer overflows, format strings, insecure functions, memory safety |
| **Secret Scanner** | All files | 50+ secret types: AWS, GCP, Azure, OpenAI, Anthropic, Hugging Face, and more |
| **Docker Scanner** | Dockerfiles, Images | Dockerfile misconfigurations, image vulnerabilities via Trivy/Grype |
| **IaC Scanner** | Terraform, K8s, CloudFormation | Infrastructure security issues, misconfigurations, compliance violations |

### Docker & Container Security
- **Dockerfile Scanning**: 15+ security rules including:
  - Running as root detection (DS001)
  - Hardcoded secrets in ENV/ARG (DS002)
  - Missing HEALTHCHECK (DS004)
  - Using `latest` tag (DS006)
  - Exposing sensitive ports (DS007)
  - ADD vs COPY misuse (DS013)
  - Privileged operations (DS014)
- **Container Image Scanning**: Integration with Trivy/Grype for CVE detection in base images
- **Docker Compose Analysis**: Parses docker-compose.yml for security issues

### Infrastructure as Code (IaC) Security
- **Multi-Framework Support**:
  - **Terraform**: HCL configuration scanning
  - **Kubernetes**: YAML manifest analysis
  - **CloudFormation**: AWS template scanning
  - **ARM Templates**: Azure resource templates
- **40+ Built-in Rules**: Including:
  - Unencrypted storage (IAC001)
  - Public access enabled (IAC002)
  - Missing logging/monitoring (IAC003)
  - Overly permissive IAM (IAC004)
  - Hardcoded credentials (IAC005)
  - Missing network policies (IAC009)
  - Privileged containers (IAC013)
- **Tool Integration**: Checkov and tfsec for comprehensive analysis

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
- **Transitive Dependency Analysis**: Builds complete dependency trees to find vulnerabilities in indirect dependencies
- **Reachability Analysis**: Determines if vulnerable code paths are actually reachable from your application
- **CISA KEV Integration**: Flags vulnerabilities in CISA's Known Exploited Vulnerabilities catalog

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

### Performance Optimizations
- **Redis Caching**: External API responses (OSV, NVD, EPSS) are cached in Redis to reduce latency and API load
  - OSV CVE lookups: 24-hour cache
  - NVD enrichment data: 24-hour cache  
  - EPSS scores: 12-hour cache
  - Common dependencies (lodash, requests, express) are often already cached
- **Embedding Reuse**: Repeat scans skip embedding generation for unchanged code chunks
  - Code chunks are fingerprinted by file path, line range, and content hash
  - Only new or modified code gets sent for embedding
  - Dramatically reduces AI API costs on incremental scans
- **Parallel Phase Execution**: Major scan phases run concurrently for 2-3x faster scans
  - SAST scanners, Docker scanning, IaC scanning, and dependency analysis run in parallel
  - Thread-safe progress tracking with ParallelPhaseTracker
  - Automatic result aggregation from all parallel phases
- **Smart Scanner Deduplication**: Cross-scanner finding deduplication
  - Merges duplicate findings from different scanners (e.g., Semgrep + Bandit)
  - Location-based and content-based matching
  - Preserves highest severity and combines metadata
- **Cache Management API**: Endpoints to view stats and clear caches
  - `GET /cache/stats`: View hit rates, memory usage, keys by namespace
  - `DELETE /cache/{namespace}`: Clear specific cache (osv, nvd, epss, embedding)

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
  - **Breadcrumb Navigation**: Quick navigation through folder hierarchy
  - **Dual Search Modes**: Search by file name or search code content across all files
  - **Syntax Highlighting**: Prism.js-powered code preview with language detection
  - **Jump to Finding**: Click finding badges to scroll directly to vulnerable lines
  - **File Diff View**: Compare file changes between scan versions
  - **Copy Code Button**: One-click copy with visual confirmation
  - **Heatmap Overlay**: Toggle finding density visualization on treemap
  - **Finding Trends Sparkline**: Mini chart showing finding history per file
  - **TODO/FIXME Scanner**: Detects code comment markers (TODO, FIXME, HACK, XXX, BUG)
  - **AI Code Explanation**: Gemini-powered explanations of what code files do
- **Improved Exploitability Display**: Clean card-based layout with colored sections for attack narrative, impact, PoC, and mitigations

### Learning Hub
VRAgent includes a comprehensive **Security Learning Hub** with educational content for security professionals:

| Topic | Description |
|-------|-------------|
| **How Scanning Works** | The 9-step pipeline VRAgent uses to analyze code |
| **AI Analysis Explained** | How Gemini AI transforms findings into intelligence |
| **VRAgent Architecture** | Docker services, data models, and system design |
| **Cyber Kill Chain** | Lockheed Martin's 7-phase attack framework |
| **MITRE ATT&CK** | Adversary tactics and techniques (14 tactics, 200+ techniques) |
| **OWASP Top 10** | The 10 most critical web application security risks |
| **OWASP Mobile Top 10** | Mobile application security risks |
| **CVE, CWE & CVSS** | Vulnerability identification and scoring systems |
| **Pentest Methodology** | Step-by-step penetration testing guide |
| **Mobile Pentesting** | iOS and Android security testing |
| **API Security** | Securing REST, GraphQL, and WebSocket APIs |
| **Auth & Crypto** | Authentication, encryption, and key management |
| **Data & Secrets** | Protecting sensitive information |
| **Fuzzing Guide** | Automated vulnerability discovery techniques |
| **Reverse Engineering** | Binary analysis and malware techniques |
| **Security Glossary** | 100+ security terms and definitions |
| **Security Commands** | Essential CLI tools (nmap, burp, metasploit, etc.) |

#### Network Analysis Learning Pages
| Topic | Description |
|-------|-------------|
| **Network Analysis Hub Guide** | Complete guide to VRAgent's network security tools with use cases and workflows |
| **Wireshark Essentials** | Beginner-friendly guide to packet analysis, display/capture filters, and security use cases |
| **Nmap Essentials** | Comprehensive Nmap guide covering scan types, NSE scripts, timing, and real-world scenarios |

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

### Network Security Analysis

VRAgent includes a dedicated **Network Analysis Hub** for analyzing network traffic and infrastructure:

#### Nmap Scanner & Analyzer
- **Live Scanning**: Run Nmap scans directly from the browser
  - Multiple scan types: Basic, Quick, Full Port, Service Detection, OS Detection, Vulnerability Scripts
  - Target validation (IP, CIDR ranges up to /24, hostnames)
  - Custom port specification
  - Real-time scan progress
- **File Upload**: Analyze existing Nmap XML/text output files
- **AI-Powered Analysis**: Gemini AI generates comprehensive security reports including:
  - Network overview and attack surface assessment
  - Risk scoring (0-100 scale)
  - Key findings with severity ratings
  - Vulnerable services identification
  - Host-by-host security posture
  - Recommendations for remediation
- **AI Chat**: Interactive chat to discuss scan results with Gemini AI
- **Report Management**: Save, view, and delete scan reports
- **Export Options**: Download reports as Markdown, PDF, or DOCX

#### PCAP Analyzer
- **Live Packet Capture**: Capture network traffic directly (requires tshark)
  - Multiple capture profiles: General, Web Traffic, DNS, Authentication, Database, VoIP
  - Interface selection
  - Custom BPF filters
  - Configurable duration and packet limits
- **File Upload**: Analyze existing PCAP/PCAPNG files
- **Traffic Analysis**: Automatic parsing of:
  - Protocol distribution and statistics
  - Connection tracking (source/destination pairs)
  - DNS queries and responses
  - HTTP requests and responses
  - Suspicious patterns detection
- **AI-Powered Security Analysis**: Gemini AI analyzes traffic for:
  - Security threats and anomalies
  - Protocol-specific vulnerabilities
  - Data exfiltration indicators
  - Authentication weaknesses
  - Recommendations
- **AI Chat**: Interactive chat to discuss PCAP analysis with Gemini AI
- **Report Persistence**: Analysis reports saved to database for later retrieval

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   React + Vite  │────▶│  FastAPI Backend │────▶│   PostgreSQL    │
│    Frontend     │     │       API        │     │   + pgvector    │
└─────────────────┘     └────────┬─────────┘     └─────────────────┘
                                 │
                    ┌────────────┼────────────┐
                    │            │            │
                    ▼            ▼            ▼
           ┌──────────────┐ ┌────────┐ ┌─────────────┐
           │ Security     │ │ Redis  │ │  External   │
           │ Scanners     │ │ Queue  │ │  APIs       │
           │ (7 tools)    │ │        │ │ (OSV/NVD)   │
           └──────────────┘ └───┬────┘ └─────────────┘
                                │
                                ▼
                        ┌─────────────────┐
                        │   RQ Worker     │
                        │  (Background)   │
                        └─────────────────┘
```

**Key Components:**
- **Frontend**: React SPA with Material UI, real-time WebSocket updates
- **Backend**: FastAPI REST API with async support
- **Database**: PostgreSQL with pgvector for embeddings
- **Workers**: Background job processing for long-running scans
- **Redis**: Job queuing, WebSocket pub/sub, and API response caching
- **Scanners**: Semgrep, Bandit, ESLint, gosec, SpotBugs, clang-tidy, Secret Scanner, Docker Scanner, IaC Scanner
- **Network Tools**: Nmap (scanning), tshark (packet capture)
- **AI**: Google Gemini for code analysis, exploitability narratives, and network analysis

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

#### Using the Learning Hub

1. Click the **Learn** icon in the sidebar (or navigate to `/learn`)
2. Browse topics organized by category:
   - **About VRAgent**: How scanning works, AI analysis, architecture
   - **Security Fundamentals**: Kill Chain, MITRE ATT&CK, OWASP
   - **Practical Guides**: Pentesting, mobile security, API security
3. Each topic includes:
   - In-depth explanations with examples
   - Quick reference tables
   - Links to external resources
   - Practical tips and best practices

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
| `GET` | `/reports/{id}/file-content/{path}` | Get file content with syntax info |
| `GET` | `/reports/{id}/file-trends/{path}` | Get finding trends for a file |
| `GET` | `/reports/{id}/todos` | Scan for TODO/FIXME comments |
| `GET` | `/reports/{id}/search-code?q={query}` | Full-text search across code |
| `POST` | `/reports/{id}/explain-code` | AI explanation for code file |
| `GET` | `/reports/{id}/export/markdown` | Export as Markdown |
| `GET` | `/reports/{id}/export/pdf` | Export as PDF |
| `GET` | `/reports/{id}/export/docx` | Export as DOCX |
| `GET` | `/reports/{id}/export/sbom/cyclonedx` | Export SBOM (CycloneDX) |
| `GET` | `/reports/{id}/export/sbom/spdx` | Export SBOM (SPDX) |
| `POST` | `/reports/{id}/chat` | Chat with AI about findings/exploits |

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
| `GET` | `/health/detailed` | Detailed health with cache stats |

### Cache Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/cache/stats` | Get cache statistics (hits, misses, memory, keys) |
| `DELETE` | `/cache/{namespace}` | Clear cache namespace (osv, nvd, epss, embedding) |

### Network Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/network/status` | Check Nmap/tshark availability |
| `POST` | `/network/nmap/analyze` | Analyze uploaded Nmap files |
| `POST` | `/network/nmap/scan` | Run live Nmap scan |
| `GET` | `/network/nmap/scan-types` | List available scan types |
| `GET` | `/network/nmap/validate-target` | Validate scan target |
| `POST` | `/network/pcap/analyze` | Analyze uploaded PCAP files |
| `POST` | `/network/pcap/capture` | Run live packet capture |
| `GET` | `/network/pcap/capture-profiles` | List capture profiles |
| `GET` | `/network/pcap/interfaces` | List network interfaces |
| `POST` | `/network/pcap/validate-filter` | Validate BPF filter |
| `GET` | `/network/pcap/status` | Check capture status |
| `GET` | `/network/reports` | List saved network reports |
| `GET` | `/network/reports/{id}` | Get specific report |
| `DELETE` | `/network/reports/{id}` | Delete a report |
| `GET` | `/network/reports/{id}/export/{format}` | Export report (markdown/pdf/docx) |
| `POST` | `/network/chat` | Chat with AI about analysis results |

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
│   │   ├── cache.py         # Redis caching layer
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
│   │   ├── exploitability.py # AI exploit analysis
│   │   ├── network.py       # Network analysis (Nmap/PCAP)
│   │   └── webhooks.py      # Webhook notifications
│   │
│   ├── services/
│   │   ├── ai_analysis_service.py    # Gemini AI analysis
│   │   ├── bandit_service.py         # Python security scanning (Bandit)
│   │   ├── clangtidy_service.py      # C/C++ security scanning (clang-tidy)
│   │   ├── codebase_service.py       # Code extraction & parsing
│   │   ├── cve_service.py            # OSV vulnerability lookup
│   │   ├── deduplication_service.py  # Cross-scanner finding deduplication
│   │   ├── dependency_service.py     # Multi-language dependency parsing
│   │   ├── docker_scan_service.py    # Docker & container security
│   │   ├── embedding_service.py      # Gemini embeddings
│   │   ├── epss_service.py           # EPSS vulnerability scoring
│   │   ├── eslint_service.py         # JavaScript/TypeScript scanning (ESLint)
│   │   ├── exploit_service.py        # AI exploitability analysis
│   │   ├── export_service.py         # Report generation (MD/PDF/DOCX)
│   │   ├── git_service.py            # Repository cloning
│   │   ├── gosec_service.py          # Go security scanning (gosec)
│   │   ├── iac_scan_service.py       # Infrastructure as Code scanning
│   │   ├── network_export_service.py # Network report exports
│   │   ├── nmap_service.py           # Nmap scanning & parsing
│   │   ├── nvd_service.py            # NVD CVE enrichment
│   │   ├── pcap_service.py           # PCAP analysis & capture
│   │   ├── project_service.py        # Project management
│   │   ├── reachability_service.py   # Call graph & reachability analysis
│   │   ├── report_service.py         # Report creation
│   │   ├── sbom_service.py           # SBOM generation (CycloneDX/SPDX)
│   │   ├── scan_service.py           # Scan orchestration
│   │   ├── secret_service.py         # Secret detection
│   │   ├── semgrep_service.py        # Multi-language SAST (Semgrep)
│   │   ├── spotbugs_service.py       # Java/Kotlin scanning (SpotBugs)
│   │   ├── transitive_deps_service.py # Transitive dependency analysis
│   │   ├── webhook_service.py        # Webhook notifications
│   │   └── websocket_service.py      # Real-time updates
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
        │   ├── ScanProgress.tsx     # Real-time scan progress
        │   └── UploadCodeForm.tsx   # Zip upload form
        └── pages/
            ├── ProjectListPage.tsx      # Project listing
            ├── ProjectDetailPage.tsx    # Project details & scans
            ├── ReportDetailPage.tsx     # Scan report view
            ├── NetworkAnalysisHub.tsx   # Network tools hub
            ├── NmapAnalyzerPage.tsx     # Nmap scanning & analysis
            ├── PcapAnalyzerPage.tsx     # PCAP capture & analysis
            ├── LearnHubPage.tsx         # Security learning hub
            └── [Learning Pages]         # Educational content (17 topics)
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

### Large Codebase Handling

VRAgent is optimized to handle large codebases (100k+ LOC) efficiently without sacrificing analysis quality:

#### Intelligent Code Chunking
- **AST-based parsing**: Python files use Abstract Syntax Tree parsing for accurate function/class boundaries
- **Language-aware splitting**: Custom parsers for JS/TS, Java/Kotlin, Go, Ruby, PHP, Rust, and C/C++
- **Size-bounded chunks**: Prevents oversized chunks that could overwhelm analysis
- **Semantic boundaries**: Preserves code context for better vulnerability detection

#### Streaming File Processing
- **Batch processing**: Files are processed in batches to limit memory usage
- **Progressive commits**: Code chunks are saved to database incrementally
- **Early termination**: Stops gracefully when limits are reached, reporting partial results

#### Smart Prioritization
- **Security keyword scoring**: Code with authentication, crypto, SQL keywords gets priority
- **High-value pattern detection**: Recognizes password assignments, API endpoints, command execution
- **File path analysis**: Prioritizes files in `/auth/`, `/api/`, `/security/` directories
- **Adaptive scaling**: Automatically adjusts limits for very large codebases

#### Large Codebase Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `MAX_SOURCE_FILES` | Maximum source files to process | `5000` |
| `MAX_TOTAL_CHUNKS` | Maximum code chunks across all files | `5000` |
| `MAX_CHUNKS_PER_FILE` | Maximum chunks per individual file | `50` |
| `CHUNK_FLUSH_THRESHOLD` | Chunks before DB flush (memory control) | `500` |
| `SCANNER_TIMEOUT` | Per-scanner timeout in seconds | `600` |
| `MAX_PARALLEL_SCANNERS` | Concurrent scanner limit | `4` |
| `MAX_FINDINGS_FOR_AI` | Max findings for AI analysis | `500` |
| `MAX_FINDINGS_FOR_LLM` | Max findings sent to LLM | `50` |

**Example configuration for very large codebases (500k+ LOC):**
```bash
MAX_TOTAL_CHUNKS=10000 \
MAX_EMBEDDING_CHUNKS=1000 \
SCANNER_TIMEOUT=1200 \
MAX_FINDINGS_FOR_AI=1000 \
docker-compose up
```

**Recommended settings by codebase size:**
| Codebase Size | Files | Recommended Config |
|---------------|-------|-------------------|
| Small (<10k LOC) | <100 | Default settings |
| Medium (10k-50k LOC) | 100-500 | Default settings |
| Large (50k-200k LOC) | 500-2000 | Default settings |
| Very Large (200k-500k LOC) | 2000-5000 | `MAX_TOTAL_CHUNKS=8000`, `SCANNER_TIMEOUT=900` |
| Massive (500k+ LOC) | 5000+ | `MAX_TOTAL_CHUNKS=15000`, `SCANNER_TIMEOUT=1200`, `MAX_EMBEDDING_CHUNKS=1500` |

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

VRAgent runs **10+ specialized security scanners** automatically based on the languages and infrastructure detected in your project:

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

#### Docker Scanner
Dockerfile and container image security:
- **Dockerfile Linting**: 15+ rules for best practices and security
  - DS001: Running as root
  - DS002: Hardcoded secrets
  - DS004: Missing HEALTHCHECK
  - DS006: Using `latest` tag
  - DS007: Sensitive port exposure
  - DS013: ADD vs COPY misuse
  - DS014: Privileged operations
- **Image Vulnerability Scanning**: Trivy/Grype integration for CVE detection
- **Docker Compose Analysis**: Multi-service security review
- Runs automatically when `Dockerfile` or `docker-compose.yml` detected

#### IaC Scanner (Terraform, Kubernetes, CloudFormation)
Infrastructure as Code security analyzer:
- **Terraform**: HCL security misconfigurations
- **Kubernetes**: YAML manifest security issues
- **CloudFormation**: AWS template vulnerabilities
- **ARM Templates**: Azure resource security
- **40+ Built-in Rules**:
  - IAC001: Unencrypted storage
  - IAC002: Public access enabled
  - IAC003: Missing logging
  - IAC004: Overly permissive IAM
  - IAC005: Hardcoded credentials
  - IAC009: Missing network policies
  - IAC013: Privileged containers
- **Tool Integration**: Checkov and tfsec when available
- Runs automatically when `.tf`, `.yaml`/`.yml` (K8s), or CloudFormation templates detected

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

---

## 📋 Changelog

### December 7, 2025 (Latest)

#### Codebase Map Enhancements

**AI Code Explanation:**
- New "Explain with AI" button in code preview header (sparkle icon)
- Uses Google Gemini 2.0 Flash to analyze and explain code files
- Provides:
  - Overview of what the file does
  - Key functions and classes explained
  - Security concerns highlighted (especially if findings exist)
  - Code quality observations
- Results displayed in collapsible panel with markdown rendering
- Loading state with visual feedback during analysis

**Full-Text Code Search:**
- Added search mode toggle (File | Code) next to the search input
- **File mode** (default): Searches file names as before
- **Code mode**: Searches actual code content across all files
- Press Enter or click the search icon to execute content search
- Results show:
  - File path
  - Line number
  - Matching content with search term highlighted
- Click any result to jump directly to that file and line
- Up to 100 matches returned per search

**Additional Codebase Map Features (this session):**
- Copy Code Button - One-click code copying with visual confirmation
- Heatmap Overlay - Toggle button to visualize finding density on treemap
- Finding Trends Sparkline - Mini chart showing finding history per file over scans
- TODO/FIXME Scanner - Detects and displays code comment markers (TODO, FIXME, HACK, XXX, BUG)

---

### December 7, 2025

#### Docker & Infrastructure as Code Scanning

**Docker Security Scanner:**
- New `docker_scan_service.py` for comprehensive container security
- **Dockerfile Linting**: 15+ security rules (DS001-DS015)
  - Running as root, hardcoded secrets, missing HEALTHCHECK
  - Using `latest` tag, sensitive ports, ADD vs COPY
- **Image Scanning**: Integration with Trivy and Grype for CVE detection
- **Docker Compose Analysis**: Multi-container security review
- Automatic detection of Dockerfiles and docker-compose.yml

**Infrastructure as Code Scanner:**
- New `iac_scan_service.py` for infrastructure security
- **Multi-Framework Support**:
  - Terraform (.tf, .tfvars)
  - Kubernetes (manifests, Helm charts)
  - CloudFormation (JSON/YAML templates)
  - ARM Templates (Azure)
- **40+ Built-in Rules** (IAC001-IAC040+)
- **Tool Integration**: Checkov and tfsec when available
- Automatic framework detection

#### Performance & Analysis Improvements

**Parallel Phase Execution:**
- Major scan phases now run concurrently (2-3x faster)
- `ParallelPhaseTracker` for thread-safe progress tracking
- SAST + Docker + IaC + Dependencies run in parallel
- Automatic result aggregation

**Scanner Deduplication:**
- New `deduplication_service.py` merges duplicate findings
- Cross-scanner matching (Semgrep + Bandit, etc.)
- Location-based and content-based deduplication
- Preserves highest severity rating

**Transitive Dependency Analysis:**
- New `transitive_deps_service.py` builds full dependency trees
- Detects vulnerabilities in indirect dependencies
- Shows dependency path to vulnerable package
- Depth tracking for prioritization

**Reachability Analysis:**
- New `reachability_service.py` for call graph analysis
- Determines if vulnerable functions are actually called
- Reduces false positives for unused vulnerable code
- Language-aware analysis for Python, JavaScript, Java, Go

**CISA KEV Integration:**
- Flags CVEs in CISA's Known Exploited Vulnerabilities catalog
- `kev_in_wild` field on findings
- Priority indicator for actively exploited vulnerabilities

#### Frontend Updates

**Improved Scan Progress Display:**
- All new phases visible in real-time progress
- Categorized phase display with icons
- Expandable categories for detailed sub-phase tracking
- Visual status indicators (complete/active/pending)

---

### December 6, 2025

#### Network Analysis Enhancements

**Nmap Analyzer - New Features:**
- **AI Chat Integration**: Added ability to chat with Gemini AI about Nmap scan results
  - Floating chat window appears after scan completion
  - Full context of scan results, hosts, findings, and AI report provided to the LLM
  - Suggested questions to help users get started
  - Markdown rendering for formatted AI responses
  - Conversation history maintained within session

- **Saved Reports Tab**: New tab to view and manage saved Nmap reports
  - Table displaying all saved Nmap reports with title, date, risk level, and findings count
  - View button to load and display any saved report
  - Delete button with confirmation to remove reports
  - Automatic refresh when switching to the tab

**Bug Fixes:**
- Fixed Nmap live scan crash (white screen) caused by:
  - Property name mismatch: backend returns `host.ports` but frontend was accessing `host.open_ports`
  - Object rendering error: `network_overview` is an object but was being rendered directly as text
  - Null safety: Added fallback for undefined `findings` array

**PCAP Analyzer:**
- **AI Chat Integration**: Added chat feature to discuss PCAP analysis results with Gemini
- **Report Persistence**: PCAP analysis reports are now saved to the database for later retrieval

**Backend API:**
- New endpoint: `POST /network/chat` - Chat with AI about network analysis results
  - Supports both Nmap and PCAP analysis types
  - Accepts message, conversation history, and scan context
  - Returns AI-generated response with full context awareness

---

### December 7, 2025

#### VR Scan Chat Integration

**New Feature: AI Chat for Vulnerability Reports**
- Added interactive chat window to VR Scan report pages (Findings and Exploitability tabs)
- Chat with Gemini AI about scan findings, attack chains, and exploit scenarios
- Full context awareness - LLM receives:
  - All findings grouped by severity (Critical, High, Medium, Low, Info)
  - AI analysis summary (false positives, severity adjustments)
  - Attack chains identified during analysis
  - Exploit scenarios with narratives and mitigations
- Suggested questions to help users get started
- Conversation history maintained for multi-turn discussions
- Context-aware UI: Blue header for Findings tab, Red header for Exploitability tab

**Backend API:**
- New endpoint: `POST /reports/{id}/chat` - Chat with AI about VR Scan results
  - Accepts message, conversation history, and context tab (findings/exploitability)
  - Returns AI-generated response with full report context

#### Learning Hub Documentation Updates

**Updated Pages with Accurate Technical Details:**

- **How Scanning Works** (`/learn/scanning`):
  - Documented accurate 9-phase parallel scanning pipeline
  - Added all 9 scanners including Trivy (Docker) and Checkov/tfsec (IaC)
  - Updated statistics: 30+ languages, 2500+ rules, 50+ secret patterns
  - Added Docker and IaC scanning sections with rule examples

- **AI Analysis Explained** (`/learn/ai-analysis`):
  - Documented hybrid heuristics + LLM approach
  - Added heuristic patterns for false positive detection and severity adjustment
  - Explained MAX_FINDINGS_FOR_LLM=50 batching strategy
  - Documented 16+ built-in exploit templates
  - Added background summary generation details

- **VRAgent Architecture** (`/learn/architecture`):
  - Expanded to 18 backend services (added Docker, IaC, AI Analysis services)
  - Updated 13-step request flow with parallel execution
  - Added pgvector, Semgrep, Trivy, Checkov to technology stack
  - Documented embedding storage and reuse strategy
