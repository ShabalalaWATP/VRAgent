# Backend Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    NODE_PATH=/usr/lib/node_modules \
    GOPATH=/go \
    PATH="/go/bin:/usr/local/go/bin:$PATH" \
    SPOTBUGS_HOME=/opt/spotbugs

# Install system dependencies including git for cloning repos,
# Node.js for ESLint, Go for Gosec, clang-tidy for C/C++, nmap for network scanning, 
# tshark for packet capture, traceroute for network path analysis, dnsutils for DNS queries, and build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpq-dev \
    git \
    curl \
    wget \
    unzip \
    default-jdk-headless \
    clang-tidy \
    nmap \
    tshark \
    libcap2-bin \
    traceroute \
    iputils-ping \
    dnsutils \
    whois \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap

# Install Go (for gosec)
RUN wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz \
    && rm go1.21.5.linux-amd64.tar.gz

# Install Gosec (Go security scanner)
RUN go install github.com/securego/gosec/v2/cmd/gosec@latest

# Install SpotBugs with Find Security Bugs plugin (for Java security scanning)
RUN mkdir -p /opt/spotbugs/plugin \
    && wget -q -O /tmp/spotbugs.zip https://github.com/spotbugs/spotbugs/releases/download/4.8.3/spotbugs-4.8.3.zip \
    && unzip -q /tmp/spotbugs.zip -d /opt \
    && mv /opt/spotbugs-4.8.3/* /opt/spotbugs/ \
    && rm -rf /opt/spotbugs-4.8.3 /tmp/spotbugs.zip \
    && wget -q -O /opt/spotbugs/plugin/findsecbugs-plugin.jar \
       https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/1.12.0/findsecbugs-plugin-1.12.0.jar \
    && chmod +x /opt/spotbugs/bin/spotbugs \
    && ln -s /opt/spotbugs/bin/spotbugs /usr/local/bin/spotbugs

# Install ESLint and security plugins globally for scanning
RUN npm install -g eslint eslint-plugin-security @eslint/js

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code into backend/ directory to match import paths
RUN mkdir -p backend
COPY . ./backend/

# Note: Running as root to allow nmap privileged scans (SYN, UDP)
# For production, consider using a separate nmap service with limited privileges

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')" || exit 1

# Default command
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
