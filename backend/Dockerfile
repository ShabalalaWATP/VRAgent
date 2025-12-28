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
    cppcheck \
    nmap \
    tshark \
    libcap2-bin \
    traceroute \
    iputils-ping \
    dnsutils \
    whois \
    ca-certificates \
    gnupg \
    fontconfig \
    fonts-dejavu-core \
    libfreetype6 \
    libharfbuzz0b \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap

# Install Docker CLI for Docker image layer analysis
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

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

# Install JADX (Java decompiler for APK analysis)
RUN wget -q -O /tmp/jadx.zip https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip \
    && mkdir -p /opt/jadx \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && chmod +x /opt/jadx/bin/jadx /opt/jadx/bin/jadx-gui \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm /tmp/jadx.zip

# Install Ghidra (binary analysis and decompilation)
ENV GHIDRA_VERSION=11.2.1 \
    GHIDRA_DATE=20241105 \
    GHIDRA_HOME=/opt/ghidra

RUN wget -q -O /tmp/ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC ${GHIDRA_HOME} \
    && chmod +x ${GHIDRA_HOME}/support/analyzeHeadless \
    && rm /tmp/ghidra.zip

# Install ESLint and security plugins globally for scanning
RUN npm install -g eslint eslint-plugin-security @eslint/js

# Install PHP and security scanning tools (PHP_CodeSniffer with security audit)
RUN apt-get update && apt-get install -y --no-install-recommends \
    php-cli \
    php-mbstring \
    php-xml \
    php-curl \
    composer \
    && rm -rf /var/lib/apt/lists/* \
    && composer global require --no-interaction squizlabs/php_codesniffer \
    && composer global require --no-interaction pheromone/phpcs-security-audit \
    && ln -sf /root/.composer/vendor/bin/phpcs /usr/local/bin/phpcs

# Install Ruby and Brakeman (Ruby/Rails security scanner)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ruby \
    ruby-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && gem install brakeman --no-document

# Install Rust and cargo-audit (Rust security scanner)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    && . /root/.cargo/env \
    && cargo install cargo-audit \
    && ln -sf /root/.cargo/bin/cargo /usr/local/bin/cargo \
    && ln -sf /root/.cargo/bin/cargo-audit /usr/local/bin/cargo-audit

ENV PATH="/root/.cargo/bin:$PATH"

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
# Single worker for dev, use --workers 2-4 for production with 20-30 users
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
