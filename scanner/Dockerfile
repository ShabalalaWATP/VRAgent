# Scanner Sidecar - Host-networked container for network security scanning
# This container runs with network_mode: host to access LAN targets
# Using specific patch version for security (3.11.11 released Dec 2024 with CVE fixes)
FROM python:3.11.11-slim-bookworm

WORKDIR /scanner

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    wget \
    unzip \
    git \
    ca-certificates \
    libcap2-bin \
    jq \
    gobuster \
    sqlmap \
    dirb \
    && rm -rf /var/lib/apt/lists/*

# Grant nmap raw socket capabilities
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

# Install Nuclei (CVE vulnerability scanner)
ENV NUCLEI_VERSION=3.2.4
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip \
    && unzip nuclei_${NUCLEI_VERSION}_linux_amd64.zip -d /usr/local/bin/ \
    && rm nuclei_${NUCLEI_VERSION}_linux_amd64.zip \
    && chmod +x /usr/local/bin/nuclei

# Download Nuclei templates (CVE detection)
RUN nuclei -update-templates -silent || true

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Wapiti via pip (not available in Debian trixie repos)
RUN pip install --no-cache-dir wapiti3

# Ensure typing_extensions is up to date (wapiti3 may downgrade it)
RUN pip install --no-cache-dir --upgrade "typing_extensions>=4.10.0"

# Copy scanner server
COPY server.py .
COPY utils.py .
COPY planner.py .

# Create directories for scan outputs and mounted wordlists
RUN mkdir -p /scans/nmap /scans/nuclei /scans/results /wordlists

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9999/health || exit 1

# Expose scanner API port
EXPOSE 9999

# Run scanner server
CMD ["python", "server.py"]
