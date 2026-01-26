# Dynamic Analysis Hub

## Overview

The Dynamic Analysis Hub provides AI-orchestrated runtime security testing, network analysis, and infrastructure assessment tools. It integrates 10+ industry-leading security tools with intelligent orchestration to perform comprehensive dynamic application security testing (DAST), network reconnaissance, and vulnerability discovery.

## Accessing Dynamic Analysis

- **URL:** `/dynamic` (standalone tools) or within a project's Dynamic Analysis tab
- **Navigation:** Click "Dynamic Analysis" button in the top navigation bar
- **Authentication:** Required (login to access)

---

## Screenshots

![Dynamic Analysis Hub](screenshots/Dynamic1.jpg)

---

## Tools Available

| Tool | Description |
|------|-------------|
| **PCAP Analyzer** | Deep packet inspection and traffic analysis |
| **Dynamic Scanner** | AI-orchestrated multi-tool security scanning |
| **SSL/TLS Scanner** | Certificate and encryption analysis |
| **DNS Reconnaissance** | DNS enumeration and security analysis |
| **Traceroute & Nmap** | Network path analysis and port scanning |
| **API Tester** | API security testing with OWASP mapping |
| **Security Fuzzer** | Web fuzzing with Agentic AI capabilities |
| **Binary Fuzzer** | Coverage-guided native binary fuzzing |
| **MITM Workbench** | Traffic interception and modification |

---

## PCAP Analyzer

Deep packet inspection for network traffic analysis with offensive security features.

### Analysis Capabilities

| Feature | Description |
|---------|-------------|
| **Protocol Decoding** | HTTP, HTTPS, DNS, FTP, SMTP, Telnet, SSH, TLS |
| **Credential Extraction** | HTTP Basic Auth, FTP passwords, cleartext credentials |
| **API Discovery** | Extract REST/GraphQL endpoints, parameters, headers |
| **TLS Analysis** | Certificate inspection, cipher suites, SNI extraction |
| **DNS Queries** | Hostname resolution, tunneling detection, query patterns |
| **Traffic Statistics** | Protocol distribution, conversation analysis, bandwidth |
| **Suspicious Patterns** | Beaconing, port scans, data exfiltration, C2 detection |

### Offensive Security Features

#### API Endpoint Discovery

Automatically extracts from HTTP traffic:

| Data Extracted | Description |
|----------------|-------------|
| **Endpoints** | Full URL paths with methods (GET, POST, PUT, DELETE) |
| **Query Parameters** | URL query string parameters |
| **Body Parameters** | POST/PUT body parameters |
| **Headers** | Request headers including custom headers |
| **Content Types** | Request and response content types |
| **Authentication** | Auth type detected (Bearer, Basic, API Key, Cookie) |
| **Request Count** | Number of times endpoint was called |

#### Authentication Token Extraction

| Token Type | Analysis Provided |
|------------|-------------------|
| **JWT** | Decode payload, check expiry, identify algorithm weaknesses |
| **Bearer Tokens** | Extract and hash for deduplication |
| **API Keys** | Identify in headers (X-API-Key, Authorization) |
| **Session Cookies** | Extract session identifiers |
| **OAuth Tokens** | Detect OAuth flows |
| **Basic Auth** | Decode and extract credentials |

**JWT Weakness Detection:**
- `alg: none` vulnerability
- Weak algorithms (HS256 with guessable secrets)
- Missing expiration claims
- Long validity periods
- Sensitive data in payload

#### Sensitive Data Detection

| Data Type | Pattern |
|-----------|---------|
| **Email Addresses** | PII in requests/responses |
| **Phone Numbers** | Various formats |
| **SSN Patterns** | US Social Security Numbers |
| **Credit Cards** | Card number patterns |
| **API Keys** | Common API key formats |
| **Passwords** | Password fields in forms |
| **Internal IPs** | Private IP address ranges |
| **Debug Info** | Stack traces, debug headers |

#### Protocol Weakness Identification

| Weakness | Description |
|----------|-------------|
| **Cleartext HTTP** | Sensitive data over unencrypted HTTP |
| **Weak TLS** | TLS 1.0/1.1, weak cipher suites |
| **Missing HSTS** | No HTTP Strict Transport Security |
| **FTP Cleartext** | FTP credentials in plaintext |
| **Telnet** | All Telnet traffic |
| **SMTP Auth** | SMTP authentication in cleartext |
| **DNS Leakage** | Unencrypted DNS queries |

### Traffic Analysis

| Analysis | Description |
|----------|-------------|
| **Conversation Tracking** | Group packets by source/dest pairs |
| **Protocol Distribution** | Breakdown by protocol (TCP, UDP, HTTP, DNS) |
| **Bandwidth Analysis** | Data transferred per host/conversation |
| **Timeline View** | Packet timing for beaconing detection |
| **Geolocation** | IP geolocation for traffic mapping |

### Supported Formats

| Format | Description |
|--------|-------------|
| **PCAP** | Standard libpcap format |
| **PCAPNG** | Wireshark next-generation format |
| **Live Capture** | Real-time capture via tshark |

### Live Capture Examples

```bash
# Capture on interface eth0 for 60 seconds
tshark -i eth0 -a duration:60 -w capture.pcap

# Capture only HTTP traffic
tshark -i eth0 -f "tcp port 80" -w http_traffic.pcap

# Capture with ring buffer (continuous)
tshark -i eth0 -b filesize:10000 -b files:5 -w capture.pcap
```

### Export Options

| Export | Description |
|--------|-------------|
| **Endpoints JSON** | All discovered API endpoints for fuzzing |
| **Tokens JSON** | Extracted authentication tokens |
| **Findings Report** | Security findings in Markdown/PDF |
| **Wireshark Filter** | Generate filter for specific traffic |

---

## Dynamic Scanner

The AI-orchestrated Dynamic Security Scanner automates the entire pentesting workflow by coordinating multiple tools in sequence.

### Scanning Phases

| Phase | Tool | Description |
|-------|------|-------------|
| **1. Reconnaissance** | Nmap | Network discovery, port scanning, OS detection |
| **2. Routing** | AI Agent | Intelligent decision on which scanners to use |
| **3. OpenVAS Scanning** | OpenVAS/GVM | Network vulnerability assessment |
| **4. Directory Enumeration** | Gobuster | Web directory and file discovery |
| **5. Web Scanning** | OWASP ZAP | Active web vulnerability scanning |
| **6. Wapiti Scanning** | Wapiti | Additional web security testing |
| **7. SQLMap Scanning** | SQLMap | SQL injection detection and exploitation |
| **8. CVE Scanning** | Nuclei | Template-based CVE detection (8000+ templates) |
| **9. Exploit Mapping** | ExploitDB | Map findings to known exploits |
| **10. AI Analysis** | Gemini | Attack narrative generation |

### AI Routing Logic

The AI Agent in Phase 2 analyzes reconnaissance results to determine optimal scan paths:

| Discovery | AI Decision |
|-----------|-------------|
| **Web server detected** | Enable ZAP, Wapiti, Nikto, directory enumeration |
| **Database ports open** | Enable SQLMap, database-specific Nuclei templates |
| **Known CVE versions** | Prioritize Nuclei CVE templates, ExploitDB mapping |
| **API endpoints found** | Enable API-specific tests, GraphQL introspection |
| **Authentication forms** | Enable credential testing, session analysis |
| **SSL/TLS issues** | Enable SSL scanning, certificate analysis |

### Integrated Tools

| Tool | Description | Templates/Rules |
|------|-------------|-----------------|
| **OWASP ZAP** | Web application scanner | OWASP Top 10, 100+ active scan rules |
| **Nuclei** | Template-based scanner | 8000+ vulnerability templates |
| **Nmap** | Network scanner | Service detection, NSE scripts |
| **OpenVAS** | Vulnerability scanner | 50,000+ NVTs |
| **SQLMap** | SQL injection tool | Automatic detection and exploitation |
| **Nikto** | Web server scanner | 6700+ vulnerability checks |
| **Subfinder** | Subdomain enumeration | Passive and active discovery |
| **Feroxbuster** | Directory discovery | Fast recursive content discovery |

### Scan Depth Options

| Depth | Duration | Coverage | Use Case |
|-------|----------|----------|----------|
| **Quick** | 5-15 min | Top 100 ports, basic web scan | Initial recon, time-sensitive |
| **Standard** | 30-60 min | Top 1000 ports, full web scan | Regular assessments |
| **Thorough** | 2-4 hours | All 65535 ports, deep analysis | Comprehensive pentest |

### Starting a Dynamic Scan

1. Navigate to Dynamic Security Scanner page
2. Enter target URL or IP address
3. Configure scan options:
   - **Scan Depth:** Quick, Standard, or Thorough
   - **Authentication:** Credentials for authenticated scanning
   - **Scope:** Include/exclude URL patterns
4. Click **"Start Scan"**
5. Monitor real-time progress through phases
6. View results as findings are discovered

### Scan Output

The scanner produces:

| Output | Description |
|--------|-------------|
| **Finding Cards** | Each vulnerability with severity, description, evidence |
| **Attack Narrative** | AI-generated story of how an attacker could exploit findings |
| **Risk Score** | Overall security score (0-100) based on findings |
| **Remediation Plan** | Prioritized fix recommendations |
| **Technical Details** | Raw tool output, requests/responses, proof |
| **CVSS Scores** | Calculated CVSS v3.1 scores per finding |
| **Export Options** | PDF report, JSON, CSV, Markdown |

### Real-Time Monitoring

During scanning, the UI shows:
- Current phase and tool running
- Live finding count by severity
- Progress percentage per phase
- Tool logs and raw output
- Pause/resume/cancel controls

---

## SSL/TLS Scanner

Comprehensive SSL/TLS security analysis with offensive features.

### How to Use

1. **Enter Target:** IP address, hostname, or URL (port 443 default)
2. **Select Scan Type:**
   - **Quick:** Certificate + protocol check (~10 seconds)
   - **Standard:** Full vulnerability scan (~30 seconds)
   - **Deep:** All checks + cipher enumeration (~2 minutes)
3. **Click "Scan"** to start analysis
4. **Review Results:** Findings organized by severity

### Security Checks

| Check | Description | Severity |
|-------|-------------|----------|
| **Certificate Validation** | Chain verification, expiry, self-signed | Medium-Critical |
| **Protocol Support** | SSLv3, TLS 1.0/1.1/1.2/1.3 detection | Medium-High |
| **Cipher Analysis** | Weak ciphers, NULL ciphers, export grades | High-Critical |
| **BEAST** | Browser Exploit Against SSL/TLS (CVE-2011-3389) | Medium |
| **POODLE** | Padding Oracle On Downgraded Legacy (CVE-2014-3566) | High |
| **CRIME** | Compression attack on TLS | Medium |
| **Heartbleed** | OpenSSL memory disclosure (CVE-2014-0160) | Critical |
| **ROBOT** | Return Of Bleichenbacher's Oracle Threat | High |
| **DROWN** | Decrypting RSA with Obsolete and Weakened eNcryption | High |
| **FREAK** | Factoring RSA Export Keys | High |
| **Logjam** | Diffie-Hellman downgrade | High |
| **Lucky13** | Timing attack on CBC mode | Medium |

### Certificate Analysis

| Field | Analysis |
|-------|----------|
| **Subject/Issuer** | Certificate chain validation |
| **Validity Period** | Expiration warnings (30/60/90 days) |
| **Key Size** | RSA < 2048 or ECC < 256 flagged |
| **Signature Algorithm** | SHA-1, MD5 flagged as weak |
| **SAN/CN Mismatch** | Hostname verification |
| **Revocation Status** | OCSP/CRL check |
| **CT Logs** | Certificate Transparency presence |

### Offensive Features

| Feature | Description |
|---------|-------------|
| **JARM Fingerprinting** | Identify C2 frameworks, malware infrastructure |
| **Suspicious Cert Detection** | Short validity, unusual patterns |
| **MITM Feasibility** | Assess traffic interception potential |
| **Certificate Pinning** | Detect pinning implementations |
| **Domain Fronting** | Detect CDN-based evasion |
| **C2 Indicators** | Known malware/C2 JARM signatures |
| **Certificate Intelligence** | Extract IoCs from certificates |

### Known JARM Signatures

The scanner includes 50+ known JARM signatures for:
- Cobalt Strike (multiple malleable profiles)
- Metasploit
- Sliver C2
- Covenant
- Empire
- Mythic
- PoshC2
- Brute Ratel

### Multi-Target Scanning

Scan multiple targets simultaneously:
- Single IP/hostname
- IP range (CIDR notation)
- List of targets (comma-separated)
- File upload (one target per line)

### Scan Output

| Output | Description |
|--------|-------------|
| **Security Grade** | A+ to F rating based on findings |
| **Protocol Support** | Matrix of supported TLS versions |
| **Cipher Suites** | Full list with strength ratings |
| **Certificate Details** | Parsed certificate information |
| **Vulnerability List** | Each issue with severity and remediation |
| **JARM Hash** | Fingerprint for threat intel matching |
| **Export** | JSON, PDF, or CSV report |

---

## DNS Reconnaissance

Comprehensive DNS enumeration and security analysis.

### How to Use

1. **Enter Domain:** Target domain name (e.g., `example.com`)
2. **Select Options:**
   - Enable/disable subdomain enumeration
   - Enable/disable zone transfer testing
   - Select custom DNS servers (optional)
3. **Click "Analyze"** to start reconnaissance
4. **Review Results:** Records, security issues, subdomains

### Record Types

| Record | Description |
|--------|-------------|
| **A/AAAA** | IPv4/IPv6 addresses |
| **MX** | Mail servers |
| **NS** | Name servers |
| **TXT** | Text records (SPF, DKIM, etc.) |
| **SOA** | Start of Authority |
| **CNAME** | Canonical names |
| **SRV** | Service records |
| **CAA** | Certificate Authority Authorization |
| **PTR** | Reverse DNS |

### Security Analysis

| Check | Description |
|-------|-------------|
| **Zone Transfer (AXFR)** | Test for misconfigured DNS servers |
| **Subdomain Enumeration** | Wordlist-based discovery (200+ subdomains) |
| **Subdomain Takeover** | Detect vulnerable CNAME configurations |
| **Dangling CNAME** | Identify orphaned DNS records |
| **SPF Analysis** | Email sender policy validation |
| **DMARC Analysis** | Email authentication policy |
| **DKIM Detection** | Email signing verification |
| **DNSSEC Validation** | DNS security extensions |
| **Wildcard Detection** | Identify catch-all DNS |

### Subdomain Takeover Detection

The scanner checks for takeover vulnerabilities on:

| Service | Fingerprint |
|---------|-------------|
| **AWS S3** | `NoSuchBucket` response |
| **GitHub Pages** | `There isn't a GitHub Pages site here` |
| **Heroku** | `No such app` |
| **Azure** | `NXDOMAIN` on *.azurewebsites.net |
| **Shopify** | `Sorry, this shop is currently unavailable` |
| **Fastly** | `Fastly error: unknown domain` |
| **Pantheon** | `404 error unknown site` |
| **Tumblr** | `There's nothing here` |
| **Zendesk** | `Help Center Closed` |

### Email Security Analysis

| Check | Good | Bad |
|-------|------|-----|
| **SPF** | `-all` (hard fail) | `+all` or missing |
| **DMARC** | `p=reject` | `p=none` or missing |
| **DKIM** | Valid selector found | No DKIM records |
| **MX** | Points to mail servers | Open relay risk |

### Cloud Provider Detection

Automatically identifies:
- AWS (CloudFront, S3, ELB, EC2)
- Azure (Blob Storage, CDN, App Service)
- Google Cloud (Cloud Storage, Load Balancer)
- Cloudflare
- Fastly
- Akamai

### WHOIS Integration

- Domain registration details
- Registrar information
- Creation/expiration dates
- Name server history
- ASN/BGP information

### Scan Output

| Output | Description |
|--------|-------------|
| **DNS Records Table** | All discovered records by type |
| **Subdomain List** | Discovered subdomains with IP addresses |
| **Security Findings** | Issues with severity and remediation |
| **Email Security Score** | SPF/DMARC/DKIM compliance rating |
| **Infrastructure Map** | Visual representation of DNS hierarchy |
| **Takeover Alerts** | Vulnerable subdomains highlighted |
| **Export** | JSON, CSV, or Markdown report |

---

## Traceroute & Nmap

Network path analysis, infrastructure mapping, and comprehensive port scanning with AI-powered analysis.

### Traceroute Features

| Feature | Description |
|---------|-------------|
| **Cross-Platform** | Works on Windows, Linux, macOS |
| **Hop-by-Hop Analysis** | Latency per hop |
| **Geographic Mapping** | IP geolocation for hops |
| **Network Inference** | Identify ISPs and network segments |
| **Firewall Detection** | Identify filtering at specific hops |
| **Packet Loss** | Detect unreliable links |
| **AI Analysis** | Security insights on network path |

### Traceroute Modes

| Mode | Description |
|------|-------------|
| **ICMP** | Standard traceroute (default) |
| **UDP** | UDP-based traceroute |
| **TCP** | TCP SYN traceroute (firewall bypass) |

### Traceroute Output

- Interactive hop visualization
- Latency graph
- Network segment identification
- Firewall/filter detection points
- AI security observations

### Nmap Scan Types

| Scan Type | Command | Description |
|-----------|---------|-------------|
| **Quick Scan** | `-T4 -F` | Fast scan of 100 most common ports |
| **Basic Scan** | `-sT -sV` | TCP connect with service version detection |
| **Full Port** | `-p-` | Scan all 65535 TCP ports |
| **Service Detection** | `-sV --version-intensity 5` | Detailed service fingerprinting |
| **OS Detection** | `-O` | Operating system identification via TCP/IP fingerprinting |
| **Aggressive** | `-A` | OS detection, version, scripts, and traceroute combined |
| **Stealth** | `-sS` | SYN scan - fast and less detectable (requires root) |
| **UDP Scan** | `-sU` | UDP port scanning (slower but finds hidden services) |
| **Script Scan** | `--script=vuln` | Run NSE vulnerability detection scripts |
| **Custom** | User-defined | Any valid Nmap arguments |

### Nmap Features

| Feature | Description |
|---------|-------------|
| **Live Scanning** | Run Nmap scans directly from browser |
| **File Upload** | Upload existing Nmap XML files for analysis |
| **AI Analysis** | AI-powered security recommendations and attack paths |
| **Network Graph** | Interactive D3.js visualization of hosts and ports |
| **Findings Table** | Security issues with severity ratings and CVE links |
| **Host Details** | Detailed drawer view for each discovered host |
| **Export** | Download results as XML, JSON, Markdown, or PDF |
| **Command Builder** | Visual Nmap command builder for custom scans |

### High-Risk Port Detection (60+ Ports)

The scanner automatically flags high-risk open ports:

#### Critical Severity

| Port | Service | Risk |
|------|---------|------|
| 23 | Telnet | Credentials transmitted in cleartext |
| 512-514 | rexec/rlogin/rsh | Remote execution without encryption |
| 2375 | Docker API | Unencrypted - full container control |
| 2377 | Docker Swarm | Cluster management access |
| 6379 | Redis | Often no authentication by default |
| 6443 | Kubernetes API | Full cluster control |
| 9200 | Elasticsearch | Often no authentication |
| 10250 | Kubelet | Kubernetes node control |
| 11211 | Memcached | No auth, DDoS amplification |
| 27017 | MongoDB | Often no authentication |
| 1099 | Java RMI | Deserialization vulnerabilities |
| 8009 | AJP | Ghostcat vulnerability |

#### High Severity

| Port | Service | Risk |
|------|---------|------|
| 21 | FTP | Cleartext credentials |
| 110/143 | POP3/IMAP | Cleartext credentials |
| 135 | MSRPC | Windows RPC exploits |
| 137-139 | NetBIOS | Information leakage, SMB access |
| 445 | SMB | EternalBlue, WannaCry, ransomware |
| 161 | SNMP | Weak community strings |
| 1433/1434 | MSSQL | Database access, SQL injection |
| 1521 | Oracle | Database access |
| 3306 | MySQL | Database access |
| 3389 | RDP | Brute force, BlueKeep |
| 5900-5902 | VNC | Weak authentication |
| 5672 | AMQP | RabbitMQ access |

#### Medium Severity

| Port | Service | Risk |
|------|---------|------|
| 25 | SMTP | Open relay |
| 53 | DNS | Zone transfer, cache poisoning |
| 389/636 | LDAP | Directory information exposure |
| 5432 | PostgreSQL | Database access |
| 8080/8000 | HTTP Alt | Development servers |
| 3000 | Node.js | Development servers |
| 9092 | Kafka | Message queue access |

### Nmap AI Analysis Output

The AI analyzer provides:

- **Executive Summary:** High-level security posture assessment
- **Attack Surface Map:** Visual representation of entry points
- **Risk Prioritization:** Ranked list of issues by exploitability
- **Attack Paths:** Step-by-step exploitation scenarios
- **Lateral Movement:** Potential paths from initial access
- **Remediation Plan:** Prioritized fix recommendations
- **Next Steps:** Suggested follow-up scans and tests

---

## API Tester

Comprehensive API security testing with 9 specialized modes and OWASP API Security Top 10 mapping.

### Testing Modes

| Mode | Description | Tests Performed |
|------|-------------|-----------------|
| **Authentication** | Test for missing/weak auth | No auth, weak tokens, bypass attempts |
| **Authorization** | IDOR, privilege escalation | Object ID manipulation, role tampering |
| **Input Validation** | Injection testing | SQLi, XSS, command injection, SSTI |
| **Rate Limiting** | DoS protection | Burst requests, missing limits |
| **CORS** | Cross-origin testing | Origin reflection, credential exposure |
| **Headers** | Security headers | HSTS, CSP, X-Frame-Options, X-XSS |
| **Information Disclosure** | Data leakage | Error messages, stack traces, debug |
| **HTTP Methods** | Verb tampering | PUT, DELETE, TRACE, OPTIONS |
| **GraphQL** | GraphQL-specific | Introspection, batching, depth |

### Input Sources

| Source | Description |
|--------|-------------|
| **Manual Entry** | Enter endpoints manually with method and parameters |
| **OpenAPI/Swagger** | Import OpenAPI 2.0/3.0 specification files |
| **PCAP Import** | Extract endpoints from PCAP traffic capture |
| **CIDR Scanning** | Discover APIs on IP range (e.g., 192.168.1.0/24) |
| **Wordlist** | Common API path enumeration (/api, /v1, /graphql) |
| **Postman Collection** | Import Postman collection JSON |

### OWASP API Security Top 10 (2023)

All findings are mapped to OWASP API Security Top 10 2023:

| ID | Name | Description | Tests |
|----|------|-------------|-------|
| **API1:2023** | Broken Object Level Authorization | APIs expose object IDs without proper access control | IDOR testing, ID enumeration, horizontal privilege escalation |
| **API2:2023** | Broken Authentication | Weak authentication mechanisms | Token analysis, auth bypass, credential stuffing |
| **API3:2023** | Broken Object Property Level Authorization | APIs return all object properties | Mass assignment, excessive data exposure |
| **API4:2023** | Unrestricted Resource Consumption | No limits on resource usage | Rate limiting, pagination abuse, large payloads |
| **API5:2023** | Broken Function Level Authorization | Missing function-level checks | Admin endpoint access, role bypass |
| **API6:2023** | Unrestricted Access to Sensitive Business Flows | Business logic abuse | Flow bypass, automation detection |
| **API7:2023** | Server Side Request Forgery | Unvalidated user-supplied URIs | SSRF payloads, internal resource access |
| **API8:2023** | Security Misconfiguration | Insecure defaults, incomplete configs | Headers, CORS, debug endpoints |
| **API9:2023** | Improper Inventory Management | Undocumented/deprecated endpoints | Endpoint discovery, version probing |
| **API10:2023** | Unsafe Consumption of APIs | Trusting third-party API data | Response validation, injection via API |

### Security Tests Performed

#### Authentication Tests

| Test | Description |
|------|-------------|
| **No Authentication** | Access without any credentials |
| **Invalid Token** | Malformed or invalid tokens |
| **Expired Token** | Tokens past expiration |
| **Algorithm Confusion** | JWT alg:none, HS256 with RS256 key |
| **Token Reuse** | Replay attacks |
| **Brute Force** | Credential guessing |

#### Authorization Tests

| Test | Description |
|------|-------------|
| **IDOR** | Change object IDs to access others' data |
| **Privilege Escalation** | Access admin functions as user |
| **Role Manipulation** | Modify role claims in tokens |
| **Path Traversal** | Access restricted paths |

#### Input Validation Tests

| Test | Payloads |
|------|----------|
| **SQL Injection** | `' OR '1'='1`, `UNION SELECT`, time-based |
| **XSS** | `<script>`, event handlers, SVG |
| **Command Injection** | `; ls`, `| cat /etc/passwd`, backticks |
| **SSTI** | `{{7*7}}`, `${7*7}`, `<%= %>` |
| **Path Traversal** | `../../../etc/passwd`, `....//` |

### Security Headers Analysis

| Header | Expected Value | Risk if Missing |
|--------|----------------|-----------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | MITM attacks |
| `Content-Security-Policy` | Restrictive policy | XSS attacks |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `X-XSS-Protection` | `1; mode=block` | XSS (legacy) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Information leak |
| `Permissions-Policy` | Restrictive | Feature abuse |

### Output

| Field | Description |
|-------|-------------|
| **Security Score** | 0-100 based on findings |
| **Findings by Severity** | Critical, High, Medium, Low, Info counts |
| **OWASP Breakdown** | Findings grouped by API Top 10 category |
| **Endpoint Results** | Per-endpoint test results |
| **Recommendations** | Prioritized remediation steps |

---

## Security Fuzzer

Web application fuzzing with 500+ built-in payloads.

### Features

| Feature | Description |
|---------|-------------|
| **500+ Payloads** | SQLi, XSS, command injection, path traversal |
| **Smart Detection** | Response analysis for vulnerability indicators |
| **Session Management** | Cookie handling, auth token refresh |
| **Rate Limiting** | Configurable request delay |
| **Parallel Requests** | Multi-threaded fuzzing |
| **Custom Payloads** | Import custom wordlists |

### Payload Categories

| Category | Count | Examples |
|----------|-------|----------|
| **SQL Injection** | 150+ | UNION, blind, time-based |
| **XSS** | 100+ | Reflected, DOM, polyglots |
| **Command Injection** | 50+ | Shell metacharacters, pipes |
| **Path Traversal** | 50+ | ../, encoding bypasses |
| **SSRF** | 30+ | Internal IPs, cloud metadata |
| **Template Injection** | 40+ | Jinja2, Freemarker, Twig |
| **XXE** | 20+ | External entity, parameter entities |
| **LDAP Injection** | 20+ | LDAP query manipulation |

### Detection Methods

| Method | Description |
|--------|-------------|
| **Response Diff** | Compare responses for anomalies |
| **Error Detection** | SQL errors, stack traces |
| **Time-Based** | Response time analysis |
| **Reflection** | Payload reflection in response |
| **OOB Callbacks** | Out-of-band data exfiltration |

### Agentic Fuzzer (AI-Powered Mode)

The Security Fuzzer includes an AI-powered Agentic mode for autonomous fuzzing with LLM decision making.

#### Agentic Features

| Feature | Description |
|---------|-------------|
| **LLM Decision Making** | AI decides next fuzzing steps |
| **Response Fingerprinting** | Tech stack detection |
| **WAF/IDS Detection** | Identify and evade protections |
| **Adaptive Payloads** | Mutate payloads based on responses |
| **Chain-of-Thought** | Reasoning about attack paths |
| **Multi-Step Attacks** | Orchestrated attack chains |
| **Blind Detection** | Time-based, OOB callback testing |
| **Session Persistence** | Save/resume fuzzing sessions |

#### AI Capabilities

| Capability | Description |
|------------|-------------|
| **Tech Detection** | Identify frameworks, languages, WAFs |
| **Payload Generation** | Context-aware payload creation |
| **Evasion Techniques** | Encoding, obfuscation, timing |
| **Attack Reasoning** | Explain why attacks work/fail |
| **PoC Generation** | Create proof-of-concept exploits |
| **CVSS Scoring** | Estimate finding severity |

#### Agentic Fuzzing Modes

| Mode | Description |
|------|-------------|
| **Discovery** | Find endpoints and parameters |
| **Targeted** | Focus on specific vulnerabilities |
| **Comprehensive** | Full attack surface coverage |
| **Stealth** | Low-and-slow to evade detection |

#### Integrated Services

- JWT Attack Service (algorithm confusion, key brute-force)
- HTTP Smuggling Detection
- OpenAPI Spec-Driven Fuzzing
- Out-of-Band (OOB) Callback Manager

---

## Binary Fuzzer

Coverage-guided binary fuzzing for native executables with AI-enhanced analysis.

### Fuzzing Engines

| Engine | Description | Best For |
|--------|-------------|----------|
| **AFL++** | American Fuzzy Lop++ (coverage-guided) | General purpose, well-instrumented binaries |
| **Honggfuzz** | Security-oriented fuzzer | Hardware-assisted coverage |
| **libFuzzer** | In-process coverage-guided | Library fuzzing |
| **Custom** | VRAgent's mutation engine | Quick testing without instrumentation |

### Mutation Strategies

| Strategy | Description | When Used |
|----------|-------------|-----------|
| **Bit Flip** | Flip individual bits | Finding bit-sensitive bugs |
| **Byte Flip** | Flip entire bytes | Magic value corruption |
| **Arithmetic** | Add/subtract from values | Integer overflow detection |
| **Interesting Values** | Boundary values (0, -1, MAX_INT) | Edge case testing |
| **Dictionary** | Token-based mutations | Format-aware fuzzing |
| **Havoc** | Random combination of mutations | Discovery phase |
| **Splice** | Combine two inputs | Exploring new paths |
| **Trim** | Minimize input size | Test case reduction |

### AI-Enhanced Features

#### Smart Seed Generation

AI analyzes the binary to create format-aware initial seeds:

| Analysis | Output |
|----------|--------|
| **Input Format Detection** | Identifies expected input format (text, binary, structured) |
| **Magic Bytes** | Generates seeds with correct file signatures |
| **Recommended Dictionary** | Extracts tokens for dictionary-based mutation |
| **Fuzzing Strategy** | Suggests optimal mutation strategy |
| **Target Analysis** | Identifies input-handling functions |

#### Coverage Advisor

AI monitors fuzzing campaigns and provides guidance:

| Feature | Description |
|---------|-------------|
| **Stuck Detection** | Identifies when coverage has plateaued |
| **Coverage Trend** | Tracks increasing, plateaued, or declining coverage |
| **Recommendations** | Suggests new seeds or strategy changes |
| **Priority Areas** | Identifies uncovered code regions |
| **Mutation Adjustments** | Recommends mutation parameter tuning |

#### Exploit Helper

AI provides deep crash analysis with exploitation guidance:

| Analysis | Description |
|----------|-------------|
| **Exploitability Score** | 0-1 score of exploitation likelihood |
| **Vulnerability Type** | Classification (buffer overflow, UAF, etc.) |
| **Root Cause Analysis** | Explains why the crash occurred |
| **Affected Functions** | Functions in crash path |
| **Exploitation Techniques** | Applicable techniques (ROP, heap spray) |
| **PoC Guidance** | Steps to develop proof-of-concept |
| **Mitigation Bypass** | How to bypass ASLR, DEP, canaries |
| **Similar CVEs** | Known CVEs with similar patterns |
| **Remediation** | Fix recommendations |

### Crash Analysis

| Type | Severity | Exploitability |
|------|----------|----------------|
| **Stack Buffer Overflow** | Critical | Exploitable - RIP/RET control |
| **Heap Corruption** | Critical | Exploitable - arbitrary write |
| **Use-After-Free** | Critical | Exploitable - type confusion |
| **Double Free** | Critical | Exploitable - heap control |
| **Format String** | Critical | Exploitable - arbitrary read/write |
| **Integer Overflow** | High | Probably Exploitable - size confusion |
| **Out-of-Bounds Read** | Medium | Information disclosure |
| **Null Pointer Deref** | Low | Probably Not Exploitable - DoS |
| **Divide by Zero** | Low | Not Exploitable - DoS |
| **Stack Exhaustion** | Low | Not Exploitable - DoS |
| **Assertion Failure** | Info | Not Exploitable - logic error |

### Exploitability Assessment

Crashes are classified using GRR/WinDbg-style severity:

| Level | Description | Examples |
|-------|-------------|----------|
| **Exploitable** | Direct code execution likely | Stack BOF with RIP control, heap corruption |
| **Probably Exploitable** | Code execution possible with effort | Partial overwrite, constrained write |
| **Probably Not Exploitable** | DoS only, no code execution | Null deref, divide by zero |
| **Not Exploitable** | Benign crash | Assertion, clean exit |
| **Unknown** | Needs manual analysis | Complex crash state |

### Features

| Feature | Description |
|---------|-------------|
| **Crash Deduplication** | Group crashes by stack trace hash |
| **Minidump Collection** | Capture Windows minidumps / Linux core dumps |
| **Stack Trace Analysis** | Symbolicated stack traces |
| **Behavior Monitoring** | File, registry, network, API call tracing |
| **Memory Safety** | AddressSanitizer (ASan) integration |
| **Coverage Tracking** | Block/edge coverage visualization |
| **Corpus Management** | Seed corpus organization and minimization |
| **Campaign Persistence** | Save/resume long-running campaigns |

### Coverage Visualization

| View | Description |
|------|-------------|
| **Heatmap** | Color-coded coverage by function |
| **Trend Chart** | Coverage growth over time |
| **Block Coverage** | Percentage of basic blocks hit |
| **Edge Coverage** | Percentage of control flow edges hit |
| **Uncovered Functions** | List of never-reached functions |

---

## MITM Workbench

AI-powered man-in-the-middle proxy for traffic interception, inspection, and modification.

### Features

| Feature | Description |
|---------|-------------|
| **HTTP/HTTPS Proxy** | Intercept web traffic with TLS termination |
| **WebSocket Inspection** | Frame-level WebSocket analysis and modification |
| **Certificate Generation** | Dynamic per-host certificate generation |
| **Rule-Based Modification** | Powerful rule engine for traffic modification |
| **AI Traffic Analysis** | Natural language rule creation and security analysis |
| **Real-Time Monitoring** | Live traffic view with filtering and search |
| **Session Recording** | Save, replay, and export traffic sessions |
| **Breakpoints** | Pause and manually modify requests/responses |

### AI-Powered Features

| Feature | Description |
|---------|-------------|
| **Natural Language Rules** | "Block all requests to tracking domains" converts to rule |
| **Auto Security Tests** | AI suggests injection points and test payloads |
| **Anomaly Detection** | Identify suspicious patterns (beaconing, exfil) |
| **Attack Suggestions** | Recommend MITM attack techniques based on traffic |
| **Session Analysis** | Summarize traffic patterns and security issues |

### WebSocket Deep Inspection

| Feature | Description |
|---------|-------------|
| **Frame Decoding** | Parse WebSocket frames (text, binary, control) |
| **Message Reconstruction** | Reassemble fragmented messages |
| **JSON Parsing** | Pretty-print JSON payloads |
| **Binary Analysis** | Hex view for binary frames |
| **Bidirectional View** | Client → Server and Server → Client |
| **Frame Modification** | Modify frames before forwarding |
| **Injection** | Inject custom frames into connection |

**WebSocket Opcodes Supported:**
- `0x0` Continuation
- `0x1` Text frame
- `0x2` Binary frame
- `0x8` Close
- `0x9` Ping
- `0xA` Pong

### Rule Engine

#### Rule Types

| Type | Description | Use Case |
|------|-------------|----------|
| **Block** | Drop matching requests | Block tracking/ads |
| **Modify Header** | Add/change/remove headers | Bypass restrictions |
| **Modify Body** | Alter request/response body | Inject payloads |
| **Delay** | Add latency (ms) | Test timeout handling |
| **Log** | Record matching traffic | Audit specific endpoints |
| **Replace** | String replacement | Protocol downgrade |
| **Redirect** | Change request destination | Redirect to attacker server |
| **Respond** | Return custom response | Mock API responses |

#### Rule Conditions

Rules support conditional matching:

```
# Match by URL pattern
url contains "/api/admin"

# Match by method
method == "POST"

# Match by header
headers["Authorization"] != ""

# Match by content type
content_type == "application/json"

# Combine conditions
method == "POST" and url contains "/login"
```

#### Rule Actions

| Action | Parameters | Example |
|--------|------------|---------|
| `set_header` | name, value | Add `X-Forwarded-For: 127.0.0.1` |
| `remove_header` | name | Remove `X-Frame-Options` |
| `replace_body` | find, replace | Replace `http://` with `https://` |
| `inject_script` | script | Inject `<script>alert(1)</script>` |
| `delay` | milliseconds | Delay by 5000ms |
| `block` | - | Drop the request |
| `log` | - | Log to session |

### Certificate Management

| Feature | Description |
|---------|-------------|
| **Auto CA Generation** | Creates root CA on first run |
| **Per-Host Certs** | Dynamic certificate generation for each host |
| **CA Export** | Export CA cert for browser/device installation |
| **Custom CA Import** | Use your own CA certificate |
| **Pinning Bypass** | Techniques for bypassing certificate pinning |

### Attack Techniques

The workbench supports these MITM attack scenarios:

| Attack | Description |
|--------|-------------|
| **SSL Stripping** | Downgrade HTTPS to HTTP |
| **Cookie Theft** | Capture session cookies |
| **Credential Interception** | Log login credentials |
| **Response Injection** | Inject malicious content |
| **Request Tampering** | Modify parameters in flight |
| **WebSocket Hijacking** | Inject messages into WS connections |
| **Protocol Downgrade** | Force use of weaker protocols |

### Session Management

| Feature | Description |
|---------|-------------|
| **Save Session** | Export captured traffic to file |
| **Load Session** | Import and replay saved sessions |
| **Export HAR** | Export as HTTP Archive format |
| **Export cURL** | Generate cURL commands for requests |
| **Filter History** | Search and filter captured traffic |
| **Clear Session** | Start fresh capture |

---

## OWASP ZAP Integration

Full integration with OWASP ZAP for DAST scanning.

### Scan Types

| Type | Description |
|------|-------------|
| **Spider** | Crawl application for endpoints |
| **AJAX Spider** | JavaScript-heavy application crawling |
| **Active Scan** | Probe for vulnerabilities |
| **Passive Scan** | Analyze traffic without active probing |
| **Full Scan** | Spider + Active + Passive |

### Authentication Methods

| Method | Description |
|--------|-------------|
| **Form-Based** | HTML form login |
| **HTTP Basic** | Basic authentication |
| **JSON-Based** | API token authentication |
| **Script-Based** | Custom authentication scripts |
| **Manual** | Pre-authenticated session |

### Alert Categories

| Risk Level | Examples |
|------------|----------|
| **High** | SQL injection, XSS, remote code execution |
| **Medium** | CSRF, clickjacking, insecure cookies |
| **Low** | Information disclosure, weak ciphers |
| **Informational** | Server banners, directory listing |

### Features

| Feature | Description |
|---------|-------------|
| **Scan Policies** | Custom scan configurations |
| **Context Management** | Scope and exclusions |
| **Alert Management** | Filter, export, false positive marking |
| **Session Handling** | Cookie and token management |
| **Report Export** | HTML, XML, JSON, Markdown |
| **API Integration** | Full ZAP API access |

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ZAP_URL` | ZAP API URL | `http://zap:8080` |
| `ZAP_API_KEY` | ZAP API key | (empty) |
| `NUCLEI_TEMPLATES_PATH` | Nuclei templates directory | `/nuclei-templates` |
| `OPENVAS_HOST` | OpenVAS/GVM host | `openvas` |
| `OPENVAS_PORT` | OpenVAS/GVM port | `9392` |

### Docker Services

| Service | Port | Description |
|---------|------|-------------|
| **ZAP** | 8090 | OWASP ZAP proxy |
| **Scanner** | 9999 | Nmap + Nuclei sidecar |
| **OpenVAS** | 9392 | Greenbone vulnerability scanner |

---

## Best Practices

### Before Scanning

1. **Get Authorization:** Ensure written permission for testing
2. **Define Scope:** Clearly identify in-scope targets
3. **Set Rate Limits:** Avoid overwhelming target systems
4. **Configure Authentication:** Set up credentials for authenticated scanning

### During Scanning

1. **Monitor Progress:** Watch for errors or blocks
2. **Check WAF Status:** Ensure you're not being blocked
3. **Review Early Findings:** Validate initial results
4. **Adjust Scope:** Refine based on discoveries

### After Scanning

1. **Verify Findings:** Manually confirm vulnerabilities
2. **Prioritize by Risk:** Focus on Critical/High first
3. **Document Evidence:** Save proof-of-concept details
4. **Generate Reports:** Export for stakeholders
5. **Link to Projects:** Save results to project for tracking

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **ZAP not connecting** | Check ZAP container: `docker compose logs zap` |
| **Nmap permission denied** | Some scans require root; use TCP connect scan |
| **OpenVAS slow to start** | First run downloads 50GB+ feeds; wait 10-15 mins |
| **Nuclei no results** | Update templates: `nuclei -update-templates` |
| **PCAP analysis fails** | Ensure scapy is installed; check file format |
| **SSL scan timeout** | Target may be blocking; try different port |
| **Fuzzer rate limited** | Reduce request rate; add delays |

---

## Related Documentation

- [Projects](PROJECT_README.md) - Linking dynamic scans to projects
- [Static Analysis](STATIC_ANALYSIS_README.md) - Source code scanning
- [Reverse Engineering](REVERSE_ENGINEERING_README.md) - Binary analysis
- [Learning Hub](LEARNING_HUB_README.md) - Network security guides
