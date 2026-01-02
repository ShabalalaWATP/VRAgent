import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  IconButton,
  Chip,
  Grid,
  TextField,
  InputAdornment,
  Tabs,
  Tab,
  List,
  ListItemButton,
  ListItemText,
  Divider,
  Card,
  CardContent,
  Button,
} from "@mui/material";
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import SearchIcon from "@mui/icons-material/Search";
import LearnPageLayout from "../components/LearnPageLayout";

// Page context for AI chat
const pageContext = `This is a comprehensive Cybersecurity Glossary page containing 300+ security terms organized by categories:
- Vulnerability Types (SQL Injection, XSS, CSRF, RCE, SSRF, XXE, Buffer Overflow, etc.)
- Security Concepts (Zero-Day, Attack Surface, Defense in Depth, Zero Trust, Threat Modeling, etc.)
- Frameworks & Standards (CVE, CWE, CVSS, EPSS, OWASP Top 10, MITRE ATT&CK, NIST, ISO 27001, etc.)
- Tools & Techniques (SAST, DAST, SCA, SBOM, Fuzzing, WAF, IDS, SIEM, etc.)
- Cryptography (Encryption, Hashing, PKI, TLS/SSL, Digital Signatures, AES, RSA, etc.)
- Attack Types (Phishing, Ransomware, DDoS, Supply Chain, Credential Stuffing, etc.)
- Incident Response (DFIR, IOC, IOA, Threat Hunting, SOC, Chain of Custody, etc.)
- Authentication & Access (MFA, SSO, OAuth, JWT, RBAC, IAM, Kerberos, etc.)
- Cloud Security (CSPM, CASB, Shared Responsibility, Container Security, etc.)
- Network Security (Firewall, IPS, VPN, Network Segmentation, DNS Security, etc.)
- Security Organizations & Groups (APT groups, government cyber units, security vendors)
- Security Tools (Ghidra, IDA Pro, Burp Suite, Metasploit, Wireshark, etc.)
- Operating Systems & Platforms (Kali Linux, Windows security, cloud platforms)
- Professional Disciplines (Red Team, Blue Team, Penetration Testing, Malware Analysis, etc.)
- Cyber Education & Certifications (OSCP, SANS courses, CompTIA, etc.)
- Emerging Technologies (Blockchain, Quantum Computing, 5G Security, Confidential Computing, etc.)
- Web3 Security (DeFi, Smart Contracts, Flash Loans, MEV, Cryptojacking, etc.)
- Privacy & Anonymity (Tor, VPN, Metadata, Differential Privacy, GDPR, etc.)
- Malware Types (RATs, Rootkits, Worms, Fileless Malware, Infostealers, etc.)
- ICS/OT Security (SCADA, PLCs, Modbus, Purdue Model, Air Gaps, etc.)
- Wireless Security (WPA3, KRACK, Evil Twin, IMSI Catcher, Bluetooth, etc.)
- API Security (BOLA, IDOR, Rate Limiting, GraphQL, OpenAPI, etc.)
- DevOps Security (CI/CD, GitOps, Secrets Management, Container Scanning, etc.)
- Data Security (DLP, Data Classification, Tokenization, Encryption at Rest, etc.)
- Identity Security (PAM, Federation, Machine Identity, Access Reviews, etc.)
- Risk & Compliance (HIPAA, CCPA, FedRAMP, Risk Assessment, Security Audit, etc.)
- Physical Security (Tailgating, Mantraps, Biometrics, CCTV, etc.)
- Security Testing (Black/White/Gray Box, Rules of Engagement, PoC, etc.)
Users can search terms, filter by category, and explore related terms.`;

interface GlossaryTerm {
  term: string;
  definition: string;
  category: string;
  relatedTerms?: string[];
}

const normalizeSearchText = (value: string) =>
  value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();

const buildSearchText = (term: GlossaryTerm) =>
  normalizeSearchText([term.term, term.definition, term.category, ...(term.relatedTerms ?? [])].join(" "));

const glossaryTerms: GlossaryTerm[] = [
  // Vulnerability Types
  { term: "SQL Injection (SQLi)", definition: "A code injection technique that exploits security vulnerabilities in an application's database layer. Attackers insert malicious SQL code into input fields to manipulate database queries, potentially accessing, modifying, or deleting data.", category: "Vulnerability Types", relatedTerms: ["NoSQL Injection", "Command Injection", "OWASP Top 10"] },
  { term: "Cross-Site Scripting (XSS)", definition: "A vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. Types include Stored XSS (persistent), Reflected XSS (non-persistent), and DOM-based XSS.", category: "Vulnerability Types", relatedTerms: ["DOM", "CSRF", "Content Security Policy"] },
  { term: "Cross-Site Request Forgery (CSRF)", definition: "An attack that tricks a victim's browser into executing unwanted actions on a web application where they're authenticated. Uses the victim's authenticated session to perform unauthorized actions.", category: "Vulnerability Types", relatedTerms: ["XSS", "Session Hijacking", "CSRF Token"] },
  { term: "Remote Code Execution (RCE)", definition: "A critical vulnerability that allows an attacker to execute arbitrary code on a target system remotely. Often the most severe type of vulnerability, leading to complete system compromise.", category: "Vulnerability Types", relatedTerms: ["Command Injection", "Deserialization", "Zero-Day"] },
  { term: "Server-Side Request Forgery (SSRF)", definition: "A vulnerability that allows attackers to induce the server-side application to make HTTP requests to an arbitrary domain. Can be used to access internal services or cloud metadata.", category: "Vulnerability Types", relatedTerms: ["XXE", "Open Redirect", "Cloud Metadata"] },
  { term: "XML External Entity (XXE)", definition: "An attack against applications that parse XML input, allowing attackers to access local files, perform SSRF attacks, or cause denial of service via recursive entity expansion.", category: "Vulnerability Types", relatedTerms: ["SSRF", "File Inclusion", "Billion Laughs Attack"] },
  { term: "Insecure Deserialization", definition: "A vulnerability where untrusted data is used to abuse the logic of an application's deserialization process, potentially leading to RCE, replay attacks, injection attacks, or privilege escalation.", category: "Vulnerability Types", relatedTerms: ["RCE", "Object Injection", "Serialization"] },
  { term: "Path Traversal", definition: "Also known as directory traversal, this vulnerability allows attackers to access files and directories stored outside the web root folder by manipulating file path references (e.g., using ../)", category: "Vulnerability Types", relatedTerms: ["File Inclusion", "LFI", "RFI"] },
  { term: "Buffer Overflow", definition: "A vulnerability where a program writes more data to a buffer than it can hold, potentially overwriting adjacent memory. Can lead to crashes, data corruption, or code execution.", category: "Vulnerability Types", relatedTerms: ["Stack Overflow", "Heap Overflow", "Memory Corruption"] },
  { term: "Race Condition", definition: "A vulnerability that occurs when the timing or ordering of events affects a program's correctness. In security contexts, can lead to privilege escalation or bypassing security checks.", category: "Vulnerability Types", relatedTerms: ["TOCTOU", "Concurrency", "Deadlock"] },
  { term: "NoSQL Injection", definition: "An injection attack targeting NoSQL databases (MongoDB, CouchDB, etc.) by manipulating query operators. Similar to SQLi but uses JSON/JavaScript syntax to bypass authentication or extract data.", category: "Vulnerability Types", relatedTerms: ["SQL Injection", "MongoDB", "Operator Injection"] },
  { term: "LDAP Injection", definition: "An attack where malicious LDAP statements are inserted into queries used for user authentication or directory lookups, potentially bypassing authentication or exposing sensitive directory information.", category: "Vulnerability Types", relatedTerms: ["Injection", "Active Directory", "Authentication Bypass"] },
  { term: "Command Injection", definition: "A vulnerability where an application passes unsafe user data to a system shell, allowing attackers to execute arbitrary operating system commands on the server.", category: "Vulnerability Types", relatedTerms: ["RCE", "OS Command Injection", "Shell Injection"] },
  { term: "Template Injection (SSTI)", definition: "Server-Side Template Injection occurs when user input is unsafely embedded in server-side templates, allowing attackers to inject template directives that execute on the server.", category: "Vulnerability Types", relatedTerms: ["RCE", "Jinja2", "Twig", "Code Injection"] },
  { term: "Local File Inclusion (LFI)", definition: "A vulnerability that allows attackers to include local files from the server, potentially exposing sensitive files like /etc/passwd or application configuration files.", category: "Vulnerability Types", relatedTerms: ["Path Traversal", "RFI", "File Disclosure"] },
  { term: "Remote File Inclusion (RFI)", definition: "A vulnerability that allows attackers to include remote files from external servers, often leading to remote code execution by including malicious scripts.", category: "Vulnerability Types", relatedTerms: ["LFI", "RCE", "PHP Include"] },
  { term: "Clickjacking", definition: "A UI redressing attack where users are tricked into clicking hidden elements by overlaying invisible frames over legitimate content, potentially triggering unintended actions.", category: "Vulnerability Types", relatedTerms: ["UI Redressing", "X-Frame-Options", "CSP"] },
  { term: "Open Redirect", definition: "A vulnerability where an application redirects users to arbitrary URLs based on user-controllable input, often used in phishing attacks to make malicious links appear legitimate.", category: "Vulnerability Types", relatedTerms: ["Phishing", "URL Validation", "SSRF"] },
  { term: "HTTP Request Smuggling", definition: "An attack that exploits differences in how front-end and back-end servers parse HTTP requests, allowing attackers to smuggle requests and bypass security controls.", category: "Vulnerability Types", relatedTerms: ["HTTP/2", "CL.TE", "TE.CL"] },
  { term: "Prototype Pollution", definition: "A JavaScript vulnerability where attackers modify Object.prototype to inject properties that affect all objects, potentially leading to denial of service or RCE.", category: "Vulnerability Types", relatedTerms: ["JavaScript", "__proto__", "Object Injection"] },
  
  // Security Concepts
  { term: "Zero-Day", definition: "A vulnerability that is unknown to the software vendor and for which no patch exists. Called 'zero-day' because developers have had zero days to fix it since discovery.", category: "Security Concepts", relatedTerms: ["Exploit", "CVE", "Patch Management"] },
  { term: "Attack Surface", definition: "The sum of all points (attack vectors) where an unauthorized user can try to enter data to or extract data from an environment. Reducing attack surface is a key security strategy.", category: "Security Concepts", relatedTerms: ["Attack Vector", "Defense in Depth", "Hardening"] },
  { term: "Defense in Depth", definition: "A layered security approach using multiple security controls throughout an IT system. If one layer fails, others still provide protection. Based on military strategy of the same name.", category: "Security Concepts", relatedTerms: ["Attack Surface", "Security Controls", "Risk Management"] },
  { term: "Principle of Least Privilege", definition: "A security concept requiring that users, programs, and processes are given only the minimum access rights needed to perform their functions. Limits damage from accidents or attacks.", category: "Security Concepts", relatedTerms: ["Access Control", "Privilege Escalation", "Zero Trust"] },
  { term: "Zero Trust", definition: "A security model that requires strict identity verification for every person and device trying to access resources, regardless of whether they're inside or outside the network perimeter.", category: "Security Concepts", relatedTerms: ["Least Privilege", "Network Segmentation", "IAM"] },
  { term: "Threat Modeling", definition: "A process for identifying potential threats, vulnerabilities, and attack vectors to a system, then prioritizing mitigations. Common frameworks include STRIDE and PASTA.", category: "Security Concepts", relatedTerms: ["Risk Assessment", "STRIDE", "Attack Surface"] },
  { term: "Penetration Testing", definition: "An authorized simulated cyberattack on a computer system to evaluate its security. Tests identify vulnerabilities that could be exploited by attackers. Also called 'pen testing' or 'ethical hacking'.", category: "Security Concepts", relatedTerms: ["Vulnerability Assessment", "Red Team", "Bug Bounty"] },
  { term: "Security by Design", definition: "An approach where security is considered from the initial design phase of a system, rather than being added as an afterthought. Leads to more robust and maintainable security.", category: "Security Concepts", relatedTerms: ["Secure SDLC", "Shift Left", "DevSecOps"] },
  { term: "Hardening", definition: "The process of securing a system by reducing its attack surface. Includes disabling unnecessary services, removing default accounts, applying patches, and implementing security configurations.", category: "Security Concepts", relatedTerms: ["Attack Surface", "CIS Benchmarks", "Configuration Management"] },
  { term: "Security Posture", definition: "The overall security status of an organization's software, hardware, networks, services, and related practices. A strong security posture indicates robust defenses against threats.", category: "Security Concepts", relatedTerms: ["Risk Management", "Compliance", "Maturity Model"] },
  { term: "CIA Triad", definition: "The three core principles of information security: Confidentiality (data is protected from unauthorized access), Integrity (data is accurate and unaltered), and Availability (data is accessible when needed).", category: "Security Concepts", relatedTerms: ["Information Security", "Data Protection", "AAA"] },
  { term: "Non-Repudiation", definition: "A security concept ensuring that a party in a transaction cannot deny having performed an action. Typically achieved through digital signatures, logging, and audit trails.", category: "Security Concepts", relatedTerms: ["Digital Signature", "Audit Trail", "Accountability"] },
  { term: "Security Through Obscurity", definition: "A security approach that relies on keeping system details secret to provide protection. Generally considered a weak strategy when used alone, as secrets are often discovered.", category: "Security Concepts", relatedTerms: ["Defense in Depth", "Open Design", "Kerckhoffs's Principle"] },
  { term: "Lateral Movement", definition: "The techniques attackers use to progressively move through a network after initial access, searching for sensitive data and high-value targets.", category: "Security Concepts", relatedTerms: ["Pivoting", "Post-Exploitation", "Kill Chain"] },
  { term: "Persistence", definition: "Techniques that adversaries use to maintain their foothold on systems across restarts, credential changes, or other interruptions that could cut off their access.", category: "Security Concepts", relatedTerms: ["Backdoor", "Scheduled Task", "Registry Keys"] },
  
  // Frameworks & Standards
  { term: "CVE (Common Vulnerabilities and Exposures)", definition: "A list of publicly disclosed computer security vulnerabilities. Each CVE has a unique identifier (e.g., CVE-2021-44228) that provides a standardized way to reference vulnerabilities.", category: "Frameworks & Standards", relatedTerms: ["NVD", "CVSS", "CWE"] },
  { term: "CWE (Common Weakness Enumeration)", definition: "A community-developed list of common software and hardware weakness types. Unlike CVE (specific instances), CWE categorizes types of vulnerabilities (e.g., CWE-79 for XSS).", category: "Frameworks & Standards", relatedTerms: ["CVE", "OWASP Top 10", "SANS Top 25"] },
  { term: "CVSS (Common Vulnerability Scoring System)", definition: "A standardized framework for rating the severity of security vulnerabilities. Scores range from 0.0 to 10.0, with 10.0 being most severe. CVSS v3.1 is the current version.", category: "Frameworks & Standards", relatedTerms: ["CVE", "EPSS", "Severity Rating"] },
  { term: "EPSS (Exploit Prediction Scoring System)", definition: "A model that estimates the probability that a vulnerability will be exploited in the wild within the next 30 days. Helps prioritize patching based on actual risk, not just CVSS score.", category: "Frameworks & Standards", relatedTerms: ["CVSS", "Risk Prioritization", "Threat Intelligence"] },
  { term: "OWASP Top 10", definition: "A regularly updated list of the ten most critical web application security risks, published by the Open Web Application Security Project. Industry standard reference for web security.", category: "Frameworks & Standards", relatedTerms: ["Injection", "Broken Authentication", "XSS"] },
  { term: "MITRE ATT&CK", definition: "A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. Used for threat modeling, detection development, and security assessments.", category: "Frameworks & Standards", relatedTerms: ["Kill Chain", "TTPs", "Threat Intelligence"] },
  { term: "Cyber Kill Chain", definition: "Developed by Lockheed Martin, a framework describing the stages of a cyberattack: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, C2, and Actions on Objectives.", category: "Frameworks & Standards", relatedTerms: ["MITRE ATT&CK", "Incident Response", "Defense in Depth"] },
  { term: "NIST Cybersecurity Framework", definition: "A set of guidelines and best practices for managing cybersecurity risk. Organized around five functions: Identify, Protect, Detect, Respond, and Recover.", category: "Frameworks & Standards", relatedTerms: ["Risk Management", "Compliance", "Controls"] },
  { term: "ISO 27001", definition: "An international standard for information security management systems (ISMS). Provides requirements for establishing, implementing, maintaining, and continually improving an ISMS.", category: "Frameworks & Standards", relatedTerms: ["ISMS", "Compliance", "Security Controls"] },
  { term: "SOC 2", definition: "A compliance framework developed by AICPA for service organizations, focusing on five trust service principles: Security, Availability, Processing Integrity, Confidentiality, and Privacy.", category: "Frameworks & Standards", relatedTerms: ["Compliance", "Audit", "Trust Services"] },
  { term: "PCI DSS", definition: "Payment Card Industry Data Security Standard - a set of security standards designed to ensure all companies that process, store, or transmit credit card information maintain a secure environment.", category: "Frameworks & Standards", relatedTerms: ["Compliance", "Payment Security", "Cardholder Data"] },
  { term: "STRIDE", definition: "A threat modeling framework identifying six categories: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.", category: "Frameworks & Standards", relatedTerms: ["Threat Modeling", "Security Design", "Risk Assessment"] },
  { term: "CIS Benchmarks", definition: "Consensus-based configuration guidelines developed by the Center for Internet Security. Provide secure configuration recommendations for operating systems, cloud providers, and applications.", category: "Frameworks & Standards", relatedTerms: ["Hardening", "Configuration Management", "Security Baseline"] },
  
  // Tools & Techniques
  { term: "Static Application Security Testing (SAST)", definition: "Analyzing source code, bytecode, or binary code to identify security vulnerabilities without executing the program. 'White-box' testing that finds issues early in development.", category: "Tools & Techniques", relatedTerms: ["DAST", "SCA", "Code Review"] },
  { term: "Dynamic Application Security Testing (DAST)", definition: "Testing a running application for vulnerabilities by simulating attacks. 'Black-box' testing that finds runtime issues like injection flaws and authentication problems.", category: "Tools & Techniques", relatedTerms: ["SAST", "IAST", "Web Scanner"] },
  { term: "Software Composition Analysis (SCA)", definition: "Identifying open source and third-party components in a codebase, then detecting known vulnerabilities, licensing issues, and outdated dependencies.", category: "Tools & Techniques", relatedTerms: ["SBOM", "Dependency", "Supply Chain"] },
  { term: "Fuzzing", definition: "An automated testing technique that provides invalid, unexpected, or random data as input to a program to discover bugs, crashes, and security vulnerabilities.", category: "Tools & Techniques", relatedTerms: ["Testing", "Buffer Overflow", "Input Validation"] },
  { term: "Code Review", definition: "Systematic examination of source code to find security vulnerabilities, bugs, and code quality issues. Can be manual or assisted by automated tools.", category: "Tools & Techniques", relatedTerms: ["SAST", "Peer Review", "Security Audit"] },
  { term: "Web Application Firewall (WAF)", definition: "A security solution that monitors, filters, and blocks HTTP traffic to and from a web application. Protects against common attacks like XSS, SQLi, and CSRF.", category: "Tools & Techniques", relatedTerms: ["Firewall", "IDS/IPS", "DDoS Protection"] },
  { term: "Intrusion Detection System (IDS)", definition: "A device or software that monitors network traffic for suspicious activity and known threats, sending alerts when potential incidents are detected.", category: "Tools & Techniques", relatedTerms: ["IPS", "SIEM", "Network Security"] },
  { term: "Security Information and Event Management (SIEM)", definition: "Technology that aggregates and analyzes security data from across an organization's IT infrastructure, providing real-time analysis and alerts for security events.", category: "Tools & Techniques", relatedTerms: ["Log Management", "SOC", "Incident Response"] },
  { term: "IAST (Interactive Application Security Testing)", definition: "Security testing that works from within the application, using software instrumentation to combine SAST and DAST elements for more accurate results.", category: "Tools & Techniques", relatedTerms: ["SAST", "DAST", "Runtime Analysis"] },
  { term: "Burp Suite", definition: "An integrated platform for web application security testing. Includes proxy, scanner, intruder, repeater, and various other tools for manual and automated testing.", category: "Tools & Techniques", relatedTerms: ["Proxy", "Web Testing", "DAST"] },
  { term: "Nmap", definition: "Network Mapper - a free and open-source network scanning tool used for host discovery, port scanning, service detection, and vulnerability assessment.", category: "Tools & Techniques", relatedTerms: ["Port Scanning", "Service Detection", "Reconnaissance"] },
  { term: "Metasploit", definition: "A penetration testing framework that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.", category: "Tools & Techniques", relatedTerms: ["Exploitation", "Payload", "Pen Testing"] },
  { term: "Wireshark", definition: "A free and open-source packet analyzer used for network troubleshooting, analysis, protocol development, and security testing.", category: "Tools & Techniques", relatedTerms: ["Packet Capture", "Network Analysis", "Protocol Analysis"] },
  { term: "Hashcat", definition: "An advanced password recovery utility supporting multiple hash types and attack modes including dictionary, brute-force, and rule-based attacks. Supports GPU acceleration.", category: "Tools & Techniques", relatedTerms: ["Password Cracking", "Hash", "Rainbow Tables"] },
  { term: "Hydra", definition: "A fast and flexible network login cracker supporting numerous protocols including SSH, FTP, HTTP, LDAP, SMB, and many others for brute-force attacks.", category: "Tools & Techniques", relatedTerms: ["Brute Force", "Password Cracking", "Authentication"] },
  
  // Cryptography
  { term: "Encryption", definition: "The process of converting information into a secure format that can only be read with the correct decryption key. Protects data confidentiality at rest and in transit.", category: "Cryptography", relatedTerms: ["Decryption", "AES", "RSA", "TLS"] },
  { term: "Hashing", definition: "A one-way function that converts data into a fixed-size string of characters (hash). Used for password storage, data integrity verification, and digital signatures.", category: "Cryptography", relatedTerms: ["SHA-256", "bcrypt", "Salt", "Collision"] },
  { term: "Public Key Infrastructure (PKI)", definition: "A framework for managing digital certificates and public-key encryption. Enables secure communication and identity verification through certificate authorities.", category: "Cryptography", relatedTerms: ["SSL/TLS", "Digital Certificate", "CA"] },
  { term: "TLS/SSL", definition: "Transport Layer Security (TLS) and its predecessor Secure Sockets Layer (SSL) are cryptographic protocols providing secure communication over networks. HTTPS uses TLS.", category: "Cryptography", relatedTerms: ["HTTPS", "Certificate", "PKI"] },
  { term: "Digital Signature", definition: "A cryptographic mechanism that provides authentication, integrity, and non-repudiation for digital messages or documents. Based on asymmetric cryptography.", category: "Cryptography", relatedTerms: ["PKI", "Hashing", "Non-repudiation"] },
  { term: "Salt", definition: "Random data added to a password before hashing to prevent rainbow table attacks and ensure identical passwords have different hashes.", category: "Cryptography", relatedTerms: ["Hashing", "bcrypt", "Password Security"] },
  { term: "Symmetric Encryption", definition: "Encryption where the same key is used for both encryption and decryption. Fast and efficient for large data. Examples: AES, DES, ChaCha20.", category: "Cryptography", relatedTerms: ["AES", "Key Management", "Block Cipher"] },
  { term: "Asymmetric Encryption", definition: "Encryption using a key pair: public key for encryption and private key for decryption. Enables secure key exchange. Examples: RSA, ECC, Diffie-Hellman.", category: "Cryptography", relatedTerms: ["RSA", "Public Key", "Private Key", "PKI"] },
  { term: "AES (Advanced Encryption Standard)", definition: "A symmetric block cipher adopted as the encryption standard by the US government. Uses 128, 192, or 256-bit keys. Widely used for securing sensitive data.", category: "Cryptography", relatedTerms: ["Symmetric Encryption", "Block Cipher", "Encryption"] },
  { term: "RSA", definition: "Rivest-Shamir-Adleman - an asymmetric cryptographic algorithm used for secure data transmission. Based on the mathematical difficulty of factoring large prime numbers.", category: "Cryptography", relatedTerms: ["Asymmetric Encryption", "Public Key", "Digital Signature"] },
  { term: "SHA (Secure Hash Algorithm)", definition: "A family of cryptographic hash functions (SHA-1, SHA-256, SHA-3). SHA-256 is widely used for password hashing, digital signatures, and blockchain.", category: "Cryptography", relatedTerms: ["Hashing", "MD5", "Integrity"] },
  { term: "bcrypt", definition: "A password hashing function designed to be computationally expensive, making brute-force attacks slow. Includes built-in salting and adjustable work factor.", category: "Cryptography", relatedTerms: ["Password Hashing", "Salt", "Argon2"] },
  { term: "Argon2", definition: "The winner of the 2015 Password Hashing Competition. Memory-hard function resistant to GPU and ASIC attacks. Recommended for new password hashing implementations.", category: "Cryptography", relatedTerms: ["bcrypt", "Password Hashing", "Key Derivation"] },
  { term: "Key Derivation Function (KDF)", definition: "A function that derives one or more secret keys from a secret value like a password. Examples include PBKDF2, bcrypt, scrypt, and Argon2.", category: "Cryptography", relatedTerms: ["Password Hashing", "PBKDF2", "Key Stretching"] },
  { term: "Certificate Authority (CA)", definition: "A trusted entity that issues digital certificates, verifying the identity of certificate holders. Part of the PKI hierarchy that enables HTTPS.", category: "Cryptography", relatedTerms: ["PKI", "SSL/TLS", "X.509"] },
  { term: "X.509", definition: "An ITU standard for public key certificates, defining the format used by TLS/SSL certificates. Contains public key, identity, and CA signature.", category: "Cryptography", relatedTerms: ["Certificate", "PKI", "CA"] },
  { term: "HMAC", definition: "Hash-based Message Authentication Code - a construction for creating a message authentication code using a cryptographic hash function and a secret key.", category: "Cryptography", relatedTerms: ["MAC", "Integrity", "Authentication"] },
  { term: "Elliptic Curve Cryptography (ECC)", definition: "An approach to public-key cryptography based on elliptic curves over finite fields. Provides equivalent security to RSA with smaller key sizes.", category: "Cryptography", relatedTerms: ["Asymmetric Encryption", "ECDSA", "Key Exchange"] },
  
  // Attack Types
  { term: "Phishing", definition: "A social engineering attack using fraudulent communications (email, SMS, phone) that appear to come from a trusted source to trick victims into revealing sensitive information.", category: "Attack Types", relatedTerms: ["Spear Phishing", "Whaling", "Social Engineering"] },
  { term: "Spear Phishing", definition: "A targeted phishing attack directed at specific individuals or organizations, using personalized information to increase credibility and success rate.", category: "Attack Types", relatedTerms: ["Phishing", "Whaling", "BEC"] },
  { term: "Ransomware", definition: "Malware that encrypts a victim's files and demands a ransom payment for the decryption key. Modern variants often also exfiltrate data (double extortion).", category: "Attack Types", relatedTerms: ["Malware", "Extortion", "Backup"] },
  { term: "DDoS (Distributed Denial of Service)", definition: "An attack that overwhelms a target with traffic from multiple sources, making it unavailable to legitimate users. Uses botnets of compromised devices.", category: "Attack Types", relatedTerms: ["DoS", "Botnet", "Availability"] },
  { term: "Man-in-the-Middle (MitM)", definition: "An attack where the attacker secretly intercepts and possibly alters communications between two parties who believe they're communicating directly.", category: "Attack Types", relatedTerms: ["ARP Spoofing", "SSL Stripping", "TLS"] },
  { term: "Supply Chain Attack", definition: "An attack that targets less-secure elements in a supply chain to compromise a primary target. Includes compromising software updates, third-party services, or hardware.", category: "Attack Types", relatedTerms: ["SolarWinds", "Dependency Confusion", "Third-Party Risk"] },
  { term: "Credential Stuffing", definition: "An attack using previously stolen username/password pairs to gain unauthorized access to accounts. Exploits password reuse across multiple services.", category: "Attack Types", relatedTerms: ["Password Spraying", "Brute Force", "MFA"] },
  { term: "Privilege Escalation", definition: "The act of exploiting a vulnerability to gain elevated access to resources that are normally protected. Can be vertical (higher privileges) or horizontal (other users).", category: "Attack Types", relatedTerms: ["Least Privilege", "Access Control", "Root"] },
  { term: "Password Spraying", definition: "A brute-force attack that tries a single password against many accounts before moving to the next password. Avoids account lockouts while testing common passwords.", category: "Attack Types", relatedTerms: ["Credential Stuffing", "Brute Force", "Lockout Bypass"] },
  { term: "Whaling", definition: "A highly targeted phishing attack aimed at senior executives or high-profile individuals. Uses carefully crafted messages impersonating trusted entities.", category: "Attack Types", relatedTerms: ["Spear Phishing", "BEC", "CEO Fraud"] },
  { term: "Business Email Compromise (BEC)", definition: "A sophisticated scam targeting businesses by impersonating executives or vendors via email to authorize fraudulent wire transfers or divulge sensitive information.", category: "Attack Types", relatedTerms: ["Whaling", "Wire Fraud", "Social Engineering"] },
  { term: "Brute Force Attack", definition: "A trial-and-error method to decode passwords or encryption keys by systematically checking all possible combinations until the correct one is found.", category: "Attack Types", relatedTerms: ["Dictionary Attack", "Password Cracking", "Rate Limiting"] },
  { term: "Dictionary Attack", definition: "A password attack that uses a list of common words, phrases, and previously leaked passwords rather than trying every possible combination.", category: "Attack Types", relatedTerms: ["Brute Force", "Wordlist", "Password Policy"] },
  { term: "Rainbow Table Attack", definition: "A precomputed table attack for cracking password hashes. Tables contain hash-password pairs for rapid lookup. Defeated by salting.", category: "Attack Types", relatedTerms: ["Hash Cracking", "Salt", "Precomputation"] },
  { term: "Kerberoasting", definition: "An attack against Active Directory where an attacker requests service tickets for service accounts and cracks them offline to reveal passwords.", category: "Attack Types", relatedTerms: ["Active Directory", "SPN", "Offline Cracking"] },
  { term: "Pass-the-Hash", definition: "An attack technique where an attacker captures a password hash and uses it to authenticate without needing to crack it. Common in Windows environments.", category: "Attack Types", relatedTerms: ["NTLM", "Mimikatz", "Lateral Movement"] },
  { term: "Golden Ticket Attack", definition: "A post-exploitation technique where attackers forge Kerberos TGT tickets to gain unrestricted access to an Active Directory domain.", category: "Attack Types", relatedTerms: ["Kerberos", "Active Directory", "Persistence"] },
  { term: "DNS Poisoning", definition: "An attack that corrupts DNS cache data, causing the name server to return incorrect IP addresses and divert traffic to malicious sites.", category: "Attack Types", relatedTerms: ["DNS Spoofing", "Cache Poisoning", "DNSSEC"] },
  { term: "ARP Spoofing", definition: "An attack where malicious ARP messages are sent to associate the attacker's MAC address with a legitimate IP address, enabling traffic interception.", category: "Attack Types", relatedTerms: ["MitM", "Network Sniffing", "Layer 2 Attack"] },
  
  // Incident Response
  { term: "Incident Response", definition: "The organized approach to addressing and managing the aftermath of a security breach or cyberattack. Goals include limiting damage and reducing recovery time and costs.", category: "Incident Response", relatedTerms: ["DFIR", "SOC", "Playbook"] },
  { term: "Digital Forensics", definition: "The process of uncovering and interpreting electronic data for use in investigations. Preserves evidence in a way that is legally admissible.", category: "Incident Response", relatedTerms: ["Incident Response", "Chain of Custody", "Evidence"] },
  { term: "IOC (Indicator of Compromise)", definition: "Forensic artifacts that indicate a potential intrusion or malicious activity. Examples include malicious IP addresses, file hashes, domain names, or unusual network traffic.", category: "Incident Response", relatedTerms: ["IOA", "Threat Intelligence", "Detection"] },
  { term: "IOA (Indicator of Attack)", definition: "Signs that an attack is currently occurring, focusing on intent and behavior rather than artifacts. More proactive than IOCs, which typically indicate past compromise.", category: "Incident Response", relatedTerms: ["IOC", "Threat Hunting", "Detection"] },
  { term: "Threat Hunting", definition: "The proactive search through networks and datasets to detect threats that evade existing security solutions. Assumes existing defenses have been bypassed.", category: "Incident Response", relatedTerms: ["SIEM", "IOC", "Threat Intelligence"] },
  { term: "Playbook", definition: "A documented set of procedures and steps to follow when responding to specific security incidents. Ensures consistent, efficient response across the team.", category: "Incident Response", relatedTerms: ["Runbook", "SOP", "Automation"] },
  { term: "Security Operations Center (SOC)", definition: "A centralized unit that deals with security issues on an organizational and technical level. Monitors, detects, analyzes, and responds to cybersecurity incidents.", category: "Incident Response", relatedTerms: ["SIEM", "Incident Response", "Monitoring"] },
  { term: "Chain of Custody", definition: "The documented chronological history of evidence handling. Critical in forensic investigations to ensure evidence integrity and admissibility in legal proceedings.", category: "Incident Response", relatedTerms: ["Digital Forensics", "Evidence", "Legal"] },
  { term: "Triage", definition: "The process of quickly assessing and prioritizing security incidents based on severity, impact, and urgency. Helps allocate limited resources effectively.", category: "Incident Response", relatedTerms: ["Incident Response", "Severity", "Priority"] },
  { term: "Root Cause Analysis (RCA)", definition: "A method of problem-solving used to identify the underlying causes of an incident. Helps prevent recurrence by addressing fundamental issues rather than symptoms.", category: "Incident Response", relatedTerms: ["Post-Mortem", "Lessons Learned", "Remediation"] },
  { term: "Mean Time to Detect (MTTD)", definition: "The average time it takes to identify a security incident. A key metric for measuring the effectiveness of security monitoring and detection capabilities.", category: "Incident Response", relatedTerms: ["MTTR", "KPI", "Detection"] },
  { term: "Mean Time to Respond (MTTR)", definition: "The average time between detecting a security incident and containing or resolving it. Critical metric for measuring incident response effectiveness.", category: "Incident Response", relatedTerms: ["MTTD", "KPI", "Response"] },
  
  // Authentication & Access
  { term: "Multi-Factor Authentication (MFA)", definition: "An authentication method requiring two or more verification factors: something you know (password), something you have (token), or something you are (biometric).", category: "Authentication & Access", relatedTerms: ["2FA", "TOTP", "SSO"] },
  { term: "Single Sign-On (SSO)", definition: "An authentication scheme allowing users to log in once and gain access to multiple related systems without re-authenticating. Improves user experience and can enhance security.", category: "Authentication & Access", relatedTerms: ["SAML", "OAuth", "Identity Provider"] },
  { term: "OAuth 2.0", definition: "An authorization framework that enables applications to obtain limited access to user accounts on HTTP services. Commonly used for 'Sign in with Google/Facebook' features.", category: "Authentication & Access", relatedTerms: ["OIDC", "JWT", "API Security"] },
  { term: "JWT (JSON Web Token)", definition: "A compact, URL-safe means of representing claims to be transferred between two parties. Often used for authentication and information exchange in web applications.", category: "Authentication & Access", relatedTerms: ["OAuth", "Session", "Token"] },
  { term: "RBAC (Role-Based Access Control)", definition: "An access control method where permissions are assigned to roles, and users are assigned to roles. Simplifies permission management in large organizations.", category: "Authentication & Access", relatedTerms: ["ABAC", "Least Privilege", "IAM"] },
  { term: "Identity and Access Management (IAM)", definition: "A framework of policies and technologies ensuring the right individuals have appropriate access to technology resources. Includes authentication, authorization, and user lifecycle management.", category: "Authentication & Access", relatedTerms: ["SSO", "MFA", "Directory Service"] },
  { term: "SAML", definition: "Security Assertion Markup Language - an XML-based standard for exchanging authentication and authorization data between identity providers and service providers for SSO.", category: "Authentication & Access", relatedTerms: ["SSO", "Identity Provider", "Federation"] },
  { term: "OpenID Connect (OIDC)", definition: "An identity layer on top of OAuth 2.0 that allows clients to verify user identity and obtain basic profile information. Simpler than SAML for modern applications.", category: "Authentication & Access", relatedTerms: ["OAuth", "SSO", "ID Token"] },
  { term: "LDAP", definition: "Lightweight Directory Access Protocol - a protocol for accessing and maintaining distributed directory information services. Commonly used for centralized authentication.", category: "Authentication & Access", relatedTerms: ["Active Directory", "Directory Service", "Authentication"] },
  { term: "Active Directory", definition: "Microsoft's directory service for Windows domain networks. Provides authentication, authorization, and centralized management of users, computers, and resources.", category: "Authentication & Access", relatedTerms: ["LDAP", "Kerberos", "Domain Controller"] },
  { term: "Kerberos", definition: "A network authentication protocol using secret-key cryptography and a trusted third party (KDC). Used by Active Directory and provides mutual authentication.", category: "Authentication & Access", relatedTerms: ["Active Directory", "TGT", "Authentication"] },
  { term: "TOTP (Time-based One-Time Password)", definition: "An algorithm that generates one-time passwords based on current time. Used in authenticator apps for MFA. Typically generates 6-8 digit codes every 30 seconds.", category: "Authentication & Access", relatedTerms: ["MFA", "2FA", "HOTP"] },
  { term: "ABAC (Attribute-Based Access Control)", definition: "An access control model where permissions are granted based on attributes of users, resources, and environment. More flexible than RBAC for complex policies.", category: "Authentication & Access", relatedTerms: ["RBAC", "Policy", "Authorization"] },
  { term: "Session Fixation", definition: "An attack where an attacker sets a user's session ID before authentication, then hijacks the session after the user logs in with that fixed ID.", category: "Authentication & Access", relatedTerms: ["Session Hijacking", "Cookie", "Authentication"] },
  { term: "Session Hijacking", definition: "An attack where an attacker takes over a user's session after they've authenticated, typically by stealing or predicting the session token.", category: "Authentication & Access", relatedTerms: ["Session Fixation", "Cookie Theft", "XSS"] },
  
  // Cloud Security
  { term: "Cloud Security Posture Management (CSPM)", definition: "Tools and practices for identifying misconfigurations and compliance risks in cloud environments. Continuously monitors cloud infrastructure against security policies.", category: "Cloud Security", relatedTerms: ["Cloud Security", "Misconfiguration", "Compliance"] },
  { term: "Cloud Access Security Broker (CASB)", definition: "Security policy enforcement points placed between cloud service users and providers. Enforces security policies, provides visibility, and protects data in the cloud.", category: "Cloud Security", relatedTerms: ["Shadow IT", "DLP", "Cloud Security"] },
  { term: "Shared Responsibility Model", definition: "A cloud security framework clarifying which security tasks are handled by the cloud provider vs. the customer. Varies by service type (IaaS, PaaS, SaaS).", category: "Cloud Security", relatedTerms: ["Cloud Security", "IaaS", "PaaS", "SaaS"] },
  { term: "Instance Metadata Service (IMDS)", definition: "A service in cloud environments providing instance metadata to running instances. SSRF attacks often target IMDS to retrieve credentials and sensitive configuration.", category: "Cloud Security", relatedTerms: ["SSRF", "Cloud Credentials", "AWS IMDSv2"] },
  { term: "Infrastructure as Code (IaC)", definition: "Managing and provisioning infrastructure through machine-readable configuration files rather than manual processes. Examples: Terraform, CloudFormation, Bicep.", category: "Cloud Security", relatedTerms: ["Terraform", "DevOps", "Configuration Management"] },
  { term: "Container Security", definition: "Practices and tools for securing containerized applications throughout the development lifecycle. Includes image scanning, runtime protection, and orchestration security.", category: "Cloud Security", relatedTerms: ["Docker", "Kubernetes", "Container Scanning"] },
  { term: "Kubernetes Security", definition: "Security practices for protecting Kubernetes clusters, including RBAC, network policies, pod security standards, secrets management, and admission controllers.", category: "Cloud Security", relatedTerms: ["Container Security", "RBAC", "Pod Security"] },
  { term: "Serverless Security", definition: "Security considerations specific to serverless computing (Functions as a Service). Includes function permissions, dependency vulnerabilities, and event injection attacks.", category: "Cloud Security", relatedTerms: ["FaaS", "AWS Lambda", "Azure Functions"] },
  
  // Network Security
  { term: "Firewall", definition: "A network security device that monitors and filters incoming and outgoing network traffic based on predetermined security rules. Can be hardware or software-based.", category: "Network Security", relatedTerms: ["WAF", "IDS/IPS", "Network Segmentation"] },
  { term: "Intrusion Prevention System (IPS)", definition: "A network security device that monitors network traffic, detects potential threats, and automatically takes action to prevent them. Active version of IDS.", category: "Network Security", relatedTerms: ["IDS", "Firewall", "Inline Security"] },
  { term: "Network Segmentation", definition: "Dividing a network into smaller segments or subnets to improve security and reduce attack surface. Limits lateral movement if one segment is compromised.", category: "Network Security", relatedTerms: ["VLAN", "Microsegmentation", "Zero Trust"] },
  { term: "VPN (Virtual Private Network)", definition: "Technology that creates a secure, encrypted connection over a less secure network. Used for remote access and site-to-site connectivity.", category: "Network Security", relatedTerms: ["Encryption", "Remote Access", "Tunneling"] },
  { term: "DMZ (Demilitarized Zone)", definition: "A network segment that sits between trusted internal networks and untrusted external networks, typically hosting public-facing services like web servers.", category: "Network Security", relatedTerms: ["Firewall", "Network Segmentation", "Perimeter Security"] },
  { term: "Proxy Server", definition: "An intermediary server that separates end users from the websites they browse. Provides anonymity, caching, content filtering, and security benefits.", category: "Network Security", relatedTerms: ["Reverse Proxy", "WAF", "Load Balancer"] },
  { term: "DNS Security Extensions (DNSSEC)", definition: "A suite of extensions adding security to the DNS protocol by enabling DNS responses to be authenticated, protecting against DNS cache poisoning.", category: "Network Security", relatedTerms: ["DNS", "DNS Poisoning", "Authentication"] },
  { term: "Port Scanning", definition: "The process of probing a server or host for open ports. Used in reconnaissance to discover services and potential vulnerabilities.", category: "Network Security", relatedTerms: ["Nmap", "Reconnaissance", "Service Discovery"] },

  // Security Organizations & Groups
  { term: "Mandiant", definition: "Cybersecurity company specializing in incident response and threat intelligence, now part of Google Cloud. Known for front-line breach response and detailed APT reporting.", category: "Security Organizations & Groups", relatedTerms: ["Incident Response", "Threat Intelligence", "Google Cloud"] },
  { term: "CrowdStrike Falcon OverWatch", definition: "CrowdStrike's managed threat hunting team that delivers 24/7 detection, investigation, and response across the Falcon platform.", category: "Security Organizations & Groups", relatedTerms: ["EDR", "Threat Hunting", "SOC"] },
  { term: "Unit 42 (Palo Alto Networks)", definition: "Threat intelligence and incident response arm of Palo Alto Networks, publishing research on malware, cloud threats, and APT activity.", category: "Security Organizations & Groups", relatedTerms: ["Threat Intelligence", "Incident Response", "Palo Alto Networks"] },
  { term: "Microsoft Threat Intelligence (MSTIC)", definition: "Microsoft's threat intelligence team tracking nation-state and criminal actors, shipping detections across Windows, Azure, and Microsoft 365.", category: "Security Organizations & Groups", relatedTerms: ["Threat Intelligence", "Cloud Security", "Vulnerability Disclosure"] },
  { term: "Cisco Talos Intelligence Group", definition: "Cisco's threat research and response team that produces Snort signatures, malware analyses, and coordinated vulnerability disclosures.", category: "Security Organizations & Groups", relatedTerms: ["Threat Intelligence", "IDS/IPS", "Malware Analysis"] },
  { term: "IBM X-Force", definition: "IBM Security's research and incident response team providing threat intelligence, red teaming, and breach response services.", category: "Security Organizations & Groups", relatedTerms: ["Incident Response", "Threat Intelligence", "SOC"] },
  { term: "Kaspersky GReAT", definition: "Kaspersky's Global Research & Analysis Team renowned for in-depth APT investigations, reverse engineering, and malware tracking.", category: "Security Organizations & Groups", relatedTerms: ["Threat Intelligence", "Malware Analysis", "APT"] },
  { term: "Secureworks Counter Threat Unit (CTU)", definition: "Secureworks' research group that tracks threat actors, publishes indicators, and develops countermeasures for customers.", category: "Security Organizations & Groups", relatedTerms: ["Threat Intelligence", "Detection Engineering", "CTU"] },
  { term: "Recorded Future Insikt Group", definition: "Recorded Future's research team producing threat intelligence reports, indicators, and actor profiles derived from their intelligence platform.", category: "Security Organizations & Groups", relatedTerms: ["Threat Intelligence", "Threat Hunting", "Intelligence"] },
  { term: "Dragos Threat Operations Center", definition: "Industrial control system-focused threat hunting and incident response team at Dragos, specializing in OT environments.", category: "Security Organizations & Groups", relatedTerms: ["ICS", "OT Security", "Threat Hunting"] },
  { term: "Google Threat Analysis Group (TAG)", definition: "Google's security team that tracks government-backed attackers, abuse campaigns, and zero-day exploitation targeting Google users.", category: "Security Organizations & Groups", relatedTerms: ["Threat Intelligence", "Zero-Day", "Google"] },
  { term: "NCC Group", definition: "Global cybersecurity consultancy providing penetration testing, red teaming, product security reviews, and incident response services.", category: "Security Organizations & Groups", relatedTerms: ["Penetration Testing", "Red Team", "Consulting"] },
  { term: "Rapid7 MDR", definition: "Rapid7's managed detection and response team delivering continuous monitoring, investigation, and threat containment for customers.", category: "Security Organizations & Groups", relatedTerms: ["Detection", "Response", "SOC"] },
  { term: "Symantec Threat Hunter Team", definition: "Broadcom/Symantec research group that develops endpoint detection content and publishes intelligence on emerging threats.", category: "Security Organizations & Groups", relatedTerms: ["Endpoint Security", "Threat Intelligence", "Malware Analysis"] },
  { term: "FIRST (Forum of Incident Response and Security Teams)", definition: "International association of CSIRTs that promotes incident response coordination, best practices, and information sharing.", category: "Security Organizations & Groups", relatedTerms: ["Incident Response", "CSIRT", "Information Sharing"] },
  { term: "US Cyber Command (USCYBERCOM)", definition: "Unified command of the U.S. Department of Defense responsible for planning, coordinating, and conducting military cyberspace operations.", category: "Security Organizations & Groups", relatedTerms: ["Military Cyber", "Offensive Security", "Defense"] },
  { term: "National Security Agency (NSA)", definition: "U.S. signals intelligence and cybersecurity agency that conducts foreign SIGINT collection and provides defensive guidance through the Cybersecurity Directorate.", category: "Security Organizations & Groups", relatedTerms: ["SIGINT", "USCYBERCOM", "Cyber Defense"] },
  { term: "Cybersecurity and Infrastructure Security Agency (CISA)", definition: "U.S. federal agency tasked with protecting civilian government networks and critical infrastructure, issuing advisories, directives, and incident support.", category: "Security Organizations & Groups", relatedTerms: ["US-CERT", "Incident Response", "Critical Infrastructure"] },
  { term: "FBI Cyber Division", definition: "Federal Bureau of Investigation unit that investigates cyber crime, nation-state intrusions, and ransomware campaigns.", category: "Security Organizations & Groups", relatedTerms: ["Law Enforcement", "Cyber Crime", "Attribution"] },
  { term: "Government Communications Headquarters (GCHQ)", definition: "UK signals intelligence and cybersecurity agency that delivers intelligence, defensive operations, and national cyber strategy support.", category: "Security Organizations & Groups", relatedTerms: ["SIGINT", "NCSC", "UK"] },
  { term: "National Cyber Security Centre (NCSC - UK)", definition: "Public-facing part of GCHQ providing guidance, incident response, and threat reporting for UK organizations and critical infrastructure.", category: "Security Organizations & Groups", relatedTerms: ["GCHQ", "Guidance", "Incident Response"] },
  { term: "ENISA", definition: "European Union Agency for Cybersecurity that develops policy support, threat landscape reports, and guidance across EU member states.", category: "Security Organizations & Groups", relatedTerms: ["EU", "Policy", "NIS2"] },
  { term: "NATO Cooperative Cyber Defence Centre of Excellence (CCDCOE)", definition: "Multinational NATO-accredited center in Tallinn focused on cyber defense research, training, and exercises like Locked Shields.", category: "Security Organizations & Groups", relatedTerms: ["NATO", "Exercises", "Policy"] },
  { term: "CERT-EU", definition: "Computer Emergency Response Team for EU institutions, agencies, and bodies, providing incident handling, alerts, and coordination.", category: "Security Organizations & Groups", relatedTerms: ["CSIRT", "EU", "Incident Response"] },
  { term: "Australian Signals Directorate (ASD)", definition: "Australia's signals intelligence and cyber defense agency responsible for offensive and defensive cyber operations.", category: "Security Organizations & Groups", relatedTerms: ["SIGINT", "ACSC", "Military Cyber"] },
  { term: "Australian Cyber Security Centre (ACSC)", definition: "Part of ASD that provides public advisories, incident response coordination, and threat intelligence for Australia.", category: "Security Organizations & Groups", relatedTerms: ["ASD", "CERT", "Guidance"] },
  { term: "Unit 8200", definition: "Israeli Defense Forces signals intelligence and cyber unit known for intelligence collection, codebreaking, and cyber operations expertise.", category: "Security Organizations & Groups", relatedTerms: ["SIGINT", "Military Cyber", "Israel"] },
  { term: "PLA Unit 61398 (APT1)", definition: "People's Liberation Army unit publicly associated by researchers with extensive cyber espionage campaigns against Western companies.", category: "Security Organizations & Groups", relatedTerms: ["China", "APT1", "Cyber Espionage"] },
  { term: "Reconnaissance General Bureau (RGB)", definition: "North Korea's intelligence agency that oversees many DPRK cyber operations alongside traditional military intelligence activities.", category: "Security Organizations & Groups", relatedTerms: ["DPRK", "Lazarus Group", "Cyber Espionage"] },
  { term: "APT28 (Fancy Bear)", definition: "Russia-linked threat actor associated with GRU Unit 26165, known for cyber espionage, credential phishing, and information operations.", category: "Security Organizations & Groups", relatedTerms: ["GRU", "Cyber Espionage", "Spear Phishing"] },
  { term: "APT29 (Cozy Bear)", definition: "Russia-linked espionage group assessed to be connected to the SVR, targeting governments, think tanks, and technology suppliers.", category: "Security Organizations & Groups", relatedTerms: ["SVR", "Supply Chain Attack", "Spear Phishing"] },
  { term: "Sandworm Team", definition: "Threat actor tied to Russia's GRU Unit 74455, responsible for disruptive operations like BlackEnergy, Industroyer, and NotPetya.", category: "Security Organizations & Groups", relatedTerms: ["GRU", "ICS", "Destructive Malware"] },
  { term: "Lazarus Group", definition: "North Korean state-sponsored group linked to espionage and financially motivated attacks, including SWIFT heists and cryptocurrency theft.", category: "Security Organizations & Groups", relatedTerms: ["DPRK", "APT", "Supply Chain Attack"] },
  { term: "APT41 (Wicked Panda)", definition: "China-based group that blends state-sponsored espionage with financially motivated intrusions across healthcare, gaming, and telecom sectors.", category: "Security Organizations & Groups", relatedTerms: ["China", "Supply Chain Attack", "Dual-Use"] },
  { term: "Hafnium", definition: "Chinese state-linked threat actor that exploited Microsoft Exchange Server zero-days in 2021 to deploy web shells and exfiltrate email.", category: "Security Organizations & Groups", relatedTerms: ["Zero-Day", "Web Shell", "China"] },
  { term: "FIN7 (Carbanak Group)", definition: "Financially motivated criminal group indicted for point-of-sale intrusions, ransomware affiliate work, and sophisticated phishing campaigns.", category: "Security Organizations & Groups", relatedTerms: ["Cyber Crime", "Ransomware", "Phishing"] },
  { term: "Wizard Spider", definition: "Cybercrime syndicate behind TrickBot and the Ryuk/Conti ransomware operations, focused on big-game hunting extortion.", category: "Security Organizations & Groups", relatedTerms: ["Ransomware", "Botnet", "Initial Access"] },
  { term: "LAPSUS$", definition: "Loose extortion group known for SIM swapping, insider recruitment, and leaking source code from major technology companies.", category: "Security Organizations & Groups", relatedTerms: ["Extortion", "Social Engineering", "Insider Threat"] },
  { term: "Evil Corp", definition: "Cybercrime group sanctioned by the U.S. for developing Dridex/Bugat banking malware and later pivoting to ransomware activity.", category: "Security Organizations & Groups", relatedTerms: ["Banking Malware", "Ransomware", "Financial Crime"] },
  { term: "Charming Kitten (APT35)", definition: "Iran-aligned threat actor focused on credential theft and surveillance via spear-phishing, fake login portals, and social engineering.", category: "Security Organizations & Groups", relatedTerms: ["Iran", "Phishing", "Credential Theft"] },
  { term: "Turla (Snake)", definition: "Russia-linked espionage group known for stealthy backdoors like Snake/Uroburos and long-term persistence in diplomatic networks.", category: "Security Organizations & Groups", relatedTerms: ["Rootkit", "Russia", "Cyber Espionage"] },
  { term: "Equation Group", definition: "Highly sophisticated actor widely believed by researchers to be tied to U.S. NSA operations, associated with advanced implants like Stuxnet and Flame.", category: "Security Organizations & Groups", relatedTerms: ["Advanced Malware", "SIGINT", "Zero-Day"] },

  // UK Military & Government Cyber Units
  { term: "National Cyber Force (NCF)", definition: "UK's offensive cyber operations unit jointly run by GCHQ and Ministry of Defence. Established in 2020, conducts operations to disrupt hostile state activities, counter terrorism, and combat serious crime in cyberspace. Headquarters in Samlesbury, Lancashire.", category: "Security Organizations & Groups", relatedTerms: ["GCHQ", "UK", "Offensive Cyber", "NCSC"] },
  { term: "13th Signal Regiment", definition: "British Army regiment providing tactical communication and electronic warfare support. Contains specialist cyber and signals intelligence capabilities for deployed operations.", category: "Security Organizations & Groups", relatedTerms: ["British Army", "Signals", "Electronic Warfare", "UK"] },
  { term: "224 Signal Squadron - Cyber Protection Team (CPT)", definition: "Specialist cyber protection team within 13th Signal Regiment providing defensive cyber operations for the British Army. Conducts vulnerability assessments, incident response, and network defense for deployed military systems.", category: "Security Organizations & Groups", relatedTerms: ["13th Signal Regiment", "British Army", "Defensive Cyber", "UK"] },
  { term: "Defence Cyber Operations Centre (DCOC) - Corsham", definition: "UK Ministry of Defence cyber operations hub located at MOD Corsham. Provides 24/7 monitoring, threat intelligence, and incident response for Defence networks. Houses Defence SOC capabilities.", category: "Security Organizations & Groups", relatedTerms: ["MOD", "SOC", "UK", "Incident Response"] },
  { term: "14th Signal Regiment (Electronic Warfare)", definition: "British Army regiment specialising in electronic warfare and signals intelligence. Provides tactical EW support including jamming, direction finding, and electronic attack capabilities.", category: "Security Organizations & Groups", relatedTerms: ["British Army", "Electronic Warfare", "SIGINT", "UK"] },
  { term: "21st Signal Regiment (Air Support)", definition: "British Army regiment providing communications and electronic warfare support to air operations. Works closely with RAF on integrated air defence and tactical communications.", category: "Security Organizations & Groups", relatedTerms: ["British Army", "RAF", "Air Support", "UK"] },
  { term: "77th Brigade", definition: "British Army formation specialising in information operations, psychological operations, and influence activities. Conducts counter-disinformation and strategic communications in support of military operations.", category: "Security Organizations & Groups", relatedTerms: ["Information Operations", "PSYOPS", "British Army", "UK"] },
  { term: "Joint Forces Cyber Group (JFCyG)", definition: "UK Joint Force component responsible for coordinating cyber operations across all three services (Army, Navy, RAF). Integrates offensive, defensive, and enabling cyber capabilities.", category: "Security Organizations & Groups", relatedTerms: ["NCF", "UK", "Joint Operations", "Cyber Operations"] },
  { term: "1st Intelligence, Surveillance and Reconnaissance Brigade", definition: "British Army brigade combining intelligence, surveillance, target acquisition, and reconnaissance (ISTAR) capabilities including cyber and electronic warfare elements.", category: "Security Organizations & Groups", relatedTerms: ["British Army", "Intelligence", "ISTAR", "UK"] },
  { term: "Royal Corps of Signals", definition: "British Army corps responsible for military communications, electronic warfare, and cyber operations. Provides the Army's primary cyber and signals capability.", category: "Security Organizations & Groups", relatedTerms: ["British Army", "Communications", "Cyber", "UK"] },
  { term: "Defence Intelligence (DI)", definition: "UK Ministry of Defence intelligence organisation providing strategic intelligence assessment and support to defence operations. Works alongside GCHQ and MI6 on national security matters.", category: "Security Organizations & Groups", relatedTerms: ["MOD", "Intelligence", "UK", "GCHQ"] },

  // US Military & Government Cyber Units (Additional)
  { term: "NSA Tailored Access Operations (TAO)", definition: "Elite hacking unit within the NSA responsible for offensive cyber operations and intelligence collection. Develops custom implants and exploits for computer network exploitation.", category: "Security Organizations & Groups", relatedTerms: ["NSA", "Offensive Cyber", "CNE", "US"] },
  { term: "Cyber National Mission Force (CNMF)", definition: "U.S. Cyber Command's primary force for defending the nation against strategic cyber threats. Conducts operations to disrupt adversary cyberspace operations.", category: "Security Organizations & Groups", relatedTerms: ["USCYBERCOM", "US", "Defensive Cyber", "National Security"] },
  { term: "780th Military Intelligence Brigade (Cyber)", definition: "U.S. Army's premier cyber operations unit providing offensive cyber, defensive cyber, and signals intelligence capabilities in support of Army and joint operations.", category: "Security Organizations & Groups", relatedTerms: ["US Army", "USCYBERCOM", "Cyber Operations", "US"] },
  { term: "Fleet Cyber Command (U.S. 10th Fleet)", definition: "U.S. Navy's cyber operations command responsible for Navy network operations, offensive and defensive cyber operations, and space operations.", category: "Security Organizations & Groups", relatedTerms: ["US Navy", "USCYBERCOM", "Cyber Operations", "US"] },
  { term: "24th Air Force (Cyber)", definition: "U.S. Air Force component providing cyber forces to U.S. Cyber Command. Responsible for Air Force network operations and cyber warfare capabilities.", category: "Security Organizations & Groups", relatedTerms: ["USAF", "USCYBERCOM", "Cyber Operations", "US"] },
  { term: "Marine Corps Forces Cyberspace Command (MARFORCYBER)", definition: "U.S. Marine Corps component to USCYBERCOM providing offensive and defensive cyber capabilities for Marine Corps and joint operations.", category: "Security Organizations & Groups", relatedTerms: ["USMC", "USCYBERCOM", "Cyber Operations", "US"] },
  { term: "Defense Information Systems Agency (DISA)", definition: "U.S. Department of Defense agency providing IT and communications support to the military. Operates DoD networks and provides cybersecurity services.", category: "Security Organizations & Groups", relatedTerms: ["DOD", "Networks", "US", "Communications"] },

  // Other Five Eyes Cyber Units
  { term: "Canadian Centre for Cyber Security (CCCS)", definition: "Canada's national authority on cybersecurity, part of the Communications Security Establishment (CSE). Provides guidance, threat intelligence, and incident response for Canadian government and critical infrastructure.", category: "Security Organizations & Groups", relatedTerms: ["Canada", "Five Eyes", "CERT", "CSE"] },
  { term: "Communications Security Establishment (CSE)", definition: "Canada's signals intelligence agency responsible for foreign SIGINT collection and cybersecurity. Equivalent to NSA/GCHQ in the Five Eyes alliance.", category: "Security Organizations & Groups", relatedTerms: ["Canada", "SIGINT", "Five Eyes", "CCCS"] },
  { term: "Canadian Forces Information Operations Group (CFIOG)", definition: "Canadian Armed Forces unit responsible for information operations, cyber operations, and electronic warfare capabilities.", category: "Security Organizations & Groups", relatedTerms: ["Canada", "Military Cyber", "CAF", "Information Operations"] },
  { term: "New Zealand Government Communications Security Bureau (GCSB)", definition: "New Zealand's signals intelligence and cybersecurity agency. Part of Five Eyes alliance, provides SIGINT and cyber security services.", category: "Security Organizations & Groups", relatedTerms: ["New Zealand", "Five Eyes", "SIGINT", "Cybersecurity"] },
  { term: "New Zealand National Cyber Security Centre (NCSC-NZ)", definition: "New Zealand's government cyber security centre within GCSB. Provides threat advisories, incident response, and security guidance for critical infrastructure.", category: "Security Organizations & Groups", relatedTerms: ["New Zealand", "GCSB", "CERT", "Five Eyes"] },

  // European Cyber Organisations
  { term: "Agence Nationale de la Sécurité des Systèmes d'Information (ANSSI)", definition: "France's national cybersecurity agency responsible for defending government networks, certifying security products, and providing guidance. Reports to the Secretary-General for National Defence.", category: "Security Organizations & Groups", relatedTerms: ["France", "Government Cyber", "Certification", "EU"] },
  { term: "Commandement de la Cyberdéfense (COMCYBER)", definition: "French Armed Forces cyber command responsible for military cyber operations, both offensive and defensive. Subordinate to the Chief of Defence Staff.", category: "Security Organizations & Groups", relatedTerms: ["France", "Military Cyber", "Offensive Cyber", "EU"] },
  { term: "Direction Générale de la Sécurité Extérieure (DGSE)", definition: "France's external intelligence agency responsible for foreign intelligence collection including SIGINT and cyber operations. French equivalent of CIA/MI6.", category: "Security Organizations & Groups", relatedTerms: ["France", "Intelligence", "SIGINT", "Cyber Espionage"] },
  { term: "Bundesamt für Sicherheit in der Informationstechnik (BSI)", definition: "Germany's Federal Office for Information Security. National cybersecurity authority providing standards, certifications, and incident response for government and critical infrastructure.", category: "Security Organizations & Groups", relatedTerms: ["Germany", "Government Cyber", "Standards", "EU"] },
  { term: "Kommando Cyber- und Informationsraum (KdoCIR)", definition: "German Armed Forces Cyber and Information Domain Command. Responsible for military cyber operations, electronic warfare, and information operations.", category: "Security Organizations & Groups", relatedTerms: ["Germany", "Military Cyber", "Bundeswehr", "EU"] },
  { term: "Bundesnachrichtendienst (BND)", definition: "Germany's foreign intelligence service responsible for SIGINT and cyber intelligence collection. Works with Five Eyes partners on joint operations.", category: "Security Organizations & Groups", relatedTerms: ["Germany", "Intelligence", "SIGINT", "EU"] },
  { term: "Nationaal Cyber Security Centrum (NCSC-NL)", definition: "Netherlands' national cyber security centre. Provides threat intelligence, incident coordination, and security guidance for Dutch government and critical infrastructure.", category: "Security Organizations & Groups", relatedTerms: ["Netherlands", "CERT", "EU", "Critical Infrastructure"] },
  { term: "Algemene Inlichtingen- en Veiligheidsdienst (AIVD)", definition: "Netherlands' domestic intelligence and security service with significant cyber intelligence capabilities. Known for advanced technical operations.", category: "Security Organizations & Groups", relatedTerms: ["Netherlands", "Intelligence", "Cyber", "EU"] },
  { term: "Militaire Inlichtingen- en Veiligheidsdienst (MIVD)", definition: "Netherlands' military intelligence and security service providing SIGINT and cyber intelligence for Dutch armed forces.", category: "Security Organizations & Groups", relatedTerms: ["Netherlands", "Military Intelligence", "SIGINT", "EU"] },
  { term: "Försvarets Radioanstalt (FRA)", definition: "Sweden's National Defence Radio Establishment responsible for signals intelligence and information security. Supports both military and civilian government agencies.", category: "Security Organizations & Groups", relatedTerms: ["Sweden", "SIGINT", "EU", "Cybersecurity"] },
  { term: "Estonian Information System Authority (RIA)", definition: "Estonia's government agency responsible for cybersecurity and digital infrastructure. Estonia is a NATO cyber defence leader following 2007 attacks.", category: "Security Organizations & Groups", relatedTerms: ["Estonia", "EU", "NATO", "e-Government"] },
  { term: "Polish Military Counterintelligence Service (SKW)", definition: "Polish military intelligence service with cyber capabilities protecting Polish armed forces from foreign intelligence and cyber threats.", category: "Security Organizations & Groups", relatedTerms: ["Poland", "Military Intelligence", "NATO", "EU"] },

  // Asia-Pacific Cyber Units
  { term: "Japan Self-Defense Forces Cyber Defense Command", definition: "Japanese military cyber command established in 2022. Responsible for defending SDF networks and developing offensive cyber capabilities amid regional tensions.", category: "Security Organizations & Groups", relatedTerms: ["Japan", "JSDF", "Military Cyber", "Asia-Pacific"] },
  { term: "National Center of Incident Readiness and Strategy for Cybersecurity (NISC)", definition: "Japan's national cybersecurity coordination centre. Develops national cyber strategy and coordinates incident response across government.", category: "Security Organizations & Groups", relatedTerms: ["Japan", "Government Cyber", "CERT", "Asia-Pacific"] },
  { term: "Republic of Korea Cyber Operations Command", definition: "South Korean military cyber command responsible for defending military networks and conducting cyber operations against North Korean threats.", category: "Security Organizations & Groups", relatedTerms: ["South Korea", "Military Cyber", "DPRK", "Asia-Pacific"] },
  { term: "National Intelligence Service (NIS - South Korea)", definition: "South Korea's primary intelligence agency with significant cyber capabilities focused on North Korean threats and regional intelligence.", category: "Security Organizations & Groups", relatedTerms: ["South Korea", "Intelligence", "DPRK", "Cyber"] },
  { term: "Singapore Cyber Security Agency (CSA)", definition: "Singapore's national agency overseeing cybersecurity strategy, operations, and ecosystem development. Leads national cyber incident response.", category: "Security Organizations & Groups", relatedTerms: ["Singapore", "Government Cyber", "CERT", "Asia-Pacific"] },
  { term: "Defence Cyber Organisation (DCO - Singapore)", definition: "Singapore Armed Forces cyber command responsible for military cyber operations and defending SAF digital infrastructure.", category: "Security Organizations & Groups", relatedTerms: ["Singapore", "Military Cyber", "SAF", "Asia-Pacific"] },
  { term: "Taiwan National Security Bureau", definition: "Taiwan's national intelligence agency with cyber operations capabilities focused on PRC threats and regional security.", category: "Security Organizations & Groups", relatedTerms: ["Taiwan", "Intelligence", "PRC", "Cyber"] },
  { term: "Indian Computer Emergency Response Team (CERT-In)", definition: "India's national CERT responsible for cybersecurity incident response, vulnerability disclosure, and threat warnings for Indian cyberspace.", category: "Security Organizations & Groups", relatedTerms: ["India", "CERT", "Government Cyber", "Asia-Pacific"] },
  { term: "Defence Cyber Agency (DCA - India)", definition: "Indian tri-service cyber command responsible for military cyber operations across Army, Navy, and Air Force.", category: "Security Organizations & Groups", relatedTerms: ["India", "Military Cyber", "Tri-Service", "Asia-Pacific"] },
  { term: "National Technical Research Organisation (NTRO - India)", definition: "India's technical intelligence agency responsible for SIGINT, imagery intelligence, and cyber operations. Reports to the National Security Advisor.", category: "Security Organizations & Groups", relatedTerms: ["India", "Intelligence", "SIGINT", "Cyber"] },

  // Russian & Chinese Cyber Units (Known)
  { term: "GRU (Main Intelligence Directorate)", definition: "Russian military intelligence agency operating multiple cyber units including Units 26165 (APT28), 74455 (Sandworm), and 29155. Conducts cyber espionage and disruptive operations globally.", category: "Security Organizations & Groups", relatedTerms: ["Russia", "APT28", "Sandworm", "Military Intelligence"] },
  { term: "SVR (Foreign Intelligence Service)", definition: "Russia's foreign intelligence service responsible for cyber espionage operations targeting governments and industry. Associated with APT29/Cozy Bear.", category: "Security Organizations & Groups", relatedTerms: ["Russia", "APT29", "Intelligence", "Cyber Espionage"] },
  { term: "FSB (Federal Security Service)", definition: "Russia's domestic security service with significant cyber capabilities including the FSB Center 16 (Berserk Bear) and Center 18. Conducts domestic surveillance and foreign cyber operations.", category: "Security Organizations & Groups", relatedTerms: ["Russia", "Intelligence", "Domestic Security", "Cyber"] },
  { term: "PLA Strategic Support Force (SSF)", definition: "Chinese military organisation consolidating space, cyber, electronic warfare, and psychological operations. Contains the former 3PLA (SIGINT) and 4PLA (EW) capabilities.", category: "Security Organizations & Groups", relatedTerms: ["China", "PLA", "SIGINT", "Cyber Operations"] },
  { term: "Ministry of State Security (MSS - China)", definition: "China's intelligence and security agency responsible for counter-intelligence and foreign intelligence including cyber espionage. Associated with multiple APT groups.", category: "Security Organizations & Groups", relatedTerms: ["China", "Intelligence", "APT", "Cyber Espionage"] },
  { term: "Cyberspace Administration of China (CAC)", definition: "Chinese government agency responsible for internet regulation, censorship, and cybersecurity policy. Implements the Great Firewall and data security regulations.", category: "Security Organizations & Groups", relatedTerms: ["China", "Regulation", "Censorship", "Policy"] },

  // Other Notable Cyber Units
  { term: "Iranian Islamic Revolutionary Guard Corps (IRGC) Cyber", definition: "Iranian cyber operations capability within the IRGC conducting espionage, disruptive attacks, and influence operations against regional adversaries and the West.", category: "Security Organizations & Groups", relatedTerms: ["Iran", "APT33", "APT34", "Military Cyber"] },
  { term: "Bureau 121 (North Korea)", definition: "North Korean cyber warfare unit under the Reconnaissance General Bureau. Estimated 6,000+ hackers conducting financial theft, espionage, and destructive attacks globally.", category: "Security Organizations & Groups", relatedTerms: ["DPRK", "Lazarus Group", "Cyber Crime", "RGB"] },
  { term: "Vietnam People's Army Cyber Command", definition: "Vietnamese military cyber capability conducting espionage operations primarily targeting regional governments and dissidents.", category: "Security Organizations & Groups", relatedTerms: ["Vietnam", "Military Cyber", "APT32", "Asia-Pacific"] },
  { term: "APT32 (OceanLotus)", definition: "Vietnam-linked threat actor conducting cyber espionage against foreign governments, journalists, and dissidents. Known for sophisticated social engineering and custom malware.", category: "Security Organizations & Groups", relatedTerms: ["Vietnam", "Cyber Espionage", "APT", "Southeast Asia"] },
  { term: "APT33 (Elfin)", definition: "Iran-linked threat actor targeting aerospace, energy, and government sectors. Known for destructive wiper malware and infrastructure attacks.", category: "Security Organizations & Groups", relatedTerms: ["Iran", "Cyber Espionage", "Wiper", "Critical Infrastructure"] },
  { term: "APT34 (OilRig)", definition: "Iran-linked threat actor focusing on Middle Eastern governments, financial institutions, and critical infrastructure. Uses spear-phishing and custom backdoors.", category: "Security Organizations & Groups", relatedTerms: ["Iran", "Cyber Espionage", "Middle East", "APT"] },
  { term: "APT38", definition: "North Korean threat actor specialising in financial theft from banks via SWIFT network attacks. Responsible for Bangladesh Bank heist and other major financial crimes.", category: "Security Organizations & Groups", relatedTerms: ["DPRK", "Financial Crime", "SWIFT", "Lazarus Group"] },
  { term: "APT40 (Leviathan)", definition: "China-linked threat actor targeting maritime industries, defence contractors, and regional governments. Associated with Hainan State Security Department.", category: "Security Organizations & Groups", relatedTerms: ["China", "MSS", "Maritime", "Cyber Espionage"] },
  { term: "Kimsuky", definition: "North Korean threat actor conducting espionage against South Korean government, think tanks, and individuals. Known for credential theft and social engineering.", category: "Security Organizations & Groups", relatedTerms: ["DPRK", "South Korea", "Credential Theft", "APT"] },
  { term: "Gamaredon", definition: "Russia-linked threat actor primarily targeting Ukrainian government and military. One of the most active groups in the Russia-Ukraine cyber conflict.", category: "Security Organizations & Groups", relatedTerms: ["Russia", "Ukraine", "FSB", "Cyber Espionage"] },
  { term: "Volt Typhoon", definition: "China-linked threat actor targeting U.S. critical infrastructure including communications, energy, and water sectors. Uses living-off-the-land techniques for stealth.", category: "Security Organizations & Groups", relatedTerms: ["China", "Critical Infrastructure", "APT", "US"] },
  { term: "Salt Typhoon", definition: "China-linked threat actor that compromised major U.S. telecommunications providers in 2024 to access wiretap systems and call records.", category: "Security Organizations & Groups", relatedTerms: ["China", "Telecommunications", "APT", "Wiretap"] },
  { term: "Scattered Spider", definition: "English-speaking cybercrime group known for social engineering help desks, SIM swapping, and ransomware attacks against major enterprises including MGM and Caesars.", category: "Security Organizations & Groups", relatedTerms: ["Cyber Crime", "Social Engineering", "Ransomware", "ALPHV"] },
  { term: "BlackCat/ALPHV", definition: "Ransomware-as-a-Service operation using Rust-based ransomware with triple extortion tactics. Known affiliates include Scattered Spider.", category: "Security Organizations & Groups", relatedTerms: ["Ransomware", "RaaS", "Extortion", "Cyber Crime"] },
  { term: "LockBit", definition: "Prolific Ransomware-as-a-Service operation responsible for thousands of attacks globally. Features fast encryption, affiliate program, and data leak site.", category: "Security Organizations & Groups", relatedTerms: ["Ransomware", "RaaS", "Cyber Crime", "Extortion"] },
  { term: "Cl0p", definition: "Ransomware group known for exploiting zero-day vulnerabilities in file transfer appliances (MOVEit, GoAnywhere) for mass data theft and extortion.", category: "Security Organizations & Groups", relatedTerms: ["Ransomware", "Zero-Day", "Data Theft", "Cyber Crime"] },

  // Security Tools
  { term: "Ghidra", definition: "A free, open-source software reverse engineering suite developed by the NSA. Includes a disassembler, decompiler, and scripting capabilities for analyzing malware and binary code.", category: "Security Tools", relatedTerms: ["IDA Pro", "Reverse Engineering", "Disassembler"] },
  { term: "IDA Pro", definition: "Industry-standard interactive disassembler and debugger for reverse engineering. Supports multiple processor architectures and includes a powerful decompiler (Hex-Rays).", category: "Security Tools", relatedTerms: ["Ghidra", "Reverse Engineering", "Debugging"] },
  { term: "radare2 (r2)", definition: "Open-source reverse engineering framework and command-line toolset for disassembly, debugging, forensics, and binary analysis. Highly scriptable and extensible.", category: "Security Tools", relatedTerms: ["Ghidra", "Binary Analysis", "Disassembler"] },
  { term: "Binary Ninja", definition: "Commercial reverse engineering platform with modern UI, intermediate language (BNIL), and powerful API for automated analysis and plugin development.", category: "Security Tools", relatedTerms: ["IDA Pro", "Reverse Engineering", "Decompiler"] },
  { term: "x64dbg", definition: "Open-source x64/x32 debugger for Windows. User-friendly interface for dynamic analysis, breakpoints, and memory manipulation during malware analysis.", category: "Security Tools", relatedTerms: ["OllyDbg", "Debugging", "Windows"] },
  { term: "OllyDbg", definition: "Classic 32-bit Windows debugger used for reverse engineering and malware analysis. Known for its intuitive interface and powerful analysis capabilities.", category: "Security Tools", relatedTerms: ["x64dbg", "Debugging", "Reverse Engineering"] },
  { term: "GDB (GNU Debugger)", definition: "The standard debugger for Unix/Linux systems. Supports multiple languages and architectures, essential for low-level debugging and exploit development.", category: "Security Tools", relatedTerms: ["LLDB", "Debugging", "Linux"] },
  { term: "LLDB", definition: "The debugger component of the LLVM project. Default debugger on macOS and iOS, supports modern architectures and integrates with Xcode.", category: "Security Tools", relatedTerms: ["GDB", "Debugging", "macOS"] },
  { term: "WinDbg", definition: "Microsoft's powerful debugger for Windows kernel and user-mode debugging. Essential for Windows internals research and driver development.", category: "Security Tools", relatedTerms: ["x64dbg", "Debugging", "Windows Kernel"] },
  { term: "Frida", definition: "Dynamic instrumentation toolkit for hooking and tracing functions in running processes. Supports Android, iOS, Windows, macOS, and Linux for runtime analysis.", category: "Security Tools", relatedTerms: ["Mobile Security", "Dynamic Analysis", "Hooking"] },
  { term: "Objection", definition: "Runtime mobile exploration toolkit powered by Frida. Simplifies common mobile security testing tasks like SSL pinning bypass and method hooking.", category: "Security Tools", relatedTerms: ["Frida", "Mobile Security", "Android"] },
  { term: "JADX", definition: "Dex to Java decompiler that produces readable Java source code from Android APK files. Essential for Android reverse engineering.", category: "Security Tools", relatedTerms: ["APKTool", "Android", "Decompiler"] },
  { term: "APKTool", definition: "Tool for reverse engineering Android APK files. Decodes resources and can rebuild APKs after modification, useful for repackaging and analysis.", category: "Security Tools", relatedTerms: ["JADX", "Android", "Reverse Engineering"] },
  { term: "Hopper", definition: "macOS and Linux disassembler for reverse engineering binaries. Features decompilation, control flow graphs, and Objective-C analysis.", category: "Security Tools", relatedTerms: ["IDA Pro", "macOS", "Disassembler"] },
  { term: "YARA", definition: "Pattern matching tool for malware researchers to identify and classify malware samples. Uses rule-based signatures to detect malicious patterns.", category: "Security Tools", relatedTerms: ["Malware Analysis", "Signatures", "Threat Hunting"] },
  { term: "Volatility", definition: "Advanced memory forensics framework for extracting digital artifacts from RAM dumps. Supports Windows, Linux, and macOS memory analysis.", category: "Security Tools", relatedTerms: ["Memory Forensics", "DFIR", "Incident Response"] },
  { term: "Sysinternals Suite", definition: "Collection of Windows system utilities by Mark Russinovich (Microsoft). Includes Process Monitor, Process Explorer, Autoruns, and other essential tools.", category: "Security Tools", relatedTerms: ["Windows", "Process Monitor", "System Administration"] },
  { term: "Process Monitor (ProcMon)", definition: "Real-time Windows monitoring tool showing file system, registry, and process activity. Essential for malware behavior analysis and troubleshooting.", category: "Security Tools", relatedTerms: ["Sysinternals", "Dynamic Analysis", "Windows"] },
  { term: "John the Ripper", definition: "Fast password cracking tool supporting many cipher and hash types. Includes wordlist-based attacks, incremental mode, and rule-based mutations.", category: "Security Tools", relatedTerms: ["Hashcat", "Password Cracking", "Offline Attack"] },
  { term: "Aircrack-ng", definition: "Complete suite of tools for 802.11 wireless network security assessment. Includes monitoring, attacking, testing, and cracking capabilities.", category: "Security Tools", relatedTerms: ["WiFi Security", "WPA", "Wireless Penetration Testing"] },
  { term: "SQLMap", definition: "Open-source penetration testing tool that automates SQL injection detection and exploitation. Supports multiple database types and advanced techniques.", category: "Security Tools", relatedTerms: ["SQL Injection", "Database Security", "Web Testing"] },
  { term: "Nikto", definition: "Open-source web server scanner that tests for dangerous files, outdated versions, and configuration issues across web servers.", category: "Security Tools", relatedTerms: ["Web Scanning", "Vulnerability Assessment", "Apache"] },
  { term: "Gobuster", definition: "Fast tool for brute-forcing URIs (directories/files), DNS subdomains, and virtual hosts. Written in Go for performance.", category: "Security Tools", relatedTerms: ["Directory Busting", "Enumeration", "Web Testing"] },
  { term: "ffuf", definition: "Fast web fuzzer written in Go for discovering directories, files, parameters, and other web application components.", category: "Security Tools", relatedTerms: ["Fuzzing", "Web Testing", "Directory Enumeration"] },
  { term: "Nuclei", definition: "Fast vulnerability scanner based on YAML templates. Community-driven with thousands of templates for CVEs, misconfigurations, and exposed panels.", category: "Security Tools", relatedTerms: ["Vulnerability Scanning", "Automation", "Templates"] },
  { term: "Responder", definition: "LLMNR, NBT-NS and MDNS poisoner for Windows credential capture. Listens for name resolution requests and captures NTLMv2 hashes.", category: "Security Tools", relatedTerms: ["Credential Harvesting", "NTLM", "Network Attack"] },
  { term: "Impacket", definition: "Collection of Python classes for working with network protocols. Essential toolkit for Windows network attacks, including SMB, LDAP, and Kerberos.", category: "Security Tools", relatedTerms: ["Python", "Windows", "Active Directory"] },
  { term: "BloodHound", definition: "Tool for mapping Active Directory relationships and attack paths. Uses graph theory to identify privilege escalation routes and misconfigurations.", category: "Security Tools", relatedTerms: ["Active Directory", "Graph Analysis", "Privilege Escalation"] },
  { term: "Mimikatz", definition: "Tool for extracting plaintext passwords, hashes, PIN codes, and Kerberos tickets from Windows memory. Widely used in post-exploitation.", category: "Security Tools", relatedTerms: ["Credential Dumping", "Windows", "Post-Exploitation"] },
  { term: "CrackMapExec (CME)", definition: "Swiss army knife for pentesting networks. Automates credential validation, enumeration, and attacks across SMB, WinRM, LDAP, and more.", category: "Security Tools", relatedTerms: ["Active Directory", "Network Penetration", "Automation"] },
  { term: "Cobalt Strike", definition: "Commercial adversary simulation platform providing post-exploitation capabilities, C2 infrastructure, and red team collaboration features.", category: "Security Tools", relatedTerms: ["Red Team", "C2", "Post-Exploitation"] },
  { term: "Empire", definition: "Post-exploitation framework with pure PowerShell 2.0 and Python agents. Supports various modules for credential harvesting, lateral movement, and persistence.", category: "Security Tools", relatedTerms: ["Post-Exploitation", "PowerShell", "C2"] },
  { term: "Sliver", definition: "Open-source, cross-platform adversary emulation/red team framework. Alternative to Cobalt Strike with implants, C2, and operator support.", category: "Security Tools", relatedTerms: ["Red Team", "C2", "Open Source"] },
  { term: "pwntools", definition: "CTF framework and exploit development library for Python. Simplifies binary exploitation, shellcode crafting, and ROP chain generation.", category: "Security Tools", relatedTerms: ["Exploit Development", "CTF", "Python"] },
  { term: "ROPgadget", definition: "Tool to search for gadgets and build ROP chains for x86/x86-64, ARM, and other architectures. Essential for modern exploit development.", category: "Security Tools", relatedTerms: ["ROP", "Exploit Development", "Binary Exploitation"] },
  { term: "angr", definition: "Platform-agnostic binary analysis framework using symbolic execution. Used for vulnerability discovery, exploit generation, and reverse engineering.", category: "Security Tools", relatedTerms: ["Symbolic Execution", "Binary Analysis", "Python"] },
  { term: "Triton", definition: "Dynamic binary analysis framework featuring dynamic symbolic execution, taint analysis, and AST representation of x86/x86-64 instructions.", category: "Security Tools", relatedTerms: ["Symbolic Execution", "Dynamic Analysis", "Intel Pin"] },
  { term: "QEMU", definition: "Generic open-source machine emulator and virtualizer. Used in security for firmware analysis, embedded system testing, and sandbox environments.", category: "Security Tools", relatedTerms: ["Emulation", "Firmware", "Virtualization"] },
  { term: "Binwalk", definition: "Firmware analysis tool for scanning, extracting, and analyzing firmware images. Identifies embedded files, compression, and filesystem contents.", category: "Security Tools", relatedTerms: ["Firmware", "IoT", "Reverse Engineering"] },
  { term: "Cutter", definition: "Free and open-source reverse engineering platform powered by radare2. Provides graphical interface for disassembly, debugging, and decompilation.", category: "Security Tools", relatedTerms: ["radare2", "Reverse Engineering", "GUI"] },
  { term: "Zeek (formerly Bro)", definition: "Powerful network analysis framework for security monitoring. Generates detailed logs of network activity for threat detection and forensics.", category: "Security Tools", relatedTerms: ["Network Security", "IDS", "Traffic Analysis"] },
  { term: "Suricata", definition: "High-performance network IDS, IPS, and network security monitoring engine. Supports multi-threading and advanced protocol detection.", category: "Security Tools", relatedTerms: ["IDS", "IPS", "Network Security"] },
  { term: "Snort", definition: "Open-source network intrusion prevention system capable of real-time traffic analysis and packet logging. Foundation for many IDS/IPS solutions.", category: "Security Tools", relatedTerms: ["IDS", "IPS", "Network Security"] },
  { term: "TheHive", definition: "Scalable security incident response platform. Enables SOC teams to collaborate on investigations, track cases, and integrate with MISP.", category: "Security Tools", relatedTerms: ["Incident Response", "SOC", "MISP"] },
  { term: "MISP", definition: "Open-source threat intelligence platform for gathering, storing, and sharing indicators of compromise and threat intelligence.", category: "Security Tools", relatedTerms: ["Threat Intelligence", "IOC", "Information Sharing"] },
  { term: "OpenVAS", definition: "Open Vulnerability Assessment Scanner - a full-featured vulnerability scanner with thousands of network vulnerability tests.", category: "Security Tools", relatedTerms: ["Vulnerability Scanning", "Nessus", "Assessment"] },
  { term: "Nessus", definition: "Widely-deployed commercial vulnerability scanner from Tenable. Comprehensive vulnerability detection for networks, applications, and compliance.", category: "Security Tools", relatedTerms: ["Vulnerability Scanning", "Compliance", "Assessment"] },
  { term: "Qualys", definition: "Cloud-based security and compliance platform offering vulnerability management, web application scanning, and asset inventory.", category: "Security Tools", relatedTerms: ["Vulnerability Management", "Cloud Security", "Compliance"] },
  { term: "Shodan", definition: "Search engine for Internet-connected devices. Indexes servers, routers, IoT devices, and reveals exposed services and vulnerabilities.", category: "Security Tools", relatedTerms: ["Reconnaissance", "IoT", "OSINT"] },
  { term: "Censys", definition: "Attack surface management platform that continuously monitors Internet assets. Similar to Shodan with focus on enterprise security.", category: "Security Tools", relatedTerms: ["Reconnaissance", "Asset Discovery", "OSINT"] },
  { term: "theHarvester", definition: "OSINT tool for gathering emails, names, subdomains, IPs, and URLs from public sources during reconnaissance phases.", category: "Security Tools", relatedTerms: ["OSINT", "Reconnaissance", "Email Harvesting"] },
  { term: "Maltego", definition: "Interactive data mining tool for link analysis and OSINT. Visualizes relationships between people, companies, domains, and infrastructure.", category: "Security Tools", relatedTerms: ["OSINT", "Link Analysis", "Reconnaissance"] },
  { term: "SpiderFoot", definition: "Automated OSINT collection tool gathering intelligence from over 100 data sources. Supports passive and active reconnaissance.", category: "Security Tools", relatedTerms: ["OSINT", "Automation", "Reconnaissance"] },
  { term: "Recon-ng", definition: "Full-featured web reconnaissance framework written in Python. Modular design with database-backed results for managing OSINT operations.", category: "Security Tools", relatedTerms: ["OSINT", "Reconnaissance", "Python"] },
  { term: "testssl.sh", definition: "Command-line tool for checking TLS/SSL configuration of servers. Identifies cipher suites, protocols, and vulnerabilities.", category: "Security Tools", relatedTerms: ["SSL/TLS", "Web Security", "Configuration"] },
  { term: "SSLyze", definition: "Fast SSL/TLS server scanning library and CLI. Analyzes server configuration for security issues and compliance requirements.", category: "Security Tools", relatedTerms: ["SSL/TLS", "Security Assessment", "Compliance"] },

  // Operating Systems & Platforms
  { term: "Windows", definition: "Microsoft's desktop and server operating system family. Dominant enterprise OS with Active Directory integration. Primary target for malware and security research.", category: "Operating Systems & Platforms", relatedTerms: ["Active Directory", "PowerShell", "Windows Defender"] },
  { term: "Linux", definition: "Open-source Unix-like operating system kernel. Powers servers, security tools, embedded systems, and Android. Essential for security professionals.", category: "Operating Systems & Platforms", relatedTerms: ["Bash", "Ubuntu", "Kali Linux"] },
  { term: "macOS", definition: "Apple's desktop operating system based on Darwin (BSD Unix). Known for security features like Gatekeeper, SIP, and XProtect.", category: "Operating Systems & Platforms", relatedTerms: ["iOS", "Apple", "Unix"] },
  { term: "iOS", definition: "Apple's mobile operating system for iPhone and iPad. Features App Store sandboxing, Secure Enclave, and strict code signing requirements.", category: "Operating Systems & Platforms", relatedTerms: ["macOS", "Mobile Security", "Jailbreak"] },
  { term: "Android", definition: "Google's open-source mobile operating system based on Linux kernel. Targets for mobile security testing, app analysis, and malware research.", category: "Operating Systems & Platforms", relatedTerms: ["Linux", "APK", "Mobile Security"] },
  { term: "Kali Linux", definition: "Debian-based Linux distribution designed for digital forensics and penetration testing. Includes 600+ pre-installed security tools.", category: "Operating Systems & Platforms", relatedTerms: ["Linux", "Penetration Testing", "Security Tools"] },
  { term: "Parrot OS", definition: "Debian-based security-focused Linux distribution. Alternative to Kali with additional privacy tools and development environment.", category: "Operating Systems & Platforms", relatedTerms: ["Kali Linux", "Linux", "Privacy"] },
  { term: "BlackArch Linux", definition: "Arch Linux-based penetration testing distribution with over 2800 tools. Lightweight and flexible for advanced users.", category: "Operating Systems & Platforms", relatedTerms: ["Kali Linux", "Linux", "Penetration Testing"] },
  { term: "REMnux", definition: "Linux toolkit for reverse-engineering and analyzing malicious software. Curated collection of tools for malware analysis workflows.", category: "Operating Systems & Platforms", relatedTerms: ["Malware Analysis", "Linux", "Reverse Engineering"] },
  { term: "FLARE VM", definition: "Windows-based security distribution from Mandiant. Customized for malware analysis, incident response, and penetration testing.", category: "Operating Systems & Platforms", relatedTerms: ["Windows", "Malware Analysis", "Mandiant"] },
  { term: "Tails", definition: "Privacy-focused live operating system designed to leave no trace. Routes all traffic through Tor for anonymity.", category: "Operating Systems & Platforms", relatedTerms: ["Privacy", "Tor", "Linux"] },
  { term: "Qubes OS", definition: "Security-oriented operating system using Xen hypervisor to isolate applications in separate VMs (qubes) for compartmentalization.", category: "Operating Systems & Platforms", relatedTerms: ["Virtualization", "Isolation", "Security"] },
  { term: "BSD (Berkeley Software Distribution)", definition: "Family of Unix-like operating systems including FreeBSD, OpenBSD, and NetBSD. OpenBSD is renowned for security focus and code auditing.", category: "Operating Systems & Platforms", relatedTerms: ["Unix", "OpenBSD", "FreeBSD"] },
  { term: "VMware", definition: "Virtualization platform for running multiple operating systems. Essential for malware analysis sandboxes and security lab environments.", category: "Operating Systems & Platforms", relatedTerms: ["Virtualization", "ESXi", "Security Lab"] },
  { term: "VirtualBox", definition: "Free, open-source virtualization software from Oracle. Popular for security research, malware analysis, and CTF environments.", category: "Operating Systems & Platforms", relatedTerms: ["Virtualization", "VMware", "Sandbox"] },
  { term: "WSL (Windows Subsystem for Linux)", definition: "Compatibility layer for running Linux binary executables natively on Windows. Enables Linux security tools in Windows environments.", category: "Operating Systems & Platforms", relatedTerms: ["Windows", "Linux", "Bash"] },
  { term: "AWS (Amazon Web Services)", definition: "Leading cloud computing platform offering compute, storage, networking, and security services. Requires understanding of IAM, VPC, and shared responsibility.", category: "Operating Systems & Platforms", relatedTerms: ["Cloud Security", "IAM", "S3"] },
  { term: "Microsoft Azure", definition: "Microsoft's cloud computing platform with enterprise focus. Integrates with Active Directory and offers extensive security services.", category: "Operating Systems & Platforms", relatedTerms: ["Cloud Security", "Active Directory", "Azure AD"] },
  { term: "Google Cloud Platform (GCP)", definition: "Google's cloud computing services offering compute, storage, ML, and security features. Known for BigQuery, Kubernetes Engine, and strong data analytics.", category: "Operating Systems & Platforms", relatedTerms: ["Cloud Security", "Kubernetes", "BeyondCorp"] },
  { term: "Raspberry Pi", definition: "Low-cost single-board computer popular for IoT projects, network monitoring, penetration testing drop boxes, and security education.", category: "Operating Systems & Platforms", relatedTerms: ["IoT", "Embedded", "Linux"] },
  { term: "Arduino", definition: "Open-source electronics platform for building embedded projects. Used in IoT security research, hardware hacking, and BadUSB devices.", category: "Operating Systems & Platforms", relatedTerms: ["IoT", "Hardware Hacking", "Embedded"] },

  // Programming & Shell Environments  
  { term: "Bash", definition: "Bourne Again Shell - default command-line shell on most Linux distributions. Essential for scripting, automation, and security tool usage.", category: "Programming & Shell", relatedTerms: ["Linux", "Shell Scripting", "Terminal"] },
  { term: "PowerShell", definition: "Microsoft's task automation and configuration management framework. Powerful for Windows administration, security testing, and post-exploitation.", category: "Programming & Shell", relatedTerms: ["Windows", "Scripting", "Empire"] },
  { term: "Zsh", definition: "Z Shell - extended Bourne shell with many improvements. Popular alternative to Bash with better completion and customization (Oh My Zsh).", category: "Programming & Shell", relatedTerms: ["Bash", "Linux", "macOS"] },
  { term: "Python", definition: "High-level programming language dominant in security tooling. Used for exploit development, automation, scripting, and building security tools.", category: "Programming & Shell", relatedTerms: ["pwntools", "Scripting", "Security Tools"] },
  { term: "Go (Golang)", definition: "Google's compiled language known for performance and simplicity. Popular for modern security tools like Nuclei, ffuf, and malware development.", category: "Programming & Shell", relatedTerms: ["Compiled Language", "Performance", "Security Tools"] },
  { term: "Rust", definition: "Systems programming language focused on safety and performance. Increasingly used for secure software development and security tooling.", category: "Programming & Shell", relatedTerms: ["Memory Safety", "Systems Programming", "Compiled"] },
  { term: "C/C++", definition: "Low-level programming languages essential for understanding vulnerabilities, exploit development, reverse engineering, and systems programming.", category: "Programming & Shell", relatedTerms: ["Memory Corruption", "Systems Programming", "Exploit Development"] },
  { term: "Assembly Language", definition: "Low-level programming language with processor-specific instructions. Essential for reverse engineering, exploit development, and malware analysis.", category: "Programming & Shell", relatedTerms: ["x86", "ARM", "Reverse Engineering"] },
  { term: "x86/x64 Architecture", definition: "Intel/AMD processor architecture dominating desktop/server computing. Understanding x86 assembly is fundamental for binary exploitation and RE.", category: "Programming & Shell", relatedTerms: ["Assembly", "Reverse Engineering", "Intel"] },
  { term: "ARM Architecture", definition: "RISC processor architecture dominant in mobile devices and embedded systems. ARM assembly knowledge essential for mobile and IoT security.", category: "Programming & Shell", relatedTerms: ["Mobile Security", "IoT", "Assembly"] },
  { term: "JavaScript", definition: "Programming language of the web. Understanding JS is essential for web security testing, XSS exploitation, and browser security research.", category: "Programming & Shell", relatedTerms: ["Web Security", "XSS", "Node.js"] },
  { term: "Ruby", definition: "Dynamic programming language used in security for Metasploit modules, web application testing, and automation scripts.", category: "Programming & Shell", relatedTerms: ["Metasploit", "Scripting", "Rails"] },
  { term: "Perl", definition: "Text processing language historically used in security tools and exploit code. Still found in legacy security scripts and one-liners.", category: "Programming & Shell", relatedTerms: ["Scripting", "Text Processing", "Legacy"] },
  { term: "SQL", definition: "Structured Query Language for database interaction. Understanding SQL is essential for SQL injection testing and database security.", category: "Programming & Shell", relatedTerms: ["SQL Injection", "Database", "MySQL"] },
  { term: "Regular Expressions (Regex)", definition: "Pattern matching syntax used across programming languages. Essential for log analysis, data extraction, and security tool filters.", category: "Programming & Shell", relatedTerms: ["Pattern Matching", "Grep", "Text Processing"] },
  { term: "Git", definition: "Distributed version control system. Essential for managing code, collaborating on security projects, and analyzing commit history for secrets.", category: "Programming & Shell", relatedTerms: ["Version Control", "GitHub", "Source Code"] },
  { term: "GitHub", definition: "Web-based platform for Git repositories. Major source for security tools, vulnerability disclosures, and code analysis. Also attack target for secrets leakage.", category: "Programming & Shell", relatedTerms: ["Git", "Open Source", "GitLeaks"] },
  { term: "tmux", definition: "Terminal multiplexer allowing multiple terminal sessions within a single window. Essential for managing long-running security assessments.", category: "Programming & Shell", relatedTerms: ["Terminal", "Linux", "Screen"] },
  { term: "SSH (Secure Shell)", definition: "Cryptographic network protocol for secure remote login and command execution. Foundation for secure system administration and tunneling.", category: "Programming & Shell", relatedTerms: ["Remote Access", "Tunneling", "Key Authentication"] },
  { term: "Netcat (nc)", definition: "Networking utility for reading/writing data across network connections using TCP/UDP. Swiss army knife for network debugging and exploitation.", category: "Programming & Shell", relatedTerms: ["Networking", "Reverse Shell", "Port Scanning"] },
  { term: "curl", definition: "Command-line tool for transferring data with URLs. Essential for API testing, web requests, and security testing automation.", category: "Programming & Shell", relatedTerms: ["HTTP", "API Testing", "Web Security"] },

  // Technologies & Protocols
  { term: "mTLS (Mutual TLS)", definition: "TLS setup where both client and server present certificates, enabling strong mutual authentication.", category: "Technologies & Protocols", relatedTerms: ["TLS", "PKI", "Client Certificate"] },
  { term: "FIDO2 / WebAuthn", definition: "Passwordless authentication standards using public-key cryptography and authenticators (security keys, platform authenticators).", category: "Technologies & Protocols", relatedTerms: ["2FA", "Passkeys", "U2F"] },
  { term: "Service Mesh", definition: "Dedicated infrastructure layer for service-to-service communication (e.g., Istio/Linkerd) providing mTLS, policy, and telemetry.", category: "Technologies & Protocols", relatedTerms: ["Kubernetes", "Envoy", "Zero Trust"] },
  { term: "GraphQL", definition: "API query language letting clients specify exactly what data they need. Requires attention to authorization, complexity, and introspection controls.", category: "Technologies & Protocols", relatedTerms: ["API Security", "REST", "BFF"] },
  { term: "gRPC", definition: "High-performance RPC framework using HTTP/2 and Protocol Buffers. Security considerations include TLS, authz, and reflection hardening.", category: "Technologies & Protocols", relatedTerms: ["HTTP/2", "Protobuf", "mTLS"] },
  { term: "WebSockets", definition: "Full-duplex communication protocol over a single TCP connection. Requires origin checks, auth, and message-level validation.", category: "Technologies & Protocols", relatedTerms: ["HTTP", "CSRF", "Real-Time"] },
  { term: "WireGuard", definition: "Modern VPN protocol using Noise-based cryptography for fast, simple, and secure tunnels.", category: "Technologies & Protocols", relatedTerms: ["VPN", "IPsec", "Noise Protocol"] },
  { term: "DNSSEC", definition: "DNS Security Extensions provide origin authentication and integrity for DNS data using digital signatures.", category: "Technologies & Protocols", relatedTerms: ["DNS", "PKI", "Resolver"] },
  { term: "QUIC", definition: "Transport protocol built on UDP with TLS 1.3 encryption and multiplexing, underpinning HTTP/3.", category: "Technologies & Protocols", relatedTerms: ["HTTP/3", "TLS 1.3", "UDP"] },

  // Cloud & Platform Security
  { term: "Kubernetes", definition: "Container orchestration platform. Security focus areas include RBAC, network policies, secrets management, admission controllers, and supply chain.", category: "Cloud & Platform", relatedTerms: ["Containers", "RBAC", "Admission Controller"] },
  { term: "Docker", definition: "Container runtime and tooling. Key risks include leaked secrets in images, exposed Docker socket, and weak isolation when privileged.", category: "Cloud & Platform", relatedTerms: ["Containers", "OCI", "Kubernetes"] },
  { term: "Helm", definition: "Package manager for Kubernetes using charts to template deployments. Templating errors can lead to insecure defaults.", category: "Cloud & Platform", relatedTerms: ["Kubernetes", "Charts", "CI/CD"] },
  { term: "Terraform", definition: "Infrastructure as Code tool for provisioning cloud resources. Security involves state protection, least privilege credentials, and drift detection.", category: "Cloud & Platform", relatedTerms: ["IaC", "Plan/Apply", "State File"] },
  { term: "Ansible", definition: "Configuration management and automation tool using YAML playbooks. Security includes vaulting secrets and idempotent hardening roles.", category: "Cloud & Platform", relatedTerms: ["Configuration Management", "SSH", "IaC"] },
  { term: "AWS IAM", definition: "Amazon Web Services Identity and Access Management service for users, roles, and policies. Core to least privilege and isolation in AWS.", category: "Cloud & Platform", relatedTerms: ["AWS", "Policies", "STS"] },
  { term: "AWS S3", definition: "Object storage service. Common risks: public buckets, weak bucket policies, server-side encryption misconfigurations.", category: "Cloud & Platform", relatedTerms: ["Cloud Storage", "ACL", "KMS"] },
  { term: "CloudTrail", definition: "AWS audit logging service capturing API activity for governance and incident response.", category: "Cloud & Platform", relatedTerms: ["AWS", "Logging", "Detection"] },
  { term: "GuardDuty", definition: "AWS threat detection service using VPC Flow Logs, DNS logs, and CloudTrail to surface findings like crypto mining or credential exfil.", category: "Cloud & Platform", relatedTerms: ["AWS", "Detection", "SIEM"] },
  { term: "Security Hub", definition: "AWS service that aggregates security alerts and compliance findings across services and partners.", category: "Cloud & Platform", relatedTerms: ["AWS", "Compliance", "Detection"] },
  { term: "IAM Roles Anywhere", definition: "AWS feature enabling workloads outside AWS to assume IAM roles using X.509 certificates.", category: "Cloud & Platform", relatedTerms: ["AWS", "IAM", "mTLS"] },
  { term: "KMS (Key Management Service)", definition: "Managed key service (e.g., AWS KMS, GCP KMS) providing key storage and cryptographic operations with policy controls.", category: "Cloud & Platform", relatedTerms: ["Encryption", "HSM", "Envelope Encryption"] },
  { term: "HSM (Hardware Security Module)", definition: "Physical/virtual device for secure key storage and cryptographic operations with tamper resistance.", category: "Cloud & Platform", relatedTerms: ["KMS", "PKI", "Secure Enclave"] },
  { term: "TPM (Trusted Platform Module)", definition: "Hardware chip for secure key storage, measurements, and attestation. Used for secure boot and disk encryption.", category: "Cloud & Platform", relatedTerms: ["Secure Boot", "BitLocker", "Attestation"] },
  { term: "Secure Boot", definition: "Boot process that verifies code integrity using cryptographic signatures, preventing unauthorized firmware or bootloader changes.", category: "Cloud & Platform", relatedTerms: ["TPM", "UEFI", "Firmware Security"] },
  { term: "eBPF", definition: "Extended Berkeley Packet Filter allows safe sandboxed programs in the kernel for observability and security. Used in modern detection and networking tools.", category: "Cloud & Platform", relatedTerms: ["Kernel", "Observability", "XDP"] },
  { term: "Sidecar Proxy", definition: "Proxy (e.g., Envoy) deployed alongside a service in a service mesh to handle mTLS, routing, and policy enforcement.", category: "Cloud & Platform", relatedTerms: ["Service Mesh", "Envoy", "mTLS"] },
  { term: "OPA (Open Policy Agent)", definition: "Policy engine using Rego to enforce authorization across microservices, Kubernetes, and APIs.", category: "Cloud & Platform", relatedTerms: ["Authorization", "Kubernetes", "Rego"] },
  { term: "SPIFFE / SPIRE", definition: "Specs and runtime for issuing workload identities (SPIFFE IDs) and secure workload-to-workload mTLS.", category: "Cloud & Platform", relatedTerms: ["Service Identity", "mTLS", "Zero Trust"] },
  { term: "Zero Trust Network Access (ZTNA)", definition: "Access model where every request is authenticated/authorized with continuous evaluation; replaces implicit perimeter trust.", category: "Cloud & Platform", relatedTerms: ["Zero Trust", "mTLS", "Device Posture"] },
  { term: "PaaS Escape", definition: "Breaking isolation in a platform-as-a-service environment to access other tenants or the underlying host.", category: "Cloud & Platform", relatedTerms: ["Multi-Tenancy", "Container Escape", "Sandbox"] },
  { term: "SSRF to IMDS", definition: "Server-Side Request Forgery targeting cloud instance metadata services (IMDS) to steal credentials or tokens.", category: "Cloud & Platform", relatedTerms: ["SSRF", "Cloud Metadata", "IAM"] },
  { term: "CSPM", definition: "Cloud Security Posture Management tools that continuously assess cloud configs for misconfigurations and compliance.", category: "Cloud & Platform", relatedTerms: ["Compliance", "Misconfiguration", "Cloud"] },
  { term: "CWPP", definition: "Cloud Workload Protection Platform providing runtime defense for VMs/containers/serverless (threat detection, hardening).", category: "Cloud & Platform", relatedTerms: ["EDR", "Container Security", "Runtime"] },

  // Identity & Access
  { term: "SCIM", definition: "System for Cross-domain Identity Management automates user provisioning and deprovisioning across systems.", category: "Identity & Access", relatedTerms: ["IAM", "SSO", "Provisioning"] },
  { term: "Conditional Access", definition: "Policy-based access control evaluating context (device, location, risk) before granting resource access.", category: "Identity & Access", relatedTerms: ["Zero Trust", "MFA", "Risk-Based Authentication"] },
  { term: "MFA Fatigue Attack", definition: "Attackers bombard users with MFA prompts hoping for approval; mitigations include number matching and rate limits.", category: "Identity & Access", relatedTerms: ["MFA", "Phishing", "Push Bombing"] },
  { term: "Passkey", definition: "Passwordless credential built on FIDO2/WebAuthn, typically synced across devices with hardware-backed keys.", category: "Identity & Access", relatedTerms: ["FIDO2", "WebAuthn", "Public Key"] },

  // Detection & Response
  { term: "EDR (Endpoint Detection and Response)", definition: "Security tooling that monitors endpoints for malicious activity with telemetry and response actions (isolation, kill process).", category: "Detection & Response", relatedTerms: ["XDR", "SIEM", "Telemetry"] },
  { term: "XDR (Extended Detection and Response)", definition: "Combines telemetry across endpoints, email, cloud, and network for unified detection/response.", category: "Detection & Response", relatedTerms: ["EDR", "SIEM", "SOAR"] },
  { term: "SOAR", definition: "Security Orchestration, Automation, and Response platforms automate playbooks to handle alerts, enrichment, and response actions.", category: "Detection & Response", relatedTerms: ["SIEM", "Runbook", "Automation"] },
  { term: "Sigma Rules", definition: "Generic detection rule format convertible to SIEM queries (e.g., Splunk, Elastic).", category: "Detection & Response", relatedTerms: ["SIEM", "Detection Engineering", "YARA"] },
  { term: "Sysmon", definition: "Windows system monitoring tool generating detailed event logs (process, network, file) for detection and forensics.", category: "Detection & Response", relatedTerms: ["EDR", "Event Logs", "Windows"] },
  { term: "JA3 / JA3S", definition: "TLS client/server fingerprinting techniques based on TLS handshake parameters for detecting malicious traffic.", category: "Detection & Response", relatedTerms: ["TLS", "Network Detection", "Fingerprinting"] },
  { term: "PCAP", definition: "Packet capture file format used to store network traffic for analysis with tools like Wireshark or Zeek.", category: "Detection & Response", relatedTerms: ["Wireshark", "Zeek", "Network Forensics"] },
  { term: "Zeek", definition: "Network security monitor that generates rich logs and detections from traffic, complementing packet captures.", category: "Detection & Response", relatedTerms: ["PCAP", "IDS", "Bro Scripts"] },
  { term: "Sigma", definition: "Generic, SIEM-agnostic signature format that can be converted to platform-specific detection queries.", category: "Detection & Response", relatedTerms: ["SIEM", "Detection Engineering", "Sigma Rules"] },
  { term: "Syslog", definition: "Standard log forwarding protocol widely used for centralizing logs and feeding SIEMs.", category: "Detection & Response", relatedTerms: ["SIEM", "Logging", "Event Pipeline"] },

  // Supply Chain & Software Integrity
  { term: "SBOM (Software Bill of Materials)", definition: "Machine-readable inventory of software components and dependencies in a product, used for vulnerability management and compliance.", category: "Supply Chain", relatedTerms: ["Dependency", "VEX", "CycloneDX"] },
  { term: "SLSA", definition: "Supply-chain Levels for Software Artifacts framework for securing build pipelines and provenance.", category: "Supply Chain", relatedTerms: ["Provenance", "Build Integrity", "CI/CD"] },
  { term: "Sigstore / Cosign", definition: "Open-source stack for signing and verifying container images and artifacts with transparency logs (Rekor).", category: "Supply Chain", relatedTerms: ["Container Security", "Signing", "Provenance"] },
  { term: "VEX", definition: "Vulnerability Exploitability eXchange document indicating whether a product is affected by a vulnerability in its SBOM.", category: "Supply Chain", relatedTerms: ["SBOM", "CVE", "Risk"] },

  // AI & ML Security
  { term: "Prompt Injection", definition: "Attacks on LLMs where crafted input manipulates the model’s instructions, causing data leaks or malicious actions.", category: "AI & ML Security", relatedTerms: ["LLM", "Data Exfiltration", "Guardrails"] },
  { term: "Model Inversion", definition: "Extracting training data attributes from a trained model’s outputs, risking privacy leaks.", category: "AI & ML Security", relatedTerms: ["Privacy", "Membership Inference", "Data Leakage"] },
  { term: "Membership Inference Attack", definition: "Determining if a specific data point was part of a model’s training set, threatening privacy.", category: "AI & ML Security", relatedTerms: ["Privacy", "Model Inversion", "LLM"] },
  { term: "Data Poisoning", definition: "Corrupting training data to alter model behavior or embed backdoors.", category: "AI & ML Security", relatedTerms: ["ML", "Backdoor", "Adversarial"] },
  { term: "Adversarial Example", definition: "Carefully perturbed input designed to fool machine learning models into misclassification.", category: "AI & ML Security", relatedTerms: ["Evasion", "Robustness", "ML"] },
  { term: "Model Card", definition: "Documentation detailing a model’s intended use, risks, and performance to support safe deployment.", category: "AI & ML Security", relatedTerms: ["Governance", "Transparency", "ML"] },
  { term: "RAG (Retrieval-Augmented Generation)", definition: "Pattern where an LLM is paired with a retrieval system to ground responses in external data.", category: "AI & ML Security", relatedTerms: ["LLM", "Vector DB", "Prompt Injection"] },
  { term: "Vector Database", definition: "Store for embedding vectors enabling similarity search (e.g., Pinecone, Weaviate, FAISS).", category: "AI & ML Security", relatedTerms: ["RAG", "Embeddings", "LLM"] },
  { term: "Guardrails", definition: "Techniques and tooling to constrain model outputs (prompt filters, safety classifiers, policy enforcement).", category: "AI & ML Security", relatedTerms: ["LLM", "Prompt Injection", "Safety"] },

  // Hardware & Firmware
  { term: "JTAG", definition: "Hardware debugging interface for testing and programming embedded devices; often exploited for firmware dumping.", category: "Hardware & Firmware", relatedTerms: ["SWD", "UART", "Firmware"] },
  { term: "UART", definition: "Serial communication interface frequently exposed on PCBs; used for console access and debugging.", category: "Hardware & Firmware", relatedTerms: ["JTAG", "Serial", "Firmware"] },
  { term: "Side-Channel Attack", definition: "Attack exploiting information leaked by hardware (timing, power, EM) rather than direct vulnerabilities.", category: "Hardware & Firmware", relatedTerms: ["Power Analysis", "Timing Attack", "Fault Injection"] },
  { term: "Fault Injection", definition: "Inducing faults (voltage/clock glitches, EM) to bypass security checks or extract secrets from hardware.", category: "Hardware & Firmware", relatedTerms: ["Side-Channel", "Secure Boot", "Glitching"] },
  { term: "Secure Enclave", definition: "Isolated hardware component for sensitive computation and key storage (e.g., Apple Secure Enclave, Intel SGX).", category: "Hardware & Firmware", relatedTerms: ["TPM", "HSM", "Trusted Execution"] },

  // UK Security (Regional)
  { term: "NCSC (UK)", definition: "UK National Cyber Security Centre, provides guidance, incident response support, and active cyber defense services.", category: "Security Organizations & Groups", relatedTerms: ["GCHQ", "CERT", "Guidance"] },
  { term: "CREST", definition: "Accreditation body for penetration testing and incident response providers in the UK and internationally.", category: "Security Organizations & Groups", relatedTerms: ["Penetration Testing", "Accreditation", "Red Team"] },
  { term: "CHECK", definition: "UK NCSC scheme for accredited companies to perform IT health checks for government and public sector.", category: "Security Programs", relatedTerms: ["NCSC", "Accreditation", "Penetration Testing"] },
  { term: "Cyber Essentials", definition: "UK government-backed baseline security certification focused on five control areas to protect against common threats.", category: "Security Programs", relatedTerms: ["UK", "Compliance", "Baseline Controls"] },
  { term: "Cyber Essentials Plus", definition: "Audited version of Cyber Essentials that includes independent technical verification.", category: "Security Programs", relatedTerms: ["UK", "Compliance", "Assessment"] },
  { term: "CLAS", definition: "Certified security advisers (legacy GCHQ/NCSC scheme) for handling government systems.", category: "Security Programs", relatedTerms: ["NCSC", "Consulting", "Accreditation"] },
  { term: "IASME", definition: "Consortium and standard used alongside Cyber Essentials for SME security and governance.", category: "Security Programs", relatedTerms: ["Cyber Essentials", "UK", "Compliance"] },
  { term: "CAF (Cyber Assessment Framework)", definition: "NCSC framework for assessing cyber resilience of UK operators of essential services.", category: "Security Programs", relatedTerms: ["NIS Directive", "UK", "Assessment"] },
  { term: "NIS Regulations (UK)", definition: "UK implementation of the EU NIS Directive, mandating security for operators of essential services and digital service providers.", category: "Compliance", relatedTerms: ["NIS Directive", "UK", "Regulation"] },
  { term: "GCHQ", definition: "UK intelligence agency responsible for signals intelligence and cyber operations; NCSC sits under it.", category: "Security Organizations & Groups", relatedTerms: ["NCSC", "SIGINT", "UK"] },
  { term: "UK GDPR", definition: "UK implementation of the General Data Protection Regulation, governing personal data protection after Brexit.", category: "Compliance", relatedTerms: ["Data Protection", "Privacy", "ICO"] },
  { term: "ICO (Information Commissioner's Office)", definition: "UK regulator responsible for data protection and enforcing UK GDPR/PECR.", category: "Security Organizations & Groups", relatedTerms: ["UK GDPR", "PECR", "Privacy"] },
  { term: "CISP (Cyber Security Information Sharing Partnership)", definition: "UK platform for threat intel sharing between industry and government.", category: "Security Programs", relatedTerms: ["Threat Intelligence", "Information Sharing", "NCSC"] },


    // Penetration Testing & Offensive
  { term: "Pivoting", definition: "Using a compromised host to route traffic to otherwise unreachable network segments.", category: "Penetration Testing", relatedTerms: ["Lateral Movement", "Tunneling", "Proxychains"] },
  { term: "Command and Control (C2)", definition: "Infrastructure and protocols used by attackers to control compromised hosts.", category: "Penetration Testing", relatedTerms: ["Beacon", "Implant", "Persistence"] },
  { term: "Beaconing", definition: "Periodic callbacks from compromised hosts to C2 servers, often with jitter and encoding to evade detection.", category: "Penetration Testing", relatedTerms: ["C2", "Evasion", "Network Detection"] },
  { term: "OPSEC (Operations Security)", definition: "Practices to avoid detection during engagements (limiting indicators, safe domains, staging).", category: "Penetration Testing", relatedTerms: ["Red Team", "Evasion", "Logging"] },
  { term: "Payload Staging", definition: "Splitting payloads into stager + stage to reduce size and bypass controls.", category: "Penetration Testing", relatedTerms: ["Loader", "Dropper", "Evasion"] },
  { term: "Living off the Land (LOTL)", definition: "Abusing built-in tools (PowerShell, WMI, certutil) to avoid dropping binaries.", category: "Penetration Testing", relatedTerms: ["LOLBAS", "Evasion", "Red Team"] },
  { term: "AS-REP Roasting", definition: "Abusing accounts without Kerberos pre-auth to request AS-REP messages and crack them offline.", category: "Penetration Testing", relatedTerms: ["Kerberos", "Active Directory", "Credential Access"] },
  { term: "Pass-the-Hash (PtH)", definition: "Using NTLM hashes directly for authentication in Windows/AD environments.", category: "Penetration Testing", relatedTerms: ["NTLM", "Lateral Movement", "Credential Access"] },
  { term: "CrackMapExec", definition: "Post-exploitation tool for enumerating and exploiting Active Directory at scale.", category: "Penetration Testing", relatedTerms: ["Active Directory", "Automation", "SMB"] },
  { term: "Payload Obfuscation", definition: "Techniques to hide payloads from detection (packing, encryption, string encoding).", category: "Penetration Testing", relatedTerms: ["Evasion", "Loader", "Packers"] },
  { term: "Silver Ticket", definition: "Forged Kerberos service ticket created with a service account hash targeting specific SPNs.", category: "Penetration Testing", relatedTerms: ["Kerberos", "Active Directory", "Credential Access"] },
  { term: "Golden Ticket", definition: "Forged Kerberos TGT created with the KRBTGT hash, granting domain-wide access.", category: "Penetration Testing", relatedTerms: ["Kerberos", "Active Directory", "Privilege Escalation"] },

    // Cyber Education & Courses
  { term: "eJPT", definition: "eLearnSecurity Junior Penetration Tester certification focused on foundational skills.", category: "Cyber Education", relatedTerms: ["Certification", "Penetration Testing", "eLearnSecurity"] },
  { term: "eCPPT", definition: "eLearnSecurity Certified Professional Penetration Tester certification covering advanced web and network exploitation.", category: "Cyber Education", relatedTerms: ["Certification", "Penetration Testing", "eLearnSecurity"] },
  { term: "OSCP", definition: "Offensive Security Certified Professional hands-on penetration testing certification with a 24-hour exam.", category: "Cyber Education", relatedTerms: ["Certification", "Penetration Testing", "Offensive Security"] },
  { term: "OSCE", definition: "Offensive Security Certified Expert (legacy) certification focusing on advanced exploitation techniques.", category: "Cyber Education", relatedTerms: ["Certification", "Exploit Development", "Offensive Security"] },
  { term: "PNPT", definition: "Practical Network Penetration Tester certification emphasizing realistic network attack paths and reporting.", category: "Cyber Education", relatedTerms: ["Certification", "Penetration Testing", "TCM"] },
  { term: "Burp Certified Practitioner", definition: "PortSwigger certification testing advanced web application testing skills using Burp Suite.", category: "Cyber Education", relatedTerms: ["Certification", "Web Security", "Burp Suite"] },
  { term: "OSWE", definition: "Offensive Security Web Expert certification focused on advanced web application exploitation and code review.", category: "Cyber Education", relatedTerms: ["Certification", "Web Security", "Offensive Security"] },
  { term: "OSED", definition: "Offensive Security Exploit Developer certification centered on exploit development for Windows binaries.", category: "Cyber Education", relatedTerms: ["Certification", "Exploit Development", "Offensive Security"] },
  { term: "OSEP", definition: "Offensive Security Experienced Penetration Tester certification focused on evasive techniques and Active Directory attacks.", category: "Cyber Education", relatedTerms: ["Certification", "Penetration Testing", "Offensive Security"] },
  { term: "OSWP", definition: "Offensive Security Wireless Professional certification covering Wi-Fi security testing.", category: "Cyber Education", relatedTerms: ["Certification", "Wireless", "Offensive Security"] },
  { term: "SANS SEC504", definition: "SANS course focused on hacker tools, techniques, and incident handling.", category: "Cyber Education", relatedTerms: ["SANS", "Incident Response", "Blue Team"] },
  { term: "SANS SEC560", definition: "SANS network penetration testing and ethical hacking course.", category: "Cyber Education", relatedTerms: ["SANS", "Penetration Testing", "Network Security"] },
  { term: "SANS SEC401", definition: "SANS Security Essentials course covering foundational security skills and blue team basics.", category: "Cyber Education", relatedTerms: ["SANS", "Security Fundamentals", "Blue Team"] },
  { term: "SANS SEC503", definition: "SANS course on intrusion detection and packet analysis for network defenders.", category: "Cyber Education", relatedTerms: ["SANS", "IDS", "Network Security"] },
  { term: "SANS SEC542", definition: "SANS web application penetration testing and ethical hacking course.", category: "Cyber Education", relatedTerms: ["SANS", "Web Security", "Penetration Testing"] },
  { term: "SANS SEC573", definition: "SANS course on Python for security professionals and automation.", category: "Cyber Education", relatedTerms: ["SANS", "Automation", "Scripting"] },
  { term: "SANS SEC660", definition: "SANS advanced penetration testing and exploit development course.", category: "Cyber Education", relatedTerms: ["SANS", "Exploit Development", "Penetration Testing"] },
  { term: "CompTIA A+", definition: "CompTIA entry-level certification covering foundational IT support and hardware/software basics.", category: "Cyber Education", relatedTerms: ["Certification", "IT Fundamentals", "CompTIA"] },
  { term: "CompTIA Network+", definition: "CompTIA certification covering networking fundamentals, protocols, and troubleshooting.", category: "Cyber Education", relatedTerms: ["Certification", "Networking", "CompTIA"] },
  { term: "CompTIA Security+", definition: "CompTIA baseline cybersecurity certification covering core security concepts.", category: "Cyber Education", relatedTerms: ["Certification", "Security Fundamentals", "CompTIA"] },
  { term: "CompTIA PenTest+", definition: "CompTIA certification focused on penetration testing planning, execution, and reporting.", category: "Cyber Education", relatedTerms: ["Certification", "Penetration Testing", "CompTIA"] },
  { term: "CompTIA CySA+", definition: "CompTIA Cybersecurity Analyst certification focused on detection and response skills.", category: "Cyber Education", relatedTerms: ["Certification", "Detection", "CompTIA"] },
  { term: "CompTIA CASP+", definition: "CompTIA Advanced Security Practitioner certification for enterprise security architecture and operations.", category: "Cyber Education", relatedTerms: ["Certification", "Architecture", "CompTIA"] },
  { term: "HTB Academy", definition: "Hack The Box Academy offers guided labs and modules for hacking and security skills.", category: "Cyber Education", relatedTerms: ["Hack The Box", "Labs", "Learning"] },
  { term: "TryHackMe", definition: "Online platform with guided cybersecurity labs and paths for beginners to advanced practitioners.", category: "Cyber Education", relatedTerms: ["Labs", "CTF", "Learning"] },

    // Professional Security Disciplines
  { term: "Vulnerability Research", definition: "The systematic process of discovering, analyzing, and documenting security vulnerabilities in software and systems. Involves fuzzing, code auditing, and reverse engineering.", category: "Professional Disciplines", relatedTerms: ["Zero-Day", "Bug Bounty", "CVE"] },
  { term: "Exploit Development", definition: "The craft of creating working exploits for vulnerabilities. Requires deep understanding of memory corruption, shellcode, ROP chains, and bypass techniques.", category: "Professional Disciplines", relatedTerms: ["Buffer Overflow", "ROP", "Shellcode"] },
  { term: "Red Teaming", definition: "Adversarial security testing simulating real-world attacks across an organization. Goes beyond penetration testing to include physical security and social engineering.", category: "Professional Disciplines", relatedTerms: ["Penetration Testing", "Blue Team", "Purple Team"] },
  { term: "Blue Team", definition: "Defensive security team responsible for monitoring, detection, and response. Operates SOC, manages security tools, and develops detection rules.", category: "Professional Disciplines", relatedTerms: ["Red Team", "SOC", "Incident Response"] },
  { term: "Purple Team", definition: "Collaborative approach combining red and blue team efforts. Red team attacks while blue team defends, sharing knowledge to improve overall security.", category: "Professional Disciplines", relatedTerms: ["Red Team", "Blue Team", "Detection Engineering"] },
  { term: "Bug Bounty Hunting", definition: "Finding and reporting security vulnerabilities in exchange for rewards. Platforms like HackerOne and Bugcrowd connect researchers with organizations.", category: "Professional Disciplines", relatedTerms: ["Vulnerability Research", "Responsible Disclosure", "HackerOne"] },
  { term: "Malware Analysis", definition: "The study of malicious software to understand its functionality, origin, and impact. Includes static analysis, dynamic analysis, and behavioral analysis.", category: "Professional Disciplines", relatedTerms: ["Reverse Engineering", "DFIR", "Threat Intelligence"] },
  { term: "Threat Intelligence", definition: "Evidence-based knowledge about existing or emerging threats. Includes tactical (IOCs), operational (TTPs), and strategic (trends) intelligence.", category: "Professional Disciplines", relatedTerms: ["IOC", "MITRE ATT&CK", "Threat Hunting"] },
  { term: "Security Engineering", definition: "Designing and building secure systems from the ground up. Involves architecture review, secure coding practices, and implementing security controls.", category: "Professional Disciplines", relatedTerms: ["Secure SDLC", "DevSecOps", "Security by Design"] },
  { term: "Application Security (AppSec)", definition: "Practice of securing applications throughout development lifecycle. Includes code review, SAST/DAST, threat modeling, and security requirements.", category: "Professional Disciplines", relatedTerms: ["SAST", "DAST", "Secure SDLC"] },
  { term: "DevSecOps", definition: "Integration of security practices into DevOps pipelines. Automates security testing, implements security gates, and shifts security left in development.", category: "Professional Disciplines", relatedTerms: ["CI/CD", "SAST", "Container Security"] },
  { term: "Security Operations (SecOps)", definition: "Day-to-day security activities including monitoring, alerting, incident response, and security tool management. Core function of SOC teams.", category: "Professional Disciplines", relatedTerms: ["SOC", "SIEM", "Incident Response"] },
  { term: "Digital Forensics and Incident Response (DFIR)", definition: "Combined discipline of investigating security incidents and preserving digital evidence. Requires both technical analysis and chain of custody procedures.", category: "Professional Disciplines", relatedTerms: ["Incident Response", "Digital Forensics", "Memory Forensics"] },
  { term: "Cloud Security", definition: "Securing cloud infrastructure, services, and data. Requires understanding shared responsibility, IAM, network security, and cloud-native threats.", category: "Professional Disciplines", relatedTerms: ["AWS", "Azure", "CSPM"] },
  { term: "Mobile Security", definition: "Securing mobile applications and devices. Includes app testing, MDM, secure development, and understanding iOS/Android security models.", category: "Professional Disciplines", relatedTerms: ["iOS", "Android", "OWASP Mobile"] },
  { term: "IoT Security", definition: "Securing Internet of Things devices and ecosystems. Addresses firmware security, protocol analysis, and embedded system vulnerabilities.", category: "Professional Disciplines", relatedTerms: ["Embedded", "Firmware", "Hardware Hacking"] },
  { term: "Hardware Security", definition: "Securing physical devices against attacks. Includes side-channel analysis, fault injection, secure boot, and hardware security modules.", category: "Professional Disciplines", relatedTerms: ["Side Channel", "HSM", "Secure Enclave"] },
  { term: "Network Security", definition: "Protecting network infrastructure and data in transit. Includes firewalls, IDS/IPS, VPNs, segmentation, and protocol security.", category: "Professional Disciplines", relatedTerms: ["Firewall", "IDS", "VPN"] },
  { term: "Cryptography Engineering", definition: "Applied cryptography for building secure systems. Involves selecting algorithms, implementing protocols, and managing keys securely.", category: "Professional Disciplines", relatedTerms: ["Encryption", "PKI", "TLS"] },
  { term: "Security Architecture", definition: "Designing security controls and structure for systems and organizations. Creates security blueprints, reference architectures, and control frameworks.", category: "Professional Disciplines", relatedTerms: ["Defense in Depth", "Zero Trust", "Threat Modeling"] },
  { term: "Governance, Risk, and Compliance (GRC)", definition: "Framework aligning IT with business objectives while managing risk and meeting compliance requirements. Includes policy development and audit preparation.", category: "Professional Disciplines", relatedTerms: ["Compliance", "Risk Management", "ISO 27001"] },
  { term: "Security Awareness Training", definition: "Educating employees about security threats and best practices. Addresses phishing, social engineering, and security policies.", category: "Professional Disciplines", relatedTerms: ["Phishing", "Social Engineering", "Human Factor"] },
  { term: "OSINT (Open Source Intelligence)", definition: "Gathering intelligence from publicly available sources. Includes social media, public records, DNS data, and leaked databases.", category: "Professional Disciplines", relatedTerms: ["Reconnaissance", "Maltego", "Social Engineering"] },
  { term: "Social Engineering", definition: "Manipulating people into divulging information or performing actions. Includes phishing, pretexting, tailgating, and other human-focused attacks.", category: "Professional Disciplines", relatedTerms: ["Phishing", "Vishing", "Physical Security"] },
  { term: "Physical Security", definition: "Protecting physical assets, facilities, and personnel. Overlaps with cybersecurity through access control, surveillance, and social engineering.", category: "Professional Disciplines", relatedTerms: ["Social Engineering", "Access Control", "Red Team"] },
  { term: "CTF (Capture The Flag)", definition: "Security competitions where participants solve challenges to find hidden 'flags'. Categories include web, crypto, pwn (binary exploitation), reverse engineering, and forensics.", category: "Professional Disciplines", relatedTerms: ["Skill Building", "Competition", "Learning"] },
  { term: "Responsible Disclosure", definition: "Practice of privately reporting vulnerabilities to vendors before public disclosure. Allows time for patches while balancing transparency and security.", category: "Professional Disciplines", relatedTerms: ["Bug Bounty", "CVE", "Vulnerability Research"] },
  { term: "Security Consulting", definition: "Providing expert security advice and services to organizations. Includes assessments, architecture review, and strategic guidance.", category: "Professional Disciplines", relatedTerms: ["Penetration Testing", "Assessment", "Advisory"] },
  { term: "Detection Engineering", definition: "Creating and tuning detection rules for security monitoring. Involves writing SIEM queries, developing behavioral analytics, and reducing false positives.", category: "Professional Disciplines", relatedTerms: ["SIEM", "Blue Team", "Sigma Rules"] },

  // Additional Cyber & Tech Terms
  // Emerging Technologies
  { term: "Blockchain", definition: "Distributed ledger technology where data is stored in blocks linked cryptographically. Foundation for cryptocurrencies and smart contracts with applications in supply chain and identity verification.", category: "Emerging Technologies", relatedTerms: ["Smart Contract", "Cryptocurrency", "Distributed Ledger"] },
  { term: "Smart Contract", definition: "Self-executing code stored on a blockchain that automatically enforces agreement terms when conditions are met. Vulnerabilities include reentrancy, integer overflow, and access control issues.", category: "Emerging Technologies", relatedTerms: ["Blockchain", "Solidity", "DeFi"] },
  { term: "Quantum Computing", definition: "Computing paradigm using quantum-mechanical phenomena like superposition and entanglement. Threatens current cryptography (RSA, ECC) while enabling new cryptographic methods (QKD).", category: "Emerging Technologies", relatedTerms: ["Post-Quantum Cryptography", "Shor's Algorithm", "Cryptography"] },
  { term: "Post-Quantum Cryptography", definition: "Cryptographic algorithms resistant to quantum computer attacks. NIST is standardizing algorithms like CRYSTALS-Kyber (key exchange) and CRYSTALS-Dilithium (signatures).", category: "Emerging Technologies", relatedTerms: ["Quantum Computing", "Lattice Cryptography", "NIST"] },
  { term: "Edge Computing", definition: "Processing data near its source rather than in centralized data centers. Reduces latency but introduces security challenges for distributed devices.", category: "Emerging Technologies", relatedTerms: ["IoT", "Fog Computing", "Latency"] },
  { term: "5G Security", definition: "Security considerations for fifth-generation cellular networks. Issues include network slicing isolation, base station spoofing, and subscriber identity protection.", category: "Emerging Technologies", relatedTerms: ["Mobile Security", "Network Slicing", "IMSI Catcher"] },
  { term: "Digital Twin", definition: "Virtual replica of physical systems used for simulation and monitoring. Security concerns include data integrity, model poisoning, and unauthorized access to sensitive replicas.", category: "Emerging Technologies", relatedTerms: ["IoT", "ICS", "Simulation"] },
  { term: "Homomorphic Encryption", definition: "Encryption scheme allowing computation on encrypted data without decryption. Enables privacy-preserving computation in cloud environments.", category: "Emerging Technologies", relatedTerms: ["Encryption", "Privacy", "Cloud Security"] },
  { term: "Confidential Computing", definition: "Hardware-based isolation protecting data during processing using secure enclaves (Intel SGX, AMD SEV). Enables trusted execution in untrusted environments.", category: "Emerging Technologies", relatedTerms: ["Secure Enclave", "TEE", "Cloud Security"] },
  { term: "Zero-Knowledge Proof (ZKP)", definition: "Cryptographic method proving knowledge of a value without revealing the value itself. Used in privacy-preserving authentication and blockchain applications.", category: "Emerging Technologies", relatedTerms: ["Privacy", "Cryptography", "Blockchain"] },
  
  // Web3 & Cryptocurrency Security
  { term: "DeFi (Decentralized Finance)", definition: "Financial services built on blockchain without traditional intermediaries. Security risks include flash loan attacks, rug pulls, oracle manipulation, and smart contract vulnerabilities.", category: "Web3 Security", relatedTerms: ["Smart Contract", "Flash Loan Attack", "Oracle"] },
  { term: "Flash Loan Attack", definition: "Exploit using uncollateralized loans that must be repaid in the same transaction. Used to manipulate prices, drain liquidity pools, or exploit vulnerable protocols.", category: "Web3 Security", relatedTerms: ["DeFi", "Smart Contract", "Arbitrage"] },
  { term: "Rug Pull", definition: "Scam where project creators abandon a project and abscond with investor funds. Common in DeFi and NFT projects with anonymous teams.", category: "Web3 Security", relatedTerms: ["DeFi", "Exit Scam", "Smart Contract"] },
  { term: "Bridge Attack", definition: "Exploiting vulnerabilities in cross-chain bridges that transfer assets between blockchains. Notable attacks include Ronin Network ($624M) and Wormhole ($320M).", category: "Web3 Security", relatedTerms: ["DeFi", "Cross-Chain", "Smart Contract"] },
  { term: "MEV (Maximal Extractable Value)", definition: "Profit extractable by miners/validators through transaction ordering. Leads to frontrunning, sandwich attacks, and transaction reordering on Ethereum.", category: "Web3 Security", relatedTerms: ["Frontrunning", "Blockchain", "Ethereum"] },
  { term: "Wallet Security", definition: "Protecting cryptocurrency wallets and private keys. Includes hardware wallets, multisig, seed phrase protection, and defense against phishing.", category: "Web3 Security", relatedTerms: ["Hardware Wallet", "Private Key", "Seed Phrase"] },
  { term: "NFT Security", definition: "Security considerations for Non-Fungible Tokens. Risks include metadata manipulation, wash trading, phishing for approvals, and smart contract vulnerabilities.", category: "Web3 Security", relatedTerms: ["Smart Contract", "Phishing", "Digital Assets"] },
  { term: "Cryptojacking", definition: "Unauthorized use of computing resources to mine cryptocurrency. Delivered through malware, compromised websites, or vulnerable servers.", category: "Web3 Security", relatedTerms: ["Cryptocurrency", "Malware", "Resource Abuse"] },
  { term: "51% Attack", definition: "Attack where an entity controls majority of blockchain mining/staking power, enabling double-spending or transaction reversal. More feasible on smaller chains.", category: "Web3 Security", relatedTerms: ["Blockchain", "Double Spending", "Consensus"] },
  { term: "Seed Phrase", definition: "Mnemonic phrase (usually 12-24 words) used to recover cryptocurrency wallets. Must be stored securely offline; compromise leads to total fund loss.", category: "Web3 Security", relatedTerms: ["Wallet Security", "Private Key", "BIP-39"] },

  // Privacy & Anonymity
  { term: "Tor (The Onion Router)", definition: "Anonymity network routing traffic through multiple encrypted relays. Used for privacy protection, censorship circumvention, and accessing .onion hidden services.", category: "Privacy & Anonymity", relatedTerms: ["Dark Web", "Anonymity", "Hidden Services"] },
  { term: "Dark Web", definition: "Portion of the internet accessible only through specialized software like Tor. Hosts legitimate privacy-focused services and illicit marketplaces.", category: "Privacy & Anonymity", relatedTerms: ["Tor", "Deep Web", "Hidden Services"] },
  { term: "VPN (Virtual Private Network)", definition: "Encrypted tunnel between device and VPN server providing privacy and bypassing geographic restrictions. Does not provide complete anonymity.", category: "Privacy & Anonymity", relatedTerms: ["Encryption", "Tunneling", "Privacy"] },
  { term: "I2P (Invisible Internet Project)", definition: "Anonymous overlay network alternative to Tor focused on internal services (eepsites). Uses garlic routing for message bundling.", category: "Privacy & Anonymity", relatedTerms: ["Tor", "Anonymity", "Overlay Network"] },
  { term: "Mix Network", definition: "Anonymous communication method using intermediary servers that mix and relay messages to obscure traffic patterns and sender identity.", category: "Privacy & Anonymity", relatedTerms: ["Tor", "Anonymity", "Traffic Analysis"] },
  { term: "Traffic Analysis", definition: "Examining network patterns to derive information without accessing content. Can reveal communication relationships even with encryption.", category: "Privacy & Anonymity", relatedTerms: ["Metadata", "Surveillance", "Tor"] },
  { term: "Metadata", definition: "Data about data - information like timestamps, sender/receiver, location, duration rather than content. Often reveals as much as content itself.", category: "Privacy & Anonymity", relatedTerms: ["Traffic Analysis", "Privacy", "Surveillance"] },
  { term: "Data Minimization", definition: "Privacy principle of collecting and retaining only data necessary for specific purposes. Required by GDPR and other privacy regulations.", category: "Privacy & Anonymity", relatedTerms: ["GDPR", "Privacy by Design", "Data Protection"] },
  { term: "Privacy by Design", definition: "Framework embedding privacy into system design from the start. Seven foundational principles developed by Ann Cavoukian.", category: "Privacy & Anonymity", relatedTerms: ["GDPR", "Data Minimization", "Security by Design"] },
  { term: "Differential Privacy", definition: "Mathematical framework for sharing aggregate information while protecting individual privacy. Used by Apple and Google for telemetry.", category: "Privacy & Anonymity", relatedTerms: ["Privacy", "Data Analysis", "Anonymization"] },
  { term: "PII (Personally Identifiable Information)", definition: "Information that can identify an individual directly or indirectly. Includes name, SSN, email, IP address, and biometric data.", category: "Privacy & Anonymity", relatedTerms: ["Data Protection", "GDPR", "Privacy"] },
  { term: "Data Masking", definition: "Obscuring sensitive data by replacing it with fictitious but realistic data. Used in development, testing, and analytics environments.", category: "Privacy & Anonymity", relatedTerms: ["Data Protection", "Anonymization", "Tokenization"] },
  { term: "Tokenization", definition: "Replacing sensitive data with non-sensitive tokens that map to the original data. Unlike encryption, tokens cannot be reversed without the token vault.", category: "Privacy & Anonymity", relatedTerms: ["Data Masking", "PCI DSS", "Data Protection"] },

  // Malware Types
  { term: "Trojan Horse", definition: "Malware disguised as legitimate software to trick users into installing it. Unlike viruses, does not self-replicate. Common delivery method for RATs and backdoors.", category: "Malware Types", relatedTerms: ["RAT", "Backdoor", "Malware"] },
  { term: "Remote Access Trojan (RAT)", definition: "Malware providing remote control over infected systems. Capabilities include keylogging, screen capture, file access, and webcam/microphone activation.", category: "Malware Types", relatedTerms: ["Trojan", "C2", "Backdoor"] },
  { term: "Worm", definition: "Self-replicating malware that spreads across networks without user interaction. Notable examples include Conficker, WannaCry, and Morris Worm.", category: "Malware Types", relatedTerms: ["Ransomware", "Propagation", "Network Security"] },
  { term: "Rootkit", definition: "Malware designed to hide its presence and other malicious activity from detection. Operates at kernel level for deep system access.", category: "Malware Types", relatedTerms: ["Kernel", "Stealth", "Persistence"] },
  { term: "Bootkit", definition: "Rootkit variant that infects boot sector or bootloader to load before the operating system. Survives OS reinstallation.", category: "Malware Types", relatedTerms: ["Rootkit", "MBR", "Secure Boot"] },
  { term: "Spyware", definition: "Malware that secretly monitors user activity and collects information. Includes keyloggers, screen recorders, and browser trackers.", category: "Malware Types", relatedTerms: ["Keylogger", "Privacy", "Surveillance"] },
  { term: "Adware", definition: "Software that displays unwanted advertisements. May be bundled with free software or installed through deceptive means.", category: "Malware Types", relatedTerms: ["PUP", "Browser Hijacker", "Malvertising"] },
  { term: "Keylogger", definition: "Software or hardware that records keystrokes to capture passwords, credentials, and sensitive information typed by users.", category: "Malware Types", relatedTerms: ["Spyware", "Credential Theft", "RAT"] },
  { term: "Fileless Malware", definition: "Malware that operates entirely in memory without writing files to disk. Uses legitimate tools (PowerShell, WMI) to evade detection.", category: "Malware Types", relatedTerms: ["LOTL", "Memory Forensics", "EDR"] },
  { term: "Polymorphic Malware", definition: "Malware that changes its code or signature with each infection to evade signature-based detection while maintaining functionality.", category: "Malware Types", relatedTerms: ["Metamorphic", "Evasion", "Signature Detection"] },
  { term: "Metamorphic Malware", definition: "Malware that rewrites its entire code base each time it propagates. More sophisticated than polymorphic malware, harder to detect.", category: "Malware Types", relatedTerms: ["Polymorphic", "Evasion", "Obfuscation"] },
  { term: "Logic Bomb", definition: "Malicious code that executes when specific conditions are met (date, user action, system event). Often planted by insiders.", category: "Malware Types", relatedTerms: ["Time Bomb", "Insider Threat", "Sabotage"] },
  { term: "Wiper", definition: "Destructive malware designed to permanently destroy data on infected systems. Used in sabotage operations (Shamoon, NotPetya, WhisperGate).", category: "Malware Types", relatedTerms: ["Destructive Malware", "Sabotage", "Data Destruction"] },
  { term: "Infostealer", definition: "Malware focused on extracting valuable data like credentials, cookies, cryptocurrency wallets, and browser data. Examples include RedLine and Raccoon.", category: "Malware Types", relatedTerms: ["Credential Theft", "Data Exfiltration", "Stealer"] },
  { term: "Banking Trojan", definition: "Malware targeting financial transactions to steal banking credentials and manipulate transactions. Uses web injection and form grabbing techniques.", category: "Malware Types", relatedTerms: ["Trojan", "Financial Crime", "Web Inject"] },
  { term: "Dropper", definition: "Malware component that downloads and installs other malicious payloads. First stage in multi-stage attacks.", category: "Malware Types", relatedTerms: ["Loader", "Payload", "Multi-Stage"] },
  { term: "Loader", definition: "Malware that loads additional payloads into memory. Often uses process injection and encryption to evade detection.", category: "Malware Types", relatedTerms: ["Dropper", "Shellcode", "Injection"] },
  { term: "Backdoor", definition: "Hidden method of bypassing normal authentication or security controls. Can be intentionally planted or result from vulnerabilities.", category: "Malware Types", relatedTerms: ["RAT", "Persistence", "C2"] },
  { term: "Botnet", definition: "Network of compromised computers controlled by an attacker. Used for DDoS attacks, spam, credential stuffing, and cryptocurrency mining.", category: "Malware Types", relatedTerms: ["DDoS", "C2", "Bot Herder"] },
  { term: "Crypter", definition: "Tool for encrypting/obfuscating malware to evade antivirus detection. Creates FUD (Fully Undetectable) variants of known malware.", category: "Malware Types", relatedTerms: ["Packer", "Obfuscation", "Evasion"] },
  { term: "Packer", definition: "Tool that compresses and encrypts executables. Used legitimately for software protection but also to obfuscate malware.", category: "Malware Types", relatedTerms: ["Crypter", "UPX", "Obfuscation"] },

  // ICS/OT Security
  { term: "ICS (Industrial Control Systems)", definition: "Systems controlling industrial processes in sectors like energy, water, and manufacturing. Includes SCADA, DCS, and PLC components.", category: "ICS/OT Security", relatedTerms: ["SCADA", "OT", "Critical Infrastructure"] },
  { term: "SCADA", definition: "Supervisory Control and Data Acquisition systems for monitoring and controlling industrial processes across large geographic areas.", category: "ICS/OT Security", relatedTerms: ["ICS", "HMI", "RTU"] },
  { term: "OT (Operational Technology)", definition: "Hardware and software that monitors and controls physical devices and processes. Distinct from IT with different security priorities (availability over confidentiality).", category: "ICS/OT Security", relatedTerms: ["ICS", "IT/OT Convergence", "Safety Systems"] },
  { term: "PLC (Programmable Logic Controller)", definition: "Industrial computer controlling manufacturing processes and machinery. Common attack target in ICS environments (Stuxnet targeted Siemens PLCs).", category: "ICS/OT Security", relatedTerms: ["ICS", "Ladder Logic", "SCADA"] },
  { term: "HMI (Human-Machine Interface)", definition: "Interface allowing operators to interact with industrial control systems. Security concerns include weak authentication and network exposure.", category: "ICS/OT Security", relatedTerms: ["SCADA", "ICS", "Operator Workstation"] },
  { term: "RTU (Remote Terminal Unit)", definition: "Microprocessor-controlled device interfacing with physical equipment in remote locations, communicating with SCADA master systems.", category: "ICS/OT Security", relatedTerms: ["SCADA", "Telemetry", "Modbus"] },
  { term: "Modbus", definition: "Serial communication protocol commonly used in ICS environments. Lacks built-in security features like authentication or encryption.", category: "ICS/OT Security", relatedTerms: ["ICS Protocol", "DNP3", "Serial Communication"] },
  { term: "DNP3 (Distributed Network Protocol)", definition: "Communication protocol used primarily in utilities and water/wastewater. DNP3 Secure Authentication adds cryptographic security.", category: "ICS/OT Security", relatedTerms: ["SCADA", "ICS Protocol", "Utilities"] },
  { term: "Purdue Model", definition: "Reference architecture for ICS network segmentation with levels from enterprise network (Level 5) to physical process (Level 0).", category: "ICS/OT Security", relatedTerms: ["Network Segmentation", "ICS", "DMZ"] },
  { term: "Safety Instrumented System (SIS)", definition: "System designed to take a process to a safe state when conditions require it. Critical target for attackers seeking physical damage.", category: "ICS/OT Security", relatedTerms: ["ICS", "Process Safety", "TRITON"] },
  { term: "Air Gap", definition: "Physical isolation of a network from other networks including the internet. Common in ICS but often bypassed through removable media or insider access.", category: "ICS/OT Security", relatedTerms: ["Network Segmentation", "ICS", "Isolation"] },
  { term: "IT/OT Convergence", definition: "Integration of information technology and operational technology networks. Creates efficiency but introduces cybersecurity risks to previously isolated systems.", category: "ICS/OT Security", relatedTerms: ["ICS", "Digital Transformation", "Attack Surface"] },

  // Wireless Security
  { term: "WPA3", definition: "Latest Wi-Fi security protocol with Simultaneous Authentication of Equals (SAE) replacing WPA2's vulnerable 4-way handshake. Provides forward secrecy.", category: "Wireless Security", relatedTerms: ["WiFi Security", "WPA2", "SAE"] },
  { term: "WPA2", definition: "Wi-Fi Protected Access 2 using AES encryption. Vulnerable to KRACK attacks and offline dictionary attacks against PSK.", category: "Wireless Security", relatedTerms: ["WiFi Security", "KRACK", "WPA3"] },
  { term: "KRACK (Key Reinstallation Attack)", definition: "Attack exploiting WPA2's 4-way handshake by forcing nonce reuse. Allows traffic decryption and packet injection.", category: "Wireless Security", relatedTerms: ["WPA2", "WiFi Security", "Nonce Reuse"] },
  { term: "Evil Twin Attack", definition: "Rogue access point mimicking a legitimate network to intercept traffic. Victims connect believing it's the real network.", category: "Wireless Security", relatedTerms: ["WiFi Security", "MitM", "Rogue AP"] },
  { term: "Wardriving", definition: "Driving around to discover and map wireless networks. Used for security assessments and by attackers to find vulnerable networks.", category: "Wireless Security", relatedTerms: ["WiFi Security", "Reconnaissance", "Kismet"] },
  { term: "Deauthentication Attack", definition: "Sending forged deauth frames to disconnect clients from wireless networks. Used to capture handshakes or deny service.", category: "Wireless Security", relatedTerms: ["WiFi Security", "DoS", "Handshake Capture"] },
  { term: "IMSI Catcher", definition: "Device that mimics cell towers to intercept mobile communications and track devices. Also called Stingray after a commercial product.", category: "Wireless Security", relatedTerms: ["Mobile Security", "Surveillance", "5G Security"] },
  { term: "Bluetooth Security", definition: "Security considerations for Bluetooth including BlueBorne vulnerabilities, Bluesnarfing (data theft), and Bluejacking (spam).", category: "Wireless Security", relatedTerms: ["Mobile Security", "IoT", "Wireless"] },
  { term: "NFC Security", definition: "Security for Near Field Communication technology used in contactless payments and access cards. Risks include eavesdropping and relay attacks.", category: "Wireless Security", relatedTerms: ["Mobile Security", "Contactless", "RFID"] },
  { term: "RFID Security", definition: "Security for Radio Frequency Identification systems. Vulnerabilities include cloning, eavesdropping, and replay attacks on access cards.", category: "Wireless Security", relatedTerms: ["NFC Security", "Access Control", "Proximity Cards"] },

  // API Security
  { term: "OWASP API Security Top 10", definition: "List of most critical API security risks including Broken Object Level Authorization, Broken Authentication, and Excessive Data Exposure.", category: "API Security", relatedTerms: ["OWASP", "REST API", "BOLA"] },
  { term: "BOLA (Broken Object Level Authorization)", definition: "API vulnerability where users can access objects belonging to other users by manipulating object IDs in requests.", category: "API Security", relatedTerms: ["IDOR", "Authorization", "API Security"] },
  { term: "IDOR (Insecure Direct Object Reference)", definition: "Access control vulnerability where user-supplied input provides direct access to objects. Common in APIs through predictable resource IDs.", category: "API Security", relatedTerms: ["BOLA", "Authorization", "Access Control"] },
  { term: "Rate Limiting", definition: "Controlling the number of requests a client can make in a time period. Prevents abuse, brute force attacks, and resource exhaustion.", category: "API Security", relatedTerms: ["API Security", "DoS Prevention", "Throttling"] },
  { term: "API Key", definition: "Simple authentication token for API access. Should be protected like passwords; insufficient alone for sensitive operations.", category: "API Security", relatedTerms: ["Authentication", "OAuth", "Bearer Token"] },
  { term: "API Gateway", definition: "Entry point for API traffic handling authentication, rate limiting, request routing, and security policies.", category: "API Security", relatedTerms: ["Microservices", "Load Balancer", "WAF"] },
  { term: "OpenAPI/Swagger", definition: "Specification for describing REST APIs. Security testing can leverage specs to identify endpoints and parameter types.", category: "API Security", relatedTerms: ["REST API", "Documentation", "API Testing"] },
  { term: "Mass Assignment", definition: "Vulnerability where APIs bind request parameters directly to object properties without filtering, allowing modification of unintended fields.", category: "API Security", relatedTerms: ["API Security", "Input Validation", "Parameter Binding"] },

  // DevOps & CI/CD Security
  { term: "CI/CD Pipeline", definition: "Automated workflow for building, testing, and deploying code. Security integration points include SAST, DAST, SCA, and secrets scanning.", category: "DevOps Security", relatedTerms: ["DevSecOps", "Build Pipeline", "Automation"] },
  { term: "GitOps", definition: "Operational framework using Git as single source of truth for declarative infrastructure and applications. Security requires protecting Git repos and enforcing reviews.", category: "DevOps Security", relatedTerms: ["IaC", "Kubernetes", "Version Control"] },
  { term: "Secrets Management", definition: "Secure storage and access of credentials, API keys, and certificates. Solutions include HashiCorp Vault, AWS Secrets Manager, and Azure Key Vault.", category: "DevOps Security", relatedTerms: ["Vault", "Credentials", "Key Management"] },
  { term: "Infrastructure as Code Security", definition: "Scanning IaC templates (Terraform, CloudFormation) for misconfigurations before deployment. Tools include Checkov, tfsec, and KICS.", category: "DevOps Security", relatedTerms: ["IaC", "CSPM", "Static Analysis"] },
  { term: "Container Image Scanning", definition: "Analyzing container images for vulnerabilities in OS packages and application dependencies. Part of secure container pipeline.", category: "DevOps Security", relatedTerms: ["Container Security", "SBOM", "Trivy"] },
  { term: "Shift Left Security", definition: "Moving security testing earlier in the development lifecycle. Catches vulnerabilities before production at lower remediation cost.", category: "DevOps Security", relatedTerms: ["DevSecOps", "SAST", "Secure SDLC"] },
  { term: "Policy as Code", definition: "Defining security and compliance policies in code for automated enforcement. Examples include OPA Rego, Sentinel, and Kyverno.", category: "DevOps Security", relatedTerms: ["OPA", "Compliance", "Automation"] },
  { term: "Artifact Repository Security", definition: "Securing package repositories (npm, PyPI, Maven). Includes dependency confusion prevention, signature verification, and access control.", category: "DevOps Security", relatedTerms: ["Supply Chain", "Dependency Confusion", "SCA"] },
  { term: "Dependency Confusion", definition: "Attack exploiting package managers that prioritize public packages over private ones. Attacker publishes malicious public package with internal package name.", category: "DevOps Security", relatedTerms: ["Supply Chain Attack", "npm", "PyPI"] },

  // Security Operations
  { term: "Alert Fatigue", definition: "Desensitization to security alerts due to high volume or false positives. Leads to missed genuine threats and analyst burnout.", category: "Security Operations", relatedTerms: ["SOC", "SIEM", "False Positive"] },
  { term: "False Positive", definition: "Alert triggered for benign activity incorrectly classified as malicious. High false positive rates reduce detection effectiveness.", category: "Security Operations", relatedTerms: ["Alert Fatigue", "Detection", "Tuning"] },
  { term: "False Negative", definition: "Failure to detect actual malicious activity. More dangerous than false positives as threats go unnoticed.", category: "Security Operations", relatedTerms: ["Detection", "Evasion", "Coverage"] },
  { term: "Runbook", definition: "Documented standard operating procedures for responding to specific alert types or incidents. Enables consistent response.", category: "Security Operations", relatedTerms: ["Playbook", "SOC", "Automation"] },
  { term: "Security Orchestration", definition: "Connecting and coordinating security tools and processes. Enables automated workflows across disparate security solutions.", category: "Security Operations", relatedTerms: ["SOAR", "Automation", "Integration"] },
  { term: "Threat Feed", definition: "Stream of threat intelligence data (IOCs, TTPs) for consumption by security tools. Sources include commercial, open source, and ISACs.", category: "Security Operations", relatedTerms: ["Threat Intelligence", "IOC", "STIX/TAXII"] },
  { term: "STIX/TAXII", definition: "Standards for expressing and exchanging threat intelligence. STIX defines structure; TAXII defines transport. Enables automated intelligence sharing.", category: "Security Operations", relatedTerms: ["Threat Intelligence", "CTI", "Information Sharing"] },
  { term: "Kill Chain Analysis", definition: "Mapping attacker activity to stages of the kill chain to understand attack progression and identify defense gaps.", category: "Security Operations", relatedTerms: ["Cyber Kill Chain", "MITRE ATT&CK", "Detection"] },

  // Data Security
  { term: "Data Classification", definition: "Categorizing data based on sensitivity level (public, internal, confidential, restricted). Determines required protection controls.", category: "Data Security", relatedTerms: ["DLP", "Data Protection", "Labeling"] },
  { term: "Data Loss Prevention (DLP)", definition: "Technologies and processes preventing unauthorized data exfiltration. Monitors endpoints, network, and cloud for sensitive data movement.", category: "Data Security", relatedTerms: ["Data Classification", "Exfiltration", "Content Inspection"] },
  { term: "Data Exfiltration", definition: "Unauthorized transfer of data from an organization. Methods include cloud storage, DNS tunneling, steganography, and physical media.", category: "Data Security", relatedTerms: ["Data Loss Prevention", "Insider Threat", "C2"] },
  { term: "Database Activity Monitoring (DAM)", definition: "Monitoring database access to detect unauthorized queries, privilege abuse, and data theft. Provides visibility into database activity.", category: "Data Security", relatedTerms: ["Database Security", "Audit", "Access Monitoring"] },
  { term: "Data Sovereignty", definition: "Requirement that data be stored and processed within specific geographic boundaries. Driven by regulations like GDPR and national security concerns.", category: "Data Security", relatedTerms: ["GDPR", "Compliance", "Data Residency"] },
  { term: "Right to be Forgotten", definition: "GDPR right requiring organizations to delete personal data upon request. Creates challenges for backup, archival, and distributed systems.", category: "Data Security", relatedTerms: ["GDPR", "Privacy", "Data Deletion"] },
  { term: "Encryption at Rest", definition: "Encrypting data stored on disk, databases, or storage media. Protects against physical theft and unauthorized access to storage.", category: "Data Security", relatedTerms: ["Encryption", "Data Protection", "Key Management"] },
  { term: "Encryption in Transit", definition: "Encrypting data during transmission over networks. Implemented via TLS/SSL, IPsec, or application-layer encryption.", category: "Data Security", relatedTerms: ["TLS", "Data Protection", "Network Security"] },

  // Identity Security
  { term: "Identity Governance", definition: "Framework for managing digital identities including provisioning, certification, and access request workflows.", category: "Identity Security", relatedTerms: ["IAM", "Access Review", "Lifecycle Management"] },
  { term: "Access Review/Certification", definition: "Periodic review of user access rights to ensure appropriateness. Required by regulations and essential for least privilege.", category: "Identity Security", relatedTerms: ["Identity Governance", "Compliance", "Least Privilege"] },
  { term: "Privileged Access Management (PAM)", definition: "Controls for protecting privileged accounts with elevated access. Features include password vaulting, session recording, and just-in-time access.", category: "Identity Security", relatedTerms: ["IAM", "Privilege Escalation", "Admin Accounts"] },
  { term: "Just-in-Time Access", definition: "Granting elevated privileges only when needed and for limited duration. Reduces standing privilege exposure.", category: "Identity Security", relatedTerms: ["PAM", "Least Privilege", "Zero Trust"] },
  { term: "Service Account", definition: "Non-human account used by applications and services. Often over-privileged and poorly managed, making them prime attack targets.", category: "Identity Security", relatedTerms: ["IAM", "Secrets Management", "Machine Identity"] },
  { term: "Machine Identity", definition: "Digital identities for workloads, services, and devices. Includes certificates, API keys, and tokens requiring lifecycle management.", category: "Identity Security", relatedTerms: ["PKI", "Service Account", "Secrets Management"] },
  { term: "Federation", definition: "Establishing trust between identity providers to enable SSO across organizational boundaries. Protocols include SAML and OIDC.", category: "Identity Security", relatedTerms: ["SSO", "SAML", "Identity Provider"] },
  { term: "Directory Services", definition: "Centralized databases storing identity and access information. Examples include Active Directory, LDAP directories, and cloud directories.", category: "Identity Security", relatedTerms: ["Active Directory", "LDAP", "IAM"] },

  // Risk & Compliance
  { term: "Risk Assessment", definition: "Process of identifying, analyzing, and evaluating risks. Considers likelihood, impact, and existing controls to prioritize mitigation.", category: "Risk & Compliance", relatedTerms: ["Threat Modeling", "Risk Management", "Vulnerability Assessment"] },
  { term: "Risk Appetite", definition: "Amount and type of risk an organization is willing to accept in pursuit of objectives. Guides security investment decisions.", category: "Risk & Compliance", relatedTerms: ["Risk Management", "Risk Tolerance", "Business Risk"] },
  { term: "Residual Risk", definition: "Risk remaining after controls are implemented. Should align with risk appetite; if not, additional controls needed.", category: "Risk & Compliance", relatedTerms: ["Risk Assessment", "Controls", "Risk Acceptance"] },
  { term: "Control Framework", definition: "Structured set of controls for managing security risks. Examples include NIST CSF, CIS Controls, and ISO 27002.", category: "Risk & Compliance", relatedTerms: ["Security Controls", "NIST", "Compliance"] },
  { term: "Security Audit", definition: "Independent assessment of security controls against standards or regulations. Can be internal or performed by third parties.", category: "Risk & Compliance", relatedTerms: ["Compliance", "Assessment", "Attestation"] },
  { term: "Penetration Test Report", definition: "Documentation of penetration testing findings including vulnerabilities, risk ratings, exploitation evidence, and remediation recommendations.", category: "Risk & Compliance", relatedTerms: ["Penetration Testing", "Vulnerability Report", "Remediation"] },
  { term: "Compensating Control", definition: "Alternative security measure when primary control cannot be implemented. Must provide equivalent protection.", category: "Risk & Compliance", relatedTerms: ["Security Controls", "Risk Mitigation", "Compliance"] },
  { term: "Exception Management", definition: "Process for documenting and approving deviations from security policies. Requires risk assessment, time limits, and executive approval.", category: "Risk & Compliance", relatedTerms: ["Policy", "Risk Acceptance", "Governance"] },
  { term: "Security Metrics", definition: "Quantitative measurements of security performance and risk. Examples include patch compliance, MTTD/MTTR, and phishing click rates.", category: "Risk & Compliance", relatedTerms: ["KPI", "Reporting", "Security Posture"] },
  { term: "HIPAA", definition: "Health Insurance Portability and Accountability Act - US regulation protecting healthcare data (PHI). Requires safeguards and breach notification.", category: "Risk & Compliance", relatedTerms: ["Compliance", "Healthcare", "PHI"] },
  { term: "FERPA", definition: "Family Educational Rights and Privacy Act - US law protecting student education records. Applies to educational institutions receiving federal funds.", category: "Risk & Compliance", relatedTerms: ["Compliance", "Education", "Privacy"] },
  { term: "CCPA/CPRA", definition: "California Consumer Privacy Act and Privacy Rights Act - state privacy laws giving consumers rights over personal information similar to GDPR.", category: "Risk & Compliance", relatedTerms: ["Privacy", "Compliance", "Data Protection"] },
  { term: "GLBA", definition: "Gramm-Leach-Bliley Act - US regulation requiring financial institutions to protect consumer financial information.", category: "Risk & Compliance", relatedTerms: ["Financial Services", "Compliance", "Privacy"] },
  { term: "FedRAMP", definition: "Federal Risk and Authorization Management Program - US government program for cloud security assessment and authorization.", category: "Risk & Compliance", relatedTerms: ["Cloud Security", "Compliance", "Government"] },

  // Physical & Operational Security
  { term: "Tailgating", definition: "Unauthorized person following an authorized person through a secure entrance. Defeated by mantraps and security awareness training.", category: "Physical Security", relatedTerms: ["Social Engineering", "Access Control", "Physical Security"] },
  { term: "Piggybacking", definition: "Similar to tailgating but with the authorized person's knowledge/consent. Still a security violation.", category: "Physical Security", relatedTerms: ["Tailgating", "Social Engineering", "Physical Security"] },
  { term: "Mantrap", definition: "Physical access control with two interlocking doors ensuring only authorized individuals pass through. Prevents tailgating.", category: "Physical Security", relatedTerms: ["Access Control", "Physical Security", "Tailgating"] },
  { term: "CCTV", definition: "Closed-circuit television for surveillance and security monitoring. Increasingly integrated with analytics and access control systems.", category: "Physical Security", relatedTerms: ["Surveillance", "Physical Security", "Monitoring"] },
  { term: "Dumpster Diving", definition: "Searching through trash to find sensitive information like documents, hardware, or credentials. Countered by shredding and secure disposal.", category: "Physical Security", relatedTerms: ["Social Engineering", "OSINT", "Data Destruction"] },
  { term: "Clean Desk Policy", definition: "Requiring employees to clear desks of sensitive materials when unattended. Prevents unauthorized access to information.", category: "Physical Security", relatedTerms: ["Physical Security", "Policy", "Data Protection"] },
  { term: "Secure Disposal", definition: "Properly destroying sensitive data and media. Includes shredding, degaussing, and certified destruction services.", category: "Physical Security", relatedTerms: ["Data Destruction", "Media Sanitization", "Compliance"] },
  { term: "Biometric Authentication", definition: "Using biological characteristics (fingerprint, face, iris, voice) for authentication. More resistant to credential theft than passwords.", category: "Physical Security", relatedTerms: ["Authentication", "MFA", "Access Control"] },

  // Security Testing
  { term: "Black Box Testing", definition: "Security testing without knowledge of internal implementation. Simulates external attacker perspective.", category: "Security Testing", relatedTerms: ["White Box", "Gray Box", "Penetration Testing"] },
  { term: "White Box Testing", definition: "Security testing with full knowledge of source code and architecture. Enables thorough analysis but differs from real-world attack conditions.", category: "Security Testing", relatedTerms: ["Black Box", "Code Review", "SAST"] },
  { term: "Gray Box Testing", definition: "Security testing with partial knowledge, typically user-level access. Balance between black and white box approaches.", category: "Security Testing", relatedTerms: ["Black Box", "White Box", "Penetration Testing"] },
  { term: "Assumed Breach", definition: "Testing methodology assuming attackers have already gained initial access. Tests internal defenses and detection capabilities.", category: "Security Testing", relatedTerms: ["Red Team", "Purple Team", "Post-Exploitation"] },
  { term: "Scope", definition: "Boundaries defining what systems, networks, and attack types are authorized during security testing. Critical for legal protection.", category: "Security Testing", relatedTerms: ["Rules of Engagement", "Penetration Testing", "Authorization"] },
  { term: "Rules of Engagement", definition: "Guidelines governing security testing including scope, timing, communication, and prohibited actions. Documented before testing begins.", category: "Security Testing", relatedTerms: ["Scope", "Penetration Testing", "Authorization"] },
  { term: "Proof of Concept (PoC)", definition: "Demonstration that a vulnerability is exploitable. Used to validate findings and communicate risk without causing damage.", category: "Security Testing", relatedTerms: ["Exploit", "Vulnerability", "Validation"] },

  // Miscellaneous Technical Terms
  { term: "Sandboxing", definition: "Isolating programs in restricted environments to limit potential damage. Used for malware analysis, browser security, and application isolation.", category: "Security Concepts", relatedTerms: ["Isolation", "Malware Analysis", "Container"] },
  { term: "Canary Token", definition: "Decoy credentials or files that trigger alerts when accessed, detecting unauthorized access or breach. Also called honeytokens.", category: "Detection & Response", relatedTerms: ["Honeypot", "Detection", "Deception"] },
  { term: "Honeypot", definition: "Decoy system designed to attract and detect attackers. Provides intelligence on attack techniques and early warning of intrusions.", category: "Detection & Response", relatedTerms: ["Canary Token", "Deception", "Threat Intelligence"] },
  { term: "Honeynet", definition: "Network of honeypots simulating an entire network environment. Provides more realistic deception and richer intelligence.", category: "Detection & Response", relatedTerms: ["Honeypot", "Deception", "Network Security"] },
  { term: "Deception Technology", definition: "Security approach using decoys, traps, and misdirection to detect and confuse attackers. Complements traditional detection.", category: "Detection & Response", relatedTerms: ["Honeypot", "Canary Token", "Detection"] },
  { term: "Blue-Green Deployment", definition: "Deployment strategy maintaining two identical environments for zero-downtime updates. Security considerations include environment synchronization and rollback.", category: "DevOps Security", relatedTerms: ["CI/CD", "Deployment", "Rollback"] },
  { term: "Canary Deployment", definition: "Gradually rolling out changes to a small subset of users before full deployment. Limits blast radius of security issues.", category: "DevOps Security", relatedTerms: ["CI/CD", "Feature Flags", "Risk Mitigation"] },
  { term: "Immutable Infrastructure", definition: "Infrastructure paradigm where servers are never modified after deployment. Changes require replacement. Prevents configuration drift and persistent threats.", category: "DevOps Security", relatedTerms: ["IaC", "Containers", "Configuration Management"] },
  { term: "Chaos Engineering", definition: "Deliberately introducing failures to test system resilience. Security applications include testing incident response and failover procedures.", category: "DevOps Security", relatedTerms: ["Resilience", "Testing", "Fault Injection"] },
  { term: "SRE (Site Reliability Engineering)", definition: "Discipline applying software engineering to operations. Security responsibilities include reliability of security controls and incident response.", category: "DevOps Security", relatedTerms: ["DevOps", "Reliability", "Operations"] },
  { term: "Observability", definition: "Ability to understand system state from external outputs (logs, metrics, traces). Essential for security monitoring and incident investigation.", category: "Security Operations", relatedTerms: ["Monitoring", "Telemetry", "SIEM"] },
  { term: "Telemetry", definition: "Automated collection and transmission of data from remote sources. Security uses include endpoint monitoring, cloud metrics, and performance data.", category: "Security Operations", relatedTerms: ["EDR", "Monitoring", "Observability"] },
  { term: "Log Aggregation", definition: "Centralizing logs from multiple sources for analysis. Foundation for SIEM, compliance, and incident investigation.", category: "Security Operations", relatedTerms: ["SIEM", "Logging", "Elasticsearch"] },
  { term: "Log Retention", definition: "Policies defining how long logs are stored. Balances compliance requirements, investigation needs, and storage costs.", category: "Security Operations", relatedTerms: ["Compliance", "SIEM", "Data Retention"] },
];

const categories = [...new Set(glossaryTerms.map((t) => t.category))];

export default function GlossaryPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState(0);
  const [selectedTerm, setSelectedTerm] = useState<GlossaryTerm | null>(glossaryTerms[0]);

  const filteredTerms = useMemo(() => {
    let terms = glossaryTerms;
    if (selectedCategory > 0) {
      terms = terms.filter((t) => t.category === categories[selectedCategory - 1]);
    }
    const normalizedQuery = normalizeSearchText(searchQuery);
    if (normalizedQuery) {
      const tokens = normalizedQuery.split(" ").filter(Boolean);
      terms = terms.filter((t) => {
        const haystack = buildSearchText(t);
        return tokens.every((token) => haystack.includes(token));
      });
    }
    return terms.slice().sort((a, b) => a.term.localeCompare(b.term));
  }, [selectedCategory, searchQuery]);

  useEffect(() => {
    if (filteredTerms.length === 0) {
      setSelectedTerm(null);
      return;
    }
    if (!selectedTerm || !filteredTerms.some((term) => term.term === selectedTerm.term)) {
      setSelectedTerm(filteredTerms[0]);
    }
  }, [filteredTerms, selectedTerm]);

  const handleRelatedTermClick = (termName: string) => {
    const found = glossaryTerms.find((t) => t.term.toLowerCase().includes(termName.toLowerCase()));
    if (found) {
      setSelectedTerm(found);
      setSearchQuery("");
      setSelectedCategory(0);
    }
  };

  const getCategoryStats = (cat: string) => glossaryTerms.filter((t) => t.category === cat).length;

  return (
    <LearnPageLayout pageTitle="Cybersecurity Glossary" pageContext={pageContext}>
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Back Button */}
      <Chip
        component={Link}
        to="/learn"
        icon={<ArrowBackIcon />}
        label="Back to Learning Hub"
        clickable
        variant="outlined"
        sx={{ borderRadius: 2, mb: 3 }}
      />

      {/* Header */}
      <Box sx={{ mb: 5 }}>
        <Typography
          variant="h3"
          sx={{
            fontWeight: 800,
            mb: 2,
            background: `linear-gradient(135deg, #10b981, #3b82f6)`,
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          📚 Security Glossary
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 800 }}>
          A comprehensive reference of {glossaryTerms.length}+ cybersecurity terms, concepts, and frameworks. Essential knowledge for security professionals.
        </Typography>
      </Box>

      {/* Category Stats */}
      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1.5, mb: 4 }}>
        {categories.map((cat) => (
          <Chip
            key={cat}
            label={`${cat} (${getCategoryStats(cat)})`}
            onClick={() => setSelectedCategory(categories.indexOf(cat) + 1)}
            sx={{
              bgcolor: selectedCategory === categories.indexOf(cat) + 1 ? "primary.main" : alpha(theme.palette.primary.main, 0.1),
              color: selectedCategory === categories.indexOf(cat) + 1 ? "white" : "primary.main",
              fontWeight: 600,
              "&:hover": { bgcolor: selectedCategory === categories.indexOf(cat) + 1 ? "primary.dark" : alpha(theme.palette.primary.main, 0.2) },
            }}
          />
        ))}
        {selectedCategory > 0 && (
          <Chip label="Clear Filter" variant="outlined" onClick={() => setSelectedCategory(0)} onDelete={() => setSelectedCategory(0)} />
        )}
      </Box>

      <Grid container spacing={3}>
        {/* Term List */}
        <Grid item xs={12} md={4}>
          <Paper sx={{ borderRadius: 3, overflow: "hidden", position: "sticky", top: 80 }}>
            <Box sx={{ p: 2, bgcolor: alpha(theme.palette.primary.main, 0.05), borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
              <TextField
                fullWidth
                size="small"
                placeholder="Search terms..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon color="action" />
                    </InputAdornment>
                  ),
                }}
              />
            </Box>
            <List sx={{ maxHeight: 500, overflow: "auto", py: 0 }}>
              {filteredTerms.length === 0 ? (
                <Box sx={{ p: 3, textAlign: "center" }}>
                  <Typography color="text.secondary">No terms found</Typography>
                </Box>
              ) : (
                filteredTerms.map((term, index) => (
                  <ListItemButton
                    key={term.term}
                    selected={selectedTerm?.term === term.term}
                    onClick={() => setSelectedTerm(term)}
                    sx={{
                      borderLeft: selectedTerm?.term === term.term ? `3px solid ${theme.palette.primary.main}` : "3px solid transparent",
                      "&.Mui-selected": { bgcolor: alpha(theme.palette.primary.main, 0.08) },
                    }}
                  >
                    <ListItemText
                      primary={term.term}
                      secondary={term.category}
                      primaryTypographyProps={{ fontWeight: selectedTerm?.term === term.term ? 700 : 500, fontSize: "0.9rem" }}
                      secondaryTypographyProps={{ fontSize: "0.75rem" }}
                    />
                  </ListItemButton>
                ))
              )}
            </List>
            <Box sx={{ p: 2, bgcolor: alpha(theme.palette.background.default, 0.5), borderTop: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
              <Typography variant="caption" color="text.secondary">
                Showing {filteredTerms.length} of {glossaryTerms.length} terms
              </Typography>
            </Box>
          </Paper>
        </Grid>

        {/* Term Detail */}
        <Grid item xs={12} md={8}>
          {selectedTerm ? (
            <Paper sx={{ p: 4, borderRadius: 3 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
                {selectedTerm.term}
              </Typography>
              <Chip label={selectedTerm.category} size="small" sx={{ mb: 3, bgcolor: alpha(theme.palette.primary.main, 0.1), color: "primary.main" }} />
              
              <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.1rem", mb: 4 }}>
                {selectedTerm.definition}
              </Typography>

              {selectedTerm.relatedTerms && selectedTerm.relatedTerms.length > 0 && (
                <Box>
                  <Divider sx={{ mb: 3 }} />
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                    🔗 Related Terms
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {selectedTerm.relatedTerms.map((related) => {
                      const exists = glossaryTerms.some((t) => t.term.toLowerCase().includes(related.toLowerCase()));
                      return (
                        <Chip
                          key={related}
                          label={related}
                          clickable={exists}
                          onClick={() => exists && handleRelatedTermClick(related)}
                          variant={exists ? "filled" : "outlined"}
                          sx={{
                            bgcolor: exists ? alpha(theme.palette.secondary.main, 0.1) : undefined,
                            color: exists ? "secondary.main" : "text.secondary",
                            cursor: exists ? "pointer" : "default",
                            "&:hover": exists ? { bgcolor: alpha(theme.palette.secondary.main, 0.2) } : {},
                          }}
                        />
                      );
                    })}
                  </Box>
                </Box>
              )}

              {/* Quick Navigation by First Letter */}
              <Box sx={{ mt: 4 }}>
                <Divider sx={{ mb: 3 }} />
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                  📖 Browse by Letter
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                  {"ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("").map((letter) => {
                    const hasTerms = glossaryTerms.some((t) => t.term.toUpperCase().startsWith(letter));
                    return (
                      <Chip
                        key={letter}
                        label={letter}
                        size="small"
                        clickable={hasTerms}
                        disabled={!hasTerms}
                        onClick={() => {
                          if (hasTerms) {
                            const firstMatch = glossaryTerms.find((t) => t.term.toUpperCase().startsWith(letter));
                            if (firstMatch) setSelectedTerm(firstMatch);
                          }
                        }}
                        sx={{
                          minWidth: 32,
                          fontWeight: 600,
                          bgcolor: hasTerms ? alpha(theme.palette.primary.main, 0.05) : undefined,
                        }}
                      />
                    );
                  })}
                </Box>
              </Box>
            </Paper>
          ) : (
            <Paper sx={{ p: 4, borderRadius: 3, textAlign: "center" }}>
              <Typography color="text.secondary">Select a term from the list</Typography>
            </Paper>
          )}
        </Grid>
      </Grid>

      {/* Bottom Navigation */}
      <Box sx={{ mt: 4, textAlign: "center" }}>
        <Button
          variant="outlined"
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate("/learn")}
          sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}
        >
          Back to Learning Hub
        </Button>
      </Box>
    </Container>
    </LearnPageLayout>
  );
}
