import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import MitmChatPanel from '../components/MitmChatPanel';
import MitmAttackPhaseIndicator from '../components/MitmAttackPhaseIndicator';
import {
  Box,
  Typography,
  Paper,
  Grid,
  TextField,
  Button,
  IconButton,
  Card,
  CardContent,
  CardActions,
  Chip,
  Switch,
  FormControlLabel,
  Checkbox,
  Select,
  MenuItem,
  InputLabel,
  FormControl,
  FormGroup,
  InputAdornment,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Tabs,
  Tab,
  Alert,
  Tooltip,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Badge,
  LinearProgress,
  Snackbar,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  CircularProgress,
  Menu,
  ListItemIcon,
  Collapse,
  AlertTitle,
  Avatar,
  Fade,
  Backdrop,
  Zoom,
  useTheme,
  alpha,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Delete as DeleteIcon,
  Add as AddIcon,
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  FilterList as FilterIcon,
  Security as SecurityIcon,
  Speed as SpeedIcon,
  Code as CodeIcon,
  Http as HttpIcon,
  Lock as LockIcon,
  LockOpen as LockOpenIcon,
  ContentCopy as CopyIcon,
  Download as DownloadIcon,
  Clear as ClearIcon,
  Visibility as ViewIcon,
  Edit as EditIcon,
  Rule as RuleIcon,
  NetworkCheck as NetworkIcon,
  SwapHoriz as SwapIcon,
  Warning as WarningIcon,
  CheckCircle as SuccessIcon,
  Error as ErrorIcon,
  Settings as SettingsIcon,
  HelpOutline as HelpIcon,
  School as TutorialIcon,
  Psychology as AIIcon,
  Description as MarkdownIcon,
  Description as DescriptionIcon,
  PictureAsPdf as PdfIcon,
  Article as WordIcon,
  TipsAndUpdates as TipIcon,
  ArrowForward as NextIcon,
  ArrowBack as BackIcon,
  BugReport as DebugIcon,
  Lightbulb as IdeaIcon,
  VerifiedUser as ShieldIcon,
  Science as ScienceIcon,
  PlayCircle as RunIcon,
  CheckCircleOutline as CheckIcon,
  Cancel as CancelIcon,
  Info as InfoIcon,
  Computer as ClientIcon,
  Storage as ServerIcon,
  Router as ProxyIcon,
  East as ArrowRightIcon,
  Wifi as WifiIcon,
  WifiOff as WifiOffIcon,
  FiberManualRecord as DotIcon,
  Close as CloseIcon,
  MenuBook as LearnIcon,
  ArrowDropDown as DropdownIcon,
  Search as SearchIcon,
  MoreVert as MoreIcon,
  Replay as ReplayIcon,
  History as HistoryIcon,
  Route as RouteIcon,
  Link as LinkIcon,
} from '@mui/icons-material';
import {
  mitmClient,
  MITMAnalysisResult,
  MITMGuidedSetup,
  MITMTestScenario,
  MITMProxyHealth,
  NaturalLanguageRuleResponse,
  AISuggestion,
  AISuggestionsResponse,
  MITMSession,
  MITMSavedScan,
  WebSocketConnection,
  WebSocketFrame,
  WebSocketRule,
  WebSocketStats,
  CACertificate,
  HostCertificate,
  CertificateInstallationInstructions,
  MITMAttackTool,
  MITMToolRecommendation,
  MITMToolExecutionResult,
  MITMAgenticSessionResult,
} from '../api/client';
import { formatMarkdownSafe } from '../utils/sanitizeHtml';

// Types
interface ProxyInstance {
  id: string;
  listen_host: string;
  listen_port: number;
  target_host: string;
  target_port: number;
  mode: 'passthrough' | 'intercept' | 'auto_modify';
  tls_enabled: boolean;
  running: boolean;
  stats: {
    requests: number;
    responses: number;
    bytes_sent: number;
    bytes_received: number;
    errors: number;
    rules_applied: number;
  };
}

interface TrafficEntry {
  id: string;
  timestamp: string;
  request: {
    method: string;
    path: string;
    host?: string;
    url?: string;
    protocol?: string;
    headers: Record<string, string>;
    body?: string;
    body_text?: string;
  };
  response?: {
    status_code: number;
    status_text: string;
    status_message?: string;
    headers: Record<string, string>;
    body?: string;
    body_text?: string;
    response_time_ms?: number;
  };
  duration_ms: number;
  modified: boolean;
  rules_applied: string[];
  tags?: string[];
  notes?: string;
}

interface InterceptionRule {
  id: string;
  name: string;
  enabled: boolean;
  priority?: number;
  group?: string | null;
  match_direction: 'request' | 'response' | 'both';
  match_host?: string;
  match_path?: string;
  match_method?: string;
  match_content_type?: string;
  match_status_code?: number;
  match_query?: Record<string, string>;
  action: 'modify' | 'drop' | 'delay';
  modify_headers?: Record<string, string>;
  remove_headers?: string[];
  modify_body?: string;
  body_find_replace?: Record<string, string>;
  body_find_replace_regex?: boolean;
  json_path_edits?: Array<{ path: string; op?: string; value?: any }>;
  modify_status_code?: number;
  modify_path?: string;
  delay_ms?: number;
  hit_count?: number;
}

interface PresetRule {
  id: string;
  name: string;
  description?: string;
}

const API_TESTER_HANDOFF_KEY = 'vragent-api-tester-handoff';
const FUZZER_HANDOFF_KEY = 'vragent-fuzzer-handoff';

// Fallback guided setup data when API fails
const FALLBACK_GUIDED_SETUP: MITMGuidedSetup = {
  title: "Man-in-the-Middle Workbench Setup Guide",
  description: "Learn to intercept, analyze, and modify HTTP/HTTPS/WebSocket traffic",
  difficulty: "Beginner",
  estimated_time: "10-15 minutes",
  steps: [
    {
      step: 1,
      title: "Understand What MITM Does",
      description: "A Man-in-the-Middle proxy sits between a client and server, allowing you to observe, modify, or inject traffic. This is essential for security testing, debugging APIs, and understanding application behavior.",
      tips: [
        "VRAgent runs in Docker - use 0.0.0.0 as listen host to accept external connections",
        "Traffic from Docker containers uses container names (e.g., 'juice-shop') as targets",
        "MITM ports 8080-8089 are exposed from the Docker container",
        "You can intercept HTTP, HTTPS (with certificate), and WebSocket traffic"
      ],
    },
    {
      step: 2,
      title: "Create Your First Proxy",
      description: "Click 'New Proxy' and configure the proxy settings. Understanding what each field means is critical for success.",
      fields: {
        "proxy_id": "A unique name for your proxy (e.g., 'juiceshop-proxy', 'api-test')",
        "listen_host": "ALWAYS use 0.0.0.0 for Docker deployments (allows connections from host machine)",
        "listen_port": "The port YOUR BROWSER connects to (8080-8089 available). Access via http://localhost:PORT",
        "target_host": "WHERE the proxy forwards traffic TO - see examples below",
        "target_port": "The port on the TARGET server (80 for HTTP, 443 for HTTPS, 3000 for Node apps, etc.)"
      },
    },
    {
      step: 3,
      title: "Choose Interception Mode",
      description: "Select how the proxy handles traffic based on your testing needs:",
      modes: [
        {
          name: "Passthrough",
          description: "Observe traffic without modification - best for initial analysis.",
          use_case: "Start here to understand normal traffic patterns"
        },
        {
          name: "Auto Modify",
          description: "Automatically apply rules to modify matching requests/responses.",
          use_case: "Use for automated security testing with rules"
        },
        {
          name: "Intercept",
          description: "Hold each request for manual review before forwarding.",
          use_case: "For detailed inspection and manual modification"
        }
      ],
    },
    {
      step: 4,
      title: "Configure Your Application",
      description: "Point your application to use the MITM proxy. Replace PORT with your listen port (e.g., 8080).",
      examples: [
        {
          type: "Direct Access",
          instructions: "Access http://localhost:PORT directly - traffic flows to your target"
        },
        {
          type: "Browser Proxy",
          instructions: "Set HTTP proxy to localhost:PORT in browser settings or use FoxyProxy"
        },
        {
          type: "curl",
          instructions: "curl -x http://localhost:PORT http://target.com/api"
        },
        {
          type: "Python requests",
          instructions: "requests.get(url, proxies={'http': 'http://localhost:PORT'})"
        },
        {
          type: "Environment Variable",
          instructions: "export HTTP_PROXY=http://localhost:PORT && export HTTPS_PROXY=http://localhost:PORT"
        }
      ],
    },
    {
      step: 5,
      title: "Start the Proxy and Capture Traffic",
      description: "Click 'Start' to activate the proxy. Traffic will appear in real-time via WebSocket streaming.",
      tips: [
        "Watch the 'Live Stream' indicator - green means connected",
        "Click any traffic entry to see full request/response details",
        "Use filters to find specific requests by method, status, or host",
        "Add tags and notes to annotate interesting traffic"
      ],
    },
    {
      step: 6,
      title: "Apply Security Test Rules",
      description: "Use preset rules for quick security testing or create custom rules:",
      presets: [
        { name: "Strip Security Headers", description: "Remove CSP, X-Frame-Options, etc." },
        { name: "Downgrade HTTPS", description: "Change HTTPS links to HTTP" },
        { name: "Add Debug Headers", description: "Inject X-Debug headers into requests" },
        { name: "Slow Response", description: "Add delays to test timeout handling" },
        { name: "Cookie Tampering", description: "Remove Secure/HttpOnly cookie flags" },
        { name: "Corrupt JSON", description: "Introduce JSON syntax errors" }
      ],
    },
    {
      step: 7,
      title: "Use AI-Powered Analysis",
      description: "Click 'Analyze' for AI-powered security analysis, or use natural language to create rules:",
      tips: [
        "AI Analysis detects sensitive data, missing headers, and vulnerabilities",
        "Natural Language Rules: Type 'Block requests to analytics.google.com'",
        "AI Suggestions: Get automatic testing recommendations based on your traffic",
        "AI works even offline with smart fallback patterns"
      ],
    },
    {
      step: 8,
      title: "Save Sessions & Export",
      description: "Save your work and export findings for documentation:",
      formats: [
        { format: "Sessions", description: "Save traffic snapshots to load later" },
        { format: "JSON Export", description: "Export all traffic as structured JSON" },
        { format: "PCAP Export", description: "Export for Wireshark analysis" },
        { format: "Markdown/PDF/Word", description: "Generate professional security reports" }
      ],
    }
  ],
  deployment_scenarios: [
    {
      title: "📍 Understanding Your Setup",
      description: "IMPORTANT: VRAgent runs INSIDE a Docker container. This affects how you specify target hosts. The key question is: WHERE is your target application running?",
      diagram: "Your Browser → localhost:PORT → VRAgent Container (proxy) → Target Application",
      key_concept: "The 'Target Host' must be reachable FROM INSIDE the VRAgent Docker container, not from your host machine."
    },
    {
      title: "🐳 Scenario 1: Target in SEPARATE Docker Container (Same Host)",
      subtitle: "Example: OWASP Juice Shop in its own container alongside VRAgent",
      description: "This is the most common setup. Juice Shop runs in its OWN container (not inside VRAgent). Both containers are on the same Docker network ('vragent-network'), so they can communicate using container names as hostnames.",
      why_it_works: "Docker provides automatic DNS resolution within a network. Container names become hostnames. When VRAgent looks for 'juice-shop', Docker's internal DNS resolves it to the container's IP (e.g., 172.18.0.5).",
      config: {
        listen_host: "0.0.0.0",
        listen_port: "8081",
        target_host: "juice-shop",
        target_port: "3000"
      },
      explanation: [
        "Listen Host: 0.0.0.0 = accept connections from outside the container (your browser)",
        "Listen Port: 8081 = you'll access http://localhost:8081 in your browser",
        "Target Host: juice-shop = the CONTAINER NAME (not IP, not localhost)",
        "Target Port: 3000 = the INTERNAL port (not the exposed 3001)"
      ],
      traffic_flow: "Browser → localhost:8081 → VRAgent proxy → juice-shop:3000 → Response back",
      verify_command: "docker ps (shows both containers running)",
      common_mistake: "Using 'localhost:3001' - this fails because localhost inside VRAgent refers to the VRAgent container itself, not your host machine"
    },
    {
      title: "💻 Scenario 2: Target on HOST Machine (Outside Docker)",
      subtitle: "Example: A local dev server running on your computer (npm start, python manage.py runserver, etc.)",
      description: "Your target app runs directly on your host machine (Windows/Mac/Linux), not in any container. You need to use a special Docker hostname to reach back to the host.",
      why_it_works: "Docker Desktop provides 'host.docker.internal' as a special DNS name that resolves to your host machine's IP from inside any container.",
      config: {
        listen_host: "0.0.0.0",
        listen_port: "8082",
        target_host: "host.docker.internal",
        target_port: "3000"
      },
      explanation: [
        "Target Host: host.docker.internal = Docker's special hostname for 'the machine running Docker'",
        "Target Port: 3000 = whatever port your local app runs on",
        "Works on Docker Desktop (Windows/Mac). On Linux, may need --add-host=host.docker.internal:host-gateway"
      ],
      traffic_flow: "Browser → localhost:8082 → VRAgent proxy → host.docker.internal:3000 → Your local app",
      verify_command: "curl http://localhost:3000 (from your host machine, should work)"
    },
    {
      title: "🖥️ Scenario 3: Target on DIFFERENT Machine (VM, Server, LAN)",
      subtitle: "Example: Web server on another VM, server, or computer on your network",
      description: "Your target is a completely separate machine - could be a VM, a server in your lab, or another computer on your WiFi/LAN.",
      why_it_works: "Docker containers can reach external IPs and hostnames just like your host machine can. Use the target's IP address or DNS hostname.",
      config: {
        listen_host: "0.0.0.0",
        listen_port: "8083",
        target_host: "192.168.1.100",
        target_port: "80"
      },
      explanation: [
        "Target Host: Use the IP address (192.168.1.100) or hostname (webserver.local) of the target machine",
        "Target Port: The port the web server listens on (80, 443, 8080, etc.)",
        "Make sure the target machine's firewall allows incoming connections"
      ],
      traffic_flow: "Browser → localhost:8083 → VRAgent proxy → 192.168.1.100:80 → Remote server",
      verify_command: "ping 192.168.1.100 (from your host to verify connectivity)"
    },
    {
      title: "🌐 Scenario 4: Target on the INTERNET",
      subtitle: "Example: Testing a public website or API (with authorization!)",
      description: "Your target is a public website or API endpoint on the internet. Only test sites you have permission to test!",
      why_it_works: "Docker containers have internet access by default. Public domain names resolve via normal DNS.",
      config: {
        listen_host: "0.0.0.0",
        listen_port: "8084",
        target_host: "testphp.vulnweb.com",
        target_port: "80"
      },
      explanation: [
        "Target Host: The domain name (no http://). Docker resolves public DNS automatically.",
        "Target Port: 80 for HTTP, 443 for HTTPS (enable TLS option for HTTPS)",
        "For HTTPS sites, you'll need to install the MITM CA certificate in your browser"
      ],
      traffic_flow: "Browser → localhost:8084 → VRAgent proxy → testphp.vulnweb.com:80 → Internet",
      verify_command: "curl http://testphp.vulnweb.com (from host to verify the site is up)",
      warning: "Only test websites you own or have explicit written permission to test!"
    }
  ],
  juice_shop_setup: {
    title: "🧃 Setting Up OWASP Juice Shop",
    description: "OWASP Juice Shop is a deliberately vulnerable web application perfect for security testing practice.",
    methods: [
      {
        name: "Option A: Add to VRAgent's docker-compose (Recommended)",
        description: "Edit docker-compose.yml to include Juice Shop on the same network as VRAgent",
        steps: [
          "Open docker-compose.yml in your VRAgent folder",
          "Add the following service under 'services:'",
          "juice-shop:",
          "  image: bkimminich/juice-shop",
          "  container_name: juice-shop",
          "  ports:",
          "    - '3001:3000'",
          "  networks:",
          "    - vragent-network",
          "Run: docker-compose up -d juice-shop",
          "Verify: docker ps (should show juice-shop running)",
          "Direct access: http://localhost:3001",
          "Through MITM: Target Host = juice-shop, Target Port = 3000"
        ]
      },
      {
        name: "Option B: Run Juice Shop Standalone (Same Docker Host)",
        description: "Run Juice Shop as a separate docker run command, but connect it to VRAgent's network",
        steps: [
          "First, find VRAgent's network: docker network ls | grep vragent",
          "Run Juice Shop connected to that network:",
          "docker run -d --name juice-shop --network vragent-network -p 3001:3000 bkimminich/juice-shop",
          "Verify it's on the same network: docker network inspect vragent-network",
          "You should see both vragent-backend and juice-shop listed",
          "MITM Config: Target Host = juice-shop, Target Port = 3000"
        ]
      },
      {
        name: "Option C: Run Juice Shop on Host Machine (Not in Docker)",
        description: "Run Juice Shop directly on your machine using Node.js",
        steps: [
          "Install Node.js 18+ from https://nodejs.org/",
          "Clone the repo: git clone https://github.com/juice-shop/juice-shop.git",
          "cd juice-shop",
          "npm install",
          "npm start",
          "Juice Shop will run on http://localhost:3000",
          "MITM Config: Target Host = host.docker.internal, Target Port = 3000"
        ]
      },
      {
        name: "Option D: Juice Shop on Different VM/Machine",
        description: "Run Juice Shop on a separate VM or server",
        steps: [
          "On the target VM, run: docker run -d -p 3000:3000 bkimminich/juice-shop",
          "Note the VM's IP address (e.g., 192.168.1.50)",
          "Ensure port 3000 is open in the VM's firewall",
          "Verify from your machine: curl http://192.168.1.50:3000",
          "MITM Config: Target Host = 192.168.1.50, Target Port = 3000"
        ]
      }
    ],
    port_explanation: {
      title: "Understanding Port Mapping (3001:3000)",
      details: [
        "Docker port mapping format: HOST_PORT:CONTAINER_PORT",
        "3001:3000 means: Access via localhost:3001, but internal port is 3000",
        "From YOUR BROWSER (outside Docker): use localhost:3001",
        "From MITM PROXY (inside Docker): use container_name:3000",
        "The proxy is INSIDE Docker, so it uses the internal/right port (3000)"
      ]
    }
  },
  common_use_cases: [
    {
      title: "🔌 API Security Testing",
      description: "Test REST/GraphQL APIs for authentication and injection vulnerabilities",
      steps: [
        "Create proxy pointing to your API server (use appropriate scenario above)",
        "Capture normal API traffic in Passthrough mode first",
        "Switch to Intercept mode to modify individual requests",
        "Use AI Analysis to automatically identify security issues",
        "Create rules to test parameter tampering, auth bypass, etc."
      ]
    },
    {
      title: "📡 WebSocket Inspection",
      description: "Analyze real-time communication protocols",
      steps: [
        "Set up proxy for WebSocket-enabled application",
        "Go to WebSocket tab to see connections and frames",
        "Create WebSocket rules for frame modification",
        "Monitor connection state and statistics"
      ]
    }
  ],
  troubleshooting: [
    {
      issue: "No traffic appearing",
      solutions: [
        "Verify proxy is started (green status indicator)",
        "Make sure you're accessing localhost:PORT in your browser (not the target directly)",
        "For Docker: Listen Host MUST be 0.0.0.0, not 127.0.0.1",
        "Ensure firewall allows traffic on the proxy port"
      ]
    },
    {
      issue: "Can't connect / ERR_EMPTY_RESPONSE",
      solutions: [
        "Check Target Host is correct (container name, IP, or hostname)",
        "For Docker containers: use container NAME (e.g., 'juice-shop'), not 'localhost'",
        "Verify target is actually running (docker ps, or curl the target directly)",
        "Check Target Port matches the INTERNAL port, not the exposed/mapped port"
      ]
    },
    {
      issue: "Why use container name instead of localhost?",
      solutions: [
        "VRAgent runs INSIDE a Docker container, not on your host",
        "'localhost' inside the container refers to the container itself, not your machine",
        "Docker provides DNS: container names resolve to container IPs on the same network",
        "Use 'docker network inspect vragent-network' to see container IPs and names"
      ]
    },
    {
      issue: "HTTPS traffic not visible",
      solutions: [
        "Enable TLS in proxy settings",
        "Download and install the CA certificate (Certificates tab)",
        "Some apps use certificate pinning - may need bypass"
      ]
    },
    {
      issue: "Target port confusion",
      solutions: [
        "docker-compose exposes ports as HOST:CONTAINER (e.g., 3001:3000)",
        "From HOST machine: use the LEFT port (3001) to access directly",
        "From MITM proxy: use the RIGHT port (3000) - it's inside Docker network",
        "Run 'docker ps' to see port mappings"
      ]
    }
  ]
};

// Enhanced preset descriptions for better UX
const PRESET_DESCRIPTIONS: Record<string, { description: string; use_case: string; icon?: string }> = {
  remove_csp: {
    description: "Removes Content-Security-Policy headers to allow inline scripts and external resources",
    use_case: "Test XSS vulnerabilities that are blocked by CSP"
  },
  remove_cors: {
    description: "Sets permissive CORS headers (Access-Control-Allow-Origin: *) on all responses",
    use_case: "Test cross-origin attacks or bypass CORS restrictions"
  },
  downgrade_https: {
    description: "Removes Strict-Transport-Security (HSTS) headers from responses",
    use_case: "Test for insecure transport fallback vulnerabilities"
  },
  add_debug_header: {
    description: "Adds X-Debug: true and X-Forwarded-For: 127.0.0.1 to all requests",
    use_case: "Trigger debug modes or bypass IP-based restrictions"
  },
  slow_response: {
    description: "Adds a 2 second delay to all responses",
    use_case: "Test timeout handling and race conditions"
  },
  inject_script: {
    description: "Injects a console.log script tag before </body> in HTML responses",
    use_case: "Demonstrate XSS injection or test script execution"
  },
  modify_json_response: {
    description: "Changes success:false to success:true and authorized:false to authorized:true",
    use_case: "Bypass client-side authorization checks"
  },
  block_analytics: {
    description: "Drops all requests to Google Analytics, Facebook, and other tracking domains",
    use_case: "Clean traffic logs or test app behavior without analytics"
  }
};

// Tab panel component
function TabPanel({ children, value, index }: { children: React.ReactNode; value: number; index: number }) {
  return (
    <div hidden={value !== index} style={{ height: '100%' }}>
      {value === index && <Box sx={{ p: 2, height: '100%' }}>{children}</Box>}
    </div>
  );
}

interface SavedReport {
  id: number;
  title: string;
  description: string;
  proxy_id: string;
  traffic_analyzed: number;
  findings_count: number;
  risk_level: string;
  risk_score: number;
  created_at: string;
}

const MITMWorkbenchPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const projectId = searchParams.get('projectId');
  const projectName = searchParams.get('projectName');

  // Saved Reports State (for loading historical data)
  const [savedReports, setSavedReports] = useState<SavedReport[]>([]);
  const [selectedReport, setSelectedReport] = useState<SavedReport | null>(null);
  const [loadingSavedReports, setLoadingSavedReports] = useState(false);
  const [viewingHistoricalData, setViewingHistoricalData] = useState(false);

  // State
  const [proxies, setProxies] = useState<ProxyInstance[]>([]);
  const [selectedProxy, setSelectedProxy] = useState<string | null>(null);
  const [traffic, setTraffic] = useState<TrafficEntry[]>([]);
  const [trafficSearch, setTrafficSearch] = useState('');
  const [trafficMethodFilter, setTrafficMethodFilter] = useState<string[]>([]);
  const [trafficStatusFilter, setTrafficStatusFilter] = useState('all');
  const [trafficHostFilter, setTrafficHostFilter] = useState('all');
  const [trafficModifiedOnly, setTrafficModifiedOnly] = useState(false);
  const [trafficWithResponseOnly, setTrafficWithResponseOnly] = useState(false);
  const [trafficSort, setTrafficSort] = useState<'newest' | 'oldest'>('newest');
  const [rules, setRules] = useState<InterceptionRule[]>([]);
  const [presets, setPresets] = useState<PresetRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [tabValue, setTabValue] = useState(0);

  // New proxy dialog
  const [newProxyOpen, setNewProxyOpen] = useState(false);
  const [newProxy, setNewProxy] = useState({
    proxy_id: '',
    listen_host: '0.0.0.0',
    listen_port: 8080,
    target_host: '',
    target_port: 80,
    mode: 'auto_modify',
    tls_enabled: false,
  });

  // New rule dialog
  const [newRuleOpen, setNewRuleOpen] = useState(false);
  const [newRule, setNewRule] = useState<Partial<InterceptionRule>>({
    name: '',
    enabled: true,
    match_direction: 'both',
    action: 'modify',
  });
  const [ruleMatchQueryInput, setRuleMatchQueryInput] = useState('');
  const [ruleModifyHeadersInput, setRuleModifyHeadersInput] = useState('');
  const [ruleRemoveHeadersInput, setRuleRemoveHeadersInput] = useState('');
  const [ruleBodyFindReplaceInput, setRuleBodyFindReplaceInput] = useState('');
  const [ruleJsonPathEditsInput, setRuleJsonPathEditsInput] = useState('');

  // Traffic detail dialog
  const [trafficDetailOpen, setTrafficDetailOpen] = useState(false);
  const [selectedTraffic, setSelectedTraffic] = useState<TrafficEntry | null>(null);
  const [trafficNotes, setTrafficNotes] = useState('');
  const [trafficTagsInput, setTrafficTagsInput] = useState('');
  const [savingTrafficMeta, setSavingTrafficMeta] = useState(false);
  const [trafficMenuAnchor, setTrafficMenuAnchor] = useState<null | HTMLElement>(null);
  const [trafficMenuEntry, setTrafficMenuEntry] = useState<TrafficEntry | null>(null);

  // Live stream (WebSocket)
  const [liveStreamEnabled, setLiveStreamEnabled] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const [wsError, setWsError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Sessions
  const [sessionsOpen, setSessionsOpen] = useState(false);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [sessions, setSessions] = useState<MITMSession[]>([]);
  const [activeSession, setActiveSession] = useState<MITMSession | null>(null);
  const [sessionName, setSessionName] = useState('');
  
  // Saved Sessions with Analysis (sidebar panel)
  const [savedSessions, setSavedSessions] = useState<MITMSavedScan[]>([]);
  const [savedSessionsExpanded, setSavedSessionsExpanded] = useState(true);
  const [loadingSavedSessions, setLoadingSavedSessions] = useState(false);
  const [autoSaveEnabled, setAutoSaveEnabled] = useState(true);
  const [viewingSavedScan, setViewingSavedScan] = useState<MITMSavedScan | null>(null);
  const [savedScanDialogOpen, setSavedScanDialogOpen] = useState(false);

  // Traffic export menu state
  const [trafficExportAnchorEl, setTrafficExportAnchorEl] = useState<null | HTMLElement>(null);
  const [trafficExporting, setTrafficExporting] = useState(false);

  // Replay state
  const [replayOpen, setReplayOpen] = useState(false);
  const [replayLoading, setReplayLoading] = useState(false);
  const [replayEntry, setReplayEntry] = useState<TrafficEntry | null>(null);
  const [replayOverrides, setReplayOverrides] = useState({
    method: '',
    path: '',
    body: '',
    addHeaders: '',
    removeHeaders: '',
    baseUrl: '',
    timeout: 20,
    verifyTls: false,
  });

  // Auto-refresh
  const [autoRefresh, setAutoRefresh] = useState(false);

  // Guided wizard state
  const [wizardOpen, setWizardOpen] = useState(false);
  const [wizardStep, setWizardStep] = useState(0);
  const [guidedSetup, setGuidedSetup] = useState<MITMGuidedSetup | null>(null);
  const [loadingGuide, setLoadingGuide] = useState(false);

  // AI Analysis state
  const [analysisResult, setAnalysisResult] = useState<(MITMAnalysisResult & { agent_activity?: any }) | null>(null);
  const [analyzingTraffic, setAnalyzingTraffic] = useState(false);
  const [showAnalysis, setShowAnalysis] = useState(false);

  // Export menu state
  const [exportAnchorEl, setExportAnchorEl] = useState<null | HTMLElement>(null);
  const [exporting, setExporting] = useState(false);

  // Beginner Features: Test Scenarios
  const [testScenarios, setTestScenarios] = useState<MITMTestScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<MITMTestScenario | null>(null);
  const [scenarioDialogOpen, setScenarioDialogOpen] = useState(false);
  const [runningScenario, setRunningScenario] = useState(false);
  const [scenarioResult, setScenarioResult] = useState<any>(null);

  // Beginner Features: Health Check
  const [proxyHealth, setProxyHealth] = useState<MITMProxyHealth | null>(null);
  const [checkingHealth, setCheckingHealth] = useState(false);

  // Beginner Features: Interactive Tutorial
  const [tutorialActive, setTutorialActive] = useState(false);
  const [tutorialStep, setTutorialStep] = useState(0);
  const [showBeginnerBanner, setShowBeginnerBanner] = useState(true);

  // Natural Language Rule Creation
  const [nlRuleInput, setNlRuleInput] = useState('');
  const [nlRuleLoading, setNlRuleLoading] = useState(false);
  const [nlRuleResult, setNlRuleResult] = useState<NaturalLanguageRuleResponse | null>(null);
  const [showNlRulePanel, setShowNlRulePanel] = useState(false);

  // AI Suggestions
  const [aiSuggestions, setAiSuggestions] = useState<AISuggestion[]>([]);
  const [aiSuggestionsLoading, setAiSuggestionsLoading] = useState(false);
  const [showAiSuggestions, setShowAiSuggestions] = useState(false);
  const [aiSuggestionsResponse, setAiSuggestionsResponse] = useState<AISuggestionsResponse | null>(null);

  // Attack Phase State (Agentic MITM)
  interface PhaseData {
    phase: string;
    name: string;
    description: string;
    is_current: boolean;
    is_complete: boolean;
    goals: string[];
    goals_achieved: string[];
    entered_at: string | null;
    completed_at: string | null;
  }
  interface PhaseProgress {
    phase: string;
    goals_total: number;
    goals_achieved: number;
    goals_achieved_list: string[];
    tools_executed: number;
    credentials_captured: number;
    sessions_hijacked: number;
    injections_successful: number;
    findings_generated: number;
    is_complete: boolean;
  }
  const [attackPhases, setAttackPhases] = useState<PhaseData[]>([]);
  const [currentPhase, setCurrentPhase] = useState<PhaseData | null>(null);
  const [phaseProgress, setPhaseProgress] = useState<PhaseProgress | null>(null);
  const [showPhaseIndicator, setShowPhaseIndicator] = useState(true);
  const [phaseLoading, setPhaseLoading] = useState(false);

  // Attack Chains State
  interface AttackChain {
    chain_id: string;
    name: string;
    description: string;
    triggers: string[];
    steps: Array<{ step_number: number; tool_id: string; description: string }>;
    expected_outcome: string;
    risk_level: string;
  }
  const [attackChains, setAttackChains] = useState<AttackChain[]>([]);
  const [chainExecutionHistory, setChainExecutionHistory] = useState<any[]>([]);
  const [chainStats, setChainStats] = useState<any>(null);

  // MITRE Mapping State
  const [mitreMapping, setMitreMapping] = useState<any>(null);
  const [mitreNarrative, setMitreNarrative] = useState<any>(null);

  // Memory/Reasoning State
  const [agentMemory, setAgentMemory] = useState<any>(null);
  const [reasoningChains, setReasoningChains] = useState<any[]>([]);

  // WebSocket Deep Inspection State
  const [wsConnections, setWsConnections] = useState<WebSocketConnection[]>([]);
  const [wsFrames, setWsFrames] = useState<WebSocketFrame[]>([]);
  const [wsRules, setWsRules] = useState<WebSocketRule[]>([]);
  const [wsStats, setWsStats] = useState<WebSocketStats | null>(null);
  const [selectedWsConnection, setSelectedWsConnection] = useState<string | null>(null);
  const [wsLoadingConnections, setWsLoadingConnections] = useState(false);
  const [wsLoadingFrames, setWsLoadingFrames] = useState(false);
  const [wsNewRuleOpen, setWsNewRuleOpen] = useState(false);
  const [wsNewRule, setWsNewRule] = useState<Partial<WebSocketRule>>({
    name: '',
    enabled: true,
    priority: 0,
    match_direction: 'both',
    action: 'passthrough',
    delay_ms: 0,
  });
  const [wsSelectedFrame, setWsSelectedFrame] = useState<WebSocketFrame | null>(null);

  // Certificate Management State
  const [caCertificate, setCaCertificate] = useState<CACertificate | null>(null);
  const [hostCertificates, setHostCertificates] = useState<HostCertificate[]>([]);
  const [certInstallInstructions, setCertInstallInstructions] = useState<CertificateInstallationInstructions | null>(null);
  const [certLoading, setCertLoading] = useState(false);
  const [certGenerating, setCertGenerating] = useState(false);
  const [showCertGenDialog, setShowCertGenDialog] = useState(false);
  const [certGenConfig, setCertGenConfig] = useState({
    common_name: 'VRAgent MITM CA',
    organization: 'VRAgent Security',
    country: 'US',
    validity_days: 365,
  });
  const [showCertInstallDialog, setShowCertInstallDialog] = useState(false);

  // Match & Replace Templates State
  const [templates, setTemplates] = useState<any[]>([]);
  const [templateCategories, setTemplateCategories] = useState<string[]>([]);
  const [templatesLoading, setTemplatesLoading] = useState(false);
  const [selectedTemplateCategory, setSelectedTemplateCategory] = useState<string>('');
  const [selectedTemplate, setSelectedTemplate] = useState<any | null>(null);
  const [showNewTemplateDialog, setShowNewTemplateDialog] = useState(false);
  const [newTemplate, setNewTemplate] = useState({
    name: '',
    category: 'Custom',
    description: '',
    match_type: 'header',
    match_pattern: '',
    replace_pattern: '',
    is_regex: false,
    case_sensitive: false,
    direction: 'both',
    tags: [] as string[],
  });
  const [templateTagsInput, setTemplateTagsInput] = useState('');
  const [testingTemplate, setTestingTemplate] = useState(false);
  const [templateTestResult, setTemplateTestResult] = useState<any | null>(null);

  // Traffic Diff Viewer State
  const [trafficDiff, setTrafficDiff] = useState<any | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);
  const [diffViewMode, setDiffViewMode] = useState<'unified' | 'side-by-side'>('side-by-side');

  // HTTP/2 & gRPC State
  const [http2Frames, setHttp2Frames] = useState<any[]>([]);
  const [http2Streams, setHttp2Streams] = useState<any[]>([]);
  const [grpcMessages, setGrpcMessages] = useState<any[]>([]);
  const [http2Loading, setHttp2Loading] = useState(false);
  const [selectedHttp2Stream, setSelectedHttp2Stream] = useState<number | null>(null);
  const [grpcServiceFilter, setGrpcServiceFilter] = useState('');

  // Agentic Tools Visibility
  const [showAgenticTools, setShowAgenticTools] = useState(true);

  // Attack Tools State - Agentic Execution
  const [attackTools, setAttackTools] = useState<any[]>([]);
  const [attackToolCategories, setAttackToolCategories] = useState<string[]>([]);
  const [attackToolsLoading, setAttackToolsLoading] = useState(false);
  const [selectedAttackCategory, setSelectedAttackCategory] = useState<string>('');
  const [attackRecommendations, setAttackRecommendations] = useState<any[]>([]);
  const [recommendationsLoading, setRecommendationsLoading] = useState(false);
  const [executingTool, setExecutingTool] = useState<string | null>(null);
  const [toolExecutionResults, setToolExecutionResults] = useState<any[]>([]);
  const [agenticSessionRunning, setAgenticSessionRunning] = useState(false);
  const [agenticSessionResult, setAgenticSessionResult] = useState<any | null>(null);
  const [showAgenticResultDialog, setShowAgenticResultDialog] = useState(false);
  const [attackToolExecutionLog, setAttackToolExecutionLog] = useState<any[]>([]);
  const [phaseStrategy, setPhaseStrategy] = useState<string>('progressive');
  const [maxAgenticTools, setMaxAgenticTools] = useState<number>(15);

  // Enhanced Agentic State
  const [agentMonitoringActive, setAgentMonitoringActive] = useState(false);
  const [agentGoals, setAgentGoals] = useState<string[]>([]);
  const [agentGoalProgress, setAgentGoalProgress] = useState<any>(null);
  const [agentStatus, setAgentStatus] = useState<any>(null);
  const [showGoalDialog, setShowGoalDialog] = useState(false);
  const [selectedGoals, setSelectedGoals] = useState<string[]>([]);

  // Theme for animations
  const theme = useTheme();

  const buildWsUrl = useCallback((proxyId: string) => {
    const base = import.meta.env.VITE_API_URL || '/api';
    const path = `/mitm/ws/${proxyId}`;
    if (base.startsWith('http://') || base.startsWith('https://')) {
      const wsBase = base.replace(/^http/, 'ws').replace(/\/$/, '');
      return `${wsBase}${path}`;
    }
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const normalizedBase = base.startsWith('/') ? base : `/${base}`;
    const baseTrimmed = normalizedBase.replace(/\/$/, '');
    return `${protocol}://${window.location.host}${baseTrimmed}${path}`;
  }, []);

  const normalizeTrafficEntry = useCallback((entry: any): TrafficEntry => {
    const request = entry.request || {};
    const response = entry.response || undefined;
    const timestamp = entry.timestamp || request.timestamp || new Date().toISOString();
    const duration = entry.duration_ms ?? response?.response_time_ms ?? 0;
    const modified = entry.modified ?? (request.modified || response?.modified || false);

    return {
      id: entry.id,
      timestamp,
      request: {
        method: request.method || 'UNKNOWN',
        path: request.path || '/',
        host: request.host,
        url: request.url,
        protocol: request.protocol,
        headers: request.headers || {},
        body: request.body ?? request.body_text ?? undefined,
        body_text: request.body_text ?? request.body ?? undefined,
      },
      response: response ? {
        status_code: response.status_code ?? 0,
        status_text: response.status_text || response.status_message || '',
        status_message: response.status_message,
        headers: response.headers || {},
        body: response.body ?? response.body_text ?? undefined,
        body_text: response.body_text ?? response.body ?? undefined,
        response_time_ms: response.response_time_ms ?? duration,
      } : undefined,
      duration_ms: duration,
      modified,
      rules_applied: entry.rules_applied || [],
      tags: entry.tags,
      notes: entry.notes,
    };
  }, []);

  // Load proxies
  const loadProxies = useCallback(async () => {
    try {
      const data = await mitmClient.listProxies();
      const normalized = (data || []).map((proxy: any) => ({
        id: proxy.id,
        listen_host: proxy.listen_host || '127.0.0.1',
        listen_port: proxy.listen_port ?? 0,
        target_host: proxy.target_host || '',
        target_port: proxy.target_port ?? 0,
        mode: proxy.mode || 'passthrough',
        tls_enabled: Boolean(proxy.tls_enabled),
        running: Boolean(proxy.running),
        stats: {
          requests: proxy.stats?.requests ?? proxy.requests ?? proxy.requests_total ?? 0,
          responses: proxy.stats?.responses ?? proxy.responses ?? proxy.responses_total ?? 0,
          bytes_sent: proxy.stats?.bytes_sent ?? proxy.bytes_sent ?? 0,
          bytes_received: proxy.stats?.bytes_received ?? proxy.bytes_received ?? 0,
          errors: proxy.stats?.errors ?? proxy.errors ?? 0,
          rules_applied: proxy.stats?.rules_applied ?? proxy.rules_applied ?? 0,
        },
      }));
      setProxies(normalized);
    } catch (err: any) {
      console.error('Failed to load proxies:', err);
    }
  }, []);

  // Load traffic for selected proxy
  const loadTraffic = useCallback(async () => {
    if (!selectedProxy) return;
    try {
      const data = await mitmClient.getTraffic(selectedProxy);
      const entries = (data as any)?.entries || [];
      const normalized = entries.map((entry: any) => normalizeTrafficEntry(entry));
      setTraffic(normalized);
    } catch (err: any) {
      console.error('Failed to load traffic:', err);
    }
  }, [selectedProxy, normalizeTrafficEntry]);

  // Load rules for selected proxy
  const loadRules = useCallback(async () => {
    if (!selectedProxy) return;
    try {
      const data = await mitmClient.getRules(selectedProxy);
      setRules(data || []);
    } catch (err: any) {
      console.error('Failed to load rules:', err);
    }
  }, [selectedProxy]);

  // Load preset rules
  const loadPresets = useCallback(async () => {
    try {
      const data = await mitmClient.getPresets();
      setPresets(data || []);
    } catch (err: any) {
      console.error('Failed to load presets:', err);
    }
  }, []);

  const loadSessions = useCallback(async () => {
    if (!selectedProxy) return;
    try {
      setSessionsLoading(true);
      const data = await mitmClient.listSessions(selectedProxy);
      setSessions(data || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load sessions');
    } finally {
      setSessionsLoading(false);
    }
  }, [selectedProxy]);

  const handleOpenSessions = async () => {
    setSessionsOpen(true);
    await loadSessions();
  };

  const handleCreateSession = async () => {
    if (!selectedProxy) return;
    try {
      setSessionsLoading(true);
      await mitmClient.createSession(selectedProxy, sessionName.trim() || undefined);
      setSessionName('');
      await loadSessions();
      setSuccess('Session saved');
    } catch (err: any) {
      setError(err.message || 'Failed to save session');
    } finally {
      setSessionsLoading(false);
    }
  };

  const handleLoadSession = async (sessionId: string) => {
    if (!selectedProxy) return;
    try {
      setSessionsLoading(true);
      const response = await mitmClient.getSession(selectedProxy, sessionId, 200, 0);
      const entries = response?.entries || [];
      setTraffic(entries.map((entry: any) => normalizeTrafficEntry(entry)));
      const meta = response?.meta || sessions.find(session => session.id === sessionId);
      if (meta) {
        setActiveSession(meta);
      } else {
        setActiveSession({
          id: sessionId,
          name: sessionId,
          created_at: new Date().toISOString(),
          entries: response?.total || entries.length,
        });
      }
      setSelectedTraffic(null);
      setSessionsOpen(false);
    } catch (err: any) {
      setError(err.message || 'Failed to load session');
    } finally {
      setSessionsLoading(false);
    }
  };

  const handleExitSession = () => {
    setActiveSession(null);
    setSelectedTraffic(null);
    loadTraffic();
  };

  // Load all saved scans from database
  const loadSavedSessions = useCallback(async () => {
    try {
      setLoadingSavedSessions(true);
      const data = await mitmClient.listSavedScans();
      // Already sorted by backend, but ensure newest first
      const sorted = (data || []).sort((a, b) =>
        (Date.parse(b.created_at ?? "") || 0) - (Date.parse(a.created_at ?? "") || 0)
      );
      setSavedSessions(sorted);
    } catch (err: any) {
      console.error('Failed to load saved sessions:', err);
    } finally {
      setLoadingSavedSessions(false);
    }
  }, []);

  // Load and view a saved scan
  const handleViewSavedScan = useCallback(async (scan: MITMSavedScan) => {
    try {
      setLoadingSavedSessions(true);
      const fullScan = await mitmClient.getSavedScan(scan.id);
      setViewingSavedScan(fullScan);
      setSavedScanDialogOpen(true);
    } catch (err: any) {
      console.error('Failed to load saved scan:', err);
      setError('Failed to load saved scan');
    } finally {
      setLoadingSavedSessions(false);
    }
  }, []);

  // Delete a saved scan
  const handleDeleteSavedScan = useCallback(async (scanId: number) => {
    try {
      await mitmClient.deleteSavedScan(scanId);
      setSavedSessions(prev => prev.filter(s => s.id !== scanId));
      setSuccess('Saved scan deleted');
    } catch (err: any) {
      console.error('Failed to delete saved scan:', err);
      setError('Failed to delete saved scan');
    }
  }, []);

  // Auto-save session with analysis
  const handleAutoSaveSession = useCallback(async (analysis: MITMAnalysisResult) => {
    if (!selectedProxy || !autoSaveEnabled) return;
    
    const currentProxy = proxies.find(p => p.id === selectedProxy);
    if (!currentProxy) return;
    
    try {
      const sessionName = `Analysis-${new Date().toISOString().split('T')[0]}-${Date.now()}`;
      await mitmClient.saveSessionWithAnalysis(selectedProxy, sessionName, analysis);
      await loadSavedSessions();
      setSuccess('Session auto-saved with analysis');
    } catch (err: any) {
      console.error('Failed to auto-save session:', err);
    }
  }, [selectedProxy, autoSaveEnabled, proxies, loadSavedSessions]);

  // Load saved session into workspace
  const handleLoadSavedSession = async (session: MITMSession) => {
    if (!session.proxy_id) {
      setError('Session missing proxy ID');
      return;
    }
    try {
      setLoadingSavedSessions(true);
      const response = await mitmClient.getSession(session.proxy_id, session.id, 200, 0);
      const entries = response?.entries || [];
      setTraffic(entries.map((entry: any) => normalizeTrafficEntry(entry)));
      setActiveSession(session);
      setSelectedProxy(session.proxy_id);
      setSelectedTraffic(null);
      
      // If session has analysis, also load it
      if (session.analysis) {
        // Reconstruct a basic analysis result to display
        // Map simplified findings to full format
        const mappedFindings = (session.analysis.findings || []).map(f => ({
          severity: f.severity,
          category: 'Security',
          title: f.title,
          description: f.description || '',
          evidence: '',
          recommendation: '',
        }));
        
        const riskScore = session.analysis.risk_score || 0;
        setAnalysisResult({
          summary: session.analysis.summary || '',
          risk_score: riskScore,
          risk_level: riskScore >= 80 ? 'critical' : 
                      riskScore >= 60 ? 'high' :
                      riskScore >= 40 ? 'medium' : 'low',
          findings: mappedFindings,
          recommendations: [],
          ai_writeup: session.analysis.ai_writeup || '',
          attack_paths: [],
          agent_activity: (session.analysis as any)?.agent_activity || {},
          traffic_analyzed: session.entries || 0,
          rules_active: 0,
        });
        setShowAnalysis(true);
      }
      
      setSuccess(`Loaded session: ${session.name}`);
    } catch (err: any) {
      setError(err.message || 'Failed to load session');
    } finally {
      setLoadingSavedSessions(false);
    }
  };

  // Delete saved session
  const handleDeleteSavedSession = async (session: MITMSession, event: React.MouseEvent) => {
    event.stopPropagation();
    if (!session.proxy_id) return;
    
    try {
      await mitmClient.deleteSession(session.proxy_id, session.id);
      await loadSavedSessions();
      setSuccess('Session deleted');
    } catch (err: any) {
      setError(err.message || 'Failed to delete session');
    }
  };

  // Initial load
  useEffect(() => {
    loadProxies();
    loadPresets();
    loadTestScenarios();
    loadSavedSessions();
  }, [loadProxies, loadPresets, loadSavedSessions]);

  // Load test scenarios
  const loadTestScenarios = async () => {
    try {
      const data = await (mitmClient as any).getTestScenarios();
      setTestScenarios(data || []);
    } catch (err: any) {
      console.error('Failed to load test scenarios:', err);
    }
  };

  // Check proxy health
  const checkProxyHealth = async () => {
    if (!selectedProxy) return;
    try {
      setCheckingHealth(true);
      const health = await (mitmClient as any).checkProxyHealth(selectedProxy);
      setProxyHealth(health);
    } catch (err: any) {
      console.error('Failed to check proxy health:', err);
    } finally {
      setCheckingHealth(false);
    }
  };

  // WebSocket Deep Inspection Functions
  const loadWebSocketConnections = useCallback(async () => {
    if (!selectedProxy) return;
    try {
      setWsLoadingConnections(true);
      const connections = await (mitmClient as any).getWebSocketConnections(selectedProxy);
      setWsConnections(connections || []);
    } catch (err: any) {
      console.error('Failed to load WebSocket connections:', err);
    } finally {
      setWsLoadingConnections(false);
    }
  }, [selectedProxy]);

  const loadWebSocketFrames = useCallback(async (connectionId: string) => {
    if (!selectedProxy) return;
    try {
      setWsLoadingFrames(true);
      const result = await (mitmClient as any).getWebSocketFrames(selectedProxy, connectionId, 200, 0);
      setWsFrames(result?.frames || []);
    } catch (err: any) {
      console.error('Failed to load WebSocket frames:', err);
    } finally {
      setWsLoadingFrames(false);
    }
  }, [selectedProxy]);

  const loadWebSocketStats = useCallback(async () => {
    if (!selectedProxy) return;
    try {
      const stats = await (mitmClient as any).getWebSocketStats(selectedProxy);
      setWsStats(stats);
    } catch (err: any) {
      console.error('Failed to load WebSocket stats:', err);
    }
  }, [selectedProxy]);

  const loadWebSocketRules = useCallback(async () => {
    if (!selectedProxy) return;
    try {
      const rules = await (mitmClient as any).getWebSocketRules(selectedProxy);
      setWsRules(rules || []);
    } catch (err: any) {
      console.error('Failed to load WebSocket rules:', err);
    }
  }, [selectedProxy]);

  const handleAddWebSocketRule = async () => {
    if (!selectedProxy) return;
    try {
      setLoading(true);
      await (mitmClient as any).addWebSocketRule(selectedProxy, wsNewRule);
      setSuccess('WebSocket rule added');
      setWsNewRuleOpen(false);
      setWsNewRule({
        name: '',
        enabled: true,
        priority: 0,
        match_direction: 'both',
        action: 'passthrough',
        delay_ms: 0,
      });
      loadWebSocketRules();
    } catch (err: any) {
      setError(err.message || 'Failed to add WebSocket rule');
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveWebSocketRule = async (ruleId: string) => {
    if (!selectedProxy) return;
    try {
      await (mitmClient as any).removeWebSocketRule(selectedProxy, ruleId);
      setSuccess('WebSocket rule removed');
      loadWebSocketRules();
    } catch (err: any) {
      setError(err.message || 'Failed to remove WebSocket rule');
    }
  };

  // Certificate Management Functions
  const loadCACertificate = useCallback(async () => {
    try {
      setCertLoading(true);
      const cert = await (mitmClient as any).getCACertificate();
      if (cert && 'common_name' in cert) {
        setCaCertificate(cert as CACertificate);
      } else {
        setCaCertificate(null);
      }
    } catch (err: any) {
      console.error('Failed to load CA certificate:', err);
    } finally {
      setCertLoading(false);
    }
  }, []);

  const loadHostCertificates = useCallback(async () => {
    try {
      const certs = await (mitmClient as any).listHostCertificates();
      setHostCertificates(certs || []);
    } catch (err: any) {
      console.error('Failed to load host certificates:', err);
    }
  }, []);

  const loadCertificateInstallInstructions = useCallback(async () => {
    try {
      const instructions = await (mitmClient as any).getCertificateInstallationInstructions();
      setCertInstallInstructions(instructions);
    } catch (err: any) {
      console.error('Failed to load certificate installation instructions:', err);
    }
  }, []);

  const handleGenerateCACertificate = async () => {
    try {
      setCertGenerating(true);
      await (mitmClient as any).generateCACertificate(certGenConfig);
      setSuccess('CA certificate generated successfully');
      setShowCertGenDialog(false);
      loadCACertificate();
      loadHostCertificates();
    } catch (err: any) {
      setError(err.message || 'Failed to generate CA certificate');
    } finally {
      setCertGenerating(false);
    }
  };

  const handleDownloadCACertificate = async (format: 'pem' | 'crt' | 'der') => {
    try {
      const blob = await (mitmClient as any).downloadCACertificate(format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vragent-ca.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      setSuccess(`CA certificate downloaded as ${format.toUpperCase()}`);
    } catch (err: any) {
      setError(err.message || 'Failed to download certificate');
    }
  };

  const handleDeleteHostCertificate = async (hostname: string) => {
    try {
      await (mitmClient as any).deleteHostCertificate(hostname);
      setSuccess(`Host certificate for ${hostname} deleted`);
      loadHostCertificates();
    } catch (err: any) {
      setError(err.message || 'Failed to delete host certificate');
    }
  };

  // Load certificates on mount
  useEffect(() => {
    loadCACertificate();
    loadHostCertificates();
  }, [loadCACertificate, loadHostCertificates]);

  // ========== Match & Replace Templates Functions ==========
  
  const loadTemplates = useCallback(async (category?: string) => {
    try {
      setTemplatesLoading(true);
      const data = await (mitmClient as any).getTemplates(category ? { category } : undefined);
      setTemplates(data || []);
    } catch (err: any) {
      console.error('Failed to load templates:', err);
    } finally {
      setTemplatesLoading(false);
    }
  }, []);

  const loadTemplateCategories = useCallback(async () => {
    try {
      const data = await (mitmClient as any).getTemplateCategories();
      setTemplateCategories(data.categories || []);
    } catch (err: any) {
      console.error('Failed to load template categories:', err);
    }
  }, []);

  const handleCreateTemplate = async () => {
    try {
      const tagsArray = templateTagsInput.split(',').map(t => t.trim()).filter(t => t);
      await (mitmClient as any).createTemplate({
        ...newTemplate,
        tags: tagsArray,
      });
      setSuccess('Custom template created!');
      setShowNewTemplateDialog(false);
      setNewTemplate({
        name: '',
        category: 'Custom',
        description: '',
        match_type: 'header',
        match_pattern: '',
        replace_pattern: '',
        is_regex: false,
        case_sensitive: false,
        direction: 'both',
        tags: [],
      });
      setTemplateTagsInput('');
      loadTemplates(selectedTemplateCategory || undefined);
    } catch (err: any) {
      setError(err.message || 'Failed to create template');
    }
  };

  const handleDeleteTemplate = async (templateId: string) => {
    try {
      await (mitmClient as any).deleteTemplate(templateId);
      setSuccess('Template deleted');
      loadTemplates(selectedTemplateCategory || undefined);
    } catch (err: any) {
      setError(err.message || 'Failed to delete template');
    }
  };

  const handleApplyTemplate = async (templateId: string) => {
    if (!selectedProxy) {
      setError('Please select a proxy first');
      return;
    }
    try {
      await (mitmClient as any).applyTemplate(selectedProxy, templateId);
      setSuccess('Template applied as interception rule!');
      loadRules();
    } catch (err: any) {
      setError(err.message || 'Failed to apply template');
    }
  };

  const handleTestTemplate = async (templateId: string) => {
    if (!selectedTraffic) {
      setError('Please select a traffic entry first');
      return;
    }
    try {
      setTestingTemplate(true);
      const result = await (mitmClient as any).testTemplate(
        templateId,
        selectedTraffic.request,
        selectedTraffic.response
      );
      setTemplateTestResult(result);
    } catch (err: any) {
      setError(err.message || 'Failed to test template');
    } finally {
      setTestingTemplate(false);
    }
  };

  // Load templates on mount
  useEffect(() => {
    loadTemplates();
    loadTemplateCategories();
  }, [loadTemplates, loadTemplateCategories]);

  // ========== Traffic Diff Viewer Functions ==========
  
  const loadTrafficDiff = useCallback(async (proxyId: string, entryId: string) => {
    try {
      setDiffLoading(true);
      const data = await (mitmClient as any).getTrafficDiff(proxyId, entryId);
      setTrafficDiff(data);
    } catch (err: any) {
      console.error('Failed to load traffic diff:', err);
      setTrafficDiff(null);
    } finally {
      setDiffLoading(false);
    }
  }, []);

  // Auto-load diff when viewing modified traffic
  useEffect(() => {
    if (selectedTraffic?.modified && selectedProxy) {
      loadTrafficDiff(selectedProxy, selectedTraffic.id);
    } else {
      setTrafficDiff(null);
    }
  }, [selectedTraffic, selectedProxy, loadTrafficDiff]);

  // ========== HTTP/2 & gRPC Functions ==========
  
  const loadHTTP2Frames = useCallback(async (proxyId: string, streamId?: number) => {
    try {
      setHttp2Loading(true);
      const data = await (mitmClient as any).getHTTP2Frames(proxyId, { stream_id: streamId });
      setHttp2Frames(data.frames || []);
    } catch (err: any) {
      console.error('Failed to load HTTP/2 frames:', err);
    } finally {
      setHttp2Loading(false);
    }
  }, []);

  const loadHTTP2Streams = useCallback(async (proxyId: string) => {
    try {
      const data = await (mitmClient as any).getHTTP2Streams(proxyId);
      setHttp2Streams(data.streams || []);
    } catch (err: any) {
      console.error('Failed to load HTTP/2 streams:', err);
    }
  }, []);

  const loadGRPCMessages = useCallback(async (proxyId: string, service?: string) => {
    try {
      const data = await (mitmClient as any).getGRPCMessages(proxyId, { service });
      setGrpcMessages(data.messages || []);
    } catch (err: any) {
      console.error('Failed to load gRPC messages:', err);
    }
  }, []);

  // Attack Tools Functions - Agentic Execution
  const loadAttackTools = useCallback(async (category?: string) => {
    try {
      setAttackToolsLoading(true);
      const data = await mitmClient.listAttackTools(category);
      setAttackTools(data.tools || []);
      setAttackToolCategories(data.categories || []);
    } catch (err: any) {
      console.error('Failed to load attack tools:', err);
      setError(err.message || 'Failed to load attack tools');
    } finally {
      setAttackToolsLoading(false);
    }
  }, []);

  const loadAttackRecommendations = useCallback(async (proxyId: string) => {
    try {
      setRecommendationsLoading(true);
      const data = await mitmClient.getAttackToolRecommendations(proxyId);
      setAttackRecommendations(data.recommendations || []);
    } catch (err: any) {
      console.error('Failed to load attack recommendations:', err);
      setError(err.message || 'Failed to get AI recommendations');
    } finally {
      setRecommendationsLoading(false);
    }
  }, []);

  const executeAttackTool = useCallback(async (proxyId: string, toolId: string, options?: Record<string, any>) => {
    try {
      setExecutingTool(toolId);
      const result = await mitmClient.executeAttackTool(proxyId, toolId, options);
      setToolExecutionResults(prev => [...prev, result]);
      if (result.success) {
        setSuccess(`Tool "${toolId}" executed successfully! Found ${result.findings?.length || 0} findings.`);
        // Refresh analysis to show new findings
        if (analysisResult) {
          handleAnalyzeTraffic();
        }
      } else {
        setError(`Tool execution had issues: ${result.errors?.join(', ') || 'Unknown error'}`);
      }
      return result;
    } catch (err: any) {
      console.error('Failed to execute attack tool:', err);
      setError(err.message || 'Failed to execute attack tool');
      return null;
    } finally {
      setExecutingTool(null);
    }
  }, [analysisResult]);

  const runAgenticSession = useCallback(async (proxyId: string, maxTools: number = 15, strategy: string = 'progressive') => {
    try {
      setAgenticSessionRunning(true);
      setAgenticSessionResult(null);
      const result = await mitmClient.runAgenticSession(proxyId, maxTools, true);
      setAgenticSessionResult(result);
      setShowAgenticResultDialog(true);
      if (result.status === 'completed' || result.status === 'partial') {
        setSuccess(`Agentic session completed! Executed ${result.tools_executed} tools, found ${result.total_findings} findings.`);
        // Refresh analysis to show new findings
        handleAnalyzeTraffic();
        // Refresh agent status
        loadAgentStatus(proxyId);
      }
      return result;
    } catch (err: any) {
      console.error('Failed to run agentic session:', err);
      setError(err.message || 'Failed to run agentic attack session');
      return null;
    } finally {
      setAgenticSessionRunning(false);
    }
  }, []);

  const loadAttackExecutionLog = useCallback(async (proxyId: string) => {
    try {
      const data = await mitmClient.getAttackToolExecutionLog(proxyId);
      setAttackToolExecutionLog(data.executions || []);
    } catch (err: any) {
      console.error('Failed to load execution log:', err);
    }
  }, []);

  // ============================================================================
  // Enhanced Agentic Functions
  // ============================================================================

  const loadAgentStatus = useCallback(async (proxyId: string) => {
    try {
      const status = await mitmClient.getAgentStatus(proxyId);
      setAgentStatus(status);
      setAgentMonitoringActive(status.monitoring_active);
      if (status.goals?.length > 0) {
        setAgentGoals(status.goals.map((g: any) => g.name));
      }
      if (status.goal_progress) {
        setAgentGoalProgress(status.goal_progress);
      }
    } catch (err: any) {
      console.error('Failed to load agent status:', err);
    }
  }, []);

  const handleSetGoals = useCallback(async (proxyId: string, goals: string[]) => {
    try {
      await mitmClient.setAttackGoals(proxyId, goals);
      setAgentGoals(goals);
      setSuccess(`Attack goals set: ${goals.join(', ')}`);
      setShowGoalDialog(false);
      // Load updated progress
      const progress = await mitmClient.getGoalProgress(proxyId);
      setAgentGoalProgress(progress);
    } catch (err: any) {
      setError(err.message || 'Failed to set attack goals');
    }
  }, []);

  const handleStartMonitoring = useCallback(async (proxyId: string) => {
    try {
      const result = await mitmClient.startTrafficMonitor(proxyId, {
        auto_analyze: true,
        capture_credentials: true,
        detect_vulnerabilities: true,
        trigger_attacks: true,
        interval_seconds: 2
      });
      setAgentMonitoringActive(true);
      setSuccess('Agent monitoring started - attacks will be triggered automatically!');
    } catch (err: any) {
      setError(err.message || 'Failed to start monitoring');
    }
  }, []);

  const handleStopMonitoring = useCallback(async (proxyId: string) => {
    try {
      await mitmClient.stopTrafficMonitor(proxyId);
      setAgentMonitoringActive(false);
      setSuccess('Agent monitoring stopped');
    } catch (err: any) {
      setError(err.message || 'Failed to stop monitoring');
    }
  }, []);

  const handleVerifyAttack = useCallback(async (proxyId: string, toolId: string) => {
    try {
      setSuccess(`Verifying attack: ${toolId}...`);
      const result = await mitmClient.verifyAttackSuccess(proxyId, toolId, 30);
      if (result.success) {
        setSuccess(`Attack verified! Indicators: ${result.indicators.join(', ')}`);
      } else {
        setError(`Attack unverified after ${result.verification_time_seconds?.toFixed(1)}s`);
      }
      return result;
    } catch (err: any) {
      setError(err.message || 'Failed to verify attack');
      return null;
    }
  }, []);

  // ============================================================================
  // Saved Reports Functions (for historical data persistence)
  // ============================================================================

  const loadSavedReports = useCallback(async () => {
    if (!projectId) return;
    try {
      setLoadingSavedReports(true);
      const response = await fetch(`/api/mitm/reports/project/${projectId}`);
      if (response.ok) {
        const data = await response.json();
        setSavedReports(data || []);
      }
    } catch (err: any) {
      console.error('Failed to load saved reports:', err);
    } finally {
      setLoadingSavedReports(false);
    }
  }, [projectId]);

  // Load saved reports when project is available
  useEffect(() => {
    if (projectId) {
      loadSavedReports();
    }
  }, [projectId, loadSavedReports]);

  const loadDataFromSavedReport = useCallback(async (reportId: number) => {
    try {
      setViewingHistoricalData(true);

      // Load phases from saved report
      const phasesResp = await fetch(`/api/mitm/reports/${reportId}/phases`);
      if (phasesResp.ok) {
        const data = await phasesResp.json();
        setAttackPhases(data.all_phases || []);
        setCurrentPhase(data.current_phase ? { name: data.current_phase, phase_type: data.current_phase } as any : null);
        setPhaseProgress(data.progress || null);
      }

      // Load chains from saved report
      const chainsResp = await fetch(`/api/mitm/reports/${reportId}/chains`);
      if (chainsResp.ok) {
        const data = await chainsResp.json();
        setAttackChains(data.available_chains || []);
        setChainExecutionHistory(data.execution_history || []);
        setChainStats(data.stats || null);
      }

      // Load MITRE mapping from saved report
      const mitreResp = await fetch(`/api/mitm/reports/${reportId}/mitre`);
      if (mitreResp.ok) {
        const data = await mitreResp.json();
        setMitreMapping(data);
      }

      // Load reasoning from saved report
      const reasoningResp = await fetch(`/api/mitm/reports/${reportId}/reasoning`);
      if (reasoningResp.ok) {
        const data = await reasoningResp.json();
        setReasoningChains(data.reasoning_chains || []);
      }

      // Load memory from saved report
      const memoryResp = await fetch(`/api/mitm/reports/${reportId}/memory`);
      if (memoryResp.ok) {
        const data = await memoryResp.json();
        setAgentMemory(data);
      }

      setSuccess(`Loaded historical data from report #${reportId}`);
    } catch (err: any) {
      console.error('Failed to load data from saved report:', err);
      setError('Failed to load historical data');
    }
  }, []);

  const handleSelectSavedReport = useCallback((report: SavedReport) => {
    setSelectedReport(report);
    loadDataFromSavedReport(report.id);
  }, [loadDataFromSavedReport]);

  // ============================================================================
  // Attack Phase Management Functions
  // ============================================================================

  const loadAttackPhases = useCallback(async (proxyId: string) => {
    try {
      setPhaseLoading(true);
      const response = await fetch(`/api/mitm/attack/${proxyId}/phase`);
      if (response.ok) {
        const data = await response.json();
        setAttackPhases(data.all_phases || []);
        setCurrentPhase(data.current_phase || null);
        setPhaseProgress(data.progress || null);
      }
    } catch (err: any) {
      console.error('Failed to load attack phases:', err);
    } finally {
      setPhaseLoading(false);
    }
  }, []);

  const loadAttackChains = useCallback(async (proxyId: string) => {
    try {
      const response = await fetch(`/api/mitm/attack/${proxyId}/chains`);
      if (response.ok) {
        const data = await response.json();
        setAttackChains(data.available_chains || []);
        setChainExecutionHistory(data.execution_history || []);
        setChainStats(data.stats || null);
      }
    } catch (err: any) {
      console.error('Failed to load attack chains:', err);
    }
  }, []);

  const loadMitreMapping = useCallback(async (proxyId: string) => {
    try {
      const response = await fetch(`/api/mitm/attack/${proxyId}/mitre`);
      if (response.ok) {
        const data = await response.json();
        setMitreMapping(data);
      }
    } catch (err: any) {
      console.error('Failed to load MITRE mapping:', err);
    }
  }, []);

  const loadAgentMemory = useCallback(async (proxyId: string) => {
    try {
      const response = await fetch(`/api/mitm/attack/${proxyId}/memory`);
      if (response.ok) {
        const data = await response.json();
        setAgentMemory(data);
      }
    } catch (err: any) {
      console.error('Failed to load agent memory:', err);
    }
  }, []);

  const loadReasoningChains = useCallback(async (proxyId: string) => {
    try {
      const response = await fetch(`/api/mitm/attack/${proxyId}/reasoning?limit=10`);
      if (response.ok) {
        const data = await response.json();
        setReasoningChains(data.reasoning_chains || []);
      }
    } catch (err: any) {
      console.error('Failed to load reasoning chains:', err);
    }
  }, []);

  // Clear historical view and reload live data
  const clearHistoricalView = useCallback(() => {
    setSelectedReport(null);
    setViewingHistoricalData(false);
    // Reload live data if proxy is selected
    if (selectedProxy) {
      loadAttackPhases(selectedProxy);
      loadAttackChains(selectedProxy);
      loadMitreMapping(selectedProxy);
      loadAgentMemory(selectedProxy);
      loadReasoningChains(selectedProxy);
    }
  }, [selectedProxy, loadAttackPhases, loadAttackChains, loadMitreMapping, loadAgentMemory, loadReasoningChains]);

  // Load attack phases when proxy is selected
  useEffect(() => {
    if (selectedProxy) {
      loadAttackPhases(selectedProxy);
    }
  }, [selectedProxy, loadAttackPhases]);

  const handleSetPhase = useCallback(async (proxyId: string, phase: string) => {
    try {
      const response = await fetch(`/api/mitm/attack/${proxyId}/phase/${phase}`, {
        method: 'POST',
      });
      if (response.ok) {
        const data = await response.json();
        setSuccess(`Transitioned to phase: ${phase}`);
        loadAttackPhases(proxyId);
      } else {
        const err = await response.json();
        setError(err.detail || 'Failed to set phase');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to set phase');
    }
  }, [loadAttackPhases]);

  const handleExecuteChain = useCallback(async (proxyId: string, chainId: string) => {
    try {
      setSuccess(`Executing attack chain: ${chainId}...`);
      const response = await fetch(`/api/mitm/attack/${proxyId}/chains/${chainId}`, {
        method: 'POST',
      });
      if (response.ok) {
        const data = await response.json();
        setSuccess(`Chain ${chainId} executed successfully!`);
        loadAttackChains(proxyId);
        loadAttackPhases(proxyId);
      } else {
        const err = await response.json();
        setError(err.detail || 'Failed to execute chain');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to execute chain');
    }
  }, [loadAttackChains, loadAttackPhases]);

  const handleRunAggressiveSession = useCallback(async (proxyId: string) => {
    try {
      setSuccess('Starting aggressive attack session...');
      const response = await fetch(`/api/mitm/attack/${proxyId}/aggressive-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          max_tools: 15,
          aggressive: true,
          goals: agentGoals.length > 0 ? agentGoals : ['compromise_authentication', 'inject_payload'],
        }),
      });
      if (response.ok) {
        const data = await response.json();
        setAgenticSessionResult(data);
        setSuccess(`Aggressive session completed! ${data.total_findings} findings, ${data.captured_data?.credentials?.length || 0} credentials captured`);
        loadAttackPhases(proxyId);
        loadAttackChains(proxyId);
        loadAgentMemory(proxyId);
      } else {
        const err = await response.json();
        setError(err.detail || 'Failed to run aggressive session');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to run aggressive session');
    }
  }, [agentGoals, loadAttackPhases, loadAttackChains, loadAgentMemory]);

  // Run test scenario
  const handleRunScenario = async (scenarioId: string) => {
    if (!selectedProxy) {
      setError('Please select a proxy first');
      return;
    }
    try {
      setRunningScenario(true);
      const result = await (mitmClient as any).runTestScenario(selectedProxy, scenarioId);
      setScenarioResult(result);
      setSuccess(`Scenario "${result.scenario.name}" applied successfully!`);
      loadRules();
      loadProxies();
    } catch (err: any) {
      setError(err.message || 'Failed to run scenario');
    } finally {
      setRunningScenario(false);
    }
  };

  // Natural Language Rule Creation
  const handleCreateNaturalLanguageRule = async () => {
    if (!nlRuleInput.trim()) {
      setError('Please enter a rule description');
      return;
    }
    try {
      setNlRuleLoading(true);
      setNlRuleResult(null);
      const result = await (mitmClient as any).createRuleFromNaturalLanguage(
        nlRuleInput,
        selectedProxy || undefined
      );
      setNlRuleResult(result);
      if (result.success) {
        setSuccess(result.applied 
          ? 'Rule created and applied to proxy!' 
          : 'Rule created successfully! Apply it to a proxy to use it.'
        );
        if (result.applied) {
          loadRules();
        }
      } else {
        setError(result.error || 'Failed to create rule from description');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to process natural language rule');
    } finally {
      setNlRuleLoading(false);
    }
  };

  // Apply AI-created rule to proxy
  const handleApplyNlRule = async () => {
    if (!nlRuleResult?.rule || !selectedProxy) {
      setError('Select a proxy and create a rule first');
      return;
    }
    try {
      setLoading(true);
      await mitmClient.addRule(selectedProxy, nlRuleResult.rule);
      setSuccess('Rule applied to proxy!');
      loadRules();
      setNlRuleResult(null);
      setNlRuleInput('');
    } catch (err: any) {
      setError(err.message || 'Failed to apply rule');
    } finally {
      setLoading(false);
    }
  };

  // Load AI Suggestions
  const handleLoadAiSuggestions = async () => {
    if (!selectedProxy) {
      setError('Please select a proxy first');
      return;
    }
    try {
      setAiSuggestionsLoading(true);
      const response = await (mitmClient as any).getAISuggestions(selectedProxy);
      setAiSuggestions(response.suggestions || []);
      setAiSuggestionsResponse(response);
      setShowAiSuggestions(true);
    } catch (err: any) {
      setError(err.message || 'Failed to get AI suggestions');
    } finally {
      setAiSuggestionsLoading(false);
    }
  };

  // Apply AI suggestion
  const handleApplyAiSuggestion = async (suggestion: AISuggestion) => {
    if (!selectedProxy || !suggestion.rule) {
      setError('No rule to apply');
      return;
    }
    try {
      setLoading(true);
      await mitmClient.addRule(selectedProxy, suggestion.rule);
      setSuccess(`Applied: ${suggestion.title}`);
      loadRules();
      // Remove applied suggestion from list
      setAiSuggestions(prev => prev.filter(s => s.id !== suggestion.id));
    } catch (err: any) {
      setError(err.message || 'Failed to apply suggestion');
    } finally {
      setLoading(false);
    }
  };

  // Create rule from suggestion's natural language
  const handleUseSuggestionNL = (suggestion: AISuggestion) => {
    setNlRuleInput(suggestion.natural_language);
    setShowNlRulePanel(true);
    setShowAiSuggestions(false);
  };

  // Load data when proxy selected
  useEffect(() => {
    if (selectedProxy) {
      setActiveSession(null);
      setSelectedTraffic(null);
      setTraffic([]);
      setAttackRecommendations([]);
      setAttackToolExecutionLog([]);
      setToolExecutionResults([]);
      setAgentStatus(null);
      setAgentGoals([]);
      setAgentGoalProgress(null);
      loadTraffic();
      loadRules();
      checkProxyHealth();
      loadWebSocketConnections();
      loadWebSocketStats();
      loadWebSocketRules();
    }
    setTrafficSearch('');
    setTrafficMethodFilter([]);
    setTrafficStatusFilter('all');
    setTrafficHostFilter('all');
    setTrafficModifiedOnly(false);
    setTrafficWithResponseOnly(false);
  }, [selectedProxy, loadTraffic, loadRules, loadWebSocketConnections, loadWebSocketStats, loadWebSocketRules]);

  useEffect(() => {
    if (!selectedTraffic) {
      setTrafficNotes('');
      setTrafficTagsInput('');
      return;
    }
    setTrafficNotes(selectedTraffic.notes || '');
    setTrafficTagsInput((selectedTraffic.tags || []).join(', '));
  }, [selectedTraffic]);

  useEffect(() => {
    if (!selectedTraffic) return;
    const updated = traffic.find(entry => entry.id === selectedTraffic.id);
    if (updated && updated !== selectedTraffic) {
      setSelectedTraffic(updated);
    }
  }, [traffic, selectedTraffic]);

  useEffect(() => {
    if (liveStreamEnabled) {
      setAutoRefresh(false);
    }
  }, [liveStreamEnabled]);

  // Auto-refresh traffic
  useEffect(() => {
    if (!autoRefresh || !selectedProxy || liveStreamEnabled || activeSession) return;
    const interval = setInterval(() => {
      loadTraffic();
      loadProxies();
    }, 2000);
    return () => clearInterval(interval);
  }, [autoRefresh, selectedProxy, liveStreamEnabled, activeSession, loadTraffic, loadProxies]);

  // Load attack tools when agentic tools are visible
  useEffect(() => {
    if (!showAgenticTools) return;
    if (attackTools.length === 0) {
      loadAttackTools();
    }
    if (selectedProxy) {
      loadAttackRecommendations(selectedProxy);
      loadAttackExecutionLog(selectedProxy);
      loadAgentStatus(selectedProxy);
    }
  }, [showAgenticTools, selectedProxy, attackTools.length, loadAttackTools, loadAttackRecommendations, loadAttackExecutionLog, loadAgentStatus]);

  // Live stream via WebSocket
  useEffect(() => {
    if (!selectedProxy || !liveStreamEnabled || activeSession) {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      setWsConnected(false);
      setWsError(null);
      return;
    }

    const ws = new WebSocket(buildWsUrl(selectedProxy));
    wsRef.current = ws;
    setWsConnected(false);
    setWsError(null);

    const handleInit = (message: any) => {
      const entries = Array.isArray(message.traffic)
        ? message.traffic
        : message.traffic?.entries || [];
      setTraffic(entries.map((entry: any) => normalizeTrafficEntry(entry)));
      if (Array.isArray(message.rules)) {
        setRules(message.rules);
      }
      if (message.status) {
        const status = message.status;
        setProxies(prev => prev.map(proxy => {
          if (proxy.id !== selectedProxy) return proxy;
          return {
            ...proxy,
            listen_host: status.listen_host ?? proxy.listen_host,
            listen_port: status.listen_port ?? proxy.listen_port,
            target_host: status.target_host ?? proxy.target_host,
            target_port: status.target_port ?? proxy.target_port,
            mode: status.mode ?? proxy.mode,
            tls_enabled: status.tls_enabled ?? proxy.tls_enabled,
            running: status.running ?? proxy.running,
            stats: {
              ...proxy.stats,
              requests: status.stats?.requests ?? status.requests ?? proxy.stats.requests,
              responses: status.stats?.responses ?? status.responses ?? proxy.stats.responses,
              bytes_sent: status.stats?.bytes_sent ?? proxy.stats.bytes_sent,
              bytes_received: status.stats?.bytes_received ?? proxy.stats.bytes_received,
              errors: status.stats?.errors ?? proxy.stats.errors,
              rules_applied: status.stats?.rules_applied ?? proxy.stats.rules_applied,
            },
          };
        }));
      }
    };

    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onerror = () => {
      setWsConnected(false);
      setWsError('Live stream connection error');
    };
    ws.onmessage = (event) => {
      let message: any;
      try {
        message = JSON.parse(event.data);
      } catch {
        return;
      }
      if (message.type === 'init') {
        handleInit(message);
        return;
      }
      if (message.type === 'traffic' && message.entry) {
        const normalized = normalizeTrafficEntry(message.entry);
        setTraffic(prev => {
          const idx = prev.findIndex(entry => entry.id === normalized.id);
          if (idx === -1) {
            return [normalized, ...prev];
          }
          const existing = prev[idx];
          const merged = {
            ...existing,
            ...normalized,
            request: { ...existing.request, ...normalized.request },
            response: normalized.response ?? existing.response,
            tags: normalized.tags !== undefined ? normalized.tags : existing.tags,
            notes: normalized.notes !== undefined ? normalized.notes : existing.notes,
            rules_applied: normalized.rules_applied ?? existing.rules_applied,
            modified: normalized.modified ?? existing.modified,
            duration_ms: normalized.duration_ms ?? existing.duration_ms,
            timestamp: normalized.timestamp ?? existing.timestamp,
          };
          const next = [...prev];
          next[idx] = merged;
          return next;
        });
      } else if (message.type === 'stats' && message.stats) {
        setProxies(prev => prev.map(proxy => {
          if (proxy.id !== selectedProxy) return proxy;
          return {
            ...proxy,
            stats: {
              ...proxy.stats,
              requests: message.stats.requests ?? proxy.stats.requests,
              responses: message.stats.responses ?? proxy.stats.responses,
              bytes_sent: message.stats.bytes_sent ?? proxy.stats.bytes_sent,
              bytes_received: message.stats.bytes_received ?? proxy.stats.bytes_received,
              errors: message.stats.errors ?? proxy.stats.errors,
              rules_applied: message.stats.rules_applied ?? proxy.stats.rules_applied,
            },
          };
        }));
      } else if (message.type === 'status') {
        if (message.deleted) {
          setProxies(prev => prev.filter(proxy => proxy.id !== selectedProxy));
          setSelectedProxy(null);
          setTraffic([]);
          setRules([]);
          return;
        }
        if (typeof message.running === 'boolean') {
          setProxies(prev => prev.map(proxy => {
            if (proxy.id !== selectedProxy) return proxy;
            return { ...proxy, running: message.running };
          }));
        }
      } else if (message.type === 'mode' && message.mode) {
        setProxies(prev => prev.map(proxy => {
          if (proxy.id !== selectedProxy) return proxy;
          return { ...proxy, mode: message.mode };
        }));
      } else if (message.type === 'rules') {
        loadRules();
      } else if (message.type === 'agent_event') {
        // Handle real-time agentic session events
        const eventData = message.data || {};
        switch (message.event) {
          case 'agentic_session_started':
            setAgenticSessionRunning(true);
            setSuccess(`Agentic session started (max ${eventData.max_tools} tools)`);
            break;
          case 'tool_execution_started':
            setSuccess(`Executing: ${eventData.tool_name} (${eventData.tools_executed + 1}/${eventData.max_tools})`);
            break;
          case 'tool_execution_completed':
            setSuccess(`Completed: ${eventData.tool_name} - ${eventData.findings_count} findings (Total: ${eventData.total_findings})`);
            // Refresh agent status to show updated findings
            if (selectedProxy) {
              loadAgentStatus(selectedProxy);
            }
            break;
          case 'agentic_session_completed':
            setAgenticSessionRunning(false);
            setSuccess(`Session complete! ${eventData.tools_executed} tools, ${eventData.total_findings} findings, ${eventData.credentials_captured} credentials`);
            // Refresh data after session completes
            if (selectedProxy) {
              loadAgentStatus(selectedProxy);
              loadAttackExecutionLog(selectedProxy);
            }
            break;
          case 'agentic_session_failed':
            setAgenticSessionRunning(false);
            setError(`Agentic session failed: ${eventData.error}`);
            break;
          case 'credential_captured':
          case 'token_captured':
            setSuccess(`Captured: ${message.event.replace('_', ' ')}`);
            if (selectedProxy) {
              loadAgentStatus(selectedProxy);
            }
            break;
          default:
            // Log other agent events for debugging
            console.log('Agent event:', message.event, eventData);
        }
      }
    };

    const pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send('ping');
      }
    }, 10000);

    return () => {
      clearInterval(pingInterval);
      ws.close();
    };
  }, [selectedProxy, liveStreamEnabled, activeSession, buildWsUrl, normalizeTrafficEntry, loadRules]);

  // Create proxy
  const handleCreateProxy = async () => {
    try {
      setLoading(true);
      await mitmClient.createProxy(newProxy as any);
      setSuccess('Proxy created successfully');
      setNewProxyOpen(false);
      setNewProxy({
        proxy_id: '',
        listen_host: '0.0.0.0',
        listen_port: 8080,
        target_host: '',
        target_port: 80,
        mode: 'auto_modify',
        tls_enabled: false,
      });
      loadProxies();
    } catch (err: any) {
      setError(err.message || 'Failed to create proxy');
    } finally {
      setLoading(false);
    }
  };

  // Start/stop proxy
  const handleToggleProxy = async (proxyId: string, running: boolean) => {
    try {
      if (running) {
        // When stopping, auto-save with project context if available
        const result = await mitmClient.stopProxy(proxyId, {
          autoSave: true,
          projectId: projectId ? parseInt(projectId, 10) : undefined,
        });
        if (result.auto_saved && result.saved_report_id) {
          if (projectId) {
            setSuccess(`Proxy stopped - scan saved to project`);
          } else {
            setSuccess(`Proxy stopped - scan saved to Saved Scans`);
          }
          // Refresh saved sessions list
          loadSavedSessions();
        } else {
          setSuccess('Proxy stopped');
        }
      } else {
        await mitmClient.startProxy(proxyId);
        setSuccess('Proxy started');
      }
      loadProxies();
    } catch (err: any) {
      setError(err.message || 'Failed to toggle proxy');
    }
  };

  // Delete proxy
  const handleDeleteProxy = async (proxyId: string) => {
    try {
      await mitmClient.deleteProxy(proxyId);
      setSuccess('Proxy deleted');
      if (selectedProxy === proxyId) {
        setSelectedProxy(null);
        setTraffic([]);
        setRules([]);
      }
      loadProxies();
    } catch (err: any) {
      setError(err.message || 'Failed to delete proxy');
    }
  };

  // Change proxy mode
  const handleChangeMode = async (proxyId: string, mode: string) => {
    try {
      await mitmClient.setProxyMode(proxyId, mode);
      setSuccess(`Mode changed to ${mode}`);
      loadProxies();
    } catch (err: any) {
      setError(err.message || 'Failed to change mode');
    }
  };

  // Clear traffic
  const handleClearTraffic = async () => {
    if (!selectedProxy) return;
    try {
      await mitmClient.clearTraffic(selectedProxy);
      setTraffic([]);
      setSelectedTraffic(null);
      setSuccess('Traffic cleared');
    } catch (err: any) {
      setError(err.message || 'Failed to clear traffic');
    }
  };

  // Add rule
  const handleAddRule = async () => {
    if (!selectedProxy) return;
    try {
      const parseJson = (value: string, label: string) => {
        if (!value.trim()) return undefined;
        try {
          return JSON.parse(value);
        } catch {
          throw new Error(`${label} must be valid JSON`);
        }
      };

      const payload: Partial<InterceptionRule> = { ...newRule };
      const matchQuery = parseJson(ruleMatchQueryInput, 'Match query');
      if (matchQuery) payload.match_query = matchQuery;
      const modifyHeaders = parseJson(ruleModifyHeadersInput, 'Modify headers');
      if (modifyHeaders) payload.modify_headers = modifyHeaders;
      if (ruleRemoveHeadersInput.trim()) {
        payload.remove_headers = ruleRemoveHeadersInput
          .split(',')
          .map(header => header.trim())
          .filter(Boolean);
      }
      const bodyFindReplace = parseJson(ruleBodyFindReplaceInput, 'Body find/replace');
      if (bodyFindReplace) payload.body_find_replace = bodyFindReplace;
      const jsonPathEdits = parseJson(ruleJsonPathEditsInput, 'JSON path edits');
      if (jsonPathEdits) payload.json_path_edits = jsonPathEdits;

      await mitmClient.addRule(selectedProxy, payload);
      setSuccess('Rule added');
      setNewRuleOpen(false);
      setNewRule({
        name: '',
        enabled: true,
        match_direction: 'both',
        action: 'modify',
      });
      setRuleMatchQueryInput('');
      setRuleModifyHeadersInput('');
      setRuleRemoveHeadersInput('');
      setRuleBodyFindReplaceInput('');
      setRuleJsonPathEditsInput('');
      loadRules();
    } catch (err: any) {
      setError(err.message || 'Failed to add rule');
    }
  };

  // Apply preset
  const handleApplyPreset = async (presetId: string) => {
    if (!selectedProxy) return;
    try {
      await mitmClient.applyPreset(selectedProxy, presetId);
      setSuccess('Preset rule applied');
      loadRules();
    } catch (err: any) {
      setError(err.message || 'Failed to apply preset');
    }
  };

  // Toggle rule
  const handleToggleRule = async (ruleId: string, enabled: boolean) => {
    if (!selectedProxy) return;
    try {
      await mitmClient.toggleRule(selectedProxy, ruleId, enabled);
      loadRules();
    } catch (err: any) {
      setError(err.message || 'Failed to toggle rule');
    }
  };

  const handleToggleRuleGroup = async (group: string, enabled: boolean) => {
    if (!selectedProxy) return;
    try {
      await mitmClient.toggleRuleGroup(selectedProxy, group, enabled);
      loadRules();
    } catch (err: any) {
      setError(err.message || 'Failed to toggle rule group');
    }
  };

  // Delete rule
  const handleDeleteRule = async (ruleId: string) => {
    if (!selectedProxy) return;
    try {
      await mitmClient.removeRule(selectedProxy, ruleId);
      setSuccess('Rule deleted');
      loadRules();
    } catch (err: any) {
      setError(err.message || 'Failed to delete rule');
    }
  };

  // Copy to clipboard
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setSuccess('Copied to clipboard');
  };

  const openTrafficMenu = (event: React.MouseEvent<HTMLElement>, entry: TrafficEntry) => {
    setTrafficMenuAnchor(event.currentTarget);
    setTrafficMenuEntry(entry);
  };

  const closeTrafficMenu = () => {
    setTrafficMenuAnchor(null);
    setTrafficMenuEntry(null);
  };

  const getTrafficUrl = (entry: TrafficEntry) => {
    if (entry.request.url) return entry.request.url;
    const protocol = entry.request.protocol || (currentProxy?.tls_enabled ? 'https' : 'http');
    const host = entry.request.host || currentProxy?.target_host || 'localhost';
    return `${protocol}://${host}${entry.request.path || '/'}`;
  };

  const handleCopyAsCurl = (entry: TrafficEntry) => {
    const url = getTrafficUrl(entry);
    const method = entry.request.method || 'GET';
    const headers = entry.request.headers || {};
    const body = entry.request.body || '';

    let command = `curl -i -X ${method} '${url}'`;
    Object.entries(headers).forEach(([key, value]) => {
      if (!key) return;
      command += ` -H '${key}: ${String(value).replace(/'/g, "\\'")}'`;
    });
    if (body) {
      command += ` --data-raw '${String(body).replace(/'/g, "\\'")}'`;
    }
    copyToClipboard(command);
    closeTrafficMenu();
  };

  const handleSendToApiTester = (entry: TrafficEntry) => {
    const url = getTrafficUrl(entry);
    let baseUrl = url;
    let path = entry.request.path || '/';
    try {
      const parsed = new URL(url);
      baseUrl = `${parsed.protocol}//${parsed.host}`;
      path = `${parsed.pathname}${parsed.search}`;
    } catch {
      baseUrl = url;
    }
    const payload = {
      baseUrl,
      endpoints: [
        {
          url: path,
          method: entry.request.method || 'GET',
        },
      ],
    };
    localStorage.setItem(API_TESTER_HANDOFF_KEY, JSON.stringify(payload));
    navigate('/network/api-tester');
    closeTrafficMenu();
  };

  const handleSendToFuzzer = (entry: TrafficEntry) => {
    const url = getTrafficUrl(entry);
    const payload = {
      targetUrl: url,
      method: entry.request.method || 'GET',
      headers: entry.request.headers || {},
      body: entry.request.body || entry.request.body_text || '',
    };
    localStorage.setItem(FUZZER_HANDOFF_KEY, JSON.stringify(payload));
    navigate('/network/fuzzer');
    closeTrafficMenu();
  };

  const handleOpenReplay = (entry: TrafficEntry) => {
    setReplayEntry(entry);
    setReplayOverrides({
      method: entry.request.method || 'GET',
      path: entry.request.path || '/',
      body: entry.request.body || entry.request.body_text || '',
      addHeaders: '',
      removeHeaders: '',
      baseUrl: '',
      timeout: 20,
      verifyTls: false,
    });
    setReplayOpen(true);
    closeTrafficMenu();
  };

  const handleReplayRequest = async () => {
    if (!selectedProxy || !replayEntry) return;
    try {
      setReplayLoading(true);
      let addHeaders: Record<string, string> | undefined;
      if (replayOverrides.addHeaders.trim()) {
        try {
          addHeaders = JSON.parse(replayOverrides.addHeaders);
        } catch {
          setError('Add headers must be valid JSON');
          return;
        }
      }
      const removeHeaders = replayOverrides.removeHeaders
        .split(',')
        .map(header => header.trim())
        .filter(Boolean);
      const response = await mitmClient.replayTrafficEntry(selectedProxy, replayEntry.id, {
        method: replayOverrides.method || undefined,
        path: replayOverrides.path || undefined,
        body: replayOverrides.body,
        add_headers: addHeaders,
        remove_headers: removeHeaders.length ? removeHeaders : undefined,
        base_url: replayOverrides.baseUrl || undefined,
        timeout: replayOverrides.timeout || undefined,
        verify_tls: replayOverrides.verifyTls,
      });
      if (response?.entry) {
        const normalized = normalizeTrafficEntry(response.entry);
        setTraffic(prev => [normalized, ...prev]);
      } else {
        loadTraffic();
      }
      setSuccess('Replay complete');
      setReplayOpen(false);
    } catch (err: any) {
      setError(err.message || 'Failed to replay request');
    } finally {
      setReplayLoading(false);
    }
  };

  const handleCreateRuleFromEntry = (entry: TrafficEntry, action: 'modify' | 'drop' = 'modify') => {
    setNewRule({
      name: `${action === 'drop' ? 'Block' : 'Match'} ${entry.request.method} ${entry.request.path}`,
      enabled: true,
      match_direction: 'request',
      match_host: entry.request.host,
      match_path: entry.request.path,
      match_method: entry.request.method,
      action,
    });
    setRuleMatchQueryInput('');
    setRuleModifyHeadersInput('');
    setRuleRemoveHeadersInput('');
    setRuleBodyFindReplaceInput('');
    setRuleJsonPathEditsInput('');
    setNewRuleOpen(true);
    closeTrafficMenu();
  };

  const handleSaveTrafficMeta = async () => {
    if (!selectedProxy || !selectedTraffic) return;
    try {
      setSavingTrafficMeta(true);
      const tags = trafficTagsInput
        .split(',')
        .map(tag => tag.trim())
        .filter(Boolean);
      const updated = await mitmClient.updateTrafficEntry(
        selectedProxy,
        selectedTraffic.id,
        { notes: trafficNotes, tags }
      );
      const normalized = normalizeTrafficEntry(updated);
      setSelectedTraffic(normalized);
      setTraffic(prev => prev.map(entry => entry.id === normalized.id ? normalized : entry));
      setSuccess('Notes saved');
    } catch (err: any) {
      setError(err.message || 'Failed to save notes');
    } finally {
      setSavingTrafficMeta(false);
    }
  };

  // Load guided setup
  const loadGuidedSetup = async () => {
    try {
      setLoadingGuide(true);
      const data = await mitmClient.getGuidedSetup();
      setGuidedSetup(data);
    } catch (err: any) {
      // Fallback to static data if API fails
      setGuidedSetup(FALLBACK_GUIDED_SETUP);
    } finally {
      setLoadingGuide(false);
    }
  };

  // Open wizard
  const handleOpenWizard = async () => {
    if (!guidedSetup) {
      await loadGuidedSetup();
    }
    setWizardOpen(true);
    setWizardStep(0);
  };

  // Analyze traffic with AI
  const handleAnalyzeTraffic = async () => {
    if (!selectedProxy) return;
    try {
      setAnalyzingTraffic(true);
      const result = await mitmClient.analyzeTraffic(selectedProxy);
      setAnalysisResult(result);
      setShowAnalysis(true);
      setSuccess('Traffic analysis complete');
      
      // Auto-save session with analysis
      if (autoSaveEnabled && result) {
        await handleAutoSaveSession(result);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to analyze traffic');
    } finally {
      setAnalyzingTraffic(false);
    }
  };

  // Export report
  const handleExportReport = async (format: 'markdown' | 'pdf' | 'docx') => {
    if (!selectedProxy) return;
    try {
      setExporting(true);
      setExportAnchorEl(null);
      const blob = await mitmClient.exportReport(selectedProxy, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const ext = format === 'markdown' ? 'md' : format;
      a.download = `mitm-report-${selectedProxy}-${new Date().toISOString().split('T')[0]}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
      setSuccess(`Report exported as ${format.toUpperCase()}`);
    } catch (err: any) {
      setError(err.message || `Failed to export ${format} report`);
    } finally {
      setExporting(false);
    }
  };

  // Get severity color
  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'info';
      default: return 'default';
    }
  };

  // Get risk level color
  const getRiskLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f44336';
      case 'medium': return '#ff9800';
      case 'low': return '#4caf50';
      default: return '#9e9e9e';
    }
  };

  // Export traffic
  const exportTraffic = async (format: 'json' | 'pcap') => {
    if (!selectedProxy) return;
    try {
      setTrafficExporting(true);
      setTrafficExportAnchorEl(null);
      let blob: Blob | null = null;
      if (activeSession) {
        if (format !== 'json') {
          setError('PCAP export is only available for live traffic');
          return;
        }
        const data = JSON.stringify(traffic, null, 2);
        blob = new Blob([data], { type: 'application/json' });
      } else {
        blob = await mitmClient.exportTraffic(selectedProxy, format);
      }
      if (!blob) return;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const ext = format === 'json' ? 'json' : 'pcap';
      const sessionSuffix = activeSession ? `-session-${activeSession.id}` : '';
      a.download = `mitm-traffic-${selectedProxy}${sessionSuffix}-${new Date().toISOString().split('T')[0]}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
      setSuccess(`Traffic exported as ${format.toUpperCase()}`);
    } catch (err: any) {
      setError(err.message || `Failed to export ${format.toUpperCase()} traffic`);
    } finally {
      setTrafficExporting(false);
    }
  };

  // Get selected proxy details
  const currentProxy = proxies.find(p => p.id === selectedProxy);

  const uniqueHosts = useMemo(() => {
    const hosts = new Set<string>();
    traffic.forEach(entry => {
      if (entry.request.host) {
        hosts.add(entry.request.host);
      }
    });
    return Array.from(hosts).sort();
  }, [traffic]);

  const uniqueMethods = useMemo(() => {
    const methods = new Set<string>();
    traffic.forEach(entry => {
      if (entry.request.method) {
        methods.add(entry.request.method);
      }
    });
    return Array.from(methods).sort();
  }, [traffic]);

  const trafficSummary = useMemo(() => {
    let modifiedCount = 0;
    let errorCount = 0;
    let durationTotal = 0;
    let durationSamples = 0;
    const hosts = new Set<string>();

    traffic.forEach(entry => {
      if (entry.modified) modifiedCount += 1;
      if (entry.request.host) hosts.add(entry.request.host);
      if (entry.response?.status_code && entry.response.status_code >= 400) {
        errorCount += 1;
      }
      if (typeof entry.duration_ms === 'number' && entry.duration_ms > 0) {
        durationTotal += entry.duration_ms;
        durationSamples += 1;
      }
    });

    return {
      total: traffic.length,
      modified: modifiedCount,
      errors: errorCount,
      hosts: hosts.size,
      avgDuration: durationSamples ? Math.round(durationTotal / durationSamples) : 0,
    };
  }, [traffic]);

  const filteredTraffic = useMemo(() => {
    const search = trafficSearch.trim().toLowerCase();
    const hasMethodFilter = trafficMethodFilter.length > 0;
    const hasHostFilter = trafficHostFilter !== 'all';

    const filtered = traffic.filter(entry => {
      if (trafficModifiedOnly && !entry.modified) return false;
      if (trafficWithResponseOnly && !entry.response) return false;
      if (hasMethodFilter && !trafficMethodFilter.includes(entry.request.method)) return false;
      if (hasHostFilter && entry.request.host !== trafficHostFilter) return false;

      if (trafficStatusFilter !== 'all') {
        if (trafficStatusFilter === 'pending') {
          if (entry.response) return false;
        } else {
          const statusCode = entry.response?.status_code;
          if (!statusCode) return false;
          const statusGroup = `${Math.floor(statusCode / 100)}xx`;
          if (statusGroup !== trafficStatusFilter) return false;
        }
      }

      if (!search) return true;

      const haystack = [
        entry.request.method,
        entry.request.path,
        entry.request.host,
        entry.request.url,
        entry.response?.status_code?.toString(),
        entry.response?.status_text,
        entry.notes,
        (entry.tags || []).join(' '),
        (entry.rules_applied || []).join(' '),
        JSON.stringify(entry.request.headers),
        entry.request.body,
        JSON.stringify(entry.response?.headers || {}),
        entry.response?.body,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();

      return haystack.includes(search);
    });

    const sorted = [...filtered].sort((a, b) => {
      const aTime = new Date(a.timestamp).getTime();
      const bTime = new Date(b.timestamp).getTime();
      return trafficSort === 'newest' ? bTime - aTime : aTime - bTime;
    });

    return sorted;
  }, [
    traffic,
    trafficSearch,
    trafficMethodFilter,
    trafficStatusFilter,
    trafficHostFilter,
    trafficModifiedOnly,
    trafficWithResponseOnly,
    trafficSort,
  ]);

  const hasActiveTrafficFilters =
    trafficSearch.trim().length > 0 ||
    trafficMethodFilter.length > 0 ||
    trafficStatusFilter !== 'all' ||
    trafficHostFilter !== 'all' ||
    trafficModifiedOnly ||
    trafficWithResponseOnly;

  const ruleGroups = useMemo(() => {
    const groups: Record<string, { total: number; enabled: number }> = {};
    rules.forEach(rule => {
      if (!rule.group) return;
      const name = rule.group;
      if (!groups[name]) {
        groups[name] = { total: 0, enabled: 0 };
      }
      groups[name].total += 1;
      if (rule.enabled) groups[name].enabled += 1;
    });
    return Object.entries(groups).map(([name, info]) => ({
      name,
      total: info.total,
      enabledCount: info.enabled,
      allEnabled: info.enabled === info.total,
    }));
  }, [rules]);

  // Format bytes
  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  // Get health status color
  const getHealthStatusColor = (status: string) => {
    switch (status) {
      case 'pass': return 'success';
      case 'fail': return 'error';
      case 'warning': return 'warning';
      default: return 'info';
    }
  };

  // Get difficulty color
  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty.toLowerCase()) {
      case 'beginner': return 'success';
      case 'intermediate': return 'warning';
      case 'advanced': return 'error';
      default: return 'default';
    }
  };

  // Tutorial steps for interactive walkthrough
  const tutorialSteps = [
    { target: 'create-proxy', title: 'Create Your First Proxy', description: 'Start by creating a new proxy instance. Click "New Proxy" to begin.' },
    { target: 'proxy-config', title: 'Configure Proxy Settings', description: 'Enter a unique name and set target address.' },
    { target: 'start-proxy', title: 'Start the Proxy', description: 'Click the play button to start intercepting traffic.' },
    { target: 'test-scenarios', title: 'Try a Test Scenario', description: 'Use pre-built scenarios to learn security testing.' },
    { target: 'traffic-log', title: 'View Traffic', description: 'See intercepted requests in real-time.' },
    { target: 'analyze', title: 'Analyze with AI', description: 'Let AI find security issues automatically.' },
  ];

  // Traffic Flow Visualization Component
  const TrafficFlowVisualization = () => {
    const isProxyRunning = currentProxy?.running;
    const hasTraffic = traffic.length > 0;
    
    return (
      <Paper 
        sx={{ 
          p: 2, 
          mb: 2, 
          background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.05)} 0%, ${alpha(theme.palette.secondary.main, 0.05)} 100%)`,
          border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
        }}
      >
        <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 2 }}>
          Traffic Flow
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 2 }}>
          {/* Client */}
          <Box sx={{ textAlign: 'center' }}>
            <Avatar sx={{ bgcolor: 'info.main', width: 56, height: 56, mb: 1, mx: 'auto' }}>
              <ClientIcon />
            </Avatar>
            <Typography variant="caption" display="block">Client App</Typography>
            <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.65rem' }}>
              Your Browser/App
            </Typography>
          </Box>

          {/* Arrow 1 */}
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              {isProxyRunning && hasTraffic && (
                <Zoom in>
                  <DotIcon sx={{ color: 'success.main', fontSize: 12, animation: 'pulse 1s infinite', mr: -1 }} />
                </Zoom>
              )}
              <ArrowRightIcon sx={{ color: isProxyRunning ? 'success.main' : 'text.disabled', fontSize: 32 }} />
            </Box>
            <Typography variant="caption" color={isProxyRunning ? 'success.main' : 'text.secondary'} sx={{ fontSize: '0.6rem' }}>
              {isProxyRunning ? 'Requests →' : 'Configure proxy'}
            </Typography>
          </Box>

          {/* Proxy */}
          <Box sx={{ textAlign: 'center' }}>
            <Badge
              badgeContent={rules.length}
              color="warning"
              overlap="circular"
              anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
            >
              <Avatar 
                sx={{ 
                  bgcolor: isProxyRunning ? 'warning.main' : 'grey.500', 
                  width: 64, 
                  height: 64, 
                  mb: 1, 
                  mx: 'auto',
                  border: `3px solid ${isProxyRunning ? theme.palette.success.main : theme.palette.grey[600]}`,
                  animation: isProxyRunning ? 'pulse 2s infinite' : 'none',
                }}
              >
                <ProxyIcon />
              </Avatar>
            </Badge>
            <Typography variant="caption" display="block" fontWeight="bold">MITM Proxy</Typography>
            <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.65rem' }}>
              {currentProxy ? `${currentProxy.listen_host}:${currentProxy.listen_port}` : 'Not selected'}
            </Typography>
            {currentProxy && (
              <Chip 
                label={currentProxy.mode} 
                size="small" 
                sx={{ mt: 0.5, fontSize: '0.6rem', height: 18 }}
                color={currentProxy.mode === 'auto_modify' ? 'warning' : 'default'}
              />
            )}
          </Box>

          {/* Arrow 2 */}
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <ArrowRightIcon sx={{ color: isProxyRunning ? 'success.main' : 'text.disabled', fontSize: 32 }} />
              {isProxyRunning && hasTraffic && (
                <Zoom in>
                  <DotIcon sx={{ color: 'success.main', fontSize: 12, animation: 'pulse 1s infinite', ml: -1 }} />
                </Zoom>
              )}
            </Box>
            <Typography variant="caption" color={isProxyRunning ? 'success.main' : 'text.secondary'} sx={{ fontSize: '0.6rem' }}>
              {isProxyRunning ? '→ Forwarded' : ''}
            </Typography>
          </Box>

          {/* Server */}
          <Box sx={{ textAlign: 'center' }}>
            <Avatar sx={{ bgcolor: 'secondary.main', width: 56, height: 56, mb: 1, mx: 'auto' }}>
              <ServerIcon />
            </Avatar>
            <Typography variant="caption" display="block">Target Server</Typography>
            <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.65rem' }}>
              {currentProxy ? `${currentProxy.target_host}:${currentProxy.target_port}` : 'Not configured'}
            </Typography>
          </Box>
        </Box>

        {/* Status bar */}
        <Box sx={{ mt: 2, display: 'flex', justifyContent: 'center', gap: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            {isProxyRunning ? (
              <WifiIcon sx={{ color: 'success.main', fontSize: 16 }} />
            ) : (
              <WifiOffIcon sx={{ color: 'text.disabled', fontSize: 16 }} />
            )}
            <Typography variant="caption" color={isProxyRunning ? 'success.main' : 'text.secondary'}>
              {isProxyRunning ? 'Connected' : 'Disconnected'}
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <HttpIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
            <Typography variant="caption" color="text.secondary">
              {traffic.length} requests captured
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <RuleIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
            <Typography variant="caption" color="text.secondary">
              {rules.length} rules active
            </Typography>
          </Box>
        </Box>
      </Paper>
    );
  };

  // Health Check Component
  const HealthCheckPanel = () => {
    if (!proxyHealth) return null;
    
    return (
      <Paper sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Avatar 
              sx={{ 
                width: 32, 
                height: 32, 
                bgcolor: proxyHealth.status === 'healthy' ? 'success.main' : 
                         proxyHealth.status === 'warning' ? 'warning.main' : 'error.main' 
              }}
            >
              {proxyHealth.status === 'healthy' ? <CheckIcon sx={{ fontSize: 18 }} /> :
               proxyHealth.status === 'warning' ? <WarningIcon sx={{ fontSize: 18 }} /> :
               <ErrorIcon sx={{ fontSize: 18 }} />}
            </Avatar>
            <Box>
              <Typography variant="subtitle2">
                Health: {proxyHealth.status.toUpperCase()}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {proxyHealth.checks.filter(c => c.status === 'pass').length}/{proxyHealth.checks.length} checks passed
              </Typography>
            </Box>
          </Box>
          <IconButton size="small" onClick={checkProxyHealth} disabled={checkingHealth}>
            {checkingHealth ? <CircularProgress size={16} /> : <RefreshIcon fontSize="small" />}
          </IconButton>
        </Box>
        
        <Grid container spacing={1}>
          {proxyHealth.checks.map((check, idx) => (
            <Grid item xs={6} key={idx}>
              <Box 
                sx={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: 0.5,
                  p: 0.5,
                  borderRadius: 1,
                  bgcolor: alpha(
                    check.status === 'pass' ? theme.palette.success.main :
                    check.status === 'fail' ? theme.palette.error.main : 
                    theme.palette.info.main, 
                    0.1
                  ),
                }}
              >
                {check.status === 'pass' && <CheckIcon sx={{ fontSize: 14, color: 'success.main' }} />}
                {check.status === 'fail' && <CancelIcon sx={{ fontSize: 14, color: 'error.main' }} />}
                {check.status === 'info' && <InfoIcon sx={{ fontSize: 14, color: 'info.main' }} />}
                {check.status === 'warning' && <WarningIcon sx={{ fontSize: 14, color: 'warning.main' }} />}
                <Typography variant="caption" sx={{ fontSize: '0.7rem' }}>{check.name}</Typography>
              </Box>
            </Grid>
          ))}
        </Grid>

        {proxyHealth.recommendations.length > 0 && (
          <Alert severity="info" sx={{ mt: 2, py: 0 }} icon={<TipIcon sx={{ fontSize: 18 }} />}>
            <Typography variant="caption">
              {proxyHealth.recommendations[0]}
            </Typography>
          </Alert>
        )}
      </Paper>
    );
  };

  return (
    <Box sx={{ p: 3, height: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Beginner Welcome Banner */}
      <Collapse in={showBeginnerBanner && proxies.length === 0}>
        <Alert 
          severity="info" 
          sx={{ mb: 2 }}
          icon={<ScienceIcon />}
          action={
            <IconButton size="small" onClick={() => setShowBeginnerBanner(false)}>
              <CloseIcon fontSize="small" />
            </IconButton>
          }
        >
          <AlertTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography fontWeight="bold">Welcome to the MITM Workbench! 👋</Typography>
            <Chip label="Beginner Friendly" size="small" color="success" />
          </AlertTitle>
          <Typography variant="body2" sx={{ mb: 1 }}>
            Learn to intercept and analyze network traffic like a security professional. No experience required!
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
            <Button size="small" variant="contained" startIcon={<TutorialIcon />} onClick={handleOpenWizard}>
              Start Tutorial
            </Button>
            <Button size="small" variant="outlined" startIcon={<LearnIcon />} href="/learn/mitm">
              Read the Guide
            </Button>
            <Button size="small" variant="outlined" startIcon={<ScienceIcon />} onClick={() => setScenarioDialogOpen(true)}>
              Try a Test Scenario
            </Button>
          </Box>
        </Alert>
      </Collapse>

      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          {projectId && (
            <Tooltip title={`Back to ${projectName || 'Project'}`}>
              <IconButton
                onClick={() => navigate(`/projects/${projectId}`)}
                sx={{ mr: 1 }}
              >
                <BackIcon />
              </IconButton>
            </Tooltip>
          )}
          <SwapIcon sx={{ fontSize: 40, color: 'warning.main' }} />
          <Box>
            <Typography variant="h4" fontWeight="bold">
              Man-in-the-Middle Workbench
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Intercept, inspect, and modify HTTP/HTTPS traffic between components
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Pre-built security test scenarios">
            <Button
              variant="outlined"
              color="warning"
              startIcon={<ScienceIcon />}
              onClick={() => setScenarioDialogOpen(true)}
            >
              Test Scenarios
            </Button>
          </Tooltip>
          <Tooltip title="Step-by-step guide for beginners">
            <Button
              variant="outlined"
              color="info"
              startIcon={<TutorialIcon />}
              onClick={handleOpenWizard}
            >
              Getting Started
            </Button>
          </Tooltip>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setNewProxyOpen(true)}
          >
            New Proxy
          </Button>
        </Box>
      </Box>

      {/* Main content */}
      <Grid container spacing={2} sx={{ flex: 1, minHeight: 0 }}>
        {/* Proxy list sidebar */}
        <Grid item xs={12} md={3}>
          <Paper sx={{ height: '100%', overflow: 'auto' }}>
            <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
              <Typography variant="h6">Proxy Instances</Typography>
            </Box>
            <List>
              {proxies.length === 0 ? (
                <ListItem>
                  <ListItemText
                    primary="No proxies configured"
                    secondary="Create a new proxy to get started"
                  />
                </ListItem>
              ) : (
                proxies.map((proxy) => (
                  <ListItem
                    key={proxy.id}
                    button
                    selected={selectedProxy === proxy.id}
                    onClick={() => setSelectedProxy(proxy.id)}
                    sx={{
                      borderLeft: selectedProxy === proxy.id ? 4 : 0,
                      borderColor: 'primary.main',
                    }}
                  >
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          {proxy.tls_enabled ? <LockIcon fontSize="small" /> : <LockOpenIcon fontSize="small" />}
                          <Typography variant="subtitle2">{proxy.id}</Typography>
                        </Box>
                      }
                      secondary={
                        <Box sx={{ mt: 0.5 }}>
                          <Typography variant="caption" display="block">
                            {proxy.listen_host}:{proxy.listen_port} → {proxy.target_host}:{proxy.target_port}
                          </Typography>
                          <Box sx={{ display: 'flex', gap: 0.5, mt: 0.5 }}>
                            <Chip
                              label={proxy.running ? 'Running' : 'Stopped'}
                              size="small"
                              color={proxy.running ? 'success' : 'default'}
                            />
                            <Chip
                              label={proxy.mode}
                              size="small"
                              color={
                                proxy.mode === 'intercept' ? 'warning' :
                                proxy.mode === 'auto_modify' ? 'info' : 'default'
                              }
                            />
                          </Box>
                        </Box>
                      }
                    />
                    <ListItemSecondaryAction>
                      <IconButton
                        size="small"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleToggleProxy(proxy.id, proxy.running);
                        }}
                      >
                        {proxy.running ? <StopIcon color="error" /> : <PlayIcon color="success" />}
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
                ))
              )}
            </List>
            
            {/* Saved Sessions Panel */}
            <Box sx={{ borderTop: 1, borderColor: 'divider' }}>
              <Box 
                sx={{ 
                  p: 2, 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'space-between',
                  cursor: 'pointer',
                  '&:hover': { bgcolor: 'action.hover' }
                }}
                onClick={() => setSavedSessionsExpanded(!savedSessionsExpanded)}
              >
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <HistoryIcon fontSize="small" color="primary" />
                  <Typography variant="subtitle2">Saved Scans</Typography>
                  <Badge badgeContent={savedSessions.length} color="primary" max={99}>
                    <Box />
                  </Badge>
                </Box>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <Tooltip title={autoSaveEnabled ? 'Auto-save enabled' : 'Auto-save disabled'}>
                    <IconButton 
                      size="small" 
                      onClick={(e) => {
                        e.stopPropagation();
                        setAutoSaveEnabled(!autoSaveEnabled);
                      }}
                    >
                      {autoSaveEnabled ? <SuccessIcon fontSize="small" color="success" /> : <CancelIcon fontSize="small" color="disabled" />}
                    </IconButton>
                  </Tooltip>
                  <IconButton
                    size="small"
                    onClick={(e) => {
                      e.stopPropagation();
                      loadSavedSessions();
                    }}
                  >
                    <RefreshIcon fontSize="small" />
                  </IconButton>
                  <ExpandMoreIcon 
                    fontSize="small" 
                    sx={{ 
                      transform: savedSessionsExpanded ? 'rotate(180deg)' : 'rotate(0deg)',
                      transition: 'transform 0.2s'
                    }} 
                  />
                </Box>
              </Box>
              
              <Collapse in={savedSessionsExpanded}>
                {loadingSavedSessions ? (
                  <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
                    <CircularProgress size={20} />
                  </Box>
                ) : savedSessions.length === 0 ? (
                  <Box sx={{ px: 2, pb: 2 }}>
                    <Alert severity="info" sx={{ fontSize: '0.75rem' }}>
                      No saved scans yet. Stop a proxy to auto-save.
                    </Alert>
                  </Box>
                ) : (
                  <List dense sx={{ pt: 0, maxHeight: savedSessions.length > 4 ? 280 : 'none', overflow: savedSessions.length > 4 ? 'auto' : 'visible' }}>
                    {savedSessions.map((scan) => (
                      <ListItem
                        key={scan.id}
                        button
                        onClick={() => handleViewSavedScan(scan)}
                        sx={{
                          borderLeft: viewingSavedScan?.id === scan.id ? 3 : 0,
                          borderColor: 'secondary.main',
                          py: 0.5,
                        }}
                      >
                        <ListItemText
                          primary={
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, flexWrap: 'wrap' }}>
                              <Typography variant="caption" fontWeight="bold" noWrap sx={{ maxWidth: 120 }}>
                                {scan.title || `Scan #${scan.id}`}
                              </Typography>
                              <Chip
                                label={scan.risk_level}
                                size="small"
                                color={
                                  scan.risk_level === 'critical' ? 'error' :
                                  scan.risk_level === 'high' ? 'error' :
                                  scan.risk_level === 'medium' ? 'warning' : 'success'
                                }
                                variant={scan.risk_level === 'critical' ? 'filled' : 'outlined'}
                                sx={{ height: 16, fontSize: '0.65rem' }}
                              />
                            </Box>
                          }
                          secondary={
                            <Box sx={{ mt: 0.25 }}>
                              <Typography variant="caption" color="text.secondary" display="block">
                                {scan.target_host ? `${scan.target_host}:${scan.target_port}` : 'Unknown target'}
                              </Typography>
                              <Typography variant="caption" color="text.secondary" display="block">
                                {scan.created_at ? new Date(scan.created_at).toLocaleDateString() : 'Unknown date'} • {scan.findings_count} findings
                              </Typography>
                              {scan.auto_saved && !scan.project_id && (
                                <Chip
                                  label="Unassigned"
                                  size="small"
                                  variant="outlined"
                                  sx={{ height: 14, fontSize: '0.6rem', mt: 0.25 }}
                                />
                              )}
                            </Box>
                          }
                        />
                        <ListItemSecondaryAction>
                          <IconButton
                            size="small"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteSavedScan(scan.id);
                            }}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </ListItemSecondaryAction>
                      </ListItem>
                    ))}
                  </List>
                )}
              </Collapse>
            </Box>
          </Paper>
        </Grid>

        {/* Main workspace */}
        <Grid item xs={12} md={9}>
          {/* Traffic Flow Visualization - always visible when proxy selected */}
          {selectedProxy && currentProxy && <TrafficFlowVisualization />}
          
          {/* Health Check Panel - when proxy selected */}
          {selectedProxy && currentProxy && <HealthCheckPanel />}

          {/* AI-Powered Natural Language Rule Creation Panel */}
          {selectedProxy && currentProxy && (
            <Paper sx={{ p: 2, mb: 2, background: `linear-gradient(135deg, ${alpha(theme.palette.secondary.main, 0.05)} 0%, ${alpha(theme.palette.primary.main, 0.05)} 100%)` }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <AIIcon color="secondary" />
                  <Typography variant="subtitle1" fontWeight="bold">
                    Natural Language Rule Creation
                  </Typography>
                  <Chip label="AI-Powered" size="small" color="secondary" variant="outlined" />
                  {currentProxy.mode === 'auto_modify' ? (
                    <Chip label="Rules Active" size="small" color="success" variant="outlined" />
                  ) : (
                    <Tooltip title="Switch to Auto Modify mode for rules to take effect">
                      <Chip 
                        label={`Mode: ${currentProxy.mode}`} 
                        size="small" 
                        color="warning" 
                        variant="outlined"
                        onClick={() => handleChangeMode(selectedProxy, 'auto_modify')}
                        sx={{ cursor: 'pointer' }}
                      />
                    </Tooltip>
                  )}
                </Box>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Tooltip title="Get AI suggestions based on captured traffic">
                    <Button
                      variant="outlined"
                      size="small"
                      startIcon={aiSuggestionsLoading ? <CircularProgress size={16} /> : <IdeaIcon />}
                      onClick={handleLoadAiSuggestions}
                      disabled={aiSuggestionsLoading || traffic.length === 0}
                    >
                      AI Suggestions
                    </Button>
                  </Tooltip>
                </Box>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Describe what you want to do in plain English, and AI will create the rule for you.
              </Typography>
              <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start' }}>
                <TextField
                  fullWidth
                  variant="outlined"
                  placeholder="e.g., &quot;Block all requests to analytics.google.com&quot; or &quot;Add a 2 second delay to all API responses&quot; or &quot;Remove the Authorization header&quot;"
                  value={nlRuleInput}
                  onChange={(e) => setNlRuleInput(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleCreateNaturalLanguageRule()}
                  disabled={nlRuleLoading}
                  multiline
                  maxRows={2}
                  InputProps={{
                    startAdornment: <CodeIcon sx={{ mr: 1, color: 'text.secondary' }} />,
                  }}
                />
                <Button
                  variant="contained"
                  color="secondary"
                  startIcon={nlRuleLoading ? <CircularProgress size={20} color="inherit" /> : <AIIcon />}
                  onClick={handleCreateNaturalLanguageRule}
                  disabled={nlRuleLoading || !nlRuleInput.trim()}
                  sx={{ minWidth: 140, height: 56 }}
                >
                  {nlRuleLoading ? 'Creating...' : 'Create Rule'}
                </Button>
              </Box>
              
              {/* NL Rule Result */}
              {nlRuleResult && (
                <Fade in>
                  <Box sx={{ mt: 2, p: 2, bgcolor: nlRuleResult.success ? alpha(theme.palette.success.main, 0.1) : alpha(theme.palette.error.main, 0.1), borderRadius: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                      {nlRuleResult.success ? <SuccessIcon color="success" /> : <ErrorIcon color="error" />}
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="subtitle2" fontWeight="bold">
                          {nlRuleResult.success ? 'Rule Created!' : 'Could not create rule'}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {nlRuleResult.interpretation}
                        </Typography>
                        {nlRuleResult.rule && (
                          <Box sx={{ mt: 1, p: 1, bgcolor: 'background.paper', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem' }}>
                            <Typography variant="caption" color="text.secondary">Generated Rule:</Typography>
                            <Typography variant="body2">
                              Pattern: <code>{(nlRuleResult.rule as any)?.pattern || (nlRuleResult.rule as any)?.match_host || '.*'}</code>
                            </Typography>
                            <Typography variant="body2">
                              Action: <Chip label={(nlRuleResult.rule as any)?.action || 'modify'} size="small" />
                            </Typography>
                          </Box>
                        )}
                        {nlRuleResult.success && !nlRuleResult.applied && nlRuleResult.rule && (
                          <Button
                            variant="contained"
                            size="small"
                            color="success"
                            startIcon={<AddIcon />}
                            onClick={handleApplyNlRule}
                            sx={{ mt: 1 }}
                          >
                            Apply to Proxy
                          </Button>
                        )}
                        {nlRuleResult.applied && (
                          <Chip 
                            icon={<CheckIcon />} 
                            label="Applied to proxy" 
                            color="success" 
                            size="small"
                            sx={{ mt: 1 }}
                          />
                        )}
                      </Box>
                      <IconButton size="small" onClick={() => setNlRuleResult(null)}>
                        <CloseIcon fontSize="small" />
                      </IconButton>
                    </Box>
                  </Box>
                </Fade>
              )}
              
              {/* Example suggestions */}
              <Box sx={{ mt: 2 }}>
                <Typography variant="caption" color="text.secondary" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <TipIcon fontSize="small" /> Try these examples:
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1 }}>
                  {[
                    'Block all analytics tracking',
                    'Add 500ms delay to API calls',
                    'Remove cookies from all requests',
                    'Replace all prices with $0.00',
                    'Add X-Debug-Mode: true header'
                  ].map((example) => (
                    <Chip
                      key={example}
                      label={example}
                      size="small"
                      variant="outlined"
                      onClick={() => setNlRuleInput(example)}
                      sx={{ cursor: 'pointer', '&:hover': { bgcolor: alpha(theme.palette.primary.main, 0.1) } }}
                    />
                  ))}
                </Box>
              </Box>
            </Paper>
          )}

          {/* AI Suggestions Panel */}
          <Collapse in={showAiSuggestions && aiSuggestions.length > 0}>
            <Paper sx={{ p: 2, mb: 2, border: `2px solid ${theme.palette.info.main}`, borderRadius: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <IdeaIcon color="info" />
                  <Typography variant="subtitle1" fontWeight="bold">
                    AI Suggestions Based on Your Traffic
                  </Typography>
                  <Chip 
                    label={`${aiSuggestions.length} suggestions`} 
                    size="small" 
                    color="info"
                  />
                </Box>
                <IconButton size="small" onClick={() => setShowAiSuggestions(false)}>
                  <CloseIcon />
                </IconButton>
              </Box>
              
              {aiSuggestionsResponse?.traffic_summary && (
                <Box sx={{ mb: 2, p: 1.5, bgcolor: alpha(theme.palette.info.main, 0.05), borderRadius: 1 }}>
                  <Typography variant="caption" color="text.secondary" gutterBottom>
                    Traffic Analysis Summary:
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 0.5 }}>
                    <Chip label={`${aiSuggestionsResponse.traffic_summary.total_requests || 0} requests`} size="small" />
                    {aiSuggestionsResponse.traffic_summary.auth_detected && (
                      <Chip label="Auth Detected" size="small" color="warning" icon={<LockIcon />} />
                    )}
                    {aiSuggestionsResponse.traffic_summary.json_apis && (
                      <Chip label="JSON APIs" size="small" color="primary" icon={<CodeIcon />} />
                    )}
                    {aiSuggestionsResponse.traffic_summary.has_cookies && (
                      <Chip label="Cookies Present" size="small" color="secondary" />
                    )}
                  </Box>
                </Box>
              )}

              <Grid container spacing={2}>
                {aiSuggestions.map((suggestion) => (
                  <Grid item xs={12} md={6} key={suggestion.id}>
                    <Card 
                      variant="outlined"
                      sx={{ 
                        height: '100%',
                        borderColor: suggestion.priority === 'high' 
                          ? theme.palette.error.main 
                          : suggestion.priority === 'medium' 
                            ? theme.palette.warning.main 
                            : theme.palette.grey[300],
                        transition: 'transform 0.2s, box-shadow 0.2s',
                        '&:hover': { transform: 'translateY(-2px)', boxShadow: 2 }
                      }}
                    >
                      <CardContent sx={{ pb: 1 }}>
                        <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 1 }}>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            {suggestion.category === 'security' && <ShieldIcon color="error" fontSize="small" />}
                            {suggestion.category === 'performance' && <SpeedIcon color="warning" fontSize="small" />}
                            {suggestion.category === 'debug' && <DebugIcon color="info" fontSize="small" />}
                            {suggestion.category === 'learning' && <TutorialIcon color="success" fontSize="small" />}
                            <Typography variant="subtitle2" fontWeight="bold">
                              {suggestion.title}
                            </Typography>
                          </Box>
                          <Chip 
                            label={suggestion.priority} 
                            size="small"
                            color={suggestion.priority === 'high' ? 'error' : suggestion.priority === 'medium' ? 'warning' : 'default'}
                          />
                        </Box>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                          {suggestion.description}
                        </Typography>
                        {suggestion.natural_language && (
                          <Typography variant="caption" sx={{ fontStyle: 'italic', display: 'block', mb: 1 }}>
                            "{suggestion.natural_language}"
                          </Typography>
                        )}
                      </CardContent>
                      <CardActions sx={{ justifyContent: 'flex-end', pt: 0 }}>
                        {suggestion.natural_language && (
                          <Tooltip title="Use this as natural language input">
                            <Button 
                              size="small" 
                              onClick={() => handleUseSuggestionNL(suggestion)}
                            >
                              Use Text
                            </Button>
                          </Tooltip>
                        )}
                        {suggestion.rule && (
                          <Button 
                            size="small" 
                            variant="contained" 
                            color="primary"
                            startIcon={<AddIcon />}
                            onClick={() => handleApplyAiSuggestion(suggestion)}
                          >
                            Quick Apply
                          </Button>
                        )}
                      </CardActions>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Collapse>

          {selectedProxy && currentProxy ? (
            <Paper sx={{ height: 'calc(100% - 200px)', display: 'flex', flexDirection: 'column' }}>
              {/* Proxy header */}
              <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider', bgcolor: 'background.default' }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Box>
                    <Typography variant="h6">{currentProxy.id}</Typography>
                    <Typography variant="body2" color="text.secondary">
                      {currentProxy.listen_host}:{currentProxy.listen_port} → {currentProxy.target_host}:{currentProxy.target_port}
                    </Typography>
                  </Box>
                  <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                    <Tooltip title="AI-powered security analysis">
                      <Button
                        variant="outlined"
                        color="secondary"
                        startIcon={analyzingTraffic ? <CircularProgress size={20} /> : <AIIcon />}
                        onClick={handleAnalyzeTraffic}
                        disabled={analyzingTraffic || traffic.length === 0}
                        size="small"
                      >
                        Analyze
                      </Button>
                    </Tooltip>
                    <Tooltip title="Export report">
                      <Button
                        variant="outlined"
                        startIcon={exporting ? <CircularProgress size={20} /> : <DownloadIcon />}
                        onClick={(e) => setExportAnchorEl(e.currentTarget)}
                        disabled={exporting}
                        size="small"
                      >
                        Export
                      </Button>
                    </Tooltip>
                    <Menu
                      anchorEl={exportAnchorEl}
                      open={Boolean(exportAnchorEl)}
                      onClose={() => setExportAnchorEl(null)}
                    >
                      <MenuItem onClick={() => handleExportReport('markdown')}>
                        <ListItemIcon><MarkdownIcon fontSize="small" /></ListItemIcon>
                        <ListItemText>Markdown (.md)</ListItemText>
                      </MenuItem>
                      <MenuItem onClick={() => handleExportReport('pdf')}>
                        <ListItemIcon><PdfIcon fontSize="small" /></ListItemIcon>
                        <ListItemText>PDF Document</ListItemText>
                      </MenuItem>
                      <MenuItem onClick={() => handleExportReport('docx')}>
                        <ListItemIcon><WordIcon fontSize="small" /></ListItemIcon>
                        <ListItemText>Word Document (.docx)</ListItemText>
                      </MenuItem>
                    </Menu>
                    <FormControl size="small" sx={{ minWidth: 140 }}>
                      <InputLabel>Mode</InputLabel>
                      <Select
                        value={currentProxy.mode}
                        label="Mode"
                        onChange={(e) => handleChangeMode(currentProxy.id, e.target.value)}
                      >
                        <MenuItem value="passthrough">Passthrough</MenuItem>
                        <MenuItem value="intercept">Intercept</MenuItem>
                        <MenuItem value="auto_modify">Auto Modify</MenuItem>
                      </Select>
                    </FormControl>
                    <Button
                      variant={currentProxy.running ? 'outlined' : 'contained'}
                      color={currentProxy.running ? 'error' : 'success'}
                      startIcon={currentProxy.running ? <StopIcon /> : <PlayIcon />}
                      onClick={() => handleToggleProxy(currentProxy.id, currentProxy.running)}
                    >
                      {currentProxy.running ? 'Stop' : 'Start'}
                    </Button>
                    <IconButton color="error" onClick={() => handleDeleteProxy(currentProxy.id)}>
                      <DeleteIcon />
                    </IconButton>
                  </Box>
                </Box>

                {/* Stats */}
                <Box sx={{ display: 'flex', gap: 3, mt: 2 }}>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Requests</Typography>
                    <Typography variant="h6">{currentProxy.stats.requests}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Responses</Typography>
                    <Typography variant="h6">{currentProxy.stats.responses}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Sent</Typography>
                    <Typography variant="h6">{formatBytes(currentProxy.stats.bytes_sent)}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Received</Typography>
                    <Typography variant="h6">{formatBytes(currentProxy.stats.bytes_received)}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Errors</Typography>
                    <Typography variant="h6" color={currentProxy.stats.errors > 0 ? 'error.main' : 'inherit'}>
                      {currentProxy.stats.errors}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Rules Applied</Typography>
                    <Typography variant="h6">{currentProxy.stats.rules_applied}</Typography>
                  </Box>
                </Box>
              </Box>

              {/* AGENTIC TOOLS SECTION */}
              <Box sx={{ px: 3, mb: 2 }}>
                <Button 
                  fullWidth 
                  variant={showAgenticTools ? "contained" : "outlined"} 
                  color="error" 
                  onClick={() => setShowAgenticTools(!showAgenticTools)}
                  startIcon={<AIIcon />}
                  endIcon={showAgenticTools ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                  sx={{ justifyContent: 'space-between' }}
                >
                  Agentic Attack Tools {agenticSessionRunning && "(Running)"}
                </Button>
                <Collapse in={showAgenticTools}>
                  <Paper sx={{ p: 2, mt: 1, border: `1px solid ${theme.palette.error.main}` }}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    
                    {/* Header */}
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <Box>
                        <Typography variant="h6">AI-Powered Attack Tools</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Execute security tools with AI recommendations - findings are automatically added
                        </Typography>
                      </Box>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Button
                          variant="outlined"
                          startIcon={attackToolsLoading ? <CircularProgress size={16} /> : <RefreshIcon />}
                          onClick={() => {
                            loadAttackTools(selectedAttackCategory || undefined);
                            if (selectedProxy) {
                              loadAttackRecommendations(selectedProxy);
                              loadAttackExecutionLog(selectedProxy);
                              loadAgentStatus(selectedProxy);
                            }
                          }}
                          disabled={attackToolsLoading}
                        >
                          Refresh
                        </Button>
                        <FormControl size="small" sx={{ minWidth: 140 }}>
                          <InputLabel>Strategy</InputLabel>
                          <Select
                            value={phaseStrategy}
                            label="Strategy"
                            onChange={(e) => setPhaseStrategy(e.target.value)}
                            disabled={agenticSessionRunning}
                          >
                            <MenuItem value="progressive">Progressive (Recommended)</MenuItem>
                            <MenuItem value="passive_only">Passive Only</MenuItem>
                            <MenuItem value="aggressive">Aggressive</MenuItem>
                          </Select>
                        </FormControl>
                        <TextField
                          size="small"
                          type="number"
                          label="Max Tools"
                          value={maxAgenticTools}
                          onChange={(e) => setMaxAgenticTools(parseInt(e.target.value) || 15)}
                          sx={{ width: 90 }}
                          inputProps={{ min: 5, max: 25 }}
                          disabled={agenticSessionRunning}
                        />
                        <Button
                          variant="contained"
                          color="error"
                          startIcon={agenticSessionRunning ? <CircularProgress size={16} color="inherit" /> : <AIIcon />}
                          onClick={() => selectedProxy && runAgenticSession(selectedProxy, maxAgenticTools, phaseStrategy)}
                          disabled={!selectedProxy || agenticSessionRunning || !traffic.length}
                        >
                          {agenticSessionRunning ? 'Running...' : 'Run Agentic Session'}
                        </Button>
                      </Box>
                    </Box>

                    {/* Agent Control Panel */}
                    <Paper sx={{ p: 2, bgcolor: 'background.default', border: '1px solid', borderColor: 'divider' }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <AIIcon color="primary" />
                          <Typography variant="subtitle1" fontWeight="bold">Agent Control</Typography>
                          {agentMonitoringActive && (
                            <Chip 
                              label="MONITORING ACTIVE" 
                              size="small" 
                              color="success" 
                              sx={{ animation: 'pulse 2s infinite' }}
                            />
                          )}
                        </Box>
                        <Box sx={{ display: 'flex', gap: 1 }}>
                          <Button
                            variant="outlined"
                            size="small"
                            onClick={() => setShowGoalDialog(true)}
                            disabled={!selectedProxy}
                          >
                            Set Goals
                          </Button>
                          {agentMonitoringActive ? (
                            <Button
                              variant="contained"
                              color="warning"
                              size="small"
                              onClick={() => selectedProxy && handleStopMonitoring(selectedProxy)}
                            >
                              Stop Monitoring
                            </Button>
                          ) : (
                            <Button
                              variant="contained"
                              color="success"
                              size="small"
                              onClick={() => selectedProxy && handleStartMonitoring(selectedProxy)}
                              disabled={!selectedProxy || !traffic.length}
                            >
                              Start Auto-Monitor
                            </Button>
                          )}
                        </Box>
                      </Box>

                      {/* Goals Progress */}
                      {agentGoals.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="caption" color="text.secondary">Active Goals:</Typography>
                          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                            {agentGoals.map((goal, idx) => (
                              <Chip
                                key={idx}
                                label={goal.replace(/_/g, ' ')}
                                size="small"
                                color="primary"
                                variant="outlined"
                              />
                            ))}
                          </Box>
                        </Box>
                      )}

                      {/* Agent Status */}
                      {agentStatus && (
                        <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                          <Box>
                            <Typography variant="caption" color="text.secondary">Findings</Typography>
                            <Typography variant="h6">{agentStatus.findings_count || 0}</Typography>
                          </Box>
                          <Box>
                            <Typography variant="caption" color="text.secondary">Credentials</Typography>
                            <Typography variant="h6" color="error.main">
                              {agentStatus.captured_data_summary?.credentials || 0}
                            </Typography>
                          </Box>
                          <Box>
                            <Typography variant="caption" color="text.secondary">Tokens</Typography>
                            <Typography variant="h6" color="warning.main">
                              {agentStatus.captured_data_summary?.tokens || 0}
                            </Typography>
                          </Box>
                          <Box>
                            <Typography variant="caption" color="text.secondary">Auto-Execute Threshold</Typography>
                            <Typography variant="h6">
                              {((agentStatus.confidence_thresholds?.auto_execute || 0.7) * 100).toFixed(0)}%
                            </Typography>
                          </Box>
                        </Box>
                      )}

                      {/* Goal Progress */}
                      {agentGoalProgress?.goals?.length > 0 && (
                        <Box sx={{ mt: 2 }}>
                          <Typography variant="caption" color="text.secondary">Goal Progress:</Typography>
                          {agentGoalProgress.goals.map((g: any, idx: number) => (
                            <Box key={idx} sx={{ mt: 1 }}>
                              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                                <Typography variant="body2">{g.goal}</Typography>
                                <Typography variant="body2">{g.completion.toFixed(0)}%</Typography>
                              </Box>
                              <LinearProgress 
                                variant="determinate" 
                                value={g.completion} 
                                color={g.completion >= 100 ? 'success' : 'primary'}
                              />
                            </Box>
                          ))}
                        </Box>
                      )}
                    </Paper>

                    {/* Mode Warning */}
                    {currentProxy && currentProxy.mode !== 'auto_modify' && (
                      <Alert severity="warning" sx={{ mt: 1 }}>
                        <AlertTitle>Limited Functionality</AlertTitle>
                        Current mode is <strong>{currentProxy.mode}</strong>. Some attack tools require 
                        <strong> auto_modify</strong> mode to actively inject payloads. 
                        Analysis-only tools will still work.
                      </Alert>
                    )}

                    {!traffic.length && (
                      <Alert severity="info">
                        <AlertTitle>No Traffic Captured</AlertTitle>
                        Start capturing traffic first. Attack tools analyze traffic patterns to recommend and execute appropriate attacks.
                      </Alert>
                    )}

                    {/* AI Recommendations Section */}
                    <Accordion defaultExpanded>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <AIIcon color="primary" />
                          <Typography variant="subtitle1">
                            AI Recommendations ({attackRecommendations.length})
                          </Typography>
                          {recommendationsLoading && <CircularProgress size={16} />}
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        {attackRecommendations.length === 0 ? (
                          <Box sx={{ textAlign: 'center', py: 2 }}>
                            <Typography variant="body2" color="text.secondary">
                              {recommendationsLoading ? 'Analyzing traffic for recommendations...' : 
                               'Click "Refresh" to get AI recommendations based on captured traffic'}
                            </Typography>
                            {!recommendationsLoading && selectedProxy && traffic.length > 0 && (
                              <Button
                                variant="outlined"
                                startIcon={<AIIcon />}
                                onClick={() => loadAttackRecommendations(selectedProxy)}
                                sx={{ mt: 1 }}
                              >
                                Get AI Recommendations
                              </Button>
                            )}
                          </Box>
                        ) : (
                          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                            {attackRecommendations.map((rec: MITMToolRecommendation, idx: number) => (
                              <Paper key={idx} variant="outlined" sx={{ p: 2 }}>
                                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
                                  <Box>
                                    <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>
                                      {rec.tool_name}
                                    </Typography>
                                    <Chip 
                                      label={`${Math.round(rec.confidence * 100)}% confidence`}
                                      size="small"
                                      color={rec.confidence > 0.8 ? 'success' : rec.confidence > 0.5 ? 'warning' : 'default'}
                                      sx={{ mt: 0.5 }}
                                    />
                                  </Box>
                                  <Button
                                    variant="contained"
                                    size="small"
                                    color="error"
                                    startIcon={executingTool === rec.tool_id ? <CircularProgress size={14} color="inherit" /> : <PlayIcon />}
                                    onClick={() => selectedProxy && executeAttackTool(selectedProxy, rec.tool_id)}
                                    disabled={!selectedProxy || executingTool === rec.tool_id}
                                  >
                                    Execute
                                  </Button>
                                </Box>
                                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                  {rec.reason}
                                </Typography>
                                <Typography variant="body2" sx={{ fontStyle: 'italic' }}>
                                  <strong>Expected Impact:</strong> {rec.expected_impact}
                                </Typography>
                                {rec.risk_warning && (
                                  <Alert severity="warning" sx={{ mt: 1, py: 0 }}>
                                    {rec.risk_warning}
                                  </Alert>
                                )}
                              </Paper>
                            ))}
                          </Box>
                        )}
                      </AccordionDetails>
                    </Accordion>

                    {/* Available Tools Section */}
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <DebugIcon />
                          <Typography variant="subtitle1">
                            All Attack Tools ({attackTools.length})
                          </Typography>
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        {/* Category Filter */}
                        <Box sx={{ mb: 2 }}>
                          <FormControl size="small" sx={{ minWidth: 200 }}>
                            <InputLabel>Filter by Category</InputLabel>
                            <Select
                              value={selectedAttackCategory}
                              onChange={(e) => {
                                setSelectedAttackCategory(e.target.value);
                                loadAttackTools(e.target.value || undefined);
                              }}
                              label="Filter by Category"
                            >
                              <MenuItem value="">All Categories</MenuItem>
                              {attackToolCategories.map((cat) => (
                                <MenuItem key={cat} value={cat}>{cat.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</MenuItem>
                              ))}
                            </Select>
                          </FormControl>
                        </Box>

                        {attackToolsLoading ? (
                          <Box sx={{ textAlign: 'center', py: 2 }}>
                            <CircularProgress size={24} />
                            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                              Loading tools...
                            </Typography>
                          </Box>
                        ) : attackTools.length === 0 ? (
                          <Typography variant="body2" color="text.secondary">
                            No attack tools available. Click Refresh to load.
                          </Typography>
                        ) : (
                          <Grid container spacing={2}>
                            {attackTools.map((tool: MITMAttackTool) => (
                              <Grid item xs={12} md={6} key={tool.id}>
                                <Card variant="outlined">
                                  <CardContent sx={{ pb: 1 }}>
                                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
                                      <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>
                                        {tool.name}
                                      </Typography>
                                      <Chip 
                                        label={tool.risk_level} 
                                        size="small"
                                        color={
                                          tool.risk_level === 'critical' ? 'error' :
                                          tool.risk_level === 'high' ? 'warning' :
                                          tool.risk_level === 'medium' ? 'info' : 'default'
                                        }
                                      />
                                    </Box>
                                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1, minHeight: 40 }}>
                                      {tool.description}
                                    </Typography>
                                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 1 }}>
                                      <Chip label={tool.category.replace(/_/g, ' ')} size="small" variant="outlined" />
                                      <Chip label={tool.execution_type} size="small" variant="outlined" color="secondary" />
                                    </Box>
                                    <Typography variant="caption" color="text.secondary">
                                      <strong>Expected findings:</strong> {tool.expected_findings?.slice(0, 2).join(', ')}
                                      {tool.expected_findings?.length > 2 && '...'}
                                    </Typography>
                                  </CardContent>
                                  <CardActions sx={{ pt: 0 }}>
                                    <Button
                                      size="small"
                                      color="error"
                                      startIcon={executingTool === tool.id ? <CircularProgress size={14} /> : <PlayIcon />}
                                      onClick={() => selectedProxy && executeAttackTool(selectedProxy, tool.id)}
                                      disabled={!selectedProxy || executingTool === tool.id}
                                    >
                                      Execute
                                    </Button>
                                    <Tooltip title={`Triggers: ${tool.triggers?.join(', ')}`}>
                                      <IconButton size="small">
                                        <InfoIcon fontSize="small" />
                                      </IconButton>
                                    </Tooltip>
                                  </CardActions>
                                </Card>
                              </Grid>
                            ))}
                          </Grid>
                        )}
                      </AccordionDetails>
                    </Accordion>

                    {/* Execution Results Section */}
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <HistoryIcon />
                          <Typography variant="subtitle1">
                            Execution Results ({toolExecutionResults.length})
                          </Typography>
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        {toolExecutionResults.length === 0 ? (
                          <Typography variant="body2" color="text.secondary">
                            No tools executed yet. Execute a tool or run an agentic session to see results.
                          </Typography>
                        ) : (
                          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                            {toolExecutionResults.map((result: any, idx: number) => (
                              <Paper key={idx} variant="outlined" sx={{ p: 2 }}>
                                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                    {result.success ? (
                                      <SuccessIcon color="success" />
                                    ) : (
                                      <ErrorIcon color="error" />
                                    )}
                                    <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>
                                      {result.tool_id}
                                    </Typography>
                                  </Box>
                                  <Typography variant="caption" color="text.secondary">
                                    {result.execution_time?.toFixed(2)}s | {result.findings?.length || 0} findings
                                  </Typography>
                                </Box>
                                <Typography variant="body2" sx={{ mb: 1 }}>
                                  {result.summary}
                                </Typography>
                                {result.captured_data && (
                                  (result.captured_data.credentials?.length || 0) > 0 ||
                                  (result.captured_data.tokens?.length || 0) > 0 ||
                                  (result.captured_data.cookies?.length || 0) > 0
                                ) && (
                                  <Alert severity="error" sx={{ mt: 1 }}>
                                    <AlertTitle>Captured Sensitive Data</AlertTitle>
                                    {result.captured_data?.credentials?.length > 0 && (
                                      <Typography variant="body2">• {result.captured_data.credentials.length} credentials captured</Typography>
                                    )}
                                    {result.captured_data?.tokens?.length > 0 && (
                                      <Typography variant="body2">• {result.captured_data.tokens.length} tokens captured</Typography>
                                    )}
                                    {result.captured_data?.cookies?.length > 0 && (
                                      <Typography variant="body2">• {result.captured_data.cookies.length} session cookies captured</Typography>
                                    )}
                                  </Alert>
                                )}
                                {result.errors && result.errors.length > 0 && (
                                  <Alert severity="warning" sx={{ mt: 1 }}>
                                    {result.errors.join(', ')}
                                  </Alert>
                                )}
                              </Paper>
                            ))}
                          </Box>
                        )}
                      </AccordionDetails>
                    </Accordion>

                    {/* Execution Log Section */}
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <DescriptionIcon />
                          <Typography variant="subtitle1">
                            Execution Log ({attackToolExecutionLog.length})
                          </Typography>
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        {attackToolExecutionLog.length === 0 ? (
                          <Typography variant="body2" color="text.secondary">
                            No execution history for this proxy.
                          </Typography>
                        ) : (
                          <TableContainer>
                            <Table size="small">
                              <TableHead>
                                <TableRow>
                                  <TableCell>Time</TableCell>
                                  <TableCell>Tool</TableCell>
                                  <TableCell>Status</TableCell>
                                  <TableCell>Findings</TableCell>
                                  <TableCell>Duration</TableCell>
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {attackToolExecutionLog.map((log: any, idx: number) => (
                                  <TableRow key={idx}>
                                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                                      {new Date(log.timestamp).toLocaleTimeString()}
                                    </TableCell>
                                    <TableCell>{log.tool_name}</TableCell>
                                    <TableCell>
                                      {log.success ? (
                                        <Chip label="Success" size="small" color="success" />
                                      ) : (
                                        <Tooltip title={log.error || 'Failed'}>
                                          <Chip label="Failed" size="small" color="error" />
                                        </Tooltip>
                                      )}
                                    </TableCell>
                                    <TableCell>{log.findings_count}</TableCell>
                                    <TableCell>{log.execution_time?.toFixed(2)}s</TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </TableContainer>
                        )}
                      </AccordionDetails>
                    </Accordion>
                    
                  </Box>
                  </Paper>
                </Collapse>
              </Box>

              {/* Attack Phase Indicator */}
              {showPhaseIndicator && selectedProxy && attackPhases.length > 0 && (
                <Box sx={{ px: 2, pt: 1 }}>
                  <MitmAttackPhaseIndicator
                    phases={attackPhases}
                    currentPhase={currentPhase}
                    progress={phaseProgress}
                    onPhaseClick={(phase) => handleSetPhase(selectedProxy, phase)}
                  />
                </Box>
              )}

              {/* Saved Reports Panel - Shows historical analysis data */}
              {projectId && savedReports.length > 0 && (
                <Box sx={{ px: 2, pb: 1 }}>
                  <Accordion defaultExpanded={!selectedProxy}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <HistoryIcon color="primary" />
                        <Typography variant="subtitle2">
                          Saved Analysis Reports ({savedReports.length})
                        </Typography>
                        {viewingHistoricalData && selectedReport && (
                          <Chip
                            label={`Viewing: ${selectedReport.title}`}
                            size="small"
                            color="info"
                            onDelete={clearHistoricalView}
                          />
                        )}
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: 'block' }}>
                        Click a report to load its phases, MITRE mapping, chains, and reasoning data.
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                        {savedReports.map((report) => (
                          <Chip
                            key={report.id}
                            label={
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                <span>{report.title || `Report #${report.id}`}</span>
                                <Chip
                                  label={report.risk_level}
                                  size="small"
                                  color={
                                    report.risk_level === 'critical' ? 'error' :
                                    report.risk_level === 'high' ? 'warning' :
                                    report.risk_level === 'medium' ? 'info' : 'default'
                                  }
                                  sx={{ ml: 0.5, height: 16, fontSize: '0.65rem' }}
                                />
                              </Box>
                            }
                            variant={selectedReport?.id === report.id ? 'filled' : 'outlined'}
                            color={selectedReport?.id === report.id ? 'primary' : 'default'}
                            onClick={() => handleSelectSavedReport(report)}
                            sx={{ cursor: 'pointer' }}
                          />
                        ))}
                      </Box>
                      {viewingHistoricalData && (
                        <Alert severity="info" sx={{ mt: 1 }}>
                          Viewing historical data from saved report. The data shown in Phases, Chains, MITRE, and Memory/Reasoning tabs is from this saved analysis.
                          <Button size="small" onClick={clearHistoricalView} sx={{ ml: 1 }}>
                            Return to Live Data
                          </Button>
                        </Alert>
                      )}
                    </AccordionDetails>
                  </Accordion>
                </Box>
              )}

              {/* Quick Action Buttons for Aggressive Mode */}
              {selectedProxy && (
                <Box sx={{ px: 2, pb: 1, display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  <Button
                    variant="contained"
                    color="error"
                    size="small"
                    startIcon={<SecurityIcon />}
                    onClick={() => handleRunAggressiveSession(selectedProxy)}
                    disabled={loading || viewingHistoricalData}
                  >
                    Aggressive Attack Session
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => {
                      if (viewingHistoricalData) {
                        clearHistoricalView();
                      }
                      loadAttackPhases(selectedProxy);
                    }}
                    disabled={phaseLoading}
                  >
                    {phaseLoading ? 'Loading...' : viewingHistoricalData ? 'Load Live Phases' : 'Refresh Phases'}
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => {
                      if (viewingHistoricalData) {
                        clearHistoricalView();
                      }
                      loadAttackChains(selectedProxy);
                    }}
                  >
                    {viewingHistoricalData ? 'Load Live Chains' : 'Load Chains'}
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => {
                      if (viewingHistoricalData) {
                        clearHistoricalView();
                      }
                      loadMitreMapping(selectedProxy);
                    }}
                  >
                    {viewingHistoricalData ? 'Load Live MITRE' : 'MITRE Mapping'}
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => {
                      if (viewingHistoricalData) {
                        clearHistoricalView();
                      }
                      loadAgentMemory(selectedProxy);
                      loadReasoningChains(selectedProxy);
                    }}
                  >
                    {viewingHistoricalData ? 'Load Live Memory' : 'Memory/Reasoning'}
                  </Button>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={showPhaseIndicator}
                        onChange={(e) => setShowPhaseIndicator(e.target.checked)}
                        size="small"
                      />
                    }
                    label="Show Phases"
                    sx={{ ml: 'auto' }}
                  />
                </Box>
              )}

              {/* Attack Chains Panel */}
              {selectedProxy && attackChains.length > 0 && (
                <Accordion sx={{ mx: 2, mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <RouteIcon color="warning" />
                      <Typography variant="subtitle2">Attack Chains</Typography>
                      <Chip label={attackChains.length} size="small" color="warning" />
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Grid container spacing={1}>
                      {attackChains.map((chain) => (
                        <Grid item xs={12} sm={6} md={4} key={chain.chain_id}>
                          <Card variant="outlined" sx={{ bgcolor: 'rgba(255,152,0,0.1)' }}>
                            <CardContent sx={{ py: 1, '&:last-child': { pb: 1 } }}>
                              <Typography variant="subtitle2" fontWeight="bold">{chain.name}</Typography>
                              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                                {chain.description}
                              </Typography>
                              <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 0.5 }}>
                                {chain.triggers.map((trigger, i) => (
                                  <Chip key={i} label={trigger} size="small" variant="outlined" sx={{ fontSize: '0.65rem', height: 18 }} />
                                ))}
                              </Box>
                              <Typography variant="caption" sx={{ display: 'block' }}>
                                {chain.steps.length} steps | Risk: <span style={{ color: chain.risk_level === 'critical' ? '#f44336' : '#ff9800' }}>{chain.risk_level}</span>
                              </Typography>
                            </CardContent>
                            <CardActions sx={{ pt: 0, pb: 1 }}>
                              <Button
                                size="small"
                                variant="contained"
                                color="warning"
                                onClick={() => handleExecuteChain(selectedProxy, chain.chain_id)}
                                startIcon={<PlayIcon />}
                              >
                                Execute
                              </Button>
                            </CardActions>
                          </Card>
                        </Grid>
                      ))}
                    </Grid>
                    {chainStats && (
                      <Box sx={{ mt: 2, pt: 1, borderTop: '1px solid rgba(255,255,255,0.1)' }}>
                        <Typography variant="caption" color="text.secondary">
                          Stats: {chainStats.total_executed || 0} chains executed | {chainStats.successful || 0} successful
                        </Typography>
                      </Box>
                    )}
                  </AccordionDetails>
                </Accordion>
              )}

              {/* MITRE ATT&CK Mapping Panel */}
              {selectedProxy && mitreMapping && (
                <Accordion sx={{ mx: 2, mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <ShieldIcon color="error" />
                      <Typography variant="subtitle2">MITRE ATT&CK Mapping</Typography>
                      <Chip label={Object.keys(mitreMapping.techniques_used || {}).length} size="small" color="error" />
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Grid container spacing={1}>
                      {Object.entries(mitreMapping.techniques_used || {}).map(([techniqueId, data]: [string, any]) => (
                        <Grid item xs={12} sm={6} md={4} key={techniqueId}>
                          <Card variant="outlined" sx={{ bgcolor: 'rgba(244,67,54,0.1)' }}>
                            <CardContent sx={{ py: 1, '&:last-child': { pb: 1 } }}>
                              <Typography variant="subtitle2" fontWeight="bold" sx={{ color: '#f44336' }}>
                                {techniqueId}
                              </Typography>
                              <Typography variant="caption" sx={{ display: 'block' }}>
                                {data.name || 'Unknown Technique'}
                              </Typography>
                              <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
                                Tactic: {data.tactic || 'Unknown'}
                              </Typography>
                              {data.tools_used && (
                                <Box sx={{ mt: 0.5 }}>
                                  {data.tools_used.map((tool: string, i: number) => (
                                    <Chip key={i} label={tool} size="small" sx={{ fontSize: '0.6rem', height: 16, mr: 0.5 }} />
                                  ))}
                                </Box>
                              )}
                            </CardContent>
                          </Card>
                        </Grid>
                      ))}
                    </Grid>
                    {mitreMapping.attack_narrative && (
                      <Box sx={{ mt: 2, p: 1, bgcolor: 'rgba(244,67,54,0.05)', borderRadius: 1 }}>
                        <Typography variant="caption" fontWeight="bold" sx={{ display: 'block', mb: 0.5 }}>
                          Attack Narrative
                        </Typography>
                        <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                          {mitreMapping.attack_narrative}
                        </Typography>
                      </Box>
                    )}
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Agent Memory & Reasoning Panel */}
              {selectedProxy && (agentMemory || reasoningChains.length > 0) && (
                <Accordion sx={{ mx: 2, mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <AIIcon color="info" />
                      <Typography variant="subtitle2">Agent Memory & Reasoning</Typography>
                      {agentMemory && (
                        <Chip label={`${agentMemory.total_memories || 0} memories`} size="small" color="info" />
                      )}
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    {agentMemory && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" gutterBottom>Memory Statistics</Typography>
                        <Grid container spacing={1}>
                          <Grid item xs={6} sm={3}>
                            <Paper sx={{ p: 1, textAlign: 'center', bgcolor: 'rgba(33,150,243,0.1)' }}>
                              <Typography variant="h6">{agentMemory.total_memories || 0}</Typography>
                              <Typography variant="caption">Memories</Typography>
                            </Paper>
                          </Grid>
                          <Grid item xs={6} sm={3}>
                            <Paper sx={{ p: 1, textAlign: 'center', bgcolor: 'rgba(76,175,80,0.1)' }}>
                              <Typography variant="h6">{agentMemory.successful_attacks || 0}</Typography>
                              <Typography variant="caption">Successful</Typography>
                            </Paper>
                          </Grid>
                          <Grid item xs={6} sm={3}>
                            <Paper sx={{ p: 1, textAlign: 'center', bgcolor: 'rgba(255,152,0,0.1)' }}>
                              <Typography variant="h6">{agentMemory.tools_learned || 0}</Typography>
                              <Typography variant="caption">Tools Learned</Typography>
                            </Paper>
                          </Grid>
                          <Grid item xs={6} sm={3}>
                            <Paper sx={{ p: 1, textAlign: 'center', bgcolor: 'rgba(156,39,176,0.1)' }}>
                              <Typography variant="h6">{(agentMemory.avg_effectiveness * 100 || 0).toFixed(0)}%</Typography>
                              <Typography variant="caption">Avg Effectiveness</Typography>
                            </Paper>
                          </Grid>
                        </Grid>
                        {agentMemory.top_performing_tools && agentMemory.top_performing_tools.length > 0 && (
                          <Box sx={{ mt: 1 }}>
                            <Typography variant="caption" color="text.secondary">Top Tools:</Typography>
                            <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mt: 0.5 }}>
                              {agentMemory.top_performing_tools.map((tool: string, i: number) => (
                                <Chip key={i} label={tool} size="small" color="success" variant="outlined" />
                              ))}
                            </Box>
                          </Box>
                        )}
                      </Box>
                    )}
                    {reasoningChains.length > 0 && (
                      <Box>
                        <Typography variant="subtitle2" gutterBottom>Recent Reasoning Chains</Typography>
                        <List dense sx={{ maxHeight: 200, overflow: 'auto' }}>
                          {reasoningChains.slice(0, 5).map((chain: any, idx: number) => (
                            <ListItem key={idx} sx={{ py: 0.5 }}>
                              <ListItemIcon sx={{ minWidth: 32 }}>
                                <IdeaIcon fontSize="small" color="primary" />
                              </ListItemIcon>
                              <ListItemText
                                primary={chain.decision || chain.tool_selected || 'Decision'}
                                secondary={
                                  <>
                                    <Typography variant="caption" component="span">
                                      Confidence: {((chain.confidence || 0) * 100).toFixed(0)}%
                                    </Typography>
                                    {chain.reasoning && (
                                      <Typography variant="caption" component="div" sx={{ color: 'text.secondary', mt: 0.5 }}>
                                        {chain.reasoning.slice(0, 100)}...
                                      </Typography>
                                    )}
                                  </>
                                }
                              />
                            </ListItem>
                          ))}
                        </List>
                        <Button
                          size="small"
                          onClick={() => loadReasoningChains(selectedProxy)}
                          sx={{ mt: 1 }}
                        >
                          Load More
                        </Button>
                      </Box>
                    )}
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Tabs */}
              <Tabs
                value={tabValue}
                onChange={(_, v) => setTabValue(v)}
                variant="scrollable"
                scrollButtons="auto"
                allowScrollButtonsMobile
                sx={{ px: 2, borderBottom: 1, borderColor: 'divider' }}
              >
                <Tab label="Traffic Log" icon={<HttpIcon />} iconPosition="start" />
                <Tab label="Interception Rules" icon={<RuleIcon />} iconPosition="start" />
                <Tab label="Preset Rules" icon={<SecurityIcon />} iconPosition="start" />
                <Tab 
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      AI Analysis
                      {analysisResult && (
                        <Chip 
                          label={analysisResult.risk_level} 
                          size="small" 
                          sx={{ 
                            bgcolor: getRiskLevelColor(analysisResult.risk_level),
                            color: 'white',
                            height: 20,
                            fontSize: '0.7rem',
                          }} 
                        />
                      )}
                    </Box>
                  } 
                  icon={<AIIcon />} 
                  iconPosition="start" 
                />
                <Tab 
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      WebSocket
                      {wsConnections.length > 0 && (
                        <Chip 
                          label={wsConnections.filter(c => c.status === 'active').length} 
                          size="small" 
                          color="primary"
                          sx={{ height: 20, fontSize: '0.7rem' }} 
                        />
                      )}
                    </Box>
                  }
                  icon={<SwapIcon />}
                  iconPosition="start"
                />
                <Tab 
                  label="Certificates"
                  icon={<LockIcon />}
                  iconPosition="start"
                />
                <Tab 
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      Templates
                      {templates.length > 0 && (
                        <Chip 
                          label={templates.length} 
                          size="small" 
                          sx={{ height: 20, fontSize: '0.7rem' }} 
                        />
                      )}
                    </Box>
                  }
                  icon={<RuleIcon />}
                  iconPosition="start"
                />
                <Tab 
                  label="HTTP/2 & gRPC"
                  icon={<SpeedIcon />}
                  iconPosition="start"
                />
              </Tabs>

              {/* Tab panels */}
              <Box sx={{ flex: 1, overflow: 'auto' }}>
                {/* Traffic Log Tab */}
                <TabPanel value={tabValue} index={0}>
                  <Box sx={{ mb: 2 }}>
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center', mb: 1 }}>
                      <FormControlLabel
                        control={
                          <Switch
                            checked={liveStreamEnabled}
                            onChange={(e) => setLiveStreamEnabled(e.target.checked)}
                            disabled={!selectedProxy || Boolean(activeSession)}
                          />
                        }
                        label={
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            Live Stream
                            {liveStreamEnabled && (
                              <Chip
                                size="small"
                                color={wsConnected ? 'success' : 'warning'}
                                icon={wsConnected ? <WifiIcon /> : <WifiOffIcon />}
                                label={wsConnected ? 'Connected' : 'Connecting'}
                              />
                            )}
                          </Box>
                        }
                      />
                      {wsError && (
                        <Tooltip title={wsError}>
                          <Chip size="small" color="error" label="Stream error" />
                        </Tooltip>
                      )}
                      <FormControlLabel
                        control={
                          <Switch
                            checked={autoRefresh}
                            onChange={(e) => setAutoRefresh(e.target.checked)}
                            disabled={liveStreamEnabled || Boolean(activeSession)}
                          />
                        }
                        label="Auto Refresh"
                      />
                      <Button
                        size="small"
                        startIcon={<RefreshIcon />}
                        onClick={loadTraffic}
                        disabled={Boolean(activeSession)}
                      >
                        Refresh
                      </Button>
                      <Button
                        size="small"
                        startIcon={<ClearIcon />}
                        onClick={handleClearTraffic}
                        disabled={Boolean(activeSession)}
                      >
                        Clear
                      </Button>
                      <Button
                        size="small"
                        startIcon={<DownloadIcon />}
                        onClick={(e) => setTrafficExportAnchorEl(e.currentTarget)}
                        disabled={traffic.length === 0 || trafficExporting}
                      >
                        Export
                      </Button>
                      <Button
                        size="small"
                        startIcon={<HistoryIcon />}
                        onClick={handleOpenSessions}
                        disabled={!selectedProxy}
                      >
                        Sessions
                      </Button>
                      <Menu
                        anchorEl={trafficExportAnchorEl}
                        open={Boolean(trafficExportAnchorEl)}
                        onClose={() => setTrafficExportAnchorEl(null)}
                      >
                        <MenuItem onClick={() => exportTraffic('json')}>
                          <ListItemIcon>
                            <MarkdownIcon fontSize="small" />
                          </ListItemIcon>
                          JSON
                        </MenuItem>
                        <MenuItem onClick={() => exportTraffic('pcap')}>
                          <ListItemIcon>
                            <NetworkIcon fontSize="small" />
                          </ListItemIcon>
                          PCAP
                        </MenuItem>
                      </Menu>
                    </Box>

                    {activeSession && (
                      <Alert
                        severity="info"
                        sx={{ mb: 1 }}
                        action={
                          <Button color="inherit" size="small" onClick={handleExitSession}>
                            Back to live
                          </Button>
                        }
                      >
                        Viewing session: {activeSession.name} - {activeSession.entries} entries
                      </Alert>
                    )}

                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
                      <TextField
                        size="small"
                        placeholder="Search path, host, headers, body"
                        value={trafficSearch}
                        onChange={(e) => setTrafficSearch(e.target.value)}
                        sx={{ minWidth: 240 }}
                        InputProps={{
                          startAdornment: (
                            <InputAdornment position="start">
                              <SearchIcon fontSize="small" />
                            </InputAdornment>
                          ),
                        }}
                      />
                      <FormControl size="small" sx={{ minWidth: 140 }}>
                        <InputLabel>Method</InputLabel>
                        <Select
                          multiple
                          value={trafficMethodFilter}
                          onChange={(e) => {
                            const value = e.target.value as string[];
                            setTrafficMethodFilter(value);
                          }}
                          renderValue={(selected) => (selected as string[]).join(', ') || 'All'}
                          label="Method"
                        >
                          {uniqueMethods.length === 0 && (
                            <MenuItem disabled value="">
                              <ListItemText primary="No methods yet" />
                            </MenuItem>
                          )}
                          {uniqueMethods.map((method) => (
                            <MenuItem key={method} value={method}>
                              <Checkbox checked={trafficMethodFilter.indexOf(method) > -1} />
                              <ListItemText primary={method} />
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                      <FormControl size="small" sx={{ minWidth: 130 }}>
                        <InputLabel>Status</InputLabel>
                        <Select
                          value={trafficStatusFilter}
                          label="Status"
                          onChange={(e) => setTrafficStatusFilter(e.target.value as string)}
                        >
                          <MenuItem value="all">All</MenuItem>
                          <MenuItem value="2xx">2xx Success</MenuItem>
                          <MenuItem value="3xx">3xx Redirect</MenuItem>
                          <MenuItem value="4xx">4xx Client</MenuItem>
                          <MenuItem value="5xx">5xx Server</MenuItem>
                          <MenuItem value="pending">Pending</MenuItem>
                        </Select>
                      </FormControl>
                      <FormControl size="small" sx={{ minWidth: 160 }}>
                        <InputLabel>Host</InputLabel>
                        <Select
                          value={trafficHostFilter}
                          label="Host"
                          onChange={(e) => setTrafficHostFilter(e.target.value as string)}
                        >
                          <MenuItem value="all">All hosts</MenuItem>
                          {uniqueHosts.map((host) => (
                            <MenuItem key={host} value={host}>{host}</MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                      <FormControl size="small" sx={{ minWidth: 120 }}>
                        <InputLabel>Sort</InputLabel>
                        <Select
                          value={trafficSort}
                          label="Sort"
                          onChange={(e) => setTrafficSort(e.target.value as 'newest' | 'oldest')}
                        >
                          <MenuItem value="newest">Newest</MenuItem>
                          <MenuItem value="oldest">Oldest</MenuItem>
                        </Select>
                      </FormControl>
                      <FormControlLabel
                        control={
                          <Switch
                            checked={trafficModifiedOnly}
                            onChange={(e) => setTrafficModifiedOnly(e.target.checked)}
                          />
                        }
                        label="Modified only"
                      />
                      <FormControlLabel
                        control={
                          <Switch
                            checked={trafficWithResponseOnly}
                            onChange={(e) => setTrafficWithResponseOnly(e.target.checked)}
                          />
                        }
                        label="With response"
                      />
                    </Box>

                    <Box sx={{ mt: 1, display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      <Chip label={`${trafficSummary.total} total`} size="small" />
                      {hasActiveTrafficFilters && (
                        <Chip label={`${filteredTraffic.length} shown`} size="small" color="info" />
                      )}
                      <Chip
                        label={`${trafficSummary.errors} errors`}
                        size="small"
                        color={trafficSummary.errors > 0 ? 'warning' : 'default'}
                      />
                      <Chip
                        label={`${trafficSummary.modified} modified`}
                        size="small"
                        color={trafficSummary.modified > 0 ? 'warning' : 'default'}
                      />
                      <Chip label={`${trafficSummary.hosts} hosts`} size="small" />
                      {trafficSummary.avgDuration > 0 && (
                        <Chip label={`Avg ${trafficSummary.avgDuration}ms`} size="small" />
                      )}
                    </Box>
                  </Box>

                  <TableContainer>
                    <Table size="small" stickyHeader>
                      <TableHead>
                        <TableRow>
                          <TableCell>Time</TableCell>
                          <TableCell>Method</TableCell>
                          <TableCell>Path</TableCell>
                          <TableCell>Status</TableCell>
                          <TableCell>Duration</TableCell>
                          <TableCell>Modified</TableCell>
                          <TableCell>Actions</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {traffic.length === 0 ? (
                          <TableRow>
                            <TableCell colSpan={7} align="center">
                              <Typography color="text.secondary">No traffic captured yet</Typography>
                            </TableCell>
                          </TableRow>
                        ) : filteredTraffic.length === 0 ? (
                          <TableRow>
                            <TableCell colSpan={7} align="center">
                              <Typography color="text.secondary">No traffic matches the current filters</Typography>
                            </TableCell>
                          </TableRow>
                        ) : (
                          filteredTraffic.map((entry) => (
                            <TableRow
                              key={entry.id}
                              hover
                              sx={{
                                bgcolor: entry.modified ? 'action.selected' : 'inherit',
                              }}
                            >
                              <TableCell>
                                <Typography variant="caption">
                                  {new Date(entry.timestamp).toLocaleTimeString()}
                                </Typography>
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={entry.request.method}
                                  size="small"
                                  color={
                                    entry.request.method === 'GET' ? 'info' :
                                    entry.request.method === 'POST' ? 'success' :
                                    entry.request.method === 'PUT' ? 'warning' :
                                    entry.request.method === 'DELETE' ? 'error' : 'default'
                                  }
                                />
                              </TableCell>
                              <TableCell>
                                <Typography
                                  variant="body2"
                                  sx={{
                                    maxWidth: 300,
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap',
                                  }}
                                >
                                  {entry.request.path}
                                </Typography>
                                {entry.request.host && (
                                  <Typography variant="caption" color="text.secondary">
                                    {entry.request.host}
                                  </Typography>
                                )}
                              </TableCell>
                              <TableCell>
                                {entry.response ? (
                                  <Chip
                                    label={entry.response.status_code}
                                    size="small"
                                    color={
                                      entry.response.status_code < 300 ? 'success' :
                                      entry.response.status_code < 400 ? 'info' :
                                      entry.response.status_code < 500 ? 'warning' : 'error'
                                    }
                                  />
                                ) : (
                                  <Typography variant="caption" color="text.secondary">Pending</Typography>
                                )}
                              </TableCell>
                              <TableCell>
                                <Typography variant="body2">
                                  {entry.duration_ms ? `${Math.round(entry.duration_ms)}ms` : '-'}
                                </Typography>
                              </TableCell>
                              <TableCell>
                                {entry.modified && (
                                  <Chip label="Modified" size="small" color="warning" />
                                )}
                              </TableCell>
                              <TableCell>
                                <Tooltip title="View details">
                                  <IconButton
                                    size="small"
                                    onClick={() => {
                                      setSelectedTraffic(entry);
                                      setTrafficDetailOpen(true);
                                    }}
                                  >
                                    <ViewIcon />
                                  </IconButton>
                                </Tooltip>
                                <Tooltip title="Actions">
                                  <IconButton
                                    size="small"
                                    onClick={(event) => openTrafficMenu(event, entry)}
                                  >
                                    <MoreIcon />
                                  </IconButton>
                                </Tooltip>
                              </TableCell>
                            </TableRow>
                          ))
                        )}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <Menu
                    anchorEl={trafficMenuAnchor}
                    open={Boolean(trafficMenuAnchor)}
                    onClose={closeTrafficMenu}
                  >
                    <MenuItem
                      onClick={() => {
                        if (trafficMenuEntry) {
                          setSelectedTraffic(trafficMenuEntry);
                          setTrafficDetailOpen(true);
                        }
                        closeTrafficMenu();
                      }}
                    >
                      <ListItemIcon>
                        <ViewIcon fontSize="small" />
                      </ListItemIcon>
                      View details
                    </MenuItem>
                    <MenuItem
                      onClick={() => trafficMenuEntry && handleCopyAsCurl(trafficMenuEntry)}
                    >
                      <ListItemIcon>
                        <CopyIcon fontSize="small" />
                      </ListItemIcon>
                      Copy as curl
                    </MenuItem>
                    <MenuItem
                      onClick={() => trafficMenuEntry && handleOpenReplay(trafficMenuEntry)}
                    >
                      <ListItemIcon>
                        <ReplayIcon fontSize="small" />
                      </ListItemIcon>
                      Replay request
                    </MenuItem>
                    <MenuItem
                      onClick={() => trafficMenuEntry && handleSendToApiTester(trafficMenuEntry)}
                    >
                      <ListItemIcon>
                        <SwapIcon fontSize="small" />
                      </ListItemIcon>
                      Send to API Tester
                    </MenuItem>
                    <MenuItem
                      onClick={() => trafficMenuEntry && handleSendToFuzzer(trafficMenuEntry)}
                    >
                      <ListItemIcon>
                        <ScienceIcon fontSize="small" />
                      </ListItemIcon>
                      Send to Fuzzer
                    </MenuItem>
                    <MenuItem
                      onClick={() => trafficMenuEntry && handleCreateRuleFromEntry(trafficMenuEntry, 'modify')}
                    >
                      <ListItemIcon>
                        <RuleIcon fontSize="small" />
                      </ListItemIcon>
                      Create rule from request
                    </MenuItem>
                    <MenuItem
                      onClick={() => trafficMenuEntry && handleCreateRuleFromEntry(trafficMenuEntry, 'drop')}
                    >
                      <ListItemIcon>
                        <CancelIcon fontSize="small" />
                      </ListItemIcon>
                      Block host
                    </MenuItem>
                  </Menu>
                </TabPanel>

                {/* Interception Rules Tab */}
                <TabPanel value={tabValue} index={1}>
                  <Box sx={{ mb: 2 }}>
                    <Button
                      variant="contained"
                      startIcon={<AddIcon />}
                      onClick={() => setNewRuleOpen(true)}
                    >
                      Add Rule
                    </Button>
                  </Box>

                  {/* Mode Warning */}
                  {rules.length > 0 && currentProxy && currentProxy.mode !== 'auto_modify' && (
                    <Alert 
                      severity="warning" 
                      sx={{ mb: 2 }}
                      action={
                        <Button 
                          color="inherit" 
                          size="small"
                          onClick={() => handleChangeMode(selectedProxy!, 'auto_modify')}
                        >
                          Switch to Auto Modify
                        </Button>
                      }
                    >
                      <strong>Rules not active!</strong> The proxy is in "{currentProxy.mode}" mode. 
                      Switch to "Auto Modify" mode for rules to automatically apply to traffic.
                    </Alert>
                  )}

                  {ruleGroups.length > 0 && (
                    <Paper variant="outlined" sx={{ p: 1.5, mb: 2 }}>
                      <Typography variant="caption" color="text.secondary">
                        Rule groups
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mt: 1 }}>
                        {ruleGroups.map(group => (
                          <FormControlLabel
                            key={group.name}
                            control={
                              <Switch
                                size="small"
                                checked={group.allEnabled}
                                onChange={(e) => handleToggleRuleGroup(group.name, e.target.checked)}
                              />
                            }
                            label={`${group.name} (${group.enabledCount}/${group.total})`}
                          />
                        ))}
                      </Box>
                    </Paper>
                  )}

                  {rules.length === 0 ? (
                    <Alert severity="info">
                      No interception rules configured. Add rules to automatically modify traffic.
                    </Alert>
                  ) : (
                    <List>
                      {rules.map((rule) => (
                        <Card key={rule.id} sx={{ mb: 1 }}>
                          <CardContent sx={{ pb: 1 }}>
                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                <Switch
                                  checked={rule.enabled}
                                  size="small"
                                  onChange={(e) => handleToggleRule(rule.id, e.target.checked)}
                                />
                                <Typography variant="subtitle1">{rule.name}</Typography>
                                <Chip
                                  label={rule.match_direction}
                                  size="small"
                                  color={
                                    rule.match_direction === 'request' ? 'primary' :
                                    rule.match_direction === 'response' ? 'secondary' : 'default'
                                  }
                                />
                                <Chip
                                  label={rule.action}
                                  size="small"
                                  color={
                                    rule.action === 'modify' ? 'info' :
                                    rule.action === 'drop' ? 'error' : 'warning'
                                  }
                                />
                              </Box>
                              <IconButton
                                size="small"
                                color="error"
                                onClick={() => handleDeleteRule(rule.id)}
                              >
                                <DeleteIcon />
                              </IconButton>
                            </Box>
                            <Box sx={{ mt: 1, display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                              {rule.group && <Chip label={`Group: ${rule.group}`} size="small" variant="outlined" />}
                              {typeof rule.priority === 'number' && <Chip label={`Priority: ${rule.priority}`} size="small" variant="outlined" />}
                              {rule.match_query && Object.keys(rule.match_query).length > 0 && (
                                <Chip label={`Query: ${Object.keys(rule.match_query).length}`} size="small" variant="outlined" />
                              )}
                              {rule.match_host && <Chip label={`Host: ${rule.match_host}`} size="small" variant="outlined" />}
                              {rule.match_path && <Chip label={`Path: ${rule.match_path}`} size="small" variant="outlined" />}
                              {rule.match_method && <Chip label={`Method: ${rule.match_method}`} size="small" variant="outlined" />}
                              {rule.match_content_type && <Chip label={`Type: ${rule.match_content_type}`} size="small" variant="outlined" />}
                              {rule.modify_path && <Chip label={`Rewrite: ${rule.modify_path}`} size="small" variant="outlined" />}
                              {typeof rule.modify_status_code === 'number' && <Chip label={`Status: ${rule.modify_status_code}`} size="small" variant="outlined" />}
                              {rule.body_find_replace_regex && <Chip label="Body regex" size="small" variant="outlined" />}
                              {rule.delay_ms && rule.delay_ms > 0 && <Chip label={`Delay: ${rule.delay_ms}ms`} size="small" variant="outlined" />}
                              {typeof rule.hit_count === 'number' && <Chip label={`Hits: ${rule.hit_count}`} size="small" variant="outlined" />}
                            </Box>
                          </CardContent>
                        </Card>
                      ))}
                    </List>
                  )}
                </TabPanel>

                {/* Preset Rules Tab */}
                <TabPanel value={tabValue} index={2}>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    Preset rules provide common MITM scenarios for security testing. Click to apply them to the current proxy.
                  </Alert>

                  {/* Mode Warning for Presets */}
                  {currentProxy && currentProxy.mode !== 'auto_modify' && (
                    <Alert 
                      severity="info" 
                      sx={{ mb: 2 }}
                      action={
                        <Button 
                          color="inherit" 
                          size="small"
                          onClick={() => handleChangeMode(selectedProxy!, 'auto_modify')}
                        >
                          Switch to Auto Modify
                        </Button>
                      }
                    >
                      Preset rules will be added but won't take effect until you switch to "Auto Modify" mode.
                    </Alert>
                  )}

                  <Grid container spacing={2}>
                    {presets.map((preset) => {
                      const presetInfo = PRESET_DESCRIPTIONS[preset.id];
                      return (
                        <Grid item xs={12} sm={6} md={4} key={preset.id}>
                          <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                            <CardContent sx={{ flexGrow: 1 }}>
                              <Typography variant="subtitle1" gutterBottom fontWeight="medium">
                                {preset.name}
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                {presetInfo?.description || preset.id.replace(/_/g, ' ')}
                              </Typography>
                              {presetInfo?.use_case && (
                                <Typography variant="caption" color="primary" sx={{ fontStyle: 'italic' }}>
                                  Use case: {presetInfo.use_case}
                                </Typography>
                              )}
                            </CardContent>
                            <CardActions>
                              <Button
                                size="small"
                                variant="outlined"
                                onClick={() => handleApplyPreset(preset.id)}
                              >
                                Apply Rule
                              </Button>
                            </CardActions>
                          </Card>
                        </Grid>
                      );
                    })}
                  </Grid>
                </TabPanel>

                {/* AI Analysis Tab */}
                <TabPanel value={tabValue} index={3}>
                  {!analysisResult ? (
                    <Box sx={{ textAlign: 'center', py: 4 }}>
                      <AIIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
                      <Typography variant="h6" color="text.secondary" gutterBottom>
                        No Analysis Available
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                        Click the "Analyze" button to run AI-powered security analysis on your captured traffic.
                      </Typography>
                      <Button
                        variant="contained"
                        color="secondary"
                        startIcon={analyzingTraffic ? <CircularProgress size={20} color="inherit" /> : <AIIcon />}
                        onClick={handleAnalyzeTraffic}
                        disabled={analyzingTraffic || traffic.length === 0}
                      >
                        {analyzingTraffic ? 'Analyzing...' : 'Analyze Traffic'}
                      </Button>
                      {traffic.length === 0 && (
                        <Typography variant="caption" display="block" color="error" sx={{ mt: 1 }}>
                          Capture some traffic first before analyzing
                        </Typography>
                      )}
                    </Box>
                  ) : (
                    <Box>
                      {/* Risk Score Overview */}
                      <Paper sx={{ p: 3, mb: 3, bgcolor: 'background.default' }}>
                        <Grid container spacing={3} alignItems="center">
                          <Grid item>
                            <Box 
                              sx={{ 
                                width: 100, 
                                height: 100, 
                                borderRadius: '50%', 
                                display: 'flex', 
                                alignItems: 'center', 
                                justifyContent: 'center',
                                bgcolor: getRiskLevelColor(analysisResult.risk_level),
                                color: 'white',
                              }}
                            >
                              <Box sx={{ textAlign: 'center' }}>
                                <Typography variant="h4" fontWeight="bold">
                                  {analysisResult.risk_score}
                                </Typography>
                                <Typography variant="caption">/100</Typography>
                              </Box>
                            </Box>
                          </Grid>
                          <Grid item xs>
                            <Typography variant="h5" gutterBottom>
                              {analysisResult.risk_level.toUpperCase()} RISK
                            </Typography>
                            <Typography variant="body1" color="text.secondary">
                              {analysisResult.summary}
                            </Typography>
                            <Box sx={{ display: 'flex', gap: 2, mt: 2, flexWrap: 'wrap' }}>
                              <Chip 
                                icon={<HttpIcon />} 
                                label={`${analysisResult.traffic_analyzed} requests analyzed`} 
                                variant="outlined" 
                              />
                              <Chip 
                                icon={<RuleIcon />} 
                                label={`${analysisResult.rules_active} rules active`} 
                                variant="outlined" 
                              />
                              <Chip 
                                icon={<WarningIcon />} 
                                label={`${analysisResult.findings.length} findings`} 
                                variant="outlined" 
                                color={analysisResult.findings.length > 0 ? 'warning' : 'default'}
                              />
                              {analysisResult.analysis_passes && (
                                <Chip 
                                  icon={<AIIcon />} 
                                  label={`${analysisResult.analysis_passes}-pass AI analysis`} 
                                  variant="outlined" 
                                  color="secondary"
                                />
                              )}
                            </Box>
                            {/* Analysis Pipeline Stats */}
                            {analysisResult.analysis_stats && (
                              <Box sx={{ mt: 2, p: 1.5, bgcolor: 'grey.900', borderRadius: 1 }}>
                                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
                                  Analysis Pipeline:
                                </Typography>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                                  <Chip size="small" label={`Pass 1: ${analysisResult.analysis_stats.pass1_findings} detected`} />
                                  <Typography variant="caption">→</Typography>
                                  <Chip size="small" label={`Pass 2: +${analysisResult.analysis_stats.pass2_ai_findings} AI findings`} color="secondary" />
                                  <Typography variant="caption">→</Typography>
                                  <Chip size="small" label={`Pass 3: ${analysisResult.analysis_stats.false_positives_removed} FPs removed`} color="success" />
                                  <Typography variant="caption">→</Typography>
                                  <Chip size="small" label={`Final: ${analysisResult.analysis_stats.final_count} verified`} color="primary" />
                                </Box>
                              </Box>
                            )}
                          </Grid>
                          <Grid item>
                            <Button
                              variant="outlined"
                              startIcon={<RefreshIcon />}
                              onClick={handleAnalyzeTraffic}
                              disabled={analyzingTraffic}
                            >
                              Re-analyze
                            </Button>
                          </Grid>
                        </Grid>
                      </Paper>

                      {/* Attack Paths (NEW) */}
                      {analysisResult.attack_paths && analysisResult.attack_paths.length > 0 && (
                        <Box sx={{ mb: 3 }}>
                          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <RouteIcon /> Attack Paths
                          </Typography>
                          {analysisResult.attack_paths.map((path: any, index: number) => (
                            <Paper key={index} sx={{ p: 2, mb: 2, bgcolor: 'background.default', border: '1px solid', borderColor: path.severity === 'critical' ? 'error.main' : 'warning.main' }}>
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
                                <Chip label={path.severity?.toUpperCase()} size="small" color={path.severity === 'critical' ? 'error' : 'warning'} />
                                <Typography variant="subtitle1" fontWeight="bold">{path.name}</Typography>
                              </Box>
                              <Typography variant="body2" color="text.secondary" paragraph>{path.description}</Typography>
                              <Typography variant="subtitle2" sx={{ mb: 1 }}>Exploitation Steps:</Typography>
                              <List dense>
                                {path.steps?.map((step: string, i: number) => (
                                  <ListItem key={i} sx={{ py: 0 }}>
                                    <ListItemIcon sx={{ minWidth: 28 }}>
                                      <Typography variant="caption" color="primary">{i + 1}.</Typography>
                                    </ListItemIcon>
                                    <ListItemText primary={step} primaryTypographyProps={{ variant: 'body2' }} />
                                  </ListItem>
                                ))}
                              </List>
                              <Alert severity="error" sx={{ mt: 1 }}>
                                <AlertTitle>Impact</AlertTitle>
                                {path.impact}
                              </Alert>
                            </Paper>
                          ))}
                        </Box>
                      )}

                      {/* Offensive Tool Activity Overview */}
                      {analysisResult.agent_activity && (
                        <Box sx={{ mb: 3 }}>
                          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <DebugIcon /> Offensive Tool Activity
                          </Typography>
                          <Paper sx={{ p: 2, bgcolor: 'background.default' }}>
                            <Grid container spacing={2} sx={{ mb: 2 }}>
                              <Grid item xs={12} md={4}>
                                <Typography variant="caption" color="text.secondary">Monitoring</Typography>
                                <Typography variant="subtitle1" fontWeight="bold">
                                  {analysisResult.agent_activity.monitoring_active ? 'Active' : 'Inactive'}
                                </Typography>
                              </Grid>
                              <Grid item xs={12} md={4}>
                                <Typography variant="caption" color="text.secondary">Captured Data</Typography>
                                <Typography variant="subtitle1" fontWeight="bold">
                                  {`Creds: ${analysisResult.agent_activity.captured_data_summary?.credentials || 0}, `}
                                  {`Tokens: ${analysisResult.agent_activity.captured_data_summary?.tokens || 0}, `}
                                  {`Cookies: ${analysisResult.agent_activity.captured_data_summary?.cookies || 0}`}
                                </Typography>
                              </Grid>
                              <Grid item xs={12} md={4}>
                                <Typography variant="caption" color="text.secondary">Goals</Typography>
                                <Typography variant="subtitle1" fontWeight="bold">
                                  {(analysisResult.agent_activity.goal_progress?.goals?.length || 0) > 0
                                    ? `${analysisResult.agent_activity.goal_progress.goals.filter((g: any) => (g.completion || 0) >= 100).length}/${analysisResult.agent_activity.goal_progress.goals.length} complete`
                                    : 'Not set'}
                                </Typography>
                              </Grid>
                            </Grid>

                            <Divider sx={{ mb: 2 }} />

                            <Typography variant="subtitle2" gutterBottom>Executed Tools</Typography>
                            {(analysisResult.agent_activity.execution_log?.length || 0) === 0 ? (
                              <Typography variant="body2" color="text.secondary">No agentic tools executed in this analysis.</Typography>
                            ) : (
                              <TableContainer>
                                <Table size="small">
                                  <TableHead>
                                    <TableRow>
                                      <TableCell>Tool</TableCell>
                                      <TableCell>Status</TableCell>
                                      <TableCell>Findings</TableCell>
                                      <TableCell>Verified</TableCell>
                                      <TableCell>Time (s)</TableCell>
                                    </TableRow>
                                  </TableHead>
                                  <TableBody>
                                    {analysisResult.agent_activity.execution_log.map((log: any, idx: number) => (
                                      <TableRow key={idx}>
                                        <TableCell>{log.tool_name || log.tool_id}</TableCell>
                                        <TableCell>
                                          {log.success ? (
                                            <Chip label="Success" size="small" color="success" />
                                          ) : (
                                            <Chip label="Failed" size="small" color="error" />
                                          )}
                                        </TableCell>
                                        <TableCell>{log.findings_count ?? 0}</TableCell>
                                        <TableCell>
                                          {analysisResult.agent_activity.verification_results?.find((v: any) => v.tool_id === log.tool_id)?.success
                                            ? 'Yes'
                                            : 'No'}
                                        </TableCell>
                                        <TableCell>{(log.execution_time ?? 0).toFixed(2)}</TableCell>
                                      </TableRow>
                                    ))}
                                  </TableBody>
                                </Table>
                              </TableContainer>
                            )}

                            <Divider sx={{ my: 2 }} />

                            <Typography variant="subtitle2" gutterBottom>Decision Log</Typography>
                            {(analysisResult.agent_activity.decision_log?.length || 0) === 0 ? (
                              <Typography variant="body2" color="text.secondary">No decision log captured yet.</Typography>
                            ) : (
                              <List dense>
                                {analysisResult.agent_activity.decision_log.slice(0, 10).map((entry: any, idx: number) => (
                                  <ListItem key={idx} sx={{ py: 0.5 }}>
                                    <ListItemText
                                      primary={
                                        <Typography variant="body2">
                                          <strong>{entry.step || `step_${idx + 1}`}</strong> — {entry.decision}
                                          {entry.tool ? ` | tool: ${entry.tool}` : ''}
                                        </Typography>
                                      }
                                      secondary={entry.reason ? `Reason: ${entry.reason}` : undefined}
                                    />
                                  </ListItem>
                                ))}
                              </List>
                            )}
                          </Paper>
                        </Box>
                      )}

                      {/* Findings */}
                      {analysisResult.findings.length > 0 && (
                        <Box sx={{ mb: 3 }}>
                          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <ShieldIcon /> Security Findings ({analysisResult.findings.length})
                          </Typography>
                          {analysisResult.findings.map((finding: any, index: number) => (
                            <Accordion key={index} sx={{ mb: 1 }}>
                              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                                  <Chip 
                                    label={finding.severity} 
                                    size="small" 
                                    color={getSeverityColor(finding.severity) as any}
                                  />
                                  <Typography fontWeight="medium">{finding.title}</Typography>
                                  <Chip label={finding.category} size="small" variant="outlined" sx={{ ml: 'auto', mr: 2 }} />
                                </Box>
                              </AccordionSummary>
                              <AccordionDetails>
                                <Typography variant="body2" paragraph>
                                  {finding.description}
                                </Typography>
                                {finding.evidence && (
                                  <Box sx={{ bgcolor: 'grey.900', p: 2, borderRadius: 1, mb: 2 }}>
                                    <Typography variant="caption" color="text.secondary">Evidence</Typography>
                                    <pre style={{ margin: 0, fontSize: '12px', whiteSpace: 'pre-wrap' }}>
                                      {finding.evidence}
                                    </pre>
                                  </Box>
                                )}
                                
                                {/* Enhanced Intelligence Section */}
                                {finding.intelligence && (
                                  <Box sx={{ mb: 2 }}>
                                    <Divider sx={{ my: 2 }} />
                                    <Typography variant="subtitle2" color="primary" gutterBottom>
                                      🔍 Vulnerability Intelligence
                                    </Typography>
                                    
                                    {finding.intelligence.cwe_id && (
                                      <Chip label={finding.intelligence.cwe_id} size="small" sx={{ mr: 1, mb: 1 }} />
                                    )}
                                    {finding.intelligence.cvss_base && (
                                      <Chip label={`CVSS: ${finding.intelligence.cvss_base}`} size="small" color="warning" sx={{ mr: 1, mb: 1 }} />
                                    )}
                                    
                                    {finding.intelligence.technical_details && (
                                      <Box sx={{ bgcolor: 'grey.900', p: 2, borderRadius: 1, mb: 2, mt: 1 }}>
                                        <Typography variant="caption" color="primary">Technical Details</Typography>
                                        <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', fontSize: '12px' }}>
                                          {finding.intelligence.technical_details}
                                        </Typography>
                                      </Box>
                                    )}
                                    
                                    {finding.intelligence.exploitation_steps && (
                                      <Box sx={{ mb: 2 }}>
                                        <Typography variant="subtitle2" color="error.main" gutterBottom>
                                          ⚔️ Exploitation Steps
                                        </Typography>
                                        <List dense>
                                          {finding.intelligence.exploitation_steps.map((step: string, i: number) => (
                                            <ListItem key={i} sx={{ py: 0 }}>
                                              <ListItemText 
                                                primary={step} 
                                                primaryTypographyProps={{ variant: 'body2', fontFamily: 'monospace', fontSize: '12px' }} 
                                              />
                                            </ListItem>
                                          ))}
                                        </List>
                                      </Box>
                                    )}
                                    
                                    {finding.intelligence.poc_payloads && (
                                      <Box sx={{ mb: 2 }}>
                                        <Typography variant="subtitle2" color="warning.main" gutterBottom>
                                          💣 PoC Payloads
                                        </Typography>
                                        <Box sx={{ bgcolor: 'grey.900', p: 2, borderRadius: 1 }}>
                                          <pre style={{ margin: 0, fontSize: '11px', whiteSpace: 'pre-wrap', color: '#ff9800' }}>
                                            {finding.intelligence.poc_payloads.slice(0, 4).join('\n')}
                                          </pre>
                                        </Box>
                                      </Box>
                                    )}
                                    
                                    {finding.intelligence.references && finding.intelligence.references.length > 0 && (
                                      <Box sx={{ mb: 2 }}>
                                        <Typography variant="subtitle2" gutterBottom>📚 References</Typography>
                                        {finding.intelligence.references.slice(0, 3).map((ref: string, i: number) => (
                                          <Typography key={i} variant="body2" component="div">
                                            <a href={ref} target="_blank" rel="noopener noreferrer" style={{ color: '#90caf9', fontSize: '12px' }}>
                                              {ref}
                                            </a>
                                          </Typography>
                                        ))}
                                      </Box>
                                    )}
                                  </Box>
                                )}
                                
                                <Alert severity="info" icon={<IdeaIcon />}>
                                  <AlertTitle>Recommendation</AlertTitle>
                                  {finding.intelligence?.remediation_detailed || finding.recommendation}
                                </Alert>
                              </AccordionDetails>
                            </Accordion>
                          ))}
                        </Box>
                      )}

                      {/* Exploit References (NEW) */}
                      {analysisResult.exploit_references && analysisResult.exploit_references.length > 0 && (
                        <Box sx={{ mb: 3 }}>
                          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <CodeIcon /> Exploit References
                          </Typography>
                          <Grid container spacing={2}>
                            {analysisResult.exploit_references.map((exploit: any, index: number) => (
                              <Grid item xs={12} md={6} key={index}>
                                <Paper sx={{ p: 2, height: '100%' }}>
                                  <Typography variant="subtitle2" fontWeight="bold">{exploit.title}</Typography>
                                  <Chip label={exploit.type} size="small" sx={{ mr: 1, mt: 1 }} />
                                  <Chip label={exploit.platform} size="small" variant="outlined" sx={{ mt: 1 }} />
                                  <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                                    {exploit.description}
                                  </Typography>
                                  {exploit.url && (
                                    <Button 
                                      size="small" 
                                      startIcon={<LinkIcon />}
                                      href={exploit.url}
                                      target="_blank"
                                      sx={{ mt: 1 }}
                                    >
                                      View Resource
                                    </Button>
                                  )}
                                </Paper>
                              </Grid>
                            ))}
                          </Grid>
                        </Box>
                      )}

                      {/* CVE References (NEW) */}
                      {analysisResult.cve_references && analysisResult.cve_references.length > 0 && (
                        <Box sx={{ mb: 3 }}>
                          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <SecurityIcon /> Related CVEs
                          </Typography>
                          <TableContainer component={Paper}>
                            <Table size="small">
                              <TableHead>
                                <TableRow>
                                  <TableCell>CVE ID</TableCell>
                                  <TableCell>CVSS</TableCell>
                                  <TableCell>Description</TableCell>
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {analysisResult.cve_references.map((cve: any, index: number) => (
                                  <TableRow key={index}>
                                    <TableCell>
                                      <a href={cve.url} target="_blank" rel="noopener noreferrer" style={{ color: '#90caf9' }}>
                                        {cve.cve_id}
                                      </a>
                                    </TableCell>
                                    <TableCell>
                                      {cve.cvss_score && (
                                        <Chip 
                                          label={cve.cvss_score} 
                                          size="small" 
                                          color={cve.cvss_score >= 9 ? 'error' : cve.cvss_score >= 7 ? 'warning' : 'default'}
                                        />
                                      )}
                                    </TableCell>
                                    <TableCell>
                                      <Typography variant="body2" sx={{ fontSize: '12px' }}>
                                        {cve.description?.substring(0, 150)}...
                                      </Typography>
                                    </TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </TableContainer>
                        </Box>
                      )}

                      {/* AI Comprehensive Writeup (NEW) */}
                      {analysisResult.ai_writeup && (
                        <Box sx={{ mb: 3 }}>
                          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <DescriptionIcon /> Penetration Test Writeup
                          </Typography>
                          <Paper sx={{ p: 3, bgcolor: 'background.default' }}>
                            <Typography
                              variant="body2"
                              component="div"
                              sx={{
                                whiteSpace: 'pre-wrap',
                                fontSize: '15px',
                                lineHeight: 1.7,
                                '& h1': { color: 'primary.main', mt: 2.5, mb: 1, fontSize: '22px', fontWeight: 700 },
                                '& h2': { color: 'primary.main', mt: 2.25, mb: 1, fontSize: '20px', fontWeight: 700 },
                                '& h3': { color: 'primary.main', mt: 2, mb: 1, fontSize: '18px', fontWeight: 700 },
                                '& h4': { color: 'primary.main', mt: 1.5, mb: 0.75, fontSize: '16px', fontWeight: 700 },
                                '& p': { mb: 1 },
                                '& ul, & ol': { pl: 3, mb: 1 },
                                '& li': { mb: 0.5 },
                                '& strong': { fontWeight: 'bold' },
                                '& em': { fontStyle: 'italic' },
                                '& code': { fontFamily: 'monospace', fontSize: '13px' },
                                '& pre': { background: 'rgba(0,0,0,0.25)', padding: 12, borderRadius: 8, overflowX: 'auto' },
                                '& pre code': { fontSize: '12.5px' },
                                '& table': { width: '100%', borderCollapse: 'collapse', marginTop: 8, marginBottom: 8 },
                                '& th, & td': { border: '1px solid rgba(255,255,255,0.12)', padding: '6px 8px' },
                                '& th': { background: 'rgba(255,255,255,0.06)', fontWeight: 700 },
                                fontFamily: 'inherit'
                              }}
                              dangerouslySetInnerHTML={{
                                __html: formatMarkdownSafe(analysisResult.ai_writeup)
                              }}
                            />
                          </Paper>
                        </Box>
                      )}

                      {/* AI Quick Analysis */}
                      {analysisResult.ai_analysis && (
                        <Box sx={{ mb: 3 }}>
                          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <AIIcon /> AI Analysis
                          </Typography>
                          <Paper sx={{ p: 2, bgcolor: 'background.default' }}>
                            <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                              {analysisResult.ai_analysis}
                            </Typography>
                          </Paper>
                        </Box>
                      )}

                      {/* Recommendations (Enhanced) */}
                      {analysisResult.recommendations && analysisResult.recommendations.length > 0 && (
                        <Box>
                          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <TipIcon /> Remediation Priorities
                          </Typography>
                          <List>
                            {analysisResult.recommendations.map((rec: any, index: number) => (
                              <ListItem key={index} sx={{ bgcolor: 'background.paper', mb: 1, borderRadius: 1 }}>
                                <ListItemIcon>
                                  {rec.priority === 'critical' ? (
                                    <ErrorIcon color="error" />
                                  ) : rec.priority === 'high' ? (
                                    <WarningIcon color="warning" />
                                  ) : (
                                    <SuccessIcon color="primary" />
                                  )}
                                </ListItemIcon>
                                <ListItemText 
                                  primary={typeof rec === 'string' ? rec : rec.title}
                                  secondary={typeof rec === 'object' ? rec.description : undefined}
                                />
                                {typeof rec === 'object' && rec.priority && (
                                  <Chip label={rec.priority} size="small" color={rec.priority === 'critical' ? 'error' : rec.priority === 'high' ? 'warning' : 'default'} />
                                )}
                              </ListItem>
                            ))}
                          </List>
                        </Box>
                      )}
                    </Box>
                  )}
                </TabPanel>

                {/* WebSocket Tab */}
                <TabPanel value={tabValue} index={4}>
                  <Box sx={{ p: 2 }}>
                    {/* WebSocket Stats */}
                    {wsStats && (
                      <Box sx={{ display: 'flex', gap: 3, mb: 3, flexWrap: 'wrap' }}>
                        <Paper sx={{ p: 2, flex: '1 1 150px', textAlign: 'center' }}>
                          <Typography variant="caption" color="text.secondary">Active Connections</Typography>
                          <Typography variant="h5" color="primary">{wsStats.active_connections}</Typography>
                        </Paper>
                        <Paper sx={{ p: 2, flex: '1 1 150px', textAlign: 'center' }}>
                          <Typography variant="caption" color="text.secondary">Total Connections</Typography>
                          <Typography variant="h5">{wsStats.total_connections}</Typography>
                        </Paper>
                        <Paper sx={{ p: 2, flex: '1 1 150px', textAlign: 'center' }}>
                          <Typography variant="caption" color="text.secondary">Client → Server</Typography>
                          <Typography variant="h5">{wsStats.frames_client_to_server}</Typography>
                        </Paper>
                        <Paper sx={{ p: 2, flex: '1 1 150px', textAlign: 'center' }}>
                          <Typography variant="caption" color="text.secondary">Server → Client</Typography>
                          <Typography variant="h5">{wsStats.frames_server_to_client}</Typography>
                        </Paper>
                        <Paper sx={{ p: 2, flex: '1 1 150px', textAlign: 'center' }}>
                          <Typography variant="caption" color="text.secondary">Rules Applied</Typography>
                          <Typography variant="h5">{wsStats.rules_applied}</Typography>
                        </Paper>
                      </Box>
                    )}

                    {/* Toolbar */}
                    <Box sx={{ display: 'flex', gap: 1, mb: 2, alignItems: 'center' }}>
                      <Button 
                        size="small" 
                        startIcon={<RefreshIcon />} 
                        onClick={() => { loadWebSocketConnections(); loadWebSocketStats(); }}
                        disabled={wsLoadingConnections}
                      >
                        Refresh
                      </Button>
                      <Button 
                        size="small" 
                        variant="outlined" 
                        startIcon={<AddIcon />}
                        onClick={() => setWsNewRuleOpen(true)}
                      >
                        Add WS Rule
                      </Button>
                    </Box>

                    <Grid container spacing={2}>
                      {/* Connections List */}
                      <Grid item xs={12} md={4}>
                        <Paper sx={{ p: 2, height: 400, overflow: 'auto' }}>
                          <Typography variant="subtitle2" gutterBottom>WebSocket Connections</Typography>
                          {wsLoadingConnections ? (
                            <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                              <CircularProgress size={24} />
                            </Box>
                          ) : wsConnections.length === 0 ? (
                            <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
                              No WebSocket connections captured
                            </Typography>
                          ) : (
                            <List dense>
                              {wsConnections.map((conn) => (
                                <ListItem 
                                  key={conn.id}
                                  button
                                  selected={selectedWsConnection === conn.id}
                                  onClick={() => {
                                    setSelectedWsConnection(conn.id);
                                    loadWebSocketFrames(conn.id);
                                  }}
                                  sx={{ 
                                    borderRadius: 1,
                                    mb: 0.5,
                                    bgcolor: selectedWsConnection === conn.id ? 'action.selected' : 'transparent',
                                  }}
                                >
                                  <ListItemIcon>
                                    <Chip 
                                      size="small" 
                                      label={conn.status} 
                                      color={conn.status === 'active' ? 'success' : 'default'}
                                      sx={{ minWidth: 70 }}
                                    />
                                  </ListItemIcon>
                                  <ListItemText 
                                    primary={`${conn.target_host}:${conn.target_port}`}
                                    secondary={`${conn.total_frames} frames • ${new Date(conn.created_at).toLocaleTimeString()}`}
                                  />
                                </ListItem>
                              ))}
                            </List>
                          )}
                        </Paper>
                      </Grid>

                      {/* Frames List */}
                      <Grid item xs={12} md={8}>
                        <Paper sx={{ p: 2, height: 400, overflow: 'auto' }}>
                          <Typography variant="subtitle2" gutterBottom>
                            WebSocket Frames {selectedWsConnection && `(${wsFrames.length} frames)`}
                          </Typography>
                          {!selectedWsConnection ? (
                            <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
                              Select a connection to view frames
                            </Typography>
                          ) : wsLoadingFrames ? (
                            <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                              <CircularProgress size={24} />
                            </Box>
                          ) : wsFrames.length === 0 ? (
                            <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
                              No frames captured
                            </Typography>
                          ) : (
                            <TableContainer sx={{ maxHeight: 320 }}>
                              <Table size="small" stickyHeader>
                                <TableHead>
                                  <TableRow>
                                    <TableCell>Time</TableCell>
                                    <TableCell>Direction</TableCell>
                                    <TableCell>Type</TableCell>
                                    <TableCell>Size</TableCell>
                                    <TableCell>Data</TableCell>
                                  </TableRow>
                                </TableHead>
                                <TableBody>
                                  {wsFrames.map((frame) => (
                                    <TableRow 
                                      key={frame.id} 
                                      hover
                                      onClick={() => setWsSelectedFrame(frame)}
                                      sx={{ 
                                        cursor: 'pointer',
                                        bgcolor: frame.modified ? alpha(theme.palette.warning.main, 0.1) : 'inherit',
                                      }}
                                    >
                                      <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                                        {new Date(frame.timestamp).toLocaleTimeString()}
                                      </TableCell>
                                      <TableCell>
                                        <Chip 
                                          size="small" 
                                          label={frame.direction === 'client_to_server' ? '→' : '←'}
                                          color={frame.direction === 'client_to_server' ? 'primary' : 'secondary'}
                                          sx={{ minWidth: 40 }}
                                        />
                                      </TableCell>
                                      <TableCell>
                                        <Chip 
                                          size="small" 
                                          label={frame.opcode_name}
                                          variant="outlined"
                                        />
                                      </TableCell>
                                      <TableCell>{frame.payload_length}B</TableCell>
                                      <TableCell sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                        {frame.payload_text || frame.payload_hex || '-'}
                                      </TableCell>
                                    </TableRow>
                                  ))}
                                </TableBody>
                              </Table>
                            </TableContainer>
                          )}
                        </Paper>
                      </Grid>
                    </Grid>

                    {/* WebSocket Rules */}
                    <Box sx={{ mt: 3 }}>
                      <Typography variant="subtitle2" gutterBottom>WebSocket Rules</Typography>
                      {wsRules.length === 0 ? (
                        <Typography variant="body2" color="text.secondary">
                          No WebSocket rules configured. Click "Add WS Rule" to create one.
                        </Typography>
                      ) : (
                        <TableContainer component={Paper}>
                          <Table size="small">
                            <TableHead>
                              <TableRow>
                                <TableCell>Enabled</TableCell>
                                <TableCell>Name</TableCell>
                                <TableCell>Direction</TableCell>
                                <TableCell>Action</TableCell>
                                <TableCell>Hits</TableCell>
                                <TableCell>Actions</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {wsRules.map((rule) => (
                                <TableRow key={rule.id}>
                                  <TableCell>
                                    <Chip 
                                      size="small" 
                                      label={rule.enabled ? 'On' : 'Off'}
                                      color={rule.enabled ? 'success' : 'default'}
                                    />
                                  </TableCell>
                                  <TableCell>{rule.name}</TableCell>
                                  <TableCell>{rule.match_direction}</TableCell>
                                  <TableCell>{rule.action}</TableCell>
                                  <TableCell>{rule.hit_count}</TableCell>
                                  <TableCell>
                                    <IconButton 
                                      size="small" 
                                      color="error"
                                      onClick={() => handleRemoveWebSocketRule(rule.id)}
                                    >
                                      <DeleteIcon fontSize="small" />
                                    </IconButton>
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      )}
                    </Box>
                  </Box>
                </TabPanel>

                {/* Certificates Tab */}
                <TabPanel value={tabValue} index={5}>
                  <Box sx={{ p: 2 }}>
                    {/* CA Certificate Section */}
                    <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <LockIcon /> CA Certificate
                    </Typography>
                    
                    {certLoading ? (
                      <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                        <CircularProgress />
                      </Box>
                    ) : caCertificate ? (
                      <Paper sx={{ p: 2, mb: 3 }}>
                        <Grid container spacing={2}>
                          <Grid item xs={12} md={6}>
                            <Typography variant="body2" color="text.secondary">Common Name</Typography>
                            <Typography variant="body1" gutterBottom>{caCertificate.common_name}</Typography>
                            
                            <Typography variant="body2" color="text.secondary">Organization</Typography>
                            <Typography variant="body1" gutterBottom>{caCertificate.organization}</Typography>
                            
                            <Typography variant="body2" color="text.secondary">Valid Until</Typography>
                            <Typography variant="body1" gutterBottom>
                              {new Date(caCertificate.valid_until).toLocaleDateString()}
                            </Typography>
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <Typography variant="body2" color="text.secondary">Fingerprint (SHA-256)</Typography>
                            <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all', mb: 2 }}>
                              {caCertificate.fingerprint_sha256}
                            </Typography>
                            
                            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                              <Button 
                                variant="contained" 
                                size="small"
                                startIcon={<DownloadIcon />}
                                onClick={() => handleDownloadCACertificate('pem')}
                              >
                                Download PEM
                              </Button>
                              <Button 
                                variant="outlined" 
                                size="small"
                                startIcon={<DownloadIcon />}
                                onClick={() => handleDownloadCACertificate('crt')}
                              >
                                Download CRT
                              </Button>
                              <Button 
                                variant="outlined" 
                                size="small"
                                startIcon={<DownloadIcon />}
                                onClick={() => handleDownloadCACertificate('der')}
                              >
                                Download DER
                              </Button>
                              <Button 
                                variant="outlined" 
                                size="small"
                                startIcon={<HelpIcon />}
                                onClick={() => {
                                  loadCertificateInstallInstructions();
                                  setShowCertInstallDialog(true);
                                }}
                              >
                                Installation Guide
                              </Button>
                            </Box>
                          </Grid>
                        </Grid>
                        
                        <Divider sx={{ my: 2 }} />
                        
                        <Button 
                          variant="outlined" 
                          color="warning"
                          startIcon={<RefreshIcon />}
                          onClick={() => setShowCertGenDialog(true)}
                        >
                          Regenerate CA Certificate
                        </Button>
                      </Paper>
                    ) : (
                      <Paper sx={{ p: 3, mb: 3, textAlign: 'center' }}>
                        <LockOpenIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
                        <Typography variant="body1" gutterBottom>
                          No CA certificate generated yet
                        </Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                          Generate a CA certificate to enable HTTPS interception
                        </Typography>
                        <Button 
                          variant="contained"
                          startIcon={<AddIcon />}
                          onClick={() => setShowCertGenDialog(true)}
                        >
                          Generate CA Certificate
                        </Button>
                      </Paper>
                    )}

                    {/* Host Certificates Section */}
                    <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 3 }}>
                      <SecurityIcon /> Host Certificates
                    </Typography>
                    
                    {hostCertificates.length === 0 ? (
                      <Typography variant="body2" color="text.secondary">
                        No host certificates generated yet. They are created automatically when intercepting HTTPS traffic.
                      </Typography>
                    ) : (
                      <TableContainer component={Paper}>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Hostname</TableCell>
                              <TableCell>Created</TableCell>
                              <TableCell>Valid Until</TableCell>
                              <TableCell>Fingerprint</TableCell>
                              <TableCell>Actions</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {hostCertificates.map((cert) => (
                              <TableRow key={cert.hostname}>
                                <TableCell sx={{ fontFamily: 'monospace' }}>{cert.hostname}</TableCell>
                                <TableCell>{new Date(cert.created_at).toLocaleDateString()}</TableCell>
                                <TableCell>{new Date(cert.valid_until).toLocaleDateString()}</TableCell>
                                <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                  {cert.fingerprint_sha256.substring(0, 32)}...
                                </TableCell>
                                <TableCell>
                                  <IconButton 
                                    size="small" 
                                    color="error"
                                    onClick={() => handleDeleteHostCertificate(cert.hostname)}
                                  >
                                    <DeleteIcon fontSize="small" />
                                  </IconButton>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    )}
                  </Box>
                </TabPanel>

                {/* Templates Tab */}
                <TabPanel value={tabValue} index={6}>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    {/* Templates Header */}
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <Box>
                        <Typography variant="h6">Match & Replace Templates</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Pre-built rule templates for common MITM modifications
                        </Typography>
                      </Box>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <FormControl size="small" sx={{ minWidth: 150 }}>
                          <InputLabel>Category</InputLabel>
                          <Select
                            value={selectedTemplateCategory}
                            label="Category"
                            onChange={(e) => {
                              setSelectedTemplateCategory(e.target.value);
                              loadTemplates(e.target.value || undefined);
                            }}
                          >
                            <MenuItem value="">All Categories</MenuItem>
                            {templateCategories.map((cat) => (
                              <MenuItem key={cat} value={cat}>{cat}</MenuItem>
                            ))}
                          </Select>
                        </FormControl>
                        <Button
                          variant="contained"
                          startIcon={<AddIcon />}
                          onClick={() => setShowNewTemplateDialog(true)}
                        >
                          Create Template
                        </Button>
                      </Box>
                    </Box>

                    {/* Templates List */}
                    {templatesLoading ? (
                      <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                        <CircularProgress />
                      </Box>
                    ) : templates.length === 0 ? (
                      <Alert severity="info">
                        No templates found. Select a category or create a custom template.
                      </Alert>
                    ) : (
                      <Grid container spacing={2}>
                        {templates.map((template) => (
                          <Grid item xs={12} md={6} lg={4} key={template.id}>
                            <Card variant="outlined">
                              <CardContent>
                                <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 1 }}>
                                  <Typography variant="subtitle1" fontWeight="medium">
                                    {template.name}
                                  </Typography>
                                  {template.is_builtin && (
                                    <Chip label="Built-in" size="small" color="default" />
                                  )}
                                </Box>
                                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                  {template.description}
                                </Typography>
                                <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1 }}>
                                  <Chip label={template.category} size="small" color="primary" variant="outlined" />
                                  <Chip label={template.match_type} size="small" />
                                  <Chip label={template.direction} size="small" />
                                </Box>
                                {template.tags && template.tags.length > 0 && (
                                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                    {template.tags.map((tag: string) => (
                                      <Chip key={tag} label={tag} size="small" variant="outlined" />
                                    ))}
                                  </Box>
                                )}
                                <Divider sx={{ my: 1 }} />
                                <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, fontSize: '0.75rem', fontFamily: 'monospace' }}>
                                  <Box><strong>Match:</strong> {template.match_pattern}</Box>
                                  <Box><strong>Replace:</strong> {template.replace_pattern}</Box>
                                </Box>
                              </CardContent>
                              <CardActions>
                                <Button
                                  size="small"
                                  startIcon={<PlayIcon />}
                                  onClick={() => handleApplyTemplate(template.id)}
                                  disabled={!selectedProxy}
                                >
                                  Apply
                                </Button>
                                <Button
                                  size="small"
                                  startIcon={<ScienceIcon />}
                                  onClick={() => {
                                    setSelectedTemplate(template);
                                    handleTestTemplate(template.id);
                                  }}
                                  disabled={!selectedTraffic || testingTemplate}
                                >
                                  Test
                                </Button>
                                {!template.is_builtin && (
                                  <IconButton
                                    size="small"
                                    color="error"
                                    onClick={() => handleDeleteTemplate(template.id)}
                                  >
                                    <DeleteIcon fontSize="small" />
                                  </IconButton>
                                )}
                              </CardActions>
                            </Card>
                          </Grid>
                        ))}
                      </Grid>
                    )}

                    {/* Template Test Result */}
                    {templateTestResult && (
                      <Paper variant="outlined" sx={{ p: 2, mt: 2 }}>
                        <Typography variant="h6" gutterBottom>Test Result</Typography>
                        <Alert severity={templateTestResult.matched ? 'success' : 'info'} sx={{ mb: 2 }}>
                          {templateTestResult.matched ? 'Template matched!' : 'Template did not match the traffic.'}
                        </Alert>
                        {templateTestResult.matched && templateTestResult.preview && (
                          <Box>
                            <Typography variant="subtitle2">Preview of Changes:</Typography>
                            <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 1 }}>
                              <pre style={{ margin: 0, fontSize: '12px', overflow: 'auto' }}>
                                {JSON.stringify(templateTestResult.preview, null, 2)}
                              </pre>
                            </Box>
                          </Box>
                        )}
                        <Button
                          size="small"
                          onClick={() => setTemplateTestResult(null)}
                          sx={{ mt: 1 }}
                        >
                          Clear Result
                        </Button>
                      </Paper>
                    )}
                  </Box>
                </TabPanel>

                {/* HTTP/2 & gRPC Tab */}
                <TabPanel value={tabValue} index={7}>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    {/* HTTP/2 & gRPC Header */}
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <Box>
                        <Typography variant="h6">HTTP/2 & gRPC Inspector</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Inspect HTTP/2 frames, streams, and gRPC messages
                        </Typography>
                      </Box>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Button
                          variant="outlined"
                          startIcon={http2Loading ? <CircularProgress size={16} /> : <RefreshIcon />}
                          onClick={() => {
                            if (selectedProxy) {
                              loadHTTP2Frames(selectedProxy);
                              loadHTTP2Streams(selectedProxy);
                              loadGRPCMessages(selectedProxy);
                            }
                          }}
                          disabled={!selectedProxy || http2Loading}
                        >
                          Refresh
                        </Button>
                      </Box>
                    </Box>

                    {/* HTTP/2 Streams */}
                    <Accordion defaultExpanded>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="subtitle1">
                          HTTP/2 Streams ({http2Streams.length})
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        {http2Streams.length === 0 ? (
                          <Typography variant="body2" color="text.secondary">
                            No HTTP/2 streams captured. HTTP/2 traffic will appear here when detected.
                          </Typography>
                        ) : (
                          <TableContainer>
                            <Table size="small">
                              <TableHead>
                                <TableRow>
                                  <TableCell>Stream ID</TableCell>
                                  <TableCell>State</TableCell>
                                  <TableCell>Method</TableCell>
                                  <TableCell>Path</TableCell>
                                  <TableCell>Frames</TableCell>
                                  <TableCell>Actions</TableCell>
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {http2Streams.map((stream: any) => (
                                  <TableRow 
                                    key={stream.stream_id}
                                    selected={selectedHttp2Stream === stream.stream_id}
                                    onClick={() => setSelectedHttp2Stream(stream.stream_id)}
                                    sx={{ cursor: 'pointer' }}
                                  >
                                    <TableCell>{stream.stream_id}</TableCell>
                                    <TableCell>
                                      <Chip 
                                        label={stream.state} 
                                        size="small" 
                                        color={stream.state === 'open' ? 'success' : 'default'} 
                                      />
                                    </TableCell>
                                    <TableCell>{stream.method}</TableCell>
                                    <TableCell sx={{ fontFamily: 'monospace', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                      {stream.path}
                                    </TableCell>
                                    <TableCell>{stream.frame_count}</TableCell>
                                    <TableCell>
                                      <IconButton
                                        size="small"
                                        onClick={() => {
                                          setSelectedHttp2Stream(stream.stream_id);
                                          if (selectedProxy) {
                                            loadHTTP2Frames(selectedProxy, stream.stream_id);
                                          }
                                        }}
                                      >
                                        <ViewIcon fontSize="small" />
                                      </IconButton>
                                    </TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </TableContainer>
                        )}
                      </AccordionDetails>
                    </Accordion>

                    {/* HTTP/2 Frames */}
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="subtitle1">
                          HTTP/2 Frames ({http2Frames.length})
                          {selectedHttp2Stream !== null && (
                            <Chip label={`Stream ${selectedHttp2Stream}`} size="small" sx={{ ml: 1 }} />
                          )}
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        {http2Frames.length === 0 ? (
                          <Typography variant="body2" color="text.secondary">
                            No HTTP/2 frames captured. Select a stream to view its frames.
                          </Typography>
                        ) : (
                          <TableContainer sx={{ maxHeight: 300 }}>
                            <Table size="small" stickyHeader>
                              <TableHead>
                                <TableRow>
                                  <TableCell>Type</TableCell>
                                  <TableCell>Stream</TableCell>
                                  <TableCell>Length</TableCell>
                                  <TableCell>Flags</TableCell>
                                  <TableCell>Timestamp</TableCell>
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {http2Frames.map((frame: any, idx: number) => (
                                  <TableRow key={idx}>
                                    <TableCell>
                                      <Chip 
                                        label={frame.frame_type} 
                                        size="small" 
                                        color={
                                          frame.frame_type === 'DATA' ? 'primary' :
                                          frame.frame_type === 'HEADERS' ? 'secondary' :
                                          frame.frame_type === 'RST_STREAM' ? 'error' : 'default'
                                        }
                                      />
                                    </TableCell>
                                    <TableCell>{frame.stream_id}</TableCell>
                                    <TableCell>{frame.length}</TableCell>
                                    <TableCell sx={{ fontFamily: 'monospace' }}>{frame.flags}</TableCell>
                                    <TableCell>{new Date(frame.timestamp).toLocaleTimeString()}</TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </TableContainer>
                        )}
                      </AccordionDetails>
                    </Accordion>

                    {/* gRPC Messages */}
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="subtitle1">
                          gRPC Messages ({grpcMessages.length})
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Box sx={{ mb: 2 }}>
                          <TextField
                            size="small"
                            label="Filter by Service"
                            value={grpcServiceFilter}
                            onChange={(e) => setGrpcServiceFilter(e.target.value)}
                            placeholder="e.g., myapp.UserService"
                            InputProps={{
                              endAdornment: grpcServiceFilter && (
                                <IconButton size="small" onClick={() => setGrpcServiceFilter('')}>
                                  <ClearIcon fontSize="small" />
                                </IconButton>
                              ),
                            }}
                          />
                        </Box>
                        {grpcMessages.length === 0 ? (
                          <Typography variant="body2" color="text.secondary">
                            No gRPC messages captured. gRPC traffic will appear here when detected over HTTP/2.
                          </Typography>
                        ) : (
                          <List dense>
                            {grpcMessages
                              .filter((msg: any) => 
                                !grpcServiceFilter || 
                                msg.service?.toLowerCase().includes(grpcServiceFilter.toLowerCase())
                              )
                              .map((msg: any, idx: number) => (
                                <ListItem key={idx} divider>
                                  <ListItemText
                                    primary={
                                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                        <Chip 
                                          label={msg.is_request ? 'Request' : 'Response'} 
                                          size="small" 
                                          color={msg.is_request ? 'primary' : 'secondary'}
                                        />
                                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                          {msg.service}/{msg.method}
                                        </Typography>
                                      </Box>
                                    }
                                    secondary={
                                      <Box sx={{ mt: 1 }}>
                                        <Typography variant="caption" color="text.secondary">
                                          Stream: {msg.stream_id} | Size: {msg.message_length} bytes
                                        </Typography>
                                        {msg.decoded_message && (
                                          <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 1 }}>
                                            <pre style={{ margin: 0, fontSize: '11px', overflow: 'auto', maxHeight: 100 }}>
                                              {JSON.stringify(msg.decoded_message, null, 2)}
                                            </pre>
                                          </Box>
                                        )}
                                      </Box>
                                    }
                                  />
                                </ListItem>
                              ))}
                          </List>
                        )}
                      </AccordionDetails>
                    </Accordion>
                  </Box>
                </TabPanel>

              </Box>
            </Paper>
          ) : (
            <Paper sx={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Box sx={{ textAlign: 'center' }}>
                <NetworkIcon sx={{ fontSize: 80, color: 'text.secondary', mb: 2 }} />
                <Typography variant="h6" color="text.secondary">
                  Select a proxy or create a new one
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Configure proxy instances to intercept traffic between components
                </Typography>
                <Button
                  variant="contained"
                  startIcon={<AddIcon />}
                  onClick={() => setNewProxyOpen(true)}
                  sx={{ mt: 2 }}
                >
                  Create New Proxy
                </Button>
              </Box>
            </Paper>
          )}
        </Grid>
      </Grid>

      {/* New Proxy Dialog */}
      <Dialog open={newProxyOpen} onClose={() => setNewProxyOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create New Proxy</DialogTitle>
        <DialogContent>
          <Alert severity="info" sx={{ mb: 2, mt: 1 }}>
            <AlertTitle>🎯 Quick Start Tips</AlertTitle>
            <Typography variant="body2">
              • <strong>Listen Host:</strong> Use <code>0.0.0.0</code> to allow external connections (other VMs, devices)<br/>
              • <strong>Target Host:</strong> IP/hostname of target (e.g., <code>192.168.1.20</code> or <code>juiceshop</code> for practice)<br/>
              • <strong>Ports 8080-8089</strong> are pre-exposed for MITM proxies
            </Typography>
          </Alert>
          <Box sx={{ pt: 1, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Proxy ID"
              value={newProxy.proxy_id}
              onChange={(e) => setNewProxy({ ...newProxy, proxy_id: e.target.value })}
              fullWidth
              helperText="Unique identifier for this proxy instance"
              placeholder="e.g., juiceshop-proxy"
            />
            <Grid container spacing={2}>
              <Grid item xs={8}>
                <TextField
                  label="Listen Host"
                  value={newProxy.listen_host}
                  onChange={(e) => setNewProxy({ ...newProxy, listen_host: e.target.value })}
                  fullWidth
                  helperText="0.0.0.0 = accept external connections, 127.0.0.1 = localhost only"
                />
              </Grid>
              <Grid item xs={4}>
                <TextField
                  label="Listen Port"
                  type="number"
                  value={newProxy.listen_port}
                  onChange={(e) => setNewProxy({ ...newProxy, listen_port: parseInt(e.target.value) })}
                  fullWidth
                  helperText="8080-8089 exposed"
                />
              </Grid>
            </Grid>
            <Grid container spacing={2}>
              <Grid item xs={8}>
                <TextField
                  label="Target Host"
                  value={newProxy.target_host}
                  onChange={(e) => setNewProxy({ ...newProxy, target_host: e.target.value })}
                  fullWidth
                  helperText="IP address, hostname, or container name (e.g., juiceshop)"
                  placeholder="e.g., 192.168.1.20 or juiceshop"
                />
              </Grid>
              <Grid item xs={4}>
                <TextField
                  label="Target Port"
                  type="number"
                  value={newProxy.target_port}
                  onChange={(e) => setNewProxy({ ...newProxy, target_port: parseInt(e.target.value) })}
                  fullWidth
                />
              </Grid>
            </Grid>
            <FormControl fullWidth>
              <InputLabel>Mode</InputLabel>
              <Select
                value={newProxy.mode}
                label="Mode"
                onChange={(e) => setNewProxy({ ...newProxy, mode: e.target.value })}
              >
                <MenuItem value="passthrough">Passthrough (observe only)</MenuItem>
                <MenuItem value="intercept">Intercept (hold for review)</MenuItem>
                <MenuItem value="auto_modify">Auto Modify (apply rules)</MenuItem>
              </Select>
            </FormControl>
            <FormControlLabel
              control={
                <Switch
                  checked={newProxy.tls_enabled}
                  onChange={(e) => setNewProxy({ ...newProxy, tls_enabled: e.target.checked })}
                />
              }
              label="Enable TLS (HTTPS)"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNewProxyOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleCreateProxy}
            disabled={!newProxy.proxy_id || loading}
          >
            Create
          </Button>
        </DialogActions>
      </Dialog>

      {/* New Rule Dialog */}
      <Dialog open={newRuleOpen} onClose={() => setNewRuleOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Add Interception Rule</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Rule Name"
              value={newRule.name || ''}
              onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
              fullWidth
            />

            <Divider>Rule Settings</Divider>

            <Grid container spacing={2}>
              <Grid item xs={6}>
                <TextField
                  label="Group"
                  value={newRule.group || ''}
                  onChange={(e) => setNewRule({ ...newRule, group: e.target.value })}
                  fullWidth
                  placeholder="e.g., auth, cache, headers"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Priority"
                  type="number"
                  value={newRule.priority ?? ''}
                  onChange={(e) => setNewRule({ ...newRule, priority: parseInt(e.target.value) || undefined })}
                  fullWidth
                  placeholder="Lower runs first"
                />
              </Grid>
            </Grid>
            
            <Divider>Match Conditions</Divider>
            
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Direction</InputLabel>
                  <Select
                    value={newRule.match_direction || 'both'}
                    label="Direction"
                    onChange={(e) => setNewRule({ ...newRule, match_direction: e.target.value as any })}
                  >
                    <MenuItem value="request">Request</MenuItem>
                    <MenuItem value="response">Response</MenuItem>
                    <MenuItem value="both">Both</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Match Host (regex)"
                  value={newRule.match_host || ''}
                  onChange={(e) => setNewRule({ ...newRule, match_host: e.target.value })}
                  fullWidth
                  placeholder="e.g., api\.example\.com"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Match Path (regex)"
                  value={newRule.match_path || ''}
                  onChange={(e) => setNewRule({ ...newRule, match_path: e.target.value })}
                  fullWidth
                  placeholder="e.g., /api/v1/.*"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Match Method"
                  value={newRule.match_method || ''}
                  onChange={(e) => setNewRule({ ...newRule, match_method: e.target.value })}
                  fullWidth
                  placeholder="e.g., POST"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Match Content-Type"
                  value={newRule.match_content_type || ''}
                  onChange={(e) => setNewRule({ ...newRule, match_content_type: e.target.value })}
                  fullWidth
                  placeholder="e.g., application/json"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Match Status Code"
                  type="number"
                  value={newRule.match_status_code || ''}
                  onChange={(e) => setNewRule({ ...newRule, match_status_code: parseInt(e.target.value) || undefined })}
                  fullWidth
                  placeholder="e.g., 200"
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  label="Match Query (JSON)"
                  value={ruleMatchQueryInput}
                  onChange={(e) => setRuleMatchQueryInput(e.target.value)}
                  fullWidth
                  multiline
                  minRows={2}
                  placeholder='{"userId": "123"}'
                />
              </Grid>
            </Grid>

            <Divider>Action</Divider>

            <FormControl fullWidth>
              <InputLabel>Action</InputLabel>
              <Select
                value={newRule.action || 'modify'}
                label="Action"
                onChange={(e) => setNewRule({ ...newRule, action: e.target.value as any })}
              >
                <MenuItem value="modify">Modify</MenuItem>
                <MenuItem value="drop">Drop</MenuItem>
                <MenuItem value="delay">Delay</MenuItem>
              </Select>
            </FormControl>

            {newRule.action === 'delay' && (
              <TextField
                label="Delay (ms)"
                type="number"
                value={newRule.delay_ms || 0}
                onChange={(e) => setNewRule({ ...newRule, delay_ms: parseInt(e.target.value) })}
                fullWidth
              />
            )}

            {newRule.action === 'modify' && (
              <>
                <Alert severity="info" sx={{ mt: 1 }}>
                  Use JSON for headers and transforms. Empty fields are ignored.
                </Alert>
                <Grid container spacing={2} sx={{ mt: 0 }}>
                  <Grid item xs={6}>
                    <TextField
                      label="Modify Path"
                      value={newRule.modify_path || ''}
                      onChange={(e) => setNewRule({ ...newRule, modify_path: e.target.value })}
                      fullWidth
                      placeholder="/new/path"
                    />
                  </Grid>
                  <Grid item xs={6}>
                    <TextField
                      label="Modify Status Code"
                      type="number"
                      value={newRule.modify_status_code ?? ''}
                      onChange={(e) => setNewRule({ ...newRule, modify_status_code: parseInt(e.target.value) || undefined })}
                      fullWidth
                      placeholder="e.g., 302"
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      label="Modify Headers (JSON)"
                      value={ruleModifyHeadersInput}
                      onChange={(e) => setRuleModifyHeadersInput(e.target.value)}
                      fullWidth
                      multiline
                      minRows={2}
                      placeholder='{"X-Debug": "true"}'
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      label="Remove Headers (comma-separated)"
                      value={ruleRemoveHeadersInput}
                      onChange={(e) => setRuleRemoveHeadersInput(e.target.value)}
                      fullWidth
                      placeholder="Authorization, Cookie"
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      label="Modify Body"
                      value={newRule.modify_body || ''}
                      onChange={(e) => setNewRule({ ...newRule, modify_body: e.target.value })}
                      fullWidth
                      multiline
                      minRows={3}
                      placeholder="Raw body replacement"
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      label="Body Find/Replace (JSON)"
                      value={ruleBodyFindReplaceInput}
                      onChange={(e) => setRuleBodyFindReplaceInput(e.target.value)}
                      fullWidth
                      multiline
                      minRows={2}
                      placeholder='{"foo": "bar"}'
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={Boolean(newRule.body_find_replace_regex)}
                          onChange={(e) => setNewRule({ ...newRule, body_find_replace_regex: e.target.checked })}
                        />
                      }
                      label="Use regex for body find/replace"
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      label="JSON Path Edits (JSON array)"
                      value={ruleJsonPathEditsInput}
                      onChange={(e) => setRuleJsonPathEditsInput(e.target.value)}
                      fullWidth
                      multiline
                      minRows={2}
                      placeholder='[{"path": "$.data.id", "op": "set", "value": "123"}]'
                    />
                  </Grid>
                </Grid>
              </>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNewRuleOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleAddRule}
            disabled={!newRule.name}
          >
            Add Rule
          </Button>
        </DialogActions>
      </Dialog>

      {/* Sessions Dialog */}
      <Dialog open={sessionsOpen} onClose={() => setSessionsOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Traffic Sessions</DialogTitle>
        <DialogContent dividers>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
              <TextField
                label="Session name"
                value={sessionName}
                onChange={(e) => setSessionName(e.target.value)}
                fullWidth
                placeholder="e.g., Login flow"
              />
              <Button
                variant="contained"
                onClick={handleCreateSession}
                disabled={sessionsLoading || !selectedProxy}
              >
                Save
              </Button>
            </Box>

            <Divider />

            {sessionsLoading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
                <CircularProgress size={24} />
              </Box>
            ) : sessions.length === 0 ? (
              <Alert severity="info">No saved sessions yet.</Alert>
            ) : (
              <List>
                {sessions.map((session) => (
                  <ListItem
                    key={session.id}
                    secondaryAction={
                      <Button
                        size="small"
                        onClick={() => handleLoadSession(session.id)}
                      >
                        Load
                      </Button>
                    }
                  >
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="subtitle2">{session.name}</Typography>
                          {activeSession?.id === session.id && (
                            <Chip label="Active" size="small" color="info" />
                          )}
                        </Box>
                      }
                      secondary={`${session.entries} entries - ${new Date(session.created_at).toLocaleString()}`}
                    />
                  </ListItem>
                ))}
              </List>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSessionsOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Traffic Detail Dialog */}
      <Dialog open={trafficDetailOpen} onClose={() => setTrafficDetailOpen(false)} maxWidth="lg" fullWidth>
        <DialogTitle>
          Traffic Details
          {selectedTraffic?.modified && (
            <Chip label="Modified" size="small" color="warning" sx={{ ml: 2 }} />
          )}
        </DialogTitle>
        <DialogContent dividers>
          {selectedTraffic && (
            <Grid container spacing={2}>
              {/* Request */}
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>Request</Typography>
                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Typography variant="subtitle2" color="primary">
                    {selectedTraffic.request.method} {selectedTraffic.request.path}
                  </Typography>
                  {selectedTraffic.request.url && (
                    <Typography variant="caption" color="text.secondary" display="block">
                      {selectedTraffic.request.url}
                    </Typography>
                  )}
                  
                  <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 2 }}>
                    Headers
                  </Typography>
                  <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 0.5 }}>
                    <pre style={{ margin: 0, fontSize: '12px', overflow: 'auto' }}>
                      {JSON.stringify(selectedTraffic.request.headers, null, 2)}
                    </pre>
                  </Box>

                  {(selectedTraffic.request.body || selectedTraffic.request.body_text) && (
                    <>
                      <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 2 }}>
                        Body
                      </Typography>
                      <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 0.5, maxHeight: 200, overflow: 'auto' }}>
                        <pre style={{ margin: 0, fontSize: '12px' }}>
                          {selectedTraffic.request.body || selectedTraffic.request.body_text}
                        </pre>
                      </Box>
                    </>
                  )}
                </Paper>
              </Grid>

              {/* Response */}
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>Response</Typography>
                {selectedTraffic.response ? (
                  <Paper variant="outlined" sx={{ p: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Chip
                        label={selectedTraffic.response.status_code}
                        color={
                          selectedTraffic.response.status_code < 300 ? 'success' :
                          selectedTraffic.response.status_code < 400 ? 'info' :
                          selectedTraffic.response.status_code < 500 ? 'warning' : 'error'
                        }
                      />
                      <Typography>{selectedTraffic.response.status_text || selectedTraffic.response.status_message}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        ({Math.round(selectedTraffic.duration_ms || 0)}ms)
                      </Typography>
                    </Box>

                    <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 2 }}>
                      Headers
                    </Typography>
                    <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 0.5 }}>
                      <pre style={{ margin: 0, fontSize: '12px', overflow: 'auto' }}>
                        {JSON.stringify(selectedTraffic.response.headers, null, 2)}
                      </pre>
                    </Box>

                    {(selectedTraffic.response.body || selectedTraffic.response.body_text) && (
                      <>
                        <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 2 }}>
                          Body
                        </Typography>
                        <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 0.5, maxHeight: 200, overflow: 'auto' }}>
                          <pre style={{ margin: 0, fontSize: '12px' }}>
                            {selectedTraffic.response.body || selectedTraffic.response.body_text}
                          </pre>
                        </Box>
                      </>
                    )}
                  </Paper>
                ) : (
                  <Alert severity="warning">Response not received yet</Alert>
                )}
              </Grid>

              {/* Rules Applied */}
              {selectedTraffic.rules_applied && selectedTraffic.rules_applied.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom>Rules Applied</Typography>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    {selectedTraffic.rules_applied.map((rule, i) => (
                      <Chip key={i} label={rule} color="warning" />
                    ))}
                  </Box>
                </Grid>
              )}

              {/* Traffic Diff Viewer (for modified traffic) */}
              {selectedTraffic.modified && (
                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <SwapIcon /> Traffic Diff
                    <FormControl size="small" sx={{ ml: 'auto' }}>
                      <Select
                        value={diffViewMode}
                        onChange={(e) => setDiffViewMode(e.target.value as 'unified' | 'side-by-side')}
                        size="small"
                      >
                        <MenuItem value="side-by-side">Side by Side</MenuItem>
                        <MenuItem value="unified">Unified</MenuItem>
                      </Select>
                    </FormControl>
                  </Typography>
                  
                  {diffLoading ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
                      <CircularProgress size={24} />
                    </Box>
                  ) : trafficDiff ? (
                    <Box>
                      {/* Request Headers Diff */}
                      {trafficDiff.request_diff?.headers_diff && (
                        <Accordion defaultExpanded>
                          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                            <Typography variant="subtitle2">
                              Request Headers
                              {trafficDiff.request_diff.headers_diff.changes?.length > 0 && (
                                <Chip label={trafficDiff.request_diff.headers_diff.changes.length} size="small" color="warning" sx={{ ml: 1 }} />
                              )}
                            </Typography>
                          </AccordionSummary>
                          <AccordionDetails>
                            {diffViewMode === 'unified' ? (
                              <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem' }}>
                                {trafficDiff.request_diff.headers_diff.unified_diff?.split('\n').map((line: string, i: number) => (
                                  <Box 
                                    key={i}
                                    sx={{ 
                                      color: line.startsWith('+') ? '#4caf50' : line.startsWith('-') ? '#f44336' : '#e0e0e0',
                                      bgcolor: line.startsWith('+') ? 'rgba(76,175,80,0.1)' : line.startsWith('-') ? 'rgba(244,67,54,0.1)' : 'transparent',
                                    }}
                                  >
                                    {line}
                                  </Box>
                                ))}
                              </Box>
                            ) : (
                              <Grid container spacing={1}>
                                <Grid item xs={6}>
                                  <Typography variant="caption" color="text.secondary">Original</Typography>
                                  <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 0.5 }}>
                                    <pre style={{ margin: 0, fontSize: '11px', overflow: 'auto', color: '#f44336' }}>
                                      {trafficDiff.request_diff.headers_diff.original && JSON.stringify(trafficDiff.request_diff.headers_diff.original, null, 2)}
                                    </pre>
                                  </Box>
                                </Grid>
                                <Grid item xs={6}>
                                  <Typography variant="caption" color="text.secondary">Modified</Typography>
                                  <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 0.5 }}>
                                    <pre style={{ margin: 0, fontSize: '11px', overflow: 'auto', color: '#4caf50' }}>
                                      {trafficDiff.request_diff.headers_diff.modified && JSON.stringify(trafficDiff.request_diff.headers_diff.modified, null, 2)}
                                    </pre>
                                  </Box>
                                </Grid>
                              </Grid>
                            )}
                          </AccordionDetails>
                        </Accordion>
                      )}

                      {/* Request Body Diff */}
                      {trafficDiff.request_diff?.body_diff && (
                        <Accordion>
                          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                            <Typography variant="subtitle2">
                              Request Body
                              {trafficDiff.request_diff.body_diff.has_changes && (
                                <Chip label="Changed" size="small" color="warning" sx={{ ml: 1 }} />
                              )}
                            </Typography>
                          </AccordionSummary>
                          <AccordionDetails>
                            <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', maxHeight: 200, overflow: 'auto' }}>
                              {trafficDiff.request_diff.body_diff.unified_diff?.split('\n').map((line: string, i: number) => (
                                <Box 
                                  key={i}
                                  sx={{ 
                                    color: line.startsWith('+') ? '#4caf50' : line.startsWith('-') ? '#f44336' : '#e0e0e0',
                                  }}
                                >
                                  {line}
                                </Box>
                              ))}
                            </Box>
                          </AccordionDetails>
                        </Accordion>
                      )}

                      {/* Response Headers Diff */}
                      {trafficDiff.response_diff?.headers_diff && (
                        <Accordion>
                          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                            <Typography variant="subtitle2">
                              Response Headers
                              {trafficDiff.response_diff.headers_diff.changes?.length > 0 && (
                                <Chip label={trafficDiff.response_diff.headers_diff.changes.length} size="small" color="info" sx={{ ml: 1 }} />
                              )}
                            </Typography>
                          </AccordionSummary>
                          <AccordionDetails>
                            <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem' }}>
                              {trafficDiff.response_diff.headers_diff.unified_diff?.split('\n').map((line: string, i: number) => (
                                <Box 
                                  key={i}
                                  sx={{ 
                                    color: line.startsWith('+') ? '#4caf50' : line.startsWith('-') ? '#f44336' : '#e0e0e0',
                                  }}
                                >
                                  {line}
                                </Box>
                              ))}
                            </Box>
                          </AccordionDetails>
                        </Accordion>
                      )}

                      {/* Response Body Diff */}
                      {trafficDiff.response_diff?.body_diff && (
                        <Accordion>
                          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                            <Typography variant="subtitle2">
                              Response Body
                              {trafficDiff.response_diff.body_diff.has_changes && (
                                <Chip label="Changed" size="small" color="info" sx={{ ml: 1 }} />
                              )}
                            </Typography>
                          </AccordionSummary>
                          <AccordionDetails>
                            <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', maxHeight: 200, overflow: 'auto' }}>
                              {trafficDiff.response_diff.body_diff.unified_diff?.split('\n').map((line: string, i: number) => (
                                <Box 
                                  key={i}
                                  sx={{ 
                                    color: line.startsWith('+') ? '#4caf50' : line.startsWith('-') ? '#f44336' : '#e0e0e0',
                                  }}
                                >
                                  {line}
                                </Box>
                              ))}
                            </Box>
                          </AccordionDetails>
                        </Accordion>
                      )}
                    </Box>
                  ) : (
                    <Alert severity="info">
                      No diff data available. The traffic may have been modified without storing the original.
                    </Alert>
                  )}
                </Grid>
              )}

              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>Notes & Tags</Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <TextField
                    label="Notes"
                    multiline
                    minRows={2}
                    value={trafficNotes}
                    onChange={(e) => setTrafficNotes(e.target.value)}
                    placeholder="Add investigation notes or findings"
                  />
                  <TextField
                    label="Tags"
                    value={trafficTagsInput}
                    onChange={(e) => setTrafficTagsInput(e.target.value)}
                    placeholder="Comma-separated tags"
                  />
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <Button
                      variant="contained"
                      startIcon={savingTrafficMeta ? <CircularProgress size={16} color="inherit" /> : <CheckIcon />}
                      onClick={handleSaveTrafficMeta}
                      disabled={savingTrafficMeta}
                    >
                      Save Notes
                    </Button>
                    {selectedTraffic.tags && selectedTraffic.tags.length > 0 && (
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
                        {selectedTraffic.tags.map((tag, index) => (
                          <Chip key={index} label={tag} size="small" />
                        ))}
                      </Box>
                    )}
                  </Box>
                </Box>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button
            startIcon={<ReplayIcon />}
            onClick={() => selectedTraffic && handleOpenReplay(selectedTraffic)}
            disabled={!selectedTraffic}
          >
            Replay
          </Button>
          <Button
            startIcon={<CopyIcon />}
            onClick={() => copyToClipboard(JSON.stringify(selectedTraffic, null, 2))}
          >
            Copy JSON
          </Button>
          <Button onClick={() => setTrafficDetailOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Replay Dialog */}
      <Dialog open={replayOpen} onClose={() => setReplayOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Replay Request</DialogTitle>
        <DialogContent dividers>
          {replayEntry && (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <Alert severity="info">
                Replaying {replayEntry.request.method} {replayEntry.request.path}
              </Alert>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <TextField
                    label="Method"
                    value={replayOverrides.method}
                    onChange={(e) => setReplayOverrides({ ...replayOverrides, method: e.target.value })}
                    fullWidth
                  />
                </Grid>
                <Grid item xs={6}>
                  <TextField
                    label="Path"
                    value={replayOverrides.path}
                    onChange={(e) => setReplayOverrides({ ...replayOverrides, path: e.target.value })}
                    fullWidth
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    label="Base URL (optional)"
                    value={replayOverrides.baseUrl}
                    onChange={(e) => setReplayOverrides({ ...replayOverrides, baseUrl: e.target.value })}
                    fullWidth
                    placeholder="https://api.example.com"
                  />
                </Grid>
                <Grid item xs={6}>
                  <TextField
                    label="Timeout (seconds)"
                    type="number"
                    value={replayOverrides.timeout}
                    onChange={(e) => setReplayOverrides({ ...replayOverrides, timeout: parseInt(e.target.value) || 0 })}
                    fullWidth
                  />
                </Grid>
                <Grid item xs={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={replayOverrides.verifyTls}
                        onChange={(e) => setReplayOverrides({ ...replayOverrides, verifyTls: e.target.checked })}
                      />
                    }
                    label="Verify TLS"
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    label="Add Headers (JSON)"
                    value={replayOverrides.addHeaders}
                    onChange={(e) => setReplayOverrides({ ...replayOverrides, addHeaders: e.target.value })}
                    fullWidth
                    multiline
                    minRows={2}
                    placeholder='{"X-Replay": "true"}'
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    label="Remove Headers (comma-separated)"
                    value={replayOverrides.removeHeaders}
                    onChange={(e) => setReplayOverrides({ ...replayOverrides, removeHeaders: e.target.value })}
                    fullWidth
                    placeholder="Authorization, Cookie"
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    label="Body"
                    value={replayOverrides.body}
                    onChange={(e) => setReplayOverrides({ ...replayOverrides, body: e.target.value })}
                    fullWidth
                    multiline
                    minRows={3}
                  />
                </Grid>
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setReplayOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleReplayRequest}
            disabled={replayLoading || !replayEntry}
          >
            {replayLoading ? 'Replaying...' : 'Replay'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Guided Wizard Dialog */}
      <Dialog open={wizardOpen} onClose={() => setWizardOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <TutorialIcon color="info" />
          <Box>
            <Typography variant="h6">Getting Started with MITM Workbench</Typography>
            <Typography variant="body2" color="text.secondary">
              {guidedSetup?.description || 'A step-by-step guide to help you get started'}
            </Typography>
          </Box>
        </DialogTitle>
        <DialogContent dividers>
          {loadingGuide ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
              <CircularProgress />
            </Box>
          ) : guidedSetup ? (
            <Box>
              <Box sx={{ mb: 3, display: 'flex', gap: 2 }}>
                <Chip 
                  icon={<TipIcon />} 
                  label={`Difficulty: ${guidedSetup.difficulty}`} 
                  color="primary" 
                  variant="outlined" 
                />
                <Chip 
                  icon={<SpeedIcon />} 
                  label={`Est. Time: ${guidedSetup.estimated_time}`} 
                  color="secondary" 
                  variant="outlined" 
                />
              </Box>

              <Stepper activeStep={wizardStep} orientation="vertical">
                {guidedSetup.steps.map((step, index) => (
                  <Step key={index}>
                    <StepLabel>
                      <Typography variant="subtitle1">{step.title}</Typography>
                    </StepLabel>
                    <StepContent>
                      <Typography variant="body2" paragraph>
                        {step.description}
                      </Typography>

                      {/* Tips */}
                      {step.tips && step.tips.length > 0 && (
                        <Alert severity="info" sx={{ mb: 2 }} icon={<TipIcon />}>
                          <Typography variant="subtitle2">Tips:</Typography>
                          <ul style={{ margin: '8px 0', paddingLeft: 20 }}>
                            {step.tips.map((tip, i) => (
                              <li key={i}><Typography variant="body2">{tip}</Typography></li>
                            ))}
                          </ul>
                        </Alert>
                      )}

                      {/* Fields */}
                      {step.fields && Object.keys(step.fields).length > 0 && (
                        <Box sx={{ mb: 2, bgcolor: 'background.default', p: 2, borderRadius: 1 }}>
                          <Typography variant="subtitle2" gutterBottom>Configuration Fields:</Typography>
                          {Object.entries(step.fields).map(([field, desc]) => (
                            <Box key={field} sx={{ display: 'flex', gap: 1, mb: 0.5 }}>
                              <Chip label={field} size="small" color="primary" />
                              <Typography variant="body2">{desc}</Typography>
                            </Box>
                          ))}
                        </Box>
                      )}

                      {/* Modes */}
                      {step.modes && step.modes.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" gutterBottom>Available Modes:</Typography>
                          <Grid container spacing={1}>
                            {step.modes.map((mode, i) => (
                              <Grid item xs={12} sm={4} key={i}>
                                <Card variant="outlined" sx={{ p: 1.5 }}>
                                  <Typography variant="subtitle2" color="primary">{mode.name}</Typography>
                                  <Typography variant="caption" display="block">{mode.description}</Typography>
                                  <Typography variant="caption" color="text.secondary">
                                    Use case: {mode.use_case}
                                  </Typography>
                                </Card>
                              </Grid>
                            ))}
                          </Grid>
                        </Box>
                      )}

                      {/* Examples */}
                      {step.examples && step.examples.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" gutterBottom>Configuration Examples:</Typography>
                          {step.examples.map((example, i) => (
                            <Accordion key={i} sx={{ mb: 1 }}>
                              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                <Chip label={example.type} size="small" sx={{ mr: 1 }} />
                                <Typography variant="body2">How to configure {example.type}</Typography>
                              </AccordionSummary>
                              <AccordionDetails>
                                <Box sx={{ bgcolor: 'grey.900', p: 2, borderRadius: 1 }}>
                                  <pre style={{ margin: 0, fontSize: '12px', whiteSpace: 'pre-wrap' }}>
                                    {example.instructions}
                                  </pre>
                                </Box>
                              </AccordionDetails>
                            </Accordion>
                          ))}
                        </Box>
                      )}

                      {/* Presets */}
                      {step.presets && step.presets.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" gutterBottom>Available Presets:</Typography>
                          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                            {step.presets.map((preset, i) => (
                              <Tooltip key={i} title={preset.description}>
                                <Chip label={preset.name} variant="outlined" />
                              </Tooltip>
                            ))}
                          </Box>
                        </Box>
                      )}

                      {/* Export formats */}
                      {step.formats && step.formats.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" gutterBottom>Export Formats:</Typography>
                          <Grid container spacing={1}>
                            {step.formats.map((fmt, i) => (
                              <Grid item xs={12} sm={4} key={i}>
                                <Card variant="outlined" sx={{ p: 1.5, textAlign: 'center' }}>
                                  {fmt.format === 'PDF' && <PdfIcon color="error" />}
                                  {fmt.format === 'Markdown' && <MarkdownIcon color="info" />}
                                  {fmt.format === 'Word' && <WordIcon color="primary" />}
                                  <Typography variant="subtitle2">{fmt.format}</Typography>
                                  <Typography variant="caption">{fmt.description}</Typography>
                                </Card>
                              </Grid>
                            ))}
                          </Grid>
                        </Box>
                      )}

                      <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
                        <Button
                          disabled={index === 0}
                          onClick={() => setWizardStep(index - 1)}
                          startIcon={<BackIcon />}
                        >
                          Back
                        </Button>
                        <Button
                          variant="contained"
                          onClick={() => {
                            if (index === guidedSetup.steps.length - 1) {
                              setWizardOpen(false);
                              setNewProxyOpen(true);
                            } else {
                              setWizardStep(index + 1);
                            }
                          }}
                          endIcon={<NextIcon />}
                        >
                          {index === guidedSetup.steps.length - 1 ? 'Create Your First Proxy' : 'Continue'}
                        </Button>
                      </Box>
                    </StepContent>
                  </Step>
                ))}
              </Stepper>

              {/* Deployment Scenarios - THE KEY SECTION */}
              {guidedSetup.deployment_scenarios && guidedSetup.deployment_scenarios.length > 0 && (
                <Box sx={{ mt: 4 }}>
                  <Divider sx={{ mb: 2 }} />
                  <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <RouteIcon color="primary" /> Where is Your Target Application?
                  </Typography>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    <AlertTitle>Key Concept</AlertTitle>
                    VRAgent runs <strong>inside a Docker container</strong>. The Target Host must be reachable from inside this container, not from your host machine.
                  </Alert>
                  {guidedSetup.deployment_scenarios.map((scenario, index) => (
                    <Accordion key={index} defaultExpanded={index === 1}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                          <Typography fontWeight="bold">{scenario.title}</Typography>
                          {scenario.subtitle && (
                            <Typography variant="caption" color="text.secondary" sx={{ ml: 'auto', mr: 2 }}>
                              {scenario.subtitle}
                            </Typography>
                          )}
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Typography variant="body2" paragraph>
                          {scenario.description}
                        </Typography>
                        
                        {scenario.why_it_works && (
                          <Alert severity="success" sx={{ mb: 2 }}>
                            <AlertTitle>Why It Works</AlertTitle>
                            {scenario.why_it_works}
                          </Alert>
                        )}
                        
                        {scenario.config && (
                          <Paper variant="outlined" sx={{ p: 2, mb: 2, bgcolor: 'grey.50' }}>
                            <Typography variant="subtitle2" gutterBottom color="primary">
                              Proxy Configuration:
                            </Typography>
                            <Grid container spacing={1}>
                              <Grid item xs={6} sm={3}>
                                <Typography variant="caption" color="text.secondary">Listen Host</Typography>
                                <Typography variant="body2" fontFamily="monospace" fontWeight="bold">
                                  {scenario.config.listen_host}
                                </Typography>
                              </Grid>
                              <Grid item xs={6} sm={3}>
                                <Typography variant="caption" color="text.secondary">Listen Port</Typography>
                                <Typography variant="body2" fontFamily="monospace" fontWeight="bold">
                                  {scenario.config.listen_port}
                                </Typography>
                              </Grid>
                              <Grid item xs={6} sm={3}>
                                <Typography variant="caption" color="text.secondary">Target Host</Typography>
                                <Typography variant="body2" fontFamily="monospace" fontWeight="bold" color="success.main">
                                  {scenario.config.target_host}
                                </Typography>
                              </Grid>
                              <Grid item xs={6} sm={3}>
                                <Typography variant="caption" color="text.secondary">Target Port</Typography>
                                <Typography variant="body2" fontFamily="monospace" fontWeight="bold">
                                  {scenario.config.target_port}
                                </Typography>
                              </Grid>
                            </Grid>
                          </Paper>
                        )}
                        
                        {scenario.explanation && scenario.explanation.length > 0 && (
                          <Box sx={{ mb: 2 }}>
                            <Typography variant="caption" color="text.secondary">Explanation:</Typography>
                            <ul style={{ margin: '4px 0', paddingLeft: 20 }}>
                              {scenario.explanation.map((exp, i) => (
                                <li key={i}><Typography variant="body2">{exp}</Typography></li>
                              ))}
                            </ul>
                          </Box>
                        )}
                        
                        {scenario.traffic_flow && (
                          <Paper variant="outlined" sx={{ p: 1.5, mb: 2, bgcolor: 'info.lighter' }}>
                            <Typography variant="caption" color="text.secondary">Traffic Flow:</Typography>
                            <Typography variant="body2" fontFamily="monospace" sx={{ mt: 0.5 }}>
                              {scenario.traffic_flow}
                            </Typography>
                          </Paper>
                        )}
                        
                        {scenario.verify_command && (
                          <Box sx={{ mb: 1 }}>
                            <Typography variant="caption" color="text.secondary">Verify with:</Typography>
                            <Typography variant="body2" fontFamily="monospace" sx={{ bgcolor: 'grey.100', p: 0.5, borderRadius: 1 }}>
                              {scenario.verify_command}
                            </Typography>
                          </Box>
                        )}
                        
                        {scenario.common_mistake && (
                          <Alert severity="warning" sx={{ mt: 1 }}>
                            <AlertTitle>Common Mistake</AlertTitle>
                            {scenario.common_mistake}
                          </Alert>
                        )}
                        
                        {scenario.warning && (
                          <Alert severity="error" sx={{ mt: 1 }}>
                            {scenario.warning}
                          </Alert>
                        )}
                      </AccordionDetails>
                    </Accordion>
                  ))}
                </Box>
              )}

              {/* Juice Shop Setup Guide - Collapsed by default */}
              {guidedSetup.juice_shop_setup && (
                <Box sx={{ mt: 3 }}>
                  <Accordion sx={{ bgcolor: 'grey.50' }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <span role="img" aria-label="juice">🧃</span>
                        <Typography variant="subtitle2">
                          Need to set up OWASP Juice Shop? Click to expand setup instructions
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" paragraph color="text.secondary">
                        {guidedSetup.juice_shop_setup.description}
                      </Typography>
                      
                      {guidedSetup.juice_shop_setup.methods.map((method, index) => (
                        <Accordion key={index} defaultExpanded={index === 0}>
                          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                            <Box>
                              <Typography fontWeight="bold" variant="body2">{method.name}</Typography>
                              <Typography variant="caption" color="text.secondary">
                                {method.description}
                              </Typography>
                            </Box>
                          </AccordionSummary>
                          <AccordionDetails>
                            <ol style={{ margin: 0, paddingLeft: 20 }}>
                              {method.steps.map((step, i) => (
                                <li key={i} style={{ marginBottom: 4 }}>
                                  <Typography 
                                    variant="body2" 
                                    fontFamily={step.includes(':') && !step.includes('http') ? 'inherit' : 'monospace'}
                                    sx={{ 
                                      bgcolor: step.startsWith('docker') || step.startsWith('npm') || step.startsWith('git') || step.startsWith('cd ') || step.startsWith('curl')
                                        ? 'grey.100' 
                                        : 'transparent',
                                      p: step.startsWith('docker') || step.startsWith('npm') || step.startsWith('git') || step.startsWith('cd ') || step.startsWith('curl')
                                        ? 0.5 
                                        : 0,
                                      borderRadius: 1,
                                    }}
                                  >
                                    {step}
                                  </Typography>
                                </li>
                              ))}
                            </ol>
                          </AccordionDetails>
                        </Accordion>
                      ))}
                      
                      {guidedSetup.juice_shop_setup.port_explanation && (
                        <Alert severity="info" sx={{ mt: 2 }}>
                          <AlertTitle>{guidedSetup.juice_shop_setup.port_explanation.title}</AlertTitle>
                          <ul style={{ margin: '4px 0', paddingLeft: 20 }}>
                            {guidedSetup.juice_shop_setup.port_explanation.details.map((detail, i) => (
                              <li key={i}><Typography variant="body2">{detail}</Typography></li>
                            ))}
                          </ul>
                        </Alert>
                      )}
                    </AccordionDetails>
                  </Accordion>
                </Box>
              )}

              {/* Common Use Cases */}
              {guidedSetup.common_use_cases && guidedSetup.common_use_cases.length > 0 && (
                <Box sx={{ mt: 4 }}>
                  <Divider sx={{ mb: 2 }} />
                  <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <IdeaIcon color="warning" /> Common Use Cases
                  </Typography>
                  <Grid container spacing={2}>
                    {guidedSetup.common_use_cases.map((useCase, index) => (
                      <Grid item xs={12} md={6} key={index}>
                        <Card variant="outlined">
                          <CardContent>
                            <Typography variant="subtitle1" color="primary" gutterBottom>
                              {useCase.title}
                            </Typography>
                            <Typography variant="body2" paragraph>
                              {useCase.description}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">Steps:</Typography>
                            <ol style={{ margin: '4px 0', paddingLeft: 20 }}>
                              {useCase.steps.map((s, i) => (
                                <li key={i}><Typography variant="caption">{s}</Typography></li>
                              ))}
                            </ol>
                          </CardContent>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>
                </Box>
              )}

              {/* Troubleshooting */}
              {guidedSetup.troubleshooting && guidedSetup.troubleshooting.length > 0 && (
                <Box sx={{ mt: 4 }}>
                  <Divider sx={{ mb: 2 }} />
                  <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <DebugIcon color="error" /> Troubleshooting
                  </Typography>
                  {guidedSetup.troubleshooting.map((item, index) => (
                    <Accordion key={index}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography color="error">{item.issue}</Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <ul style={{ margin: 0, paddingLeft: 20 }}>
                          {item.solutions.map((sol, i) => (
                            <li key={i}><Typography variant="body2">{sol}</Typography></li>
                          ))}
                        </ul>
                      </AccordionDetails>
                    </Accordion>
                  ))}
                </Box>
              )}
            </Box>
          ) : (
            <Alert severity="warning">
              Failed to load guided setup. Please try again.
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setWizardOpen(false)}>Close</Button>
          <Button 
            variant="contained" 
            onClick={() => { setWizardOpen(false); setNewProxyOpen(true); }}
            startIcon={<AddIcon />}
          >
            Create Proxy Now
          </Button>
        </DialogActions>
      </Dialog>

      {/* Test Scenarios Dialog */}
      <Dialog 
        open={scenarioDialogOpen} 
        onClose={() => setScenarioDialogOpen(false)} 
        maxWidth="lg" 
        fullWidth
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <ScienceIcon color="warning" />
          <Box>
            <Typography variant="h6">Security Test Scenarios</Typography>
            <Typography variant="body2" color="text.secondary">
              Pre-built scenarios to learn security testing - just click and run!
            </Typography>
          </Box>
        </DialogTitle>
        <DialogContent dividers>
          {!selectedProxy && (
            <Alert severity="warning" sx={{ mb: 2 }}>
              <AlertTitle>Create a Proxy First</AlertTitle>
              You need to create and select a proxy before running test scenarios.
              <Button 
                size="small" 
                sx={{ ml: 2 }} 
                onClick={() => { setScenarioDialogOpen(false); setNewProxyOpen(true); }}
              >
                Create Proxy
              </Button>
            </Alert>
          )}

          {scenarioResult && (
            <Alert severity="success" sx={{ mb: 2 }} onClose={() => setScenarioResult(null)}>
              <AlertTitle>✅ {scenarioResult.message}</AlertTitle>
              <Typography variant="body2">
                {scenarioResult.rules_added} rules added. Mode set to: {scenarioResult.mode}
              </Typography>
              <Box sx={{ mt: 1 }}>
                <Typography variant="caption" fontWeight="bold">Next Steps:</Typography>
                <ul style={{ margin: '4px 0', paddingLeft: 20 }}>
                  {scenarioResult.next_steps?.map((step: string, i: number) => (
                    <li key={i}><Typography variant="caption">{step}</Typography></li>
                  ))}
                </ul>
              </Box>
            </Alert>
          )}

          <Grid container spacing={2}>
            {testScenarios.map((scenario) => (
              <Grid item xs={12} sm={6} md={4} key={scenario.id}>
                <Card 
                  sx={{ 
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    transition: 'transform 0.2s, box-shadow 0.2s',
                    '&:hover': {
                      transform: 'translateY(-4px)',
                      boxShadow: 4,
                    },
                    border: selectedScenario?.id === scenario.id ? `2px solid ${theme.palette.primary.main}` : undefined,
                  }}
                >
                  <CardContent sx={{ flex: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                      <Avatar sx={{ bgcolor: 'warning.main', width: 36, height: 36 }}>
                        {scenario.icon === 'security' && <SecurityIcon sx={{ fontSize: 20 }} />}
                        {scenario.icon === 'lock_open' && <LockOpenIcon sx={{ fontSize: 20 }} />}
                        {scenario.icon === 'public' && <NetworkIcon sx={{ fontSize: 20 }} />}
                        {scenario.icon === 'remove_circle' && <CancelIcon sx={{ fontSize: 20 }} />}
                        {scenario.icon === 'edit' && <EditIcon sx={{ fontSize: 20 }} />}
                        {scenario.icon === 'speed' && <SpeedIcon sx={{ fontSize: 20 }} />}
                        {scenario.icon === 'code' && <CodeIcon sx={{ fontSize: 20 }} />}
                        {scenario.icon === 'visibility' && <ViewIcon sx={{ fontSize: 20 }} />}
                        {!['security', 'lock_open', 'public', 'remove_circle', 'edit', 'speed', 'code', 'visibility'].includes(scenario.icon) && <ScienceIcon sx={{ fontSize: 20 }} />}
                      </Avatar>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="subtitle1" fontWeight="bold" sx={{ lineHeight: 1.2 }}>
                          {scenario.name}
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 0.5, mt: 0.5 }}>
                          <Chip 
                            label={scenario.difficulty} 
                            size="small" 
                            color={getDifficultyColor(scenario.difficulty) as any}
                            sx={{ height: 18, fontSize: '0.65rem' }}
                          />
                          <Chip 
                            label={scenario.estimated_time} 
                            size="small" 
                            variant="outlined"
                            sx={{ height: 18, fontSize: '0.65rem' }}
                          />
                        </Box>
                      </Box>
                    </Box>
                    
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2, minHeight: 40 }}>
                      {scenario.description}
                    </Typography>

                    <Typography variant="caption" fontWeight="bold" color="text.secondary">
                      What to look for:
                    </Typography>
                    <ul style={{ margin: '4px 0', paddingLeft: 16 }}>
                      {scenario.what_to_look_for.slice(0, 2).map((item, i) => (
                        <li key={i}>
                          <Typography variant="caption" color="text.secondary">{item}</Typography>
                        </li>
                      ))}
                    </ul>
                  </CardContent>
                  <CardActions sx={{ p: 2, pt: 0 }}>
                    <Button
                      variant="contained"
                      size="small"
                      fullWidth
                      startIcon={runningScenario ? <CircularProgress size={16} color="inherit" /> : <RunIcon />}
                      onClick={() => handleRunScenario(scenario.id)}
                      disabled={!selectedProxy || runningScenario}
                    >
                      {runningScenario ? 'Running...' : 'Run Scenario'}
                    </Button>
                    <Tooltip title="View details">
                      <IconButton size="small" onClick={() => setSelectedScenario(scenario)}>
                        <InfoIcon />
                      </IconButton>
                    </Tooltip>
                  </CardActions>
                </Card>
              </Grid>
            ))}
          </Grid>

          {/* Scenario Detail Panel */}
          {selectedScenario && (
            <Paper sx={{ mt: 3, p: 2, bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="h6">{selectedScenario.name}</Typography>
                <IconButton size="small" onClick={() => setSelectedScenario(null)}>
                  <CloseIcon />
                </IconButton>
              </Box>
              
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <ViewIcon fontSize="small" /> What to Look For
                  </Typography>
                  <List dense>
                    {selectedScenario.what_to_look_for.map((item, i) => (
                      <ListItem key={i} sx={{ py: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <DotIcon sx={{ fontSize: 8 }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: 'body2' }} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <LearnIcon fontSize="small" /> Learning Points
                  </Typography>
                  <List dense>
                    {selectedScenario.learning_points.map((item, i) => (
                      <ListItem key={i} sx={{ py: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <TipIcon sx={{ fontSize: 14, color: 'warning.main' }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: 'body2' }} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
              </Grid>

              {selectedScenario.rules.length > 0 && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <RuleIcon fontSize="small" /> Rules Applied ({selectedScenario.rules.length})
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    {selectedScenario.rules.map((rule, i) => (
                      <Chip 
                        key={i}
                        label={rule.name || `Rule ${i + 1}`}
                        size="small"
                        variant="outlined"
                        color="warning"
                      />
                    ))}
                  </Box>
                </Box>
              )}
            </Paper>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setScenarioDialogOpen(false)}>Close</Button>
          {selectedProxy && selectedScenario && (
            <Button
              variant="contained"
              startIcon={runningScenario ? <CircularProgress size={16} color="inherit" /> : <RunIcon />}
              onClick={() => handleRunScenario(selectedScenario.id)}
              disabled={runningScenario}
            >
              Run "{selectedScenario.name}"
            </Button>
          )}
        </DialogActions>
      </Dialog>

      {/* WebSocket Rule Dialog */}
      <Dialog open={wsNewRuleOpen} onClose={() => setWsNewRuleOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Add WebSocket Rule</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Rule Name"
              value={wsNewRule.name || ''}
              onChange={(e) => setWsNewRule({ ...wsNewRule, name: e.target.value })}
              fullWidth
              placeholder="e.g., Block Binary Messages"
            />
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Direction</InputLabel>
                  <Select
                    value={wsNewRule.match_direction || 'both'}
                    label="Direction"
                    onChange={(e) => setWsNewRule({ ...wsNewRule, match_direction: e.target.value })}
                  >
                    <MenuItem value="client_to_server">Client → Server</MenuItem>
                    <MenuItem value="server_to_client">Server → Client</MenuItem>
                    <MenuItem value="both">Both</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Action</InputLabel>
                  <Select
                    value={wsNewRule.action || 'passthrough'}
                    label="Action"
                    onChange={(e) => setWsNewRule({ ...wsNewRule, action: e.target.value })}
                  >
                    <MenuItem value="passthrough">Passthrough</MenuItem>
                    <MenuItem value="modify">Modify</MenuItem>
                    <MenuItem value="drop">Drop</MenuItem>
                    <MenuItem value="delay">Delay</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
            <TextField
              label="Match Payload Pattern (regex)"
              value={wsNewRule.match_payload_pattern || ''}
              onChange={(e) => setWsNewRule({ ...wsNewRule, match_payload_pattern: e.target.value })}
              fullWidth
              placeholder="e.g., .*login.*"
            />
            <TextField
              label="Match JSON Path"
              value={wsNewRule.match_json_path || ''}
              onChange={(e) => setWsNewRule({ ...wsNewRule, match_json_path: e.target.value })}
              fullWidth
              placeholder="e.g., $.type"
              helperText="JSONPath expression to match in JSON payloads"
            />
            {wsNewRule.action === 'delay' && (
              <TextField
                label="Delay (ms)"
                type="number"
                value={wsNewRule.delay_ms || 0}
                onChange={(e) => setWsNewRule({ ...wsNewRule, delay_ms: parseInt(e.target.value) || 0 })}
                fullWidth
              />
            )}
            <TextField
              label="Priority"
              type="number"
              value={wsNewRule.priority || 0}
              onChange={(e) => setWsNewRule({ ...wsNewRule, priority: parseInt(e.target.value) || 0 })}
              fullWidth
              helperText="Lower values run first"
            />
            <FormControlLabel
              control={
                <Switch
                  checked={wsNewRule.enabled !== false}
                  onChange={(e) => setWsNewRule({ ...wsNewRule, enabled: e.target.checked })}
                />
              }
              label="Enabled"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setWsNewRuleOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleAddWebSocketRule}
            disabled={!wsNewRule.name || loading}
          >
            Add Rule
          </Button>
        </DialogActions>
      </Dialog>

      {/* Certificate Generation Dialog */}
      <Dialog open={showCertGenDialog} onClose={() => setShowCertGenDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Generate CA Certificate</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2, mt: 1 }}>
            Generating a new CA certificate will invalidate all existing host certificates. 
            Users will need to reinstall the new CA certificate.
          </Alert>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Common Name"
              value={certGenConfig.common_name}
              onChange={(e) => setCertGenConfig({ ...certGenConfig, common_name: e.target.value })}
              fullWidth
            />
            <TextField
              label="Organization"
              value={certGenConfig.organization}
              onChange={(e) => setCertGenConfig({ ...certGenConfig, organization: e.target.value })}
              fullWidth
            />
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <TextField
                  label="Country Code"
                  value={certGenConfig.country}
                  onChange={(e) => setCertGenConfig({ ...certGenConfig, country: e.target.value })}
                  fullWidth
                  inputProps={{ maxLength: 2 }}
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Validity (days)"
                  type="number"
                  value={certGenConfig.validity_days}
                  onChange={(e) => setCertGenConfig({ ...certGenConfig, validity_days: parseInt(e.target.value) || 365 })}
                  fullWidth
                />
              </Grid>
            </Grid>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowCertGenDialog(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleGenerateCACertificate}
            disabled={certGenerating}
            startIcon={certGenerating ? <CircularProgress size={16} /> : null}
          >
            {certGenerating ? 'Generating...' : 'Generate'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Certificate Installation Instructions Dialog */}
      <Dialog open={showCertInstallDialog} onClose={() => setShowCertInstallDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Certificate Installation Guide</DialogTitle>
        <DialogContent>
          {certInstallInstructions ? (
            <Box>
              <Alert severity="info" sx={{ mb: 2 }}>
                Install the CA certificate to trust HTTPS connections intercepted by the MITM proxy.
              </Alert>
              
              <Typography variant="subtitle2" gutterBottom>Certificate Details</Typography>
              <Paper sx={{ p: 2, mb: 2, bgcolor: 'background.default' }}>
                <Typography variant="body2"><strong>Name:</strong> {certInstallInstructions.ca_certificate.common_name}</Typography>
                <Typography variant="body2"><strong>Valid Until:</strong> {certInstallInstructions.ca_certificate.valid_until}</Typography>
                <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                  <strong>Fingerprint:</strong> {certInstallInstructions.ca_certificate.fingerprint}
                </Typography>
              </Paper>

              <Typography variant="subtitle2" gutterBottom>Installation Instructions</Typography>
              {Object.entries(certInstallInstructions.instructions).map(([platform, info]) => (
                <Accordion key={platform}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography>{info.title}</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {info.steps.map((step, idx) => (
                        <ListItem key={idx}>
                          <ListItemIcon>
                            <Chip label={idx + 1} size="small" />
                          </ListItemIcon>
                          <ListItemText primary={step} />
                        </ListItem>
                      ))}
                    </List>
                    {info.command && (
                      <Paper sx={{ p: 1, bgcolor: 'grey.900', mt: 1 }}>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', color: 'grey.100' }}>
                          {info.command}
                        </Typography>
                        <IconButton 
                          size="small" 
                          onClick={() => {
                            navigator.clipboard.writeText(info.command!);
                            setSuccess('Command copied to clipboard');
                          }}
                          sx={{ color: 'grey.400' }}
                        >
                          <CopyIcon fontSize="small" />
                        </IconButton>
                      </Paper>
                    )}
                    {info.note && (
                      <Alert severity="info" sx={{ mt: 1 }}>
                        {info.note}
                      </Alert>
                    )}
                  </AccordionDetails>
                </Accordion>
              ))}
            </Box>
          ) : (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
              <CircularProgress />
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowCertInstallDialog(false)}>Close</Button>
          <Button 
            variant="contained"
            startIcon={<DownloadIcon />}
            onClick={() => handleDownloadCACertificate('pem')}
          >
            Download Certificate
          </Button>
        </DialogActions>
      </Dialog>

      {/* WebSocket Frame Detail Dialog */}
      <Dialog open={!!wsSelectedFrame} onClose={() => setWsSelectedFrame(null)} maxWidth="md" fullWidth>
        <DialogTitle>WebSocket Frame Details</DialogTitle>
        <DialogContent>
          {wsSelectedFrame && (
            <Box>
              <Grid container spacing={2} sx={{ mb: 2 }}>
                <Grid item xs={6} md={3}>
                  <Typography variant="caption" color="text.secondary">Direction</Typography>
                  <Typography>{wsSelectedFrame.direction}</Typography>
                </Grid>
                <Grid item xs={6} md={3}>
                  <Typography variant="caption" color="text.secondary">Type</Typography>
                  <Typography>{wsSelectedFrame.opcode_name}</Typography>
                </Grid>
                <Grid item xs={6} md={3}>
                  <Typography variant="caption" color="text.secondary">Size</Typography>
                  <Typography>{wsSelectedFrame.payload_length} bytes</Typography>
                </Grid>
                <Grid item xs={6} md={3}>
                  <Typography variant="caption" color="text.secondary">Time</Typography>
                  <Typography>{new Date(wsSelectedFrame.timestamp).toLocaleString()}</Typography>
                </Grid>
              </Grid>
              
              {wsSelectedFrame.modified && (
                <Alert severity="warning" sx={{ mb: 2 }}>
                  This frame was modified by a rule
                </Alert>
              )}

              <Typography variant="subtitle2" gutterBottom>Payload</Typography>
              {wsSelectedFrame.payload_json ? (
                <Paper sx={{ p: 2, bgcolor: 'grey.900', maxHeight: 400, overflow: 'auto' }}>
                  <pre style={{ margin: 0, color: '#e0e0e0', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                    {JSON.stringify(wsSelectedFrame.payload_json, null, 2)}
                  </pre>
                </Paper>
              ) : wsSelectedFrame.payload_text ? (
                <Paper sx={{ p: 2, bgcolor: 'grey.900', maxHeight: 400, overflow: 'auto' }}>
                  <Typography sx={{ fontFamily: 'monospace', color: '#e0e0e0', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    {wsSelectedFrame.payload_text}
                  </Typography>
                </Paper>
              ) : wsSelectedFrame.payload_hex ? (
                <Paper sx={{ p: 2, bgcolor: 'grey.900', maxHeight: 400, overflow: 'auto' }}>
                  <Typography sx={{ fontFamily: 'monospace', color: '#e0e0e0', wordBreak: 'break-all' }}>
                    {wsSelectedFrame.payload_hex}
                  </Typography>
                </Paper>
              ) : (
                <Typography color="text.secondary">No payload data</Typography>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setWsSelectedFrame(null)}>Close</Button>
          {wsSelectedFrame?.payload_text && (
            <Button
              startIcon={<CopyIcon />}
              onClick={() => {
                navigator.clipboard.writeText(wsSelectedFrame.payload_text || '');
                setSuccess('Payload copied to clipboard');
              }}
            >
              Copy Payload
            </Button>
          )}
        </DialogActions>
      </Dialog>

      {/* New Template Dialog */}
      <Dialog open={showNewTemplateDialog} onClose={() => setShowNewTemplateDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Create Custom Template</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Template Name"
              value={newTemplate.name}
              onChange={(e) => setNewTemplate({ ...newTemplate, name: e.target.value })}
              fullWidth
              required
            />
            <TextField
              label="Description"
              value={newTemplate.description}
              onChange={(e) => setNewTemplate({ ...newTemplate, description: e.target.value })}
              fullWidth
              multiline
              rows={2}
              required
            />
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Category</InputLabel>
                  <Select
                    value={newTemplate.category}
                    label="Category"
                    onChange={(e) => setNewTemplate({ ...newTemplate, category: e.target.value })}
                  >
                    <MenuItem value="Custom">Custom</MenuItem>
                    <MenuItem value="Security Testing">Security Testing</MenuItem>
                    <MenuItem value="Debugging">Debugging</MenuItem>
                    <MenuItem value="Development">Development</MenuItem>
                    <MenuItem value="API Testing">API Testing</MenuItem>
                    <MenuItem value="Mobile Testing">Mobile Testing</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Match Type</InputLabel>
                  <Select
                    value={newTemplate.match_type}
                    label="Match Type"
                    onChange={(e) => setNewTemplate({ ...newTemplate, match_type: e.target.value })}
                  >
                    <MenuItem value="header">Header</MenuItem>
                    <MenuItem value="body">Body</MenuItem>
                    <MenuItem value="url">URL</MenuItem>
                    <MenuItem value="status">Status Code</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
            <TextField
              label="Match Pattern"
              value={newTemplate.match_pattern}
              onChange={(e) => setNewTemplate({ ...newTemplate, match_pattern: e.target.value })}
              fullWidth
              placeholder={newTemplate.is_regex ? 'Regular expression' : 'Exact match string'}
              required
            />
            <TextField
              label="Replace Pattern"
              value={newTemplate.replace_pattern}
              onChange={(e) => setNewTemplate({ ...newTemplate, replace_pattern: e.target.value })}
              fullWidth
              placeholder="Replacement text (use $1, $2 for regex groups)"
              required
            />
            <Grid container spacing={2}>
              <Grid item xs={4}>
                <FormControl fullWidth>
                  <InputLabel>Direction</InputLabel>
                  <Select
                    value={newTemplate.direction}
                    label="Direction"
                    onChange={(e) => setNewTemplate({ ...newTemplate, direction: e.target.value })}
                  >
                    <MenuItem value="request">Request</MenuItem>
                    <MenuItem value="response">Response</MenuItem>
                    <MenuItem value="both">Both</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={4}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={newTemplate.is_regex}
                      onChange={(e) => setNewTemplate({ ...newTemplate, is_regex: e.target.checked })}
                    />
                  }
                  label="Use Regex"
                />
              </Grid>
              <Grid item xs={4}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={newTemplate.case_sensitive}
                      onChange={(e) => setNewTemplate({ ...newTemplate, case_sensitive: e.target.checked })}
                    />
                  }
                  label="Case Sensitive"
                />
              </Grid>
            </Grid>
            <TextField
              label="Tags (comma-separated)"
              value={templateTagsInput}
              onChange={(e) => setTemplateTagsInput(e.target.value)}
              fullWidth
              placeholder="e.g., security, header-manipulation, auth"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowNewTemplateDialog(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleCreateTemplate}
            disabled={!newTemplate.name || !newTemplate.match_pattern || !newTemplate.replace_pattern}
          >
            Create Template
          </Button>
        </DialogActions>
      </Dialog>

      {/* Attack Goal Selection Dialog */}
      <Dialog
        open={showGoalDialog}
        onClose={() => setShowGoalDialog(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <AIIcon color="primary" />
            Set Attack Goals
          </Box>
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Select attack goals for the agent to prioritize. The agent will choose tools and actions
            that help achieve these goals.
          </Typography>
          <FormGroup>
            {[
              { id: 'compromise_authentication', label: 'Compromise Authentication', desc: 'Capture or bypass authentication mechanisms' },
              { id: 'exfiltrate_data', label: 'Exfiltrate Data', desc: 'Capture sensitive data from traffic' },
              { id: 'inject_payload', label: 'Inject Payloads', desc: 'Successfully inject scripts or content' },
              { id: 'downgrade_security', label: 'Downgrade Security', desc: 'Remove or bypass security mechanisms' },
              { id: 'map_attack_surface', label: 'Map Attack Surface', desc: 'Discover vulnerabilities and attack vectors' },
            ].map((goal) => (
              <FormControlLabel
                key={goal.id}
                control={
                  <Checkbox
                    checked={selectedGoals.includes(goal.id)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedGoals([...selectedGoals, goal.id]);
                      } else {
                        setSelectedGoals(selectedGoals.filter(g => g !== goal.id));
                      }
                    }}
                  />
                }
                label={
                  <Box>
                    <Typography variant="body1">{goal.label}</Typography>
                    <Typography variant="caption" color="text.secondary">{goal.desc}</Typography>
                  </Box>
                }
              />
            ))}
          </FormGroup>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowGoalDialog(false)}>Cancel</Button>
          <Button
            variant="contained"
            disabled={selectedGoals.length === 0 || !selectedProxy}
            onClick={() => selectedProxy && handleSetGoals(selectedProxy, selectedGoals)}
          >
            Set Goals ({selectedGoals.length})
          </Button>
        </DialogActions>
      </Dialog>

      {/* Agentic Session Results Dialog */}
      <Dialog 
        open={showAgenticResultDialog} 
        onClose={() => setShowAgenticResultDialog(false)} 
        maxWidth="lg" 
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <AIIcon color="primary" />
            Agentic Attack Session Results
          </Box>
        </DialogTitle>
        <DialogContent>
          {agenticSessionResult && (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
              {/* Summary Stats */}
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                <Paper sx={{ p: 2, flex: 1, minWidth: 150 }}>
                  <Typography variant="caption" color="text.secondary">Status</Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    {agenticSessionResult.status === 'completed' ? (
                      <SuccessIcon color="success" />
                    ) : agenticSessionResult.status === 'partial' ? (
                      <WarningIcon color="warning" />
                    ) : (
                      <ErrorIcon color="error" />
                    )}
                    <Typography variant="h6" sx={{ textTransform: 'capitalize' }}>
                      {agenticSessionResult.status}
                    </Typography>
                  </Box>
                </Paper>
                <Paper sx={{ p: 2, flex: 1, minWidth: 150 }}>
                  <Typography variant="caption" color="text.secondary">Tools Executed</Typography>
                  <Typography variant="h6">
                    {agenticSessionResult.tools_executed} / {agenticSessionResult.tools_recommended}
                  </Typography>
                </Paper>
                <Paper sx={{ p: 2, flex: 1, minWidth: 150 }}>
                  <Typography variant="caption" color="text.secondary">Findings</Typography>
                  <Typography variant="h6" color="error.main">
                    {agenticSessionResult.total_findings}
                  </Typography>
                </Paper>
                <Paper sx={{ p: 2, flex: 1, minWidth: 150 }}>
                  <Typography variant="caption" color="text.secondary">Duration</Typography>
                  <Typography variant="h6">
                    {agenticSessionResult.duration_seconds?.toFixed(1)}s
                  </Typography>
                </Paper>
              </Box>

              {/* AI Summary */}
              {agenticSessionResult.ai_summary && (
                <Alert severity="info" icon={<AIIcon />}>
                  <AlertTitle>AI Analysis Summary</AlertTitle>
                  <Typography variant="body2">{agenticSessionResult.ai_summary}</Typography>
                </Alert>
              )}

              {/* Agent Decision Log - Shows reasoning and feedback */}
              {agenticSessionResult.decision_log && agenticSessionResult.decision_log.length > 0 && (
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="subtitle1">
                        Agent Decision Log ({agenticSessionResult.decision_log.length} steps)
                      </Typography>
                      <Chip 
                        label="AI Reasoning" 
                        size="small" 
                        color="secondary" 
                        variant="outlined"
                      />
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                      {agenticSessionResult.decision_log.map((log: any, idx: number) => (
                        <Paper 
                          key={idx} 
                          variant="outlined" 
                          sx={{ 
                            p: 1.5, 
                            borderLeft: 3, 
                            borderColor: log.decision === 'execute' ? 'success.main' : 
                                        log.decision === 'stop' ? 'warning.main' : 'info.main'
                          }}
                        >
                          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                            <Typography variant="caption" color="primary" sx={{ fontWeight: 'bold' }}>
                              {log.step}
                            </Typography>
                            {log.decision && (
                              <Chip 
                                label={log.decision.toUpperCase()} 
                                size="small" 
                                color={log.decision === 'execute' ? 'success' : 'warning'}
                              />
                            )}
                          </Box>
                          {log.tool && (
                            <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                              Tool: {log.tool} (confidence: {(log.confidence * 100).toFixed(0)}%)
                            </Typography>
                          )}
                          {log.reason && (
                            <Typography variant="body2" color="text.secondary">
                              {log.reason}
                            </Typography>
                          )}
                          {log.analysis && (
                            <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                              {log.analysis}
                            </Typography>
                          )}
                          {log.feedback && (
                            <Typography variant="body2" color="success.main" sx={{ mt: 0.5 }}>
                              📊 {log.feedback}
                            </Typography>
                          )}
                          {log.suggested_follow_up && log.suggested_follow_up.length > 0 && (
                            <Box sx={{ mt: 0.5 }}>
                              <Typography variant="caption" color="text.secondary">
                                Suggested follow-ups: {log.suggested_follow_up.slice(0, 3).join(', ')}
                              </Typography>
                            </Box>
                          )}
                          {log.based_on && (
                            <Typography variant="caption" color="text.secondary" display="block">
                              {log.based_on}
                            </Typography>
                          )}
                        </Paper>
                      ))}
                    </Box>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Captured Data */}
              {agenticSessionResult.captured_data && 
               (agenticSessionResult.captured_data.credentials?.length > 0 || 
                agenticSessionResult.captured_data.tokens?.length > 0) && (
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="subtitle1" color="error">
                        Captured Credentials/Tokens
                      </Typography>
                      <Chip 
                        label={`${(agenticSessionResult.captured_data.credentials?.length || 0) + (agenticSessionResult.captured_data.tokens?.length || 0)} items`} 
                        size="small" 
                        color="error"
                      />
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Alert severity="error" sx={{ mb: 2 }}>
                      The following sensitive data was captured during the attack simulation. 
                      This demonstrates real security vulnerabilities!
                    </Alert>
                    {agenticSessionResult.captured_data.credentials?.map((cred: any, idx: number) => (
                      <Paper key={idx} variant="outlined" sx={{ p: 1, mb: 1, bgcolor: 'error.dark', opacity: 0.9 }}>
                        <Typography variant="caption">Type: {cred.type}</Typography>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {cred.username && `User: ${cred.username}`}
                          {cred.value && ` | Value: ${cred.value.substring(0, 20)}...`}
                        </Typography>
                      </Paper>
                    ))}
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Findings */}
              {agenticSessionResult.findings && agenticSessionResult.findings.length > 0 && (
                <Accordion defaultExpanded>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle1">
                      Findings ({agenticSessionResult.findings.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                      {agenticSessionResult.findings.map((finding: any, idx: number) => (
                        <Paper key={idx} variant="outlined" sx={{ p: 2 }}>
                          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>
                              {finding.title}
                            </Typography>
                            <Chip 
                              label={finding.severity} 
                              size="small"
                              color={
                                finding.severity?.toLowerCase() === 'critical' ? 'error' :
                                finding.severity?.toLowerCase() === 'high' ? 'warning' :
                                finding.severity?.toLowerCase() === 'medium' ? 'info' : 'default'
                              }
                            />
                          </Box>
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                            {finding.description}
                          </Typography>
                          {finding.evidence && (
                            <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 1 }}>
                              <Typography variant="caption" color="text.secondary">Evidence:</Typography>
                              <pre style={{ margin: 0, fontSize: '11px', overflow: 'auto', maxHeight: 80 }}>
                                {finding.evidence}
                              </pre>
                            </Box>
                          )}
                        </Paper>
                      ))}
                    </Box>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Execution Details */}
              {agenticSessionResult.execution_results && agenticSessionResult.execution_results.length > 0 && (
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle1">
                      Tool Execution Details ({agenticSessionResult.execution_results.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>Tool</TableCell>
                            <TableCell>Status</TableCell>
                            <TableCell>Findings</TableCell>
                            <TableCell>Duration</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {agenticSessionResult.execution_results.map((result: any, idx: number) => (
                            <TableRow key={idx}>
                              <TableCell>{result.tool_id}</TableCell>
                              <TableCell>
                                {result.success ? (
                                  <Chip label="Success" size="small" color="success" />
                                ) : (
                                  <Chip label="Failed" size="small" color="error" />
                                )}
                              </TableCell>
                              <TableCell>{result.findings?.length || 0}</TableCell>
                              <TableCell>{result.execution_time?.toFixed(2)}s</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </AccordionDetails>
                </Accordion>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowAgenticResultDialog(false)}>Close</Button>
          <Button 
            variant="contained" 
            onClick={() => {
              setShowAgenticResultDialog(false);
              setTabValue(3); // Switch to AI Analysis tab
            }}
          >
            View Full Analysis
          </Button>
        </DialogActions>
      </Dialog>

      {/* Saved Scan Detail Dialog */}
      <Dialog
        open={savedScanDialogOpen}
        onClose={() => {
          setSavedScanDialogOpen(false);
          setViewingSavedScan(null);
        }}
        maxWidth="lg"
        fullWidth
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <HistoryIcon color="primary" />
            <Box>
              <Typography variant="h6">
                {viewingSavedScan?.title || 'Saved Scan'}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {viewingSavedScan?.target_host}:{viewingSavedScan?.target_port} •{' '}
                {viewingSavedScan?.created_at ? new Date(viewingSavedScan.created_at).toLocaleString() : ''}
              </Typography>
            </Box>
          </Box>
          <Chip
            label={viewingSavedScan?.risk_level || 'info'}
            color={
              viewingSavedScan?.risk_level === 'critical' ? 'error' :
              viewingSavedScan?.risk_level === 'high' ? 'error' :
              viewingSavedScan?.risk_level === 'medium' ? 'warning' : 'success'
            }
          />
        </DialogTitle>
        <DialogContent dividers sx={{ maxHeight: '70vh' }}>
          {viewingSavedScan ? (
            <Box>
              {/* Summary */}
              {viewingSavedScan.summary && (
                <Box sx={{ mb: 3 }}>
                  <Typography variant="h6" gutterBottom>Summary</Typography>
                  <Paper sx={{ p: 2, bgcolor: 'background.default' }}>
                    <Typography variant="body2">{viewingSavedScan.summary}</Typography>
                  </Paper>
                </Box>
              )}

              {/* Findings */}
              {viewingSavedScan.findings && viewingSavedScan.findings.length > 0 && (
                <Box sx={{ mb: 3 }}>
                  <Typography variant="h6" gutterBottom>
                    Findings ({viewingSavedScan.findings.length})
                  </Typography>
                  <List dense>
                    {viewingSavedScan.findings.slice(0, 20).map((finding: any, idx: number) => (
                      <ListItem key={idx} sx={{ py: 0.5 }}>
                        <ListItemText
                          primary={
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              <Chip
                                label={finding.severity || 'info'}
                                size="small"
                                color={
                                  finding.severity === 'critical' ? 'error' :
                                  finding.severity === 'high' ? 'error' :
                                  finding.severity === 'medium' ? 'warning' : 'default'
                                }
                                sx={{ minWidth: 60 }}
                              />
                              <Typography variant="body2">{finding.title || finding.type}</Typography>
                            </Box>
                          }
                          secondary={finding.description}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              )}

              {/* Attack Chains */}
              {viewingSavedScan.attack_chains && viewingSavedScan.attack_chains.length > 0 && (
                <Box sx={{ mb: 3 }}>
                  <Typography variant="h6" gutterBottom>Attack Chains</Typography>
                  {viewingSavedScan.attack_chains.map((chain: any, idx: number) => (
                    <Accordion key={idx} defaultExpanded={idx === 0}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <RouteIcon fontSize="small" color="primary" />
                          <Typography variant="subtitle2">{chain.name || `Chain ${idx + 1}`}</Typography>
                          {chain.severity && (
                            <Chip label={chain.severity} size="small" color="warning" />
                          )}
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Typography variant="body2" color="text.secondary" paragraph>
                          {chain.description}
                        </Typography>
                        {chain.steps && (
                          <List dense>
                            {chain.steps.map((step: any, stepIdx: number) => (
                              <ListItem key={stepIdx}>
                                <ListItemText
                                  primary={`${stepIdx + 1}. ${step.tool || step.action || 'Step'}`}
                                  secondary={step.result || step.description}
                                />
                              </ListItem>
                            ))}
                          </List>
                        )}
                      </AccordionDetails>
                    </Accordion>
                  ))}
                </Box>
              )}

              {/* Decision Log */}
              {viewingSavedScan.decision_log && viewingSavedScan.decision_log.length > 0 && (
                <Box sx={{ mb: 3 }}>
                  <Typography variant="h6" gutterBottom>Decision Log</Typography>
                  <TableContainer component={Paper} variant="outlined">
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Step</TableCell>
                          <TableCell>Decision</TableCell>
                          <TableCell>Tool</TableCell>
                          <TableCell>Reason</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {viewingSavedScan.decision_log.slice(0, 30).map((log: any, idx: number) => (
                          <TableRow key={idx}>
                            <TableCell>{log.step}</TableCell>
                            <TableCell>{log.decision}</TableCell>
                            <TableCell>
                              {log.tool && <Chip label={log.tool} size="small" />}
                            </TableCell>
                            <TableCell>
                              <Typography variant="caption">{log.reason}</Typography>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              )}

              {/* Tools Used */}
              {viewingSavedScan.tools_used && viewingSavedScan.tools_used.length > 0 && (
                <Box sx={{ mb: 3 }}>
                  <Typography variant="h6" gutterBottom>Tools Used</Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {viewingSavedScan.tools_used.map((tool: string, idx: number) => (
                      <Chip key={idx} label={tool} size="small" variant="outlined" />
                    ))}
                  </Box>
                </Box>
              )}
            </Box>
          ) : (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
              <CircularProgress />
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => {
            setSavedScanDialogOpen(false);
            setViewingSavedScan(null);
          }}>
            Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Notifications */}
      <Snackbar
        open={!!error}
        autoHideDuration={6000}
        onClose={() => setError(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert severity="error" onClose={() => setError(null)}>
          {error}
        </Alert>
      </Snackbar>

      <Snackbar
        open={!!success}
        autoHideDuration={3000}
        onClose={() => setSuccess(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert severity="success" onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      </Snackbar>

      {/* AI Chat Panel - only show after analysis completed */}
      <MitmChatPanel
        analysisResult={analysisResult}
        trafficLog={traffic}
        proxyConfig={currentProxy || null}
        rules={rules}
      />
    </Box>
  );
};

export default MITMWorkbenchPage;
