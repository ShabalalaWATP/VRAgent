import React, { useState, useRef, useCallback, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Grid,
  Chip,
  Alert,
  CircularProgress,
  LinearProgress,
  Divider,
  IconButton,
  Tooltip,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  Tabs,
  Tab,
  Badge,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Collapse,
  alpha,
  useTheme,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Menu,
} from '@mui/material';
import {
  PlayArrow,
  Stop,
  BugReport,
  Memory,
  Speed,
  Timer,
  ExpandMore,
  ExpandLess,
  OpenInFull,
  CloseFullscreen,
  Refresh,
  Download,
  Warning,
  Error as ErrorIcon,
  CheckCircle,
  Info,
  Folder,
  Description,
  Terminal,
  Assessment,
  Security,
  Code,
  TrendingUp,
  Storage,
  Star,
  Science,
  RocketLaunch,
  School,
  NavigateNext,
  NavigateBefore,
  Check,
  Lightbulb,
  HelpOutline,
  Timeline,
  ShowChart,
  FolderOpen,
  Close,
  ContentCopy,
  Article,
  PictureAsPdf,
  Visibility,
  DataObject,
  BugReportOutlined,
  MemoryOutlined,
  Psychology,
  AutoAwesome,
  Inventory,
  Delete,
  FilePresent,
  Compress,
  Upload,
  Search,
  FilterList,
  Sort,
  InsertDriveFile,
  TextSnippet,
  TrendingDown,
  SelectAll,
  PictureAsPdf as PdfIcon,
  Chat as ChatIcon,
  SmartToy as SmartToyIcon,
  Person as PersonIcon,
  Send as SendIcon,
  DeveloperBoard,
  Architecture,
  Hub,
  Computer,
  SettingsEthernet,
  FlashOn,
  Speed as SpeedIcon,
} from '@mui/icons-material';
import ReactMarkdown from 'react-markdown';
import { ChatCodeBlock } from '../components/ChatCodeBlock';
import { jsPDF } from 'jspdf';
import { saveAs } from 'file-saver';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';

// Chat message interface
interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

// Batch analysis result interface
interface BatchExploitResult {
  crash_id: string;
  crash_type: string;
  exploitability: string;
  exploitability_score: number;
  vulnerability_type: string;
  root_cause: string;
  poc_guidance: string;
}

// QEMU Mode Types
interface QemuCapabilities {
  available: boolean;
  architectures: string[];
  features: {
    persistent_qemu: boolean;
    compcov: boolean;
    instrim: boolean;
  };
  version: string | null;
  tools: Record<string, string | null>;
  error_message?: string;
  summary?: {
    can_fuzz_closed_source: boolean;
    supported_architectures: string[];
    has_persistent_mode: boolean;
    has_compcov: boolean;
  };
  how_to_fix?: string;
}

interface BinaryArchitectureInfo {
  architecture: string;
  bits: number | string;
  endian: string;
  is_stripped: boolean;
  is_pie: boolean;
  file_type: string;
  libraries?: string[];
}

interface QemuBinaryAnalysis {
  binary_path: string;
  architecture: BinaryArchitectureInfo;
  recommendations: {
    mode: string;
    tips: string[];
    warnings: string[];
    optimal_settings: Record<string, any>;
  };
  qemu_supported: boolean;
  beginner_summary: {
    what_is_this_binary: string;
    can_we_fuzz_it: boolean;
    difficulty: string;
    things_to_know: string[];
    warnings?: string[];
    helpful_tips?: string[];
  };
}

interface QemuTraceAnalysis {
  unique_basic_blocks: number;
  total_basic_blocks: number;
  execution_time_ms: number;
  hot_spots?: { address: string; count: number }[];
  coverage_map?: string;
}

interface QemuHelp {
  overview: string;
  when_to_use: string[];
  modes: {
    standard: { description: string; pros: string[]; cons: string[] };
    persistent: { description: string; pros: string[]; cons: string[] };
    compcov: { description: string; pros: string[]; cons: string[] };
  };
  supported_architectures: string[];
  common_issues: { issue: string; solution: string }[];
  tips: string[];
}

// Types
interface FuzzingConfig {
  target_path: string;
  target_args: string;
  seed_dir: string;
  output_dir: string;
  timeout_ms: number;
  max_iterations: number | null;
  max_time_seconds: number | null;
  dictionary: string[];
  // Phase 2: Coverage-guided options
  coverage_guided: boolean;
  scheduler_strategy: string;
}

interface FuzzingStats {
  total_executions: number;
  total_crashes: number;
  unique_crashes: number;
  total_timeouts: number;
  exec_per_sec: number;
  elapsed_seconds: number;
  // Phase 2: Coverage stats
  total_edges: number;
  coverage_pct: number;
  corpus_size: number;
  favored_inputs: number;
  new_coverage_inputs: number;
  // Phase 3: Memory safety stats
  memory_errors: number;
  heap_errors: number;
  stack_errors: number;
  uaf_errors: number;
  exploitable_errors: number;
}

interface CrashBucket {
  id: string;
  crash_type: string;
  severity: string;
  stack_hash: string;
  sample_count: number;
  first_seen: string;
  last_seen: string;
  sample_crashes: string[];
  notes: string;
  // Extended details for crash dialog
  stack_trace?: string[];
  registers?: Record<string, string>;
  memory_dump?: string;
  crash_address?: string;
  faulting_instruction?: string;
  input_file?: string;
  input_data?: string; // Base64 or hex encoded
}

interface CrashDetails {
  bucket: CrashBucket;
  expanded: boolean;
}

// Corpus file interface
interface CorpusFile {
  id: string;
  filename: string;
  size: number;
  coverage_edges: number;
  is_favored: boolean;
  created_at: string;
  source: 'seed' | 'mutation' | 'crash';
  data?: string; // Base64 encoded
  preview?: string;
}

// AI Analysis result interface
interface AIAnalysisResult {
  crash_id: string;
  summary: string;
  root_cause: string;
  exploitability: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  attack_vector?: string;
  affected_components: string[];
  recommendations: string[];
  similar_cves?: string[];
  confidence: number;
  analysis_timestamp: string;
}

interface FuzzingEvent {
  type: string;
  [key: string]: any;
}

// Severity color mapping
const severityColors: Record<string, 'error' | 'warning' | 'info' | 'success'> = {
  exploitable: 'error',
  probably_exploitable: 'warning',
  probably_not_exploitable: 'info',
  not_exploitable: 'success',
  unknown: 'info',
};

const crashTypeLabels: Record<string, string> = {
  access_violation_read: 'Access Violation (Read)',
  access_violation_write: 'Access Violation (Write)',
  access_violation_execute: 'Access Violation (Execute)',
  stack_buffer_overflow: 'Stack Buffer Overflow',
  heap_corruption: 'Heap Corruption',
  use_after_free: 'Use After Free',
  double_free: 'Double Free',
  null_pointer: 'Null Pointer Dereference',
  divide_by_zero: 'Divide by Zero',
  integer_overflow: 'Integer Overflow',
  stack_exhaustion: 'Stack Exhaustion',
  assertion_failure: 'Assertion Failure',
  timeout: 'Timeout',
  unknown: 'Unknown',
};

const schedulerStrategies = [
  { value: 'power_schedule', label: 'Power Schedule (AFL-style adaptive)' },
  { value: 'favored_first', label: 'Favored First (unique edge priority)' },
  { value: 'rare_edge', label: 'Rare Edge (hit rare code paths)' },
  { value: 'round_robin', label: 'Round Robin (cycle all seeds)' },
  { value: 'random', label: 'Random Selection' },
];

// Wizard steps for beginners
const WIZARD_STEPS = [
  {
    id: 'welcome',
    title: 'Welcome to Binary Fuzzing',
    icon: <RocketLaunch />,
    description: `Binary fuzzing is an automated technique to find security vulnerabilities in compiled programs by feeding them random or semi-random inputs.

**What you'll learn:**
- How to set up your first fuzzing session
- Understanding coverage-guided fuzzing
- Interpreting crash results

**Prerequisites:**
- A compiled executable (EXE, ELF, etc.)
- Sample input files (seeds) for your target
- Basic understanding of what your target program does`,
    tips: [
      'Start with a simple target that processes file input',
      'Use a debug build with symbols for better crash analysis',
      'Consider compiling with AddressSanitizer for enhanced detection',
    ],
  },
  {
    id: 'target',
    title: 'Configure Your Target',
    icon: <Terminal />,
    description: `The **target executable** is the program you want to test for vulnerabilities.

**Target Path:** Full path to the executable file
- Example: \`C:\\tools\\pdfparser.exe\` or \`/usr/bin/imagemagick\`

**Command Line Arguments:** How the target receives input
- Use \`@@\` as a placeholder for the input file path
- Example: \`-i @@ -o /dev/null\` means the fuzzer replaces \`@@\` with the test file

**Common patterns:**
- File input: \`@@\` or \`--input @@\`
- Stdin: Leave empty (fuzzer will pipe input)
- Multiple args: \`-f @@ --verbose --timeout 5\``,
    tips: [
      'Use @@ to mark where the input file should go',
      'Test your target manually first to understand its behavior',
      'Disable unnecessary features like GUI or network access',
    ],
  },
  {
    id: 'seeds',
    title: 'Prepare Seed Files',
    icon: <FolderOpen />,
    description: `**Seed files** are valid sample inputs that the fuzzer will mutate to find bugs.

**Why seeds matter:**
- Good seeds help the fuzzer reach deeper code paths
- They should represent different features of your target
- Smaller seeds = faster fuzzing

**Seed Directory:** Folder containing your initial test files

**Best practices:**
- Include diverse examples (different file sizes, features)
- Use minimal valid files (smallest working input)
- Avoid duplicates and very large files`,
    tips: [
      'Start with 5-20 small, valid input files',
      'Include edge cases: empty files, minimal valid files',
      'Use corpus minimization tools if you have many seeds',
    ],
  },
  {
    id: 'coverage',
    title: 'Coverage-Guided Fuzzing',
    icon: <TrendingUp />,
    description: `**Coverage guidance** tracks which code paths your inputs execute, helping the fuzzer explore new areas.

**How it works:**
1. Fuzzer runs an input and records which code "edges" were hit
2. If a mutated input discovers new edges, it's saved
3. The corpus grows with inputs that explore unique paths

**Scheduler Strategies:**
- **Power Schedule:** AFL-style adaptive energy allocation
- **Favored First:** Prioritize inputs hitting unique edges
- **Rare Edge:** Focus on rarely-executed code paths

**Edge Count:** Number of unique control-flow transitions discovered`,
    tips: [
      'Enable coverage guidance for best results',
      'Watch the "Edges Discovered" metric - it should grow',
      'A plateauing edge count may mean the target is fully explored',
    ],
  },
  {
    id: 'crashes',
    title: 'Understanding Crashes',
    icon: <BugReport />,
    description: `When the fuzzer finds inputs that crash your target, it categorizes them by **type** and **exploitability**.

**Crash Types:**
- **Stack Buffer Overflow:** Writing past stack buffer bounds
- **Heap Corruption:** Invalid heap memory operations
- **Use After Free:** Accessing freed memory
- **Null Pointer:** Dereferencing null/invalid pointers

**Exploitability:**
- 🔴 **Exploitable:** High chance of code execution
- 🟠 **Probably Exploitable:** Likely exploitable
- 🟡 **Probably Not Exploitable:** Unlikely to be exploitable
- 🟢 **Not Exploitable:** Crashes but no security impact

**Crash Buckets:** Similar crashes are grouped by their stack trace hash`,
    tips: [
      'Focus on "Exploitable" crashes first',
      'Check the crash input file to understand the trigger',
      'Use a debugger (GDB/WinDbg) for detailed analysis',
    ],
  },
  {
    id: 'start',
    title: 'Start Fuzzing!',
    icon: <PlayArrow />,
    description: `You're ready to start fuzzing! Here's what to expect:

**During fuzzing:**
- **exec/sec:** Execution speed (higher = faster testing)
- **Unique Crashes:** Distinct bugs found
- **Edges Discovered:** Code coverage metric
- **Corpus Size:** Number of interesting inputs saved

**Good signs:**
- Edge count growing steadily
- exec/sec remaining stable
- Finding crashes (that's the goal!)

**When to stop:**
- Edge count plateaus for extended time
- Reached your time/iteration limit
- Found enough bugs to analyze`,
    tips: [
      'Let it run for at least an hour for meaningful results',
      'Monitor memory usage - fuzzing can be resource intensive',
      'Export your crashes for later analysis',
    ],
  },
];

// Coverage data point for charting
interface CoverageDataPoint {
  time: number;
  edges: number;
  corpus: number;
  crashes: number;
}

const BinaryFuzzerPage: React.FC = () => {
  const theme = useTheme();
  
  // State
  const [config, setConfig] = useState<FuzzingConfig>({
    target_path: '',
    target_args: '@@',
    seed_dir: '',
    output_dir: '',
    timeout_ms: 5000,
    max_iterations: 10000,
    max_time_seconds: null,
    dictionary: [],
    // Phase 2 defaults
    coverage_guided: true,
    scheduler_strategy: 'power_schedule',
  });

  const [isRunning, setIsRunning] = useState(false);
  const [stats, setStats] = useState<FuzzingStats>({
    total_executions: 0,
    total_crashes: 0,
    unique_crashes: 0,
    total_timeouts: 0,
    exec_per_sec: 0,
    elapsed_seconds: 0,
    // Phase 2
    total_edges: 0,
    coverage_pct: 0,
    corpus_size: 0,
    favored_inputs: 0,
    new_coverage_inputs: 0,
    // Phase 3: Memory safety
    memory_errors: 0,
    heap_errors: 0,
    stack_errors: 0,
    uaf_errors: 0,
    exploitable_errors: 0,
  });
  const [crashes, setCrashes] = useState<CrashBucket[]>([]);
  const [events, setEvents] = useState<FuzzingEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState(0);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [dictionaryInput, setDictionaryInput] = useState('');
  
  // Wizard state
  const [wizardMode, setWizardMode] = useState(false);
  const [wizardStep, setWizardStep] = useState(0);
  const [showGuide, setShowGuide] = useState(true);
  
  // Coverage history for chart
  const [coverageHistory, setCoverageHistory] = useState<CoverageDataPoint[]>([]);
  const coverageChartRef = useRef<HTMLDivElement>(null);
  
  // Crash details dialog state
  const [selectedCrash, setSelectedCrash] = useState<CrashBucket | null>(null);
  const [crashDialogOpen, setCrashDialogOpen] = useState(false);
  const [crashDialogTab, setCrashDialogTab] = useState(0);
  
  // Export state
  const [exportMenuAnchor, setExportMenuAnchor] = useState<null | HTMLElement>(null);
  const [exportLoading, setExportLoading] = useState(false);
  
  // Corpus Browser state
  const [corpusFiles, setCorpusFiles] = useState<CorpusFile[]>([]);
  const [selectedCorpusFile, setSelectedCorpusFile] = useState<CorpusFile | null>(null);
  const [corpusDialogOpen, setCorpusDialogOpen] = useState(false);
  const [corpusFilter, setCorpusFilter] = useState<'all' | 'seed' | 'mutation' | 'favored'>('all');
  const [corpusSortBy, setCorpusSortBy] = useState<'date' | 'size' | 'coverage'>('date');
  const [corpusSearchQuery, setCorpusSearchQuery] = useState('');
  
  // AI Analysis state
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysisResult | null>(null);
  const [aiAnalysisLoading, setAiAnalysisLoading] = useState(false);
  const [aiAnalysisError, setAiAnalysisError] = useState<string | null>(null);
  
  // Enhanced AI Features state
  const [aiSeeds, setAiSeeds] = useState<{
    name: string;
    path: string;
    size: number;
    description: string;
    format_type: string;
    mutation_hints: string[];
  }[]>([]);
  const [aiSeedGenerating, setAiSeedGenerating] = useState(false);
  const [aiSeedAnalysis, setAiSeedAnalysis] = useState<{
    input_format_analysis: string;
    fuzzing_strategy: string;
    recommended_dictionary: string[];
  } | null>(null);
  
  const [coverageAdvice, setCoverageAdvice] = useState<{
    is_stuck: boolean;
    stuck_reason: string | null;
    coverage_trend: string;
    recommendations: string[];
    mutation_adjustments: Record<string, any>;
    priority_areas: string[];
  } | null>(null);
  const [coverageAdviceLoading, setCoverageAdviceLoading] = useState(false);
  
  const [exploitAnalysis, setExploitAnalysis] = useState<{
    crash_id: string;
    exploitability: string;
    exploitability_score: number;
    vulnerability_type: string;
    root_cause: string;
    affected_functions: string[];
    exploitation_techniques: string[];
    poc_guidance: string;
    mitigation_bypass: string[];
    similar_cves: string[];
    remediation: string;
    detailed_analysis: string;
  } | null>(null);
  const [exploitAnalysisLoading, setExploitAnalysisLoading] = useState(false);
  
  const [binaryAnalysis, setBinaryAnalysis] = useState<{
    file_type: string;
    architecture: string;
    is_stripped: boolean;
    has_symbols: boolean;
    input_functions: string[];
    security_functions: string[];
    interesting_strings: string[];
  } | null>(null);
  const [binaryAnalysisLoading, setBinaryAnalysisLoading] = useState(false);
  
  // AI feature sub-tab (0: Seed Gen, 1: Coverage, 2: Exploit, 3: Summary)
  const [aiSubTab, setAiSubTab] = useState<number>(0);
  
  // Auto-advisor state (uses existing coverageHistory)
  const [lastCoverageUpdate, setLastCoverageUpdate] = useState<number>(0);
  const [autoAdvisorEnabled, setAutoAdvisorEnabled] = useState(true);
  const [autoAdvisorTriggered, setAutoAdvisorTriggered] = useState(false);
  
  // Batch analysis state
  const [batchAnalysisResults, setBatchAnalysisResults] = useState<BatchExploitResult[]>([]);
  const [batchAnalysisLoading, setBatchAnalysisLoading] = useState(false);
  const [batchAnalysisProgress, setBatchAnalysisProgress] = useState(0);
  
  // AI Chat state
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMaximized, setChatMaximized] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatEndRef = useRef<HTMLDivElement | null>(null);
  
  // File Upload state
  const [uploadedBinary, setUploadedBinary] = useState<{
    binary_id: string;
    name: string;
    path: string;
    size: number;
    file_type: string;
  } | null>(null);
  const [uploadedSeeds, setUploadedSeeds] = useState<{
    seed_id: string;
    name: string;
    path: string;
    size: number;
  }[]>([]);
  const [binaryUploading, setBinaryUploading] = useState(false);
  const [seedsUploading, setSeedsUploading] = useState(false);
  const [availableBinaries, setAvailableBinaries] = useState<{
    binary_id: string;
    name: string;
    path: string;
    size: number;
    uploaded_at: string;
  }[]>([]);
  const [aflStatus, setAflStatus] = useState<{
    installed: boolean;
    version: string | null;
    tools: Record<string, string | null>;
  } | null>(null);
  const binaryInputRef = useRef<HTMLInputElement>(null);
  const seedsInputRef = useRef<HTMLInputElement>(null);

  // QEMU Mode State
  const [qemuCapabilities, setQemuCapabilities] = useState<QemuCapabilities | null>(null);
  const [qemuCapabilitiesLoading, setQemuCapabilitiesLoading] = useState(false);
  const [qemuBinaryAnalysis, setQemuBinaryAnalysis] = useState<QemuBinaryAnalysis | null>(null);
  const [qemuBinaryAnalysisLoading, setQemuBinaryAnalysisLoading] = useState(false);
  const [qemuTraceAnalysis, setQemuTraceAnalysis] = useState<QemuTraceAnalysis | null>(null);
  const [qemuTraceLoading, setQemuTraceLoading] = useState(false);
  const [qemuHelp, setQemuHelp] = useState<QemuHelp | null>(null);
  const [qemuHelpLoading, setQemuHelpLoading] = useState(false);
  const [qemuSubTab, setQemuSubTab] = useState(0);
  const [qemuFuzzConfig, setQemuFuzzConfig] = useState({
    mode: 'standard' as 'standard' | 'persistent' | 'compcov',
    persistent_address: '',
    persistent_count: 10000,
    enable_compcov: false,
    timeout_ms: 10000,
    memory_limit_mb: 512,
    env_vars: {} as Record<string, string>,
  });
  const [qemuFuzzLoading, setQemuFuzzLoading] = useState(false);
  const [qemuTraceInputFile, setQemuTraceInputFile] = useState('');
  const [qemuTraceInputData, setQemuTraceInputData] = useState('');

  // WebSocket ref
  const wsRef = useRef<WebSocket | null>(null);

  // Connect WebSocket
  const connectWebSocket = useCallback(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/binary-fuzzer/ws`;

    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log('Binary Fuzzer WebSocket connected');
      setError(null);
    };

    ws.onmessage = (event) => {
      try {
        const data: FuzzingEvent = JSON.parse(event.data);
        handleFuzzingEvent(data);
      } catch (e) {
        console.error('Failed to parse WebSocket message:', e);
      }
    };

    ws.onerror = (event) => {
      console.error('WebSocket error:', event);
      setError('WebSocket connection error');
    };

    ws.onclose = () => {
      console.log('WebSocket disconnected');
      setIsRunning(false);
    };

    wsRef.current = ws;
  }, []);

  // Handle fuzzing events
  const handleFuzzingEvent = useCallback((event: FuzzingEvent) => {
    setEvents((prev) => [...prev.slice(-99), event]); // Keep last 100 events

    switch (event.type) {
      case 'session_started':
      case 'session_start':  // AFL++ event
        setSessionId(event.session_id);
        setIsRunning(true);
        // Initialize corpus size from session start
        if (event.corpus_size) {
          setStats((prev) => ({ ...prev, corpus_size: event.corpus_size }));
        }
        break;

      case 'stats_update':
        setStats({
          total_executions: event.iteration || 0,
          total_crashes: event.total_crashes || 0,
          unique_crashes: event.unique_crashes || 0,
          total_timeouts: event.timeouts || 0,
          exec_per_sec: event.exec_per_sec || 0,
          elapsed_seconds: event.elapsed_seconds || 0,
          // Phase 2: Coverage stats
          total_edges: event.total_edges || 0,
          coverage_pct: event.coverage_pct || 0,
          corpus_size: event.corpus_size || 0,
          favored_inputs: event.favored_inputs || 0,
          new_coverage_inputs: event.new_coverage_inputs || 0,
          // Phase 3: Memory safety stats
          memory_errors: event.memory_errors || 0,
          heap_errors: event.heap_errors || 0,
          stack_errors: event.stack_errors || 0,
          uaf_errors: event.uaf_errors || 0,
          exploitable_errors: event.exploitable_errors || 0,
        });
        // Record coverage history for chart (every 5 seconds or so)
        setCoverageHistory((prev) => {
          const elapsed = event.elapsed_seconds || 0;
          // Only add new point if at least 5 seconds have passed
          if (prev.length === 0 || elapsed - prev[prev.length - 1].time >= 5) {
            return [...prev.slice(-100), { // Keep last 100 points
              time: elapsed,
              edges: event.total_edges || 0,
              corpus: event.corpus_size || 0,
              crashes: event.unique_crashes || 0,
            }];
          }
          return prev;
        });
        break;

      // AFL++ real-time status event
      case 'status':
        if (event.stats) {
          setStats({
            total_executions: event.stats.execs_done || 0,
            total_crashes: event.stats.unique_crashes || 0,
            unique_crashes: event.stats.unique_crashes || 0,
            total_timeouts: event.stats.unique_hangs || 0,
            exec_per_sec: event.stats.execs_per_sec || 0,
            elapsed_seconds: event.runtime_seconds || 0,
            total_edges: event.stats.paths_total || 0,
            coverage_pct: event.stats.map_coverage || 0,
            corpus_size: event.stats.paths_found || 0,
            favored_inputs: event.stats.pending_favs || 0,
            new_coverage_inputs: event.stats.paths_found || 0,
            memory_errors: 0,
            heap_errors: 0,
            stack_errors: 0,
            uaf_errors: 0,
            exploitable_errors: 0,
          });
          // Update crash list from AFL++
          if (event.crashes && event.crashes.length > 0) {
            setCrashes(event.crashes.map((c: { id: string; size: number; timestamp: number; input_preview: string }) => ({
              id: c.id,
              crash_type: 'UNKNOWN',
              severity: 'unknown',
              stack_hash: c.id.substring(0, 16),
              sample_count: 1,
              first_seen: new Date(c.timestamp * 1000).toISOString(),
              last_seen: new Date(c.timestamp * 1000).toISOString(),
              sample_crashes: [c.id],
              notes: `Size: ${c.size} bytes`,
            })));
          }
          // Record coverage history
          setCoverageHistory((prev) => {
            const elapsed = event.runtime_seconds || 0;
            if (prev.length === 0 || elapsed - prev[prev.length - 1].time >= 5) {
              return [...prev.slice(-100), {
                time: elapsed,
                edges: event.stats.paths_total || 0,
                corpus: event.stats.paths_found || 0,
                crashes: event.stats.unique_crashes || 0,
              }];
            }
            return prev;
          });
        }
        break;

      case 'new_coverage':
        // Update corpus size when new coverage is found
        setStats((prev) => ({
          ...prev,
          total_edges: event.total_edges || prev.total_edges,
          corpus_size: event.corpus_size || prev.corpus_size,
          new_coverage_inputs: (prev.new_coverage_inputs || 0) + 1,
        }));
        break;

      case 'new_crash':
        setCrashes((prev) => [
          {
            id: event.bucket_id,
            crash_type: event.crash_type,
            severity: event.severity,
            stack_hash: event.input_hash?.substring(0, 16) || '',
            sample_count: 1,
            first_seen: new Date().toISOString(),
            last_seen: new Date().toISOString(),
            sample_crashes: [event.crash_id],
            notes: '',
          },
          ...prev,
        ]);
        break;

      case 'duplicate_crash':
        setCrashes((prev) =>
          prev.map((c) =>
            c.id === event.bucket_id
              ? { ...c, sample_count: c.sample_count + 1, last_seen: new Date().toISOString() }
              : c
          )
        );
        break;

      case 'session_completed':
      case 'session_end':  // AFL++ event
      case 'session_stopped':  // AFL++ stop event
      case 'cancelled':
      case 'max_iterations_reached':
      case 'max_time_reached':
        setIsRunning(false);
        break;

      case 'error':
        setError(event.error);
        setIsRunning(false);
        break;
    }
  }, []);

  // Start fuzzing
  const startFuzzing = useCallback(() => {
    // Use uploaded binary path if available, otherwise use config
    const targetPath = uploadedBinary?.path || config.target_path;
    const seedDir = uploadedSeeds.length > 0 
      ? `/fuzzing/seeds/${uploadedBinary?.binary_id}`
      : config.seed_dir;
    
    if (!targetPath) {
      setError('Please upload a binary or specify a target path');
      return;
    }

    // Determine whether to use AFL++ or built-in fuzzer
    const useAfl = aflStatus?.installed && uploadedBinary;
    const wsEndpoint = useAfl ? '/api/binary-fuzzer/afl/ws' : '/api/binary-fuzzer/ws';
    
    // Build the start message
    const startMessage = useAfl
      ? {
          action: 'start',
          target_path: targetPath,
          target_args: config.target_args || '@@',
          input_dir: seedDir || '/fuzzing/seeds',
          output_dir: `/fuzzing/output/${uploadedBinary?.binary_id}`,
          timeout_ms: config.timeout_ms,
          memory_limit_mb: 256,
          use_qemu: true,
        }
      : {
          action: 'start',
          target_path: targetPath,
          target_args: config.target_args,
          seed_dir: seedDir,
          output_dir: config.output_dir || `/fuzzing/output/${Date.now()}`,
          timeout_ms: config.timeout_ms,
          max_iterations: config.max_iterations,
          max_time_seconds: config.max_time_seconds,
          dictionary: config.dictionary.length > 0 ? config.dictionary : undefined,
          coverage_guided: config.coverage_guided,
          scheduler_strategy: config.scheduler_strategy,
        };

    // Connect to the appropriate WebSocket
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}${wsEndpoint}`;
    
    // Close existing connection if different endpoint
    if (wsRef.current) {
      wsRef.current.close();
    }

    const ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
      console.log(`Fuzzer WebSocket connected (${useAfl ? 'AFL++' : 'built-in'})`);
      setError(null);
      // Send start message
      ws.send(JSON.stringify(startMessage));
    };

    ws.onmessage = (event) => {
      try {
        const data: FuzzingEvent = JSON.parse(event.data);
        handleFuzzingEvent(data);
      } catch (e) {
        console.error('Failed to parse WebSocket message:', e);
      }
    };

    ws.onerror = (event) => {
      console.error('WebSocket error:', event);
      setError('WebSocket connection error');
    };

    ws.onclose = () => {
      console.log('WebSocket disconnected');
      setIsRunning(false);
    };

    wsRef.current = ws;
    
    // Reset state
    setEvents([]);
    setCrashes([]);
    setCoverageHistory([]);
    setStats({
      total_executions: 0,
      total_crashes: 0,
      unique_crashes: 0,
      total_timeouts: 0,
      exec_per_sec: 0,
      elapsed_seconds: 0,
      total_edges: 0,
      coverage_pct: 0,
      corpus_size: 0,
      favored_inputs: 0,
      new_coverage_inputs: 0,
      memory_errors: 0,
      heap_errors: 0,
      stack_errors: 0,
      uaf_errors: 0,
      exploitable_errors: 0,
    });
    setIsRunning(true);
  }, [config, uploadedBinary, uploadedSeeds, aflStatus]);

  // Stop fuzzing
  const stopFuzzing = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: 'stop' }));
    }
    setIsRunning(false);
  }, []);

  // Add dictionary entry
  const addDictionaryEntry = useCallback(() => {
    if (dictionaryInput.trim()) {
      setConfig((prev) => ({
        ...prev,
        dictionary: [...prev.dictionary, dictionaryInput.trim()],
      }));
      setDictionaryInput('');
    }
  }, [dictionaryInput]);

  // Open crash details dialog
  const openCrashDialog = useCallback((crash: CrashBucket) => {
    setSelectedCrash(crash);
    setCrashDialogOpen(true);
    setCrashDialogTab(0);
  }, []);

  // Close crash details dialog
  const closeCrashDialog = useCallback(() => {
    setCrashDialogOpen(false);
    setSelectedCrash(null);
  }, []);

  // Copy to clipboard helper with fallback
  const copyToClipboard = useCallback((text: string) => {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      navigator.clipboard.writeText(text).catch((err) => {
        console.warn('Clipboard API failed, using fallback:', err);
        fallbackCopyToClipboard(text);
      });
    } else {
      fallbackCopyToClipboard(text);
    }
  }, []);

  // Fallback for older browsers or non-HTTPS contexts
  const fallbackCopyToClipboard = (text: string) => {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-9999px';
    textArea.style.top = '-9999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
      document.execCommand('copy');
    } catch (err) {
      console.error('Fallback copy failed:', err);
    }
    document.body.removeChild(textArea);
  };

  // Generate hex dump from input data
  const generateHexDump = useCallback((data: string, bytesPerLine: number = 16): string[] => {
    // Simulate hex dump for crash input
    const lines: string[] = [];
    const bytes = data || 'No input data available';
    for (let i = 0; i < Math.min(bytes.length, 256); i += bytesPerLine) {
      const slice = bytes.slice(i, i + bytesPerLine);
      const hex = Array.from(slice).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
      const ascii = Array.from(slice).map(c => (c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126) ? c : '.').join('');
      lines.push(`${i.toString(16).padStart(8, '0')}  ${hex.padEnd(bytesPerLine * 3 - 1, ' ')}  |${ascii}|`);
    }
    return lines;
  }, []);

  // Generate Markdown report
  const generateMarkdownReport = useCallback((): string => {
    const now = new Date().toLocaleString();
    let md = `# 🔬 Binary Fuzzing Security Report\n\n`;
    md += `**Generated:** ${now}\n\n`;
    md += `**Target:** \`${config.target_path}\`\n\n`;
    md += `**Arguments:** \`${config.target_args}\`\n\n`;
    md += `**Seed Directory:** \`${config.seed_dir}\`\n\n`;
    md += `---\n\n`;

    // Executive Summary
    md += `## 📊 Executive Summary\n\n`;
    md += `| Metric | Value |\n`;
    md += `|--------|-------|\n`;
    md += `| Total Executions | ${stats.total_executions.toLocaleString()} |\n`;
    md += `| Unique Crashes | ${stats.unique_crashes} |\n`;
    md += `| Total Crashes | ${stats.total_crashes} |\n`;
    md += `| Timeouts | ${stats.total_timeouts} |\n`;
    md += `| Execution Speed | ${stats.exec_per_sec.toFixed(1)} exec/sec |\n`;
    md += `| Elapsed Time | ${Math.floor(stats.elapsed_seconds)}s |\n\n`;

    if (config.coverage_guided) {
      md += `### Coverage Statistics\n\n`;
      md += `| Metric | Value |\n`;
      md += `|--------|-------|\n`;
      md += `| Edges Discovered | ${stats.total_edges.toLocaleString()} |\n`;
      md += `| Corpus Size | ${stats.corpus_size} |\n`;
      md += `| Favored Inputs | ${stats.favored_inputs} |\n`;
      md += `| New Coverage Inputs | ${stats.new_coverage_inputs} |\n\n`;
    }

    if (stats.memory_errors > 0) {
      md += `### Memory Safety Analysis\n\n`;
      md += `| Error Type | Count |\n`;
      md += `|------------|-------|\n`;
      md += `| Memory Errors | ${stats.memory_errors} |\n`;
      md += `| Heap Errors | ${stats.heap_errors} |\n`;
      md += `| Stack Errors | ${stats.stack_errors} |\n`;
      md += `| Use-After-Free | ${stats.uaf_errors} |\n`;
      md += `| Exploitable | ${stats.exploitable_errors} |\n\n`;
    }

    // Crash Details
    if (crashes.length > 0) {
      md += `## 🐛 Crash Analysis\n\n`;
      md += `Found **${crashes.length}** unique crash buckets:\n\n`;

      crashes.forEach((crash, i) => {
        const severityEmoji = crash.severity === 'exploitable' ? '🔴' :
                             crash.severity === 'probably_exploitable' ? '🟠' :
                             crash.severity === 'probably_not_exploitable' ? '🟡' : '🟢';
        
        md += `### ${severityEmoji} Crash #${i + 1}: ${crashTypeLabels[crash.crash_type] || crash.crash_type}\n\n`;
        md += `- **Bucket ID:** \`${crash.id}\`\n`;
        md += `- **Severity:** ${crash.severity.replace(/_/g, ' ').toUpperCase()}\n`;
        md += `- **Sample Count:** ${crash.sample_count}\n`;
        md += `- **First Seen:** ${new Date(crash.first_seen).toLocaleString()}\n`;
        md += `- **Last Seen:** ${new Date(crash.last_seen).toLocaleString()}\n`;
        md += `- **Stack Hash:** \`${crash.stack_hash}\`\n`;

        if (crash.crash_address) {
          md += `- **Crash Address:** \`${crash.crash_address}\`\n`;
        }
        if (crash.faulting_instruction) {
          md += `- **Faulting Instruction:** \`${crash.faulting_instruction}\`\n`;
        }

        if (crash.stack_trace && crash.stack_trace.length > 0) {
          md += `\n**Stack Trace:**\n\`\`\`\n${crash.stack_trace.join('\n')}\n\`\`\`\n`;
        }

        md += `\n`;
      });
    }

    // Recommendations
    md += `## 💡 Recommendations\n\n`;
    if (crashes.filter(c => c.severity === 'exploitable').length > 0) {
      md += `⚠️ **Critical:** ${crashes.filter(c => c.severity === 'exploitable').length} exploitable crashes found. Prioritize these for immediate remediation.\n\n`;
    }
    if (crashes.filter(c => c.crash_type === 'stack_buffer_overflow').length > 0) {
      md += `- Consider enabling stack canaries and ASLR\n`;
    }
    if (crashes.filter(c => c.crash_type === 'heap_corruption' || c.crash_type === 'use_after_free').length > 0) {
      md += `- Review heap allocation patterns and implement safe memory handling\n`;
    }
    md += `- Run with AddressSanitizer for detailed memory analysis\n`;
    md += `- Consider fuzz testing for longer duration to find deeper bugs\n\n`;

    md += `---\n\n`;
    md += `*Report generated by Binary Vulnerability Fuzzer*\n`;

    return md;
  }, [config, stats, crashes]);

  // Export as Markdown
  const exportMarkdown = useCallback(() => {
    setExportLoading(true);
    try {
      const md = generateMarkdownReport();
      const blob = new Blob([md], { type: 'text/markdown' });
      saveAs(blob, `fuzzing-report-${new Date().toISOString().slice(0, 10)}.md`);
    } finally {
      setExportLoading(false);
      setExportMenuAnchor(null);
    }
  }, [generateMarkdownReport]);

  // Export as PDF
  const exportPDF = useCallback(() => {
    setExportLoading(true);
    try {
      const doc = new jsPDF();
      const pageWidth = doc.internal.pageSize.getWidth();
      let y = 20;

      // Title
      doc.setFontSize(20);
      doc.setTextColor(220, 53, 69);
      doc.text('Binary Fuzzing Security Report', pageWidth / 2, y, { align: 'center' });
      y += 15;

      // Metadata
      doc.setFontSize(10);
      doc.setTextColor(100);
      doc.text(`Generated: ${new Date().toLocaleString()}`, pageWidth / 2, y, { align: 'center' });
      y += 10;
      doc.text(`Target: ${config.target_path}`, 20, y);
      y += 15;

      // Executive Summary
      doc.setFontSize(14);
      doc.setTextColor(0);
      doc.text('Executive Summary', 20, y);
      y += 10;

      doc.setFontSize(10);
      const summaryData = [
        ['Total Executions', stats.total_executions.toLocaleString()],
        ['Unique Crashes', stats.unique_crashes.toString()],
        ['Timeouts', stats.total_timeouts.toString()],
        ['Execution Speed', `${stats.exec_per_sec.toFixed(1)} exec/sec`],
        ['Elapsed Time', `${Math.floor(stats.elapsed_seconds)}s`],
      ];

      if (config.coverage_guided) {
        summaryData.push(['Edges Discovered', stats.total_edges.toLocaleString()]);
        summaryData.push(['Corpus Size', stats.corpus_size.toString()]);
      }

      summaryData.forEach(([label, value]) => {
        doc.text(`${label}: ${value}`, 25, y);
        y += 6;
      });
      y += 10;

      // Crashes
      if (crashes.length > 0) {
        doc.setFontSize(14);
        doc.text(`Crash Analysis (${crashes.length} unique)`, 20, y);
        y += 10;

        doc.setFontSize(9);
        crashes.slice(0, 10).forEach((crash, i) => {
          if (y > 270) {
            doc.addPage();
            y = 20;
          }

          const severityColor = crash.severity === 'exploitable' ? [220, 53, 69] :
                               crash.severity === 'probably_exploitable' ? [255, 193, 7] : [40, 167, 69];
          doc.setTextColor(severityColor[0], severityColor[1], severityColor[2]);
          doc.text(`#${i + 1} [${crash.severity.toUpperCase()}]`, 25, y);
          
          doc.setTextColor(0);
          doc.text(` ${crashTypeLabels[crash.crash_type] || crash.crash_type}`, 80, y);
          y += 5;
          doc.setTextColor(100);
          doc.text(`   Bucket: ${crash.id} | Count: ${crash.sample_count}`, 25, y);
          y += 8;
        });
      }

      // Footer
      doc.setFontSize(8);
      doc.setTextColor(150);
      doc.text('Generated by Binary Vulnerability Fuzzer', pageWidth / 2, 290, { align: 'center' });

      doc.save(`fuzzing-report-${new Date().toISOString().slice(0, 10)}.pdf`);
    } finally {
      setExportLoading(false);
      setExportMenuAnchor(null);
    }
  }, [config, stats, crashes]);

  // Export crash as GDB script
  const exportCrashGDB = useCallback((crash: CrashBucket) => {
    let script = `# GDB Script for Crash Analysis\n`;
    script += `# Bucket: ${crash.id}\n`;
    script += `# Type: ${crashTypeLabels[crash.crash_type] || crash.crash_type}\n`;
    script += `# Severity: ${crash.severity}\n\n`;
    script += `file ${config.target_path}\n`;
    script += `# Load crash input\n`;
    if (crash.input_file) {
      script += `run ${config.target_args.replace('@@', crash.input_file)}\n`;
    } else {
      script += `run ${config.target_args}\n`;
    }
    script += `\n# Useful commands:\n`;
    script += `# bt - backtrace\n`;
    script += `# info registers - show register state\n`;
    script += `# x/32xw $esp - examine stack\n`;
    script += `# x/i $eip - examine instruction\n`;

    const blob = new Blob([script], { type: 'text/plain' });
    saveAs(blob, `crash-${crash.id}.gdb`);
  }, [config]);

  // ==========================================
  // Corpus Browser Functions
  // ==========================================
  
  // Generate mock corpus data (in production, this would come from the backend)
  const generateMockCorpusData = useCallback((): CorpusFile[] => {
    const files: CorpusFile[] = [];
    const sources: ('seed' | 'mutation' | 'crash')[] = ['seed', 'mutation', 'crash'];
    
    // Generate based on actual stats
    const numFiles = Math.max(stats.corpus_size || 5, 5);
    
    for (let i = 0; i < numFiles; i++) {
      const source = sources[Math.floor(Math.random() * (i < 3 ? 1 : 3))]; // First few are seeds
      const isCrash = source === 'crash';
      files.push({
        id: `corpus-${i.toString().padStart(6, '0')}`,
        filename: isCrash ? `crash-${Date.now() + i}.bin` : `id:${i.toString().padStart(6, '0')},src:${source}`,
        size: Math.floor(Math.random() * 4096) + 64,
        coverage_edges: Math.floor(Math.random() * 500) + 10,
        is_favored: Math.random() > 0.7,
        created_at: new Date(Date.now() - Math.random() * 3600000).toISOString(),
        source,
        preview: generateRandomHexPreview(),
      });
    }
    return files.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }, [stats.corpus_size]);

  const generateRandomHexPreview = (): string => {
    const bytes: string[] = [];
    for (let i = 0; i < 32; i++) {
      bytes.push(Math.floor(Math.random() * 256).toString(16).padStart(2, '0'));
    }
    return bytes.join(' ').toUpperCase();
  };

  // Refresh corpus files
  const refreshCorpusFiles = useCallback(() => {
    // In production, this would fetch from the backend
    setCorpusFiles(generateMockCorpusData());
  }, [generateMockCorpusData]);

  // Initialize corpus on session start
  useEffect(() => {
    if (isRunning && corpusFiles.length === 0) {
      refreshCorpusFiles();
    }
  }, [isRunning, corpusFiles.length, refreshCorpusFiles]);

  // Filter and sort corpus files
  const filteredCorpusFiles = React.useMemo(() => {
    let filtered = [...corpusFiles];
    
    // Apply filter
    if (corpusFilter === 'seed') {
      filtered = filtered.filter(f => f.source === 'seed');
    } else if (corpusFilter === 'mutation') {
      filtered = filtered.filter(f => f.source === 'mutation');
    } else if (corpusFilter === 'favored') {
      filtered = filtered.filter(f => f.is_favored);
    }
    
    // Apply search
    if (corpusSearchQuery) {
      const query = corpusSearchQuery.toLowerCase();
      filtered = filtered.filter(f => 
        f.filename.toLowerCase().includes(query) || 
        f.id.toLowerCase().includes(query)
      );
    }
    
    // Apply sort
    switch (corpusSortBy) {
      case 'size':
        filtered.sort((a, b) => b.size - a.size);
        break;
      case 'coverage':
        filtered.sort((a, b) => b.coverage_edges - a.coverage_edges);
        break;
      case 'date':
      default:
        filtered.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    }
    
    return filtered;
  }, [corpusFiles, corpusFilter, corpusSortBy, corpusSearchQuery]);

  // Open corpus file preview
  const openCorpusPreview = useCallback((file: CorpusFile) => {
    setSelectedCorpusFile(file);
    setCorpusDialogOpen(true);
  }, []);

  // Close corpus dialog
  const closeCorpusDialog = useCallback(() => {
    setSelectedCorpusFile(null);
    setCorpusDialogOpen(false);
  }, []);

  // Delete corpus file
  const deleteCorpusFile = useCallback((fileId: string) => {
    setCorpusFiles(prev => prev.filter(f => f.id !== fileId));
  }, []);

  // Toggle favorite status
  const toggleFavorite = useCallback((fileId: string) => {
    setCorpusFiles(prev => prev.map(f => 
      f.id === fileId ? { ...f, is_favored: !f.is_favored } : f
    ));
  }, []);

  // Export corpus file
  const exportCorpusFile = useCallback((file: CorpusFile) => {
    // Generate mock binary data for export
    const data = file.preview?.split(' ').map(hex => parseInt(hex, 16)) || [];
    const blob = new Blob([new Uint8Array(data)], { type: 'application/octet-stream' });
    saveAs(blob, file.filename);
  }, []);

  // ==========================================
  // AI Crash Analysis Functions
  // ==========================================
  
  // Perform AI analysis on a crash
  const performAIAnalysis = useCallback(async (crash: CrashBucket) => {
    setAiAnalysisLoading(true);
    setAiAnalysisError(null);
    
    try {
      // Simulate AI analysis (in production, this would call the backend AI service)
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Generate analysis based on crash type
      const analysis = generateCrashAnalysis(crash);
      setAiAnalysis(analysis);
    } catch (err) {
      setAiAnalysisError('Failed to perform AI analysis. Please try again.');
    } finally {
      setAiAnalysisLoading(false);
    }
  }, []);

  // Generate AI crash analysis based on crash data
  const generateCrashAnalysis = (crash: CrashBucket): AIAnalysisResult => {
    const analysisTemplates: Record<string, Partial<AIAnalysisResult>> = {
      stack_buffer_overflow: {
        summary: 'Stack-based buffer overflow detected. The program wrote beyond the bounds of a stack-allocated buffer, potentially overwriting return addresses or saved frame pointers.',
        root_cause: 'Insufficient bounds checking on user-controlled input before copying to a fixed-size stack buffer. The input length exceeds the buffer capacity, causing adjacent stack memory to be overwritten.',
        exploitability: 'critical',
        attack_vector: 'An attacker can craft malicious input to overwrite the return address and redirect execution to shellcode or ROP gadgets.',
        affected_components: ['Input validation', 'Memory management', 'Control flow integrity'],
        recommendations: [
          'Use safe string functions (strncpy, snprintf) with explicit bounds checking',
          'Enable stack canaries (-fstack-protector-all) for runtime detection',
          'Implement ASLR and DEP/NX for exploit mitigation',
          'Consider using memory-safe languages for security-critical components',
          'Add input length validation before buffer operations',
        ],
        similar_cves: ['CVE-2021-44228', 'CVE-2020-1938', 'CVE-2019-11477'],
        confidence: 0.92,
      },
      heap_corruption: {
        summary: 'Heap memory corruption detected. The program corrupted heap metadata or adjacent heap objects, potentially allowing arbitrary write primitives.',
        root_cause: 'Heap buffer overflow or invalid heap operations corrupted allocator metadata. This may result from writing beyond allocated heap buffer boundaries.',
        exploitability: 'high',
        attack_vector: 'Heap corruption can be leveraged for arbitrary write primitives through heap metadata manipulation, enabling code execution.',
        affected_components: ['Dynamic memory allocation', 'Heap management', 'Buffer handling'],
        recommendations: [
          'Use AddressSanitizer during development to detect heap issues early',
          'Implement heap hardening (guard pages, randomization)',
          'Validate all input sizes before memory allocation',
          'Use safe allocator wrappers with bounds tracking',
          'Consider using smart pointers or RAII patterns',
        ],
        similar_cves: ['CVE-2021-22555', 'CVE-2020-0796', 'CVE-2019-8912'],
        confidence: 0.87,
      },
      use_after_free: {
        summary: 'Use-after-free vulnerability detected. The program accessed memory that was previously freed, potentially leading to arbitrary code execution.',
        root_cause: 'A pointer to freed memory (dangling pointer) was dereferenced. This typically occurs when object lifetime is not properly tracked across different code paths.',
        exploitability: 'critical',
        attack_vector: 'By controlling the contents of reallocated memory at the freed location, an attacker can hijack virtual function calls or corrupt critical data structures.',
        affected_components: ['Object lifecycle management', 'Reference counting', 'Memory deallocation'],
        recommendations: [
          'Set pointers to NULL immediately after freeing',
          'Use smart pointers (unique_ptr, shared_ptr) for automatic lifetime management',
          'Implement reference counting for shared objects',
          'Enable ASAN\'s use-after-free detection in testing',
          'Consider temporal memory safety mechanisms',
        ],
        similar_cves: ['CVE-2021-21224', 'CVE-2020-6819', 'CVE-2019-11707'],
        confidence: 0.94,
      },
      access_violation_write: {
        summary: 'Write access violation detected. The program attempted to write to an invalid or protected memory address.',
        root_cause: 'Dereferencing an invalid pointer during a write operation. This may be caused by NULL pointer dereference, out-of-bounds array access, or use of uninitialized pointers.',
        exploitability: 'high',
        attack_vector: 'If the write address can be controlled by attacker input, this could be leveraged for arbitrary write primitives to modify program behavior.',
        affected_components: ['Pointer arithmetic', 'Array bounds checking', 'Memory access patterns'],
        recommendations: [
          'Add NULL checks before pointer dereference',
          'Implement bounds checking for array operations',
          'Initialize all pointers to NULL on declaration',
          'Use static analysis tools to detect potential null dereferences',
          'Enable memory protection mechanisms (DEP, W^X)',
        ],
        similar_cves: ['CVE-2021-34527', 'CVE-2020-0601', 'CVE-2019-0708'],
        confidence: 0.85,
      },
      double_free: {
        summary: 'Double-free vulnerability detected. The program attempted to free memory that was already freed, corrupting heap metadata.',
        root_cause: 'Memory was freed twice, typically due to missing or incorrect tracking of allocation state. This corrupts the allocator\'s free list.',
        exploitability: 'high',
        attack_vector: 'Double-free can be exploited to gain arbitrary write primitives through heap list manipulation techniques.',
        affected_components: ['Memory deallocation', 'Object ownership', 'Resource cleanup'],
        recommendations: [
          'Set pointers to NULL after freeing to prevent double-free',
          'Use RAII patterns for automatic resource management',
          'Implement clear ownership semantics',
          'Enable allocator hardening (tcmalloc, jemalloc secure options)',
          'Add defensive NULL checks before free operations',
        ],
        similar_cves: ['CVE-2021-3156', 'CVE-2020-8835', 'CVE-2019-11833'],
        confidence: 0.91,
      },
    };

    const template = analysisTemplates[crash.crash_type] || {
      summary: `A ${crashTypeLabels[crash.crash_type] || crash.crash_type} crash was detected during fuzzing. Further manual analysis is recommended to determine the security impact.`,
      root_cause: 'The exact root cause requires manual analysis of the crash context and program state.',
      exploitability: 'unknown' as const,
      affected_components: ['Requires investigation'],
      recommendations: [
        'Analyze the crash with a debugger to understand the root cause',
        'Review the code path leading to the crash',
        'Check for input validation issues',
        'Test with sanitizers enabled for more context',
      ],
      confidence: 0.6,
    };

    return {
      crash_id: crash.id,
      summary: template.summary!,
      root_cause: template.root_cause!,
      exploitability: template.exploitability!,
      attack_vector: template.attack_vector,
      affected_components: template.affected_components!,
      recommendations: template.recommendations!,
      similar_cves: template.similar_cves,
      confidence: template.confidence!,
      analysis_timestamp: new Date().toISOString(),
    };
  };

  // Clear AI analysis
  const clearAIAnalysis = useCallback(() => {
    setAiAnalysis(null);
    setAiAnalysisError(null);
  }, []);

  // ==========================================
  // Enhanced AI Feature Functions
  // ==========================================
  
  // Analyze binary structure
  const analyzeBinary = useCallback(async () => {
    if (!uploadedBinary) return;
    
    setBinaryAnalysisLoading(true);
    try {
      const response = await fetch(`/api/binary-fuzzer/ai/binary-analysis/${uploadedBinary.binary_id}`, {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}` }
      });
      
      if (!response.ok) throw new Error('Failed to analyze binary');
      
      const data = await response.json();
      setBinaryAnalysis(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Binary analysis failed');
    } finally {
      setBinaryAnalysisLoading(false);
    }
  }, [uploadedBinary]);
  
  // Generate AI-powered smart seeds
  const generateAISeeds = useCallback(async (numSeeds: number = 10) => {
    if (!uploadedBinary) return;
    
    setAiSeedGenerating(true);
    setError(null);
    
    try {
      const response = await fetch('/api/binary-fuzzer/ai/generate-seeds', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}`
        },
        body: JSON.stringify({
          binary_id: uploadedBinary.binary_id,
          num_seeds: numSeeds
        })
      });
      
      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || 'Failed to generate AI seeds');
      }
      
      const data = await response.json();
      setAiSeeds(data.seeds || []);
      setAiSeedAnalysis({
        input_format_analysis: data.input_format_analysis,
        fuzzing_strategy: data.fuzzing_strategy,
        recommended_dictionary: data.dictionary || []
      });
      
      // Update uploaded seeds list with AI-generated seeds
      setUploadedSeeds(prev => [
        ...prev,
        ...data.seeds.map((s: any) => ({
          seed_id: s.name,
          name: s.name,
          path: s.path,
          size: s.size
        }))
      ]);
      
      // Update config seed_dir if provided
      if (data.seeds_dir) {
        setConfig(prev => ({
          ...prev,
          seed_dir: data.seeds_dir
        }));
      }
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'AI seed generation failed');
    } finally {
      setAiSeedGenerating(false);
    }
  }, [uploadedBinary]);
  
  // Get AI coverage advice
  const getAICoverageAdvice = useCallback(async () => {
    if (!sessionId) return;
    
    setCoverageAdviceLoading(true);
    setError(null);
    
    try {
      const response = await fetch('/api/binary-fuzzer/ai/coverage-advice', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}`
        },
        body: JSON.stringify({
          session_id: sessionId,
          stats_history: stats,
          current_corpus: corpusFiles.length,
          crashes: crashes.length
        })
      });
      
      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || 'Failed to get coverage advice');
      }
      
      const data = await response.json();
      setCoverageAdvice(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Coverage advice failed');
    } finally {
      setCoverageAdviceLoading(false);
    }
  }, [sessionId, stats, corpusFiles, crashes]);
  
  // Perform deep exploit analysis on a crash
  const performExploitAnalysis = useCallback(async (crash: CrashBucket) => {
    setExploitAnalysisLoading(true);
    setError(null);
    
    try {
      const response = await fetch('/api/binary-fuzzer/ai/exploit-analysis', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}`
        },
        body: JSON.stringify({
          crash_data: {
            crash_id: crash.id,
            crash_type: crash.crash_type,
            severity: crash.severity,
            crash_address: crash.crash_address,
            faulting_instruction: crash.faulting_instruction,
            stack_trace: crash.stack_trace,
            registers: crash.registers,
            memory_dump: crash.memory_dump,
            sample_count: crash.sample_count,
            first_seen: crash.first_seen,
            stack_hash: crash.stack_hash,
            input_file: crash.input_file
          },
          include_poc: true
        })
      });
      
      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || 'Failed to analyze exploit');
      }
      
      const data = await response.json();
      setExploitAnalysis(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Exploit analysis failed');
    } finally {
      setExploitAnalysisLoading(false);
    }
  }, []);
  
  // Get comprehensive AI session summary
  const getAISessionSummary = useCallback(async () => {
    if (!sessionId) return;
    
    setAiAnalysisLoading(true);
    setAiAnalysisError(null);
    
    try {
      const response = await fetch(`/api/binary-fuzzer/ai/session-summary/${sessionId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}`
        },
        body: JSON.stringify({
          binary_path: config.target_path,
          stats: stats,
          crashes: crashes,
          corpus_size: corpusFiles.length
        })
      });
      
      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || 'Failed to get session summary');
      }
      
      const data = await response.json();
      // Update AI analysis with comprehensive summary
      setAiAnalysis({
        crash_id: sessionId || 'session-summary',
        summary: data.summary || 'Session analysis complete',
        root_cause: data.recommendations?.join('\n') || '',
        exploitability: data.severity || 'unknown',
        attack_vector: data.key_findings?.join('\n') || '',
        affected_components: data.priority_crashes || [],
        recommendations: data.recommendations || [],
        similar_cves: [],
        confidence: 0.85,
        analysis_timestamp: new Date().toISOString()
      });
    } catch (err) {
      setAiAnalysisError(err instanceof Error ? err.message : 'Session summary failed');
    } finally {
      setAiAnalysisLoading(false);
    }
  }, [sessionId, config.target_path, stats, crashes, corpusFiles]);

  // Get exploitability color
  const getExploitabilityColor = (level: string): 'error' | 'warning' | 'info' | 'success' => {
    switch (level) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'info';
    }
  };

  // ==========================================
  // Coverage History & Auto-Trigger Functions
  // ==========================================
  
  // Track coverage history for visualization and auto-trigger
  useEffect(() => {
    if (isRunning && stats) {
      const now = Date.now();
      // Record coverage every 10 seconds
      if (now - lastCoverageUpdate > 10000) {
        setCoverageHistory(prev => {
          const newPoint: CoverageDataPoint = {
            time: prev.length * 10, // seconds elapsed
            edges: stats.total_edges || 0,
            corpus: stats.corpus_size || 0,
            crashes: crashes.length
          };
          // Keep last 360 points (1 hour at 10s intervals)
          const updated = [...prev, newPoint].slice(-360);
          return updated;
        });
        setLastCoverageUpdate(now);
        
        // Check for stall detection
        if (autoAdvisorEnabled && !autoAdvisorTriggered && coverageHistory.length >= 30) {
          const recentHistory = coverageHistory.slice(-30); // Last 5 minutes at 10s intervals
          const oldestEdges = recentHistory[0]?.edges || 0;
          const newestEdges = stats.total_edges || 0;
          
          // If no new edges found in the stall detection window
          if (newestEdges <= oldestEdges && newestEdges > 0) {
            console.log('Coverage stall detected, auto-triggering advisor');
            setAutoAdvisorTriggered(true);
            getAICoverageAdvice();
          }
        }
      }
    }
  }, [isRunning, stats, crashes, lastCoverageUpdate, autoAdvisorEnabled, autoAdvisorTriggered, coverageHistory, getAICoverageAdvice]);
  
  // Reset auto-trigger when fuzzing restarts
  useEffect(() => {
    if (!isRunning) {
      setAutoAdvisorTriggered(false);
    }
  }, [isRunning]);
  
  // ==========================================
  // Batch Crash Analysis Functions
  // ==========================================
  
  // Analyze all crashes in batch
  const performBatchCrashAnalysis = useCallback(async () => {
    if (crashes.length === 0) return;
    
    setBatchAnalysisLoading(true);
    setBatchAnalysisProgress(0);
    setBatchAnalysisResults([]);
    setError(null);
    
    const results: BatchExploitResult[] = [];
    
    for (let i = 0; i < crashes.length; i++) {
      const crash = crashes[i];
      setBatchAnalysisProgress(Math.round(((i + 1) / crashes.length) * 100));
      
      try {
        const response = await fetch('/api/binary-fuzzer/ai/exploit-analysis', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}`
          },
          body: JSON.stringify({
            crash_data: {
              crash_id: crash.id,
              crash_type: crash.crash_type,
              severity: crash.severity,
              crash_address: crash.crash_address,
              faulting_instruction: crash.faulting_instruction,
              stack_trace: crash.stack_trace,
              registers: crash.registers,
              memory_dump: crash.memory_dump,
              sample_count: crash.sample_count,
              first_seen: crash.first_seen,
              stack_hash: crash.stack_hash,
              input_file: crash.input_file
            },
            include_poc: false // Skip PoC for batch to speed up
          })
        });
        
        if (response.ok) {
          const data = await response.json();
          results.push({
            crash_id: crash.id,
            crash_type: crash.crash_type,
            exploitability: data.exploitability,
            exploitability_score: data.exploitability_score,
            vulnerability_type: data.vulnerability_type,
            root_cause: data.root_cause,
            poc_guidance: data.poc_guidance || ''
          });
        }
      } catch (err) {
        console.error(`Failed to analyze crash ${crash.id}:`, err);
      }
    }
    
    // Sort by exploitability score (highest first)
    results.sort((a, b) => b.exploitability_score - a.exploitability_score);
    setBatchAnalysisResults(results);
    setBatchAnalysisLoading(false);
  }, [crashes]);
  
  // ==========================================
  // Export Report Functions
  // ==========================================
  
  // Generate comprehensive AI Markdown report
  const generateAIMarkdownReport = useCallback(() => {
    const timestamp = new Date().toISOString();
    const binaryName = uploadedBinary?.name || config.target_path.split('/').pop() || 'Unknown';
    
    let report = `# Binary Fuzzing AI Analysis Report\n\n`;
    report += `**Generated:** ${new Date().toLocaleString()}\n`;
    report += `**Target Binary:** ${binaryName}\n`;
    report += `**Session ID:** ${sessionId || 'N/A'}\n\n`;
    
    // Executive Summary
    report += `## Executive Summary\n\n`;
    report += `- **Total Executions:** ${stats?.total_executions?.toLocaleString() || 0}\n`;
    report += `- **Total Crashes Found:** ${crashes.length}\n`;
    report += `- **Unique Crash Types:** ${new Set(crashes.map(c => c.crash_type)).size}\n`;
    report += `- **Code Coverage:** ${stats?.coverage_pct?.toFixed(2) || 0}%\n`;
    report += `- **Corpus Size:** ${stats?.corpus_size || 0}\n\n`;
    
    // Binary Analysis
    if (binaryAnalysis) {
      report += `## Binary Analysis\n\n`;
      report += `| Property | Value |\n|----------|-------|\n`;
      report += `| File Type | ${binaryAnalysis.file_type} |\n`;
      report += `| Architecture | ${binaryAnalysis.architecture} |\n`;
      report += `| Stripped | ${binaryAnalysis.is_stripped ? 'Yes' : 'No'} |\n`;
      report += `| Has Symbols | ${binaryAnalysis.has_symbols ? 'Yes' : 'No'} |\n\n`;
      
      if (binaryAnalysis.input_functions.length > 0) {
        report += `### Input Functions\n`;
        report += binaryAnalysis.input_functions.map(f => `- \`${f}\``).join('\n') + '\n\n';
      }
    }
    
    // AI Seed Generation Results
    if (aiSeedAnalysis) {
      report += `## AI Seed Generation\n\n`;
      report += `**Input Format Analysis:** ${aiSeedAnalysis.input_format_analysis}\n\n`;
      report += `**Fuzzing Strategy:** ${aiSeedAnalysis.fuzzing_strategy}\n\n`;
      if (aiSeeds.length > 0) {
        report += `### Generated Seeds (${aiSeeds.length})\n\n`;
        report += `| Name | Size | Format | Description |\n|------|------|--------|-------------|\n`;
        aiSeeds.forEach(seed => {
          report += `| ${seed.name} | ${seed.size}B | ${seed.format_type} | ${seed.description} |\n`;
        });
        report += '\n';
      }
    }
    
    // Coverage Analysis
    if (coverageAdvice) {
      report += `## Coverage Analysis\n\n`;
      report += `**Status:** ${coverageAdvice.is_stuck ? '⚠️ Coverage Plateau Detected' : '✅ Normal Progress'}\n\n`;
      report += `**Trend:** ${coverageAdvice.coverage_trend}\n\n`;
      if (coverageAdvice.stuck_reason) {
        report += `**Reason:** ${coverageAdvice.stuck_reason}\n\n`;
      }
      if (coverageAdvice.recommendations.length > 0) {
        report += `### Recommendations\n\n`;
        coverageAdvice.recommendations.forEach((rec, i) => {
          report += `${i + 1}. ${rec}\n`;
        });
        report += '\n';
      }
    }
    
    // Crash Analysis
    if (batchAnalysisResults.length > 0) {
      report += `## Crash Analysis (${batchAnalysisResults.length} crashes)\n\n`;
      
      // Summary table
      report += `| Crash ID | Type | Exploitability | Score | Vulnerability |\n`;
      report += `|----------|------|----------------|-------|---------------|\n`;
      batchAnalysisResults.forEach(r => {
        report += `| ${r.crash_id} | ${r.crash_type} | ${r.exploitability} | ${Math.round(r.exploitability_score * 100)}% | ${r.vulnerability_type} |\n`;
      });
      report += '\n';
      
      // Detailed analysis for critical/high
      const critical = batchAnalysisResults.filter(r => r.exploitability === 'critical' || r.exploitability === 'high');
      if (critical.length > 0) {
        report += `### Critical/High Severity Crashes\n\n`;
        critical.forEach(r => {
          report += `#### ${r.crash_id}\n\n`;
          report += `- **Exploitability:** ${r.exploitability.toUpperCase()} (${Math.round(r.exploitability_score * 100)}%)\n`;
          report += `- **Vulnerability Type:** ${r.vulnerability_type}\n`;
          report += `- **Root Cause:** ${r.root_cause}\n`;
          if (r.poc_guidance) {
            report += `- **PoC Guidance:** ${r.poc_guidance}\n`;
          }
          report += '\n';
        });
      }
    } else if (crashes.length > 0) {
      report += `## Crashes Found (${crashes.length})\n\n`;
      report += `| ID | Type | Severity | First Seen |\n|----|----|----------|------------|\n`;
      crashes.forEach(c => {
        report += `| ${c.id} | ${c.crash_type} | ${c.severity} | ${new Date(c.first_seen).toLocaleString()} |\n`;
      });
      report += '\n';
    }
    
    // Session Summary
    if (aiAnalysis) {
      report += `## AI Session Summary\n\n`;
      report += `**Overall Severity:** ${aiAnalysis.exploitability.toUpperCase()}\n\n`;
      report += `### Summary\n${aiAnalysis.summary}\n\n`;
      if (aiAnalysis.recommendations.length > 0) {
        report += `### Recommendations\n`;
        aiAnalysis.recommendations.forEach((rec, i) => {
          report += `${i + 1}. ${rec}\n`;
        });
      }
    }
    
    report += `\n---\n*Report generated by VRAgent AI Fuzzer*\n`;
    
    return report;
  }, [uploadedBinary, config.target_path, sessionId, stats, crashes, binaryAnalysis, aiSeedAnalysis, aiSeeds, coverageAdvice, batchAnalysisResults, aiAnalysis]);
  
  // Export AI report as Markdown
  const exportMarkdownReport = useCallback(() => {
    const report = generateAIMarkdownReport();
    const blob = new Blob([report], { type: 'text/markdown' });
    const filename = `fuzzing-report-${sessionId || 'session'}-${Date.now()}.md`;
    saveAs(blob, filename);
  }, [generateAIMarkdownReport, sessionId]);
  
  // Export as PDF
  const exportPdfReport = useCallback(() => {
    const doc = new jsPDF();
    const binaryName = uploadedBinary?.name || config.target_path.split('/').pop() || 'Unknown';
    
    // Title
    doc.setFontSize(20);
    doc.text('Binary Fuzzing AI Analysis Report', 20, 20);
    
    doc.setFontSize(10);
    doc.text(`Generated: ${new Date().toLocaleString()}`, 20, 30);
    doc.text(`Target: ${binaryName}`, 20, 36);
    
    let y = 50;
    
    // Executive Summary
    doc.setFontSize(14);
    doc.text('Executive Summary', 20, y);
    y += 10;
    
    doc.setFontSize(10);
    doc.text(`Total Executions: ${stats?.total_executions?.toLocaleString() || 0}`, 25, y); y += 6;
    doc.text(`Total Crashes: ${crashes.length}`, 25, y); y += 6;
    doc.text(`Code Coverage: ${stats?.coverage_pct?.toFixed(2) || 0}%`, 25, y); y += 6;
    doc.text(`Corpus Size: ${stats?.corpus_size || 0}`, 25, y); y += 15;
    
    // Crash Summary
    if (batchAnalysisResults.length > 0) {
      doc.setFontSize(14);
      doc.text('Crash Analysis Summary', 20, y);
      y += 10;
      
      doc.setFontSize(9);
      const critical = batchAnalysisResults.filter(r => r.exploitability === 'critical').length;
      const high = batchAnalysisResults.filter(r => r.exploitability === 'high').length;
      const medium = batchAnalysisResults.filter(r => r.exploitability === 'medium').length;
      const low = batchAnalysisResults.filter(r => r.exploitability === 'low').length;
      
      doc.text(`Critical: ${critical} | High: ${high} | Medium: ${medium} | Low: ${low}`, 25, y);
      y += 10;
      
      // Top 5 critical crashes
      const topCrashes = batchAnalysisResults.slice(0, 5);
      topCrashes.forEach(crash => {
        if (y > 270) { doc.addPage(); y = 20; }
        doc.text(`• ${crash.crash_id}: ${crash.vulnerability_type} (${crash.exploitability})`, 25, y);
        y += 6;
      });
    }
    
    // Recommendations
    if (aiAnalysis?.recommendations && aiAnalysis.recommendations.length > 0) {
      y += 10;
      if (y > 250) { doc.addPage(); y = 20; }
      
      doc.setFontSize(14);
      doc.text('Recommendations', 20, y);
      y += 10;
      
      doc.setFontSize(9);
      aiAnalysis.recommendations.slice(0, 5).forEach((rec, i) => {
        if (y > 270) { doc.addPage(); y = 20; }
        const lines = doc.splitTextToSize(`${i + 1}. ${rec}`, 170);
        doc.text(lines, 25, y);
        y += lines.length * 5 + 3;
      });
    }
    
    // Footer
    doc.setFontSize(8);
    doc.text('Report generated by VRAgent AI Fuzzer', 20, 285);
    
    const filename = `fuzzing-report-${sessionId || 'session'}-${Date.now()}.pdf`;
    doc.save(filename);
  }, [uploadedBinary, config.target_path, stats, crashes, batchAnalysisResults, aiAnalysis, sessionId]);

  // ==========================================
  // QEMU Mode Functions
  // ==========================================

  // Fetch QEMU capabilities
  const fetchQemuCapabilities = useCallback(async () => {
    setQemuCapabilitiesLoading(true);
    try {
      const response = await fetch('/api/binary-fuzzer/qemu/capabilities', {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}` }
      });
      if (response.ok) {
        const data = await response.json();
        setQemuCapabilities(data);
      } else {
        setError('Failed to fetch QEMU capabilities');
      }
    } catch (err) {
      setError('Failed to fetch QEMU capabilities: ' + (err instanceof Error ? err.message : 'Unknown error'));
    } finally {
      setQemuCapabilitiesLoading(false);
    }
  }, []);

  // Analyze binary for QEMU mode
  const analyzeQemuBinary = useCallback(async (binaryPath: string) => {
    if (!binaryPath) {
      setError('Please specify a binary path to analyze');
      return;
    }
    setQemuBinaryAnalysisLoading(true);
    setQemuBinaryAnalysis(null);
    try {
      const response = await fetch('/api/binary-fuzzer/qemu/analyze-binary', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}`
        },
        body: JSON.stringify({ binary_path: binaryPath })
      });
      if (response.ok) {
        const data = await response.json();
        setQemuBinaryAnalysis(data);
      } else {
        const errData = await response.json();
        setError(errData.detail || 'Failed to analyze binary');
      }
    } catch (err) {
      setError('Failed to analyze binary: ' + (err instanceof Error ? err.message : 'Unknown error'));
    } finally {
      setQemuBinaryAnalysisLoading(false);
    }
  }, []);

  // Run QEMU trace analysis
  const runQemuTrace = useCallback(async (binaryPath: string, inputFile?: string, inputDataBase64?: string) => {
    if (!binaryPath) {
      setError('Please specify a binary path');
      return;
    }
    setQemuTraceLoading(true);
    setQemuTraceAnalysis(null);
    try {
      const response = await fetch('/api/binary-fuzzer/qemu/trace', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}`
        },
        body: JSON.stringify({
          binary_path: binaryPath,
          input_file: inputFile || undefined,
          input_data_base64: inputDataBase64 || undefined,
          timeout_seconds: 30.0
        })
      });
      if (response.ok) {
        const data = await response.json();
        setQemuTraceAnalysis(data.trace_analysis);
      } else {
        const errData = await response.json();
        setError(errData.detail || 'Failed to run QEMU trace');
      }
    } catch (err) {
      setError('Failed to run QEMU trace: ' + (err instanceof Error ? err.message : 'Unknown error'));
    } finally {
      setQemuTraceLoading(false);
    }
  }, []);

  // Start QEMU mode fuzzing
  const startQemuFuzzing = useCallback(async () => {
    const targetPath = uploadedBinary?.path || config.target_path;
    if (!targetPath) {
      setError('Please upload a binary or specify a target path');
      return;
    }

    setQemuFuzzLoading(true);
    try {
      const response = await fetch('/api/binary-fuzzer/qemu/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}`
        },
        body: JSON.stringify({
          target_path: targetPath,
          target_args: config.target_args || '@@',
          architecture: qemuBinaryAnalysis?.architecture?.architecture || undefined,
          mode: qemuFuzzConfig.mode,
          persistent_address: qemuFuzzConfig.persistent_address || undefined,
          persistent_count: qemuFuzzConfig.persistent_count,
          enable_compcov: qemuFuzzConfig.enable_compcov,
          input_dir: config.seed_dir || '/fuzzing/seeds',
          output_dir: config.output_dir || `/fuzzing/output/${Date.now()}`,
          timeout_ms: qemuFuzzConfig.timeout_ms,
          memory_limit_mb: qemuFuzzConfig.memory_limit_mb,
          env_vars: qemuFuzzConfig.env_vars
        })
      });

      if (response.ok) {
        const data = await response.json();
        setSessionId(data.session_id);
        // Switch to AFL WebSocket for real-time updates
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/api/binary-fuzzer/afl/ws`;
        
        if (wsRef.current) {
          wsRef.current.close();
        }
        
        const ws = new WebSocket(wsUrl);
        ws.onopen = () => {
          console.log('QEMU Fuzzer WebSocket connected');
          ws.send(JSON.stringify({
            action: 'start',
            target_path: targetPath,
            target_args: config.target_args || '@@',
            input_dir: config.seed_dir || '/fuzzing/seeds',
            output_dir: data.output_dir,
            timeout_ms: qemuFuzzConfig.timeout_ms,
            memory_limit_mb: qemuFuzzConfig.memory_limit_mb,
            use_qemu: true,
          }));
        };
        ws.onmessage = (event) => {
          try {
            const eventData: FuzzingEvent = JSON.parse(event.data);
            handleFuzzingEvent(eventData);
          } catch (e) {
            console.error('Failed to parse WebSocket message:', e);
          }
        };
        ws.onerror = () => setError('WebSocket connection error');
        ws.onclose = () => setIsRunning(false);
        wsRef.current = ws;
        
        setIsRunning(true);
        setActiveTab(0); // Switch to Crashes tab to monitor progress
      } else {
        const errData = await response.json();
        setError(errData.detail || 'Failed to start QEMU fuzzing');
      }
    } catch (err) {
      setError('Failed to start QEMU fuzzing: ' + (err instanceof Error ? err.message : 'Unknown error'));
    } finally {
      setQemuFuzzLoading(false);
    }
  }, [uploadedBinary, config, qemuBinaryAnalysis, qemuFuzzConfig, handleFuzzingEvent]);

  // Fetch QEMU help
  const fetchQemuHelp = useCallback(async (forBeginners: boolean = true) => {
    setQemuHelpLoading(true);
    try {
      const response = await fetch(`/api/binary-fuzzer/qemu/help?for_beginners=${forBeginners}`, {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}` }
      });
      if (response.ok) {
        const data = await response.json();
        setQemuHelp(data);
      }
    } catch (err) {
      console.error('Failed to fetch QEMU help:', err);
    } finally {
      setQemuHelpLoading(false);
    }
  }, []);

  // Load QEMU capabilities when tab is selected
  useEffect(() => {
    if (activeTab === 4 && !qemuCapabilities && !qemuCapabilitiesLoading) {
      fetchQemuCapabilities();
    }
  }, [activeTab, qemuCapabilities, qemuCapabilitiesLoading, fetchQemuCapabilities]);

  // ==========================================
  // AI Chat Functions
  // ==========================================
  
  // Scroll chat to bottom when messages change
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatMessages]);
  
  // Send chat message
  const sendChatMessage = useCallback(async () => {
    if (!chatInput.trim() || chatLoading) return;
    
    const userMessage: ChatMessage = { role: 'user', content: chatInput };
    setChatMessages(prev => [...prev, userMessage]);
    setChatInput('');
    setChatLoading(true);
    
    // Build context from current fuzzing state
    const context = {
      sessionActive: !!sessionId,
      isRunning,
      totalCrashes: crashes.length,
      crashTypes: [...new Set(crashes.map(c => c.crash_type))],
      exploitableCrashes: crashes.filter(c => c.severity === 'exploitable').length,
      coverageStats: stats ? {
        totalEdges: stats.total_edges,
        coveragePct: stats.coverage_pct,
        corpusSize: stats.corpus_size,
        executions: stats.total_executions
      } : null,
      binaryName: uploadedBinary?.name || config.target_path.split('/').pop() || 'Unknown',
      hasAISeedAnalysis: !!aiSeedAnalysis,
      hasCoverageAdvice: !!coverageAdvice,
      hasBatchResults: batchAnalysisResults.length > 0,
      batchSummary: batchAnalysisResults.length > 0 ? {
        critical: batchAnalysisResults.filter(r => r.exploitability === 'critical').length,
        high: batchAnalysisResults.filter(r => r.exploitability === 'high').length,
        medium: batchAnalysisResults.filter(r => r.exploitability === 'medium').length,
        low: batchAnalysisResults.filter(r => r.exploitability === 'low').length
      } : null
    };
    
    try {
      const response = await fetch('/api/binary-fuzzer/ai/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}`
        },
        body: JSON.stringify({
          message: chatInput,
          context: context,
          history: chatMessages.slice(-10) // Last 10 messages for context
        })
      });
      
      if (response.ok) {
        const data = await response.json();
        const assistantMessage: ChatMessage = { role: 'assistant', content: data.response };
        setChatMessages(prev => [...prev, assistantMessage]);
      } else {
        // Fallback to local response
        const fallbackResponse = generateLocalChatResponse(chatInput, context);
        const assistantMessage: ChatMessage = { role: 'assistant', content: fallbackResponse };
        setChatMessages(prev => [...prev, assistantMessage]);
      }
    } catch (err) {
      // Fallback to local response on error
      const fallbackResponse = generateLocalChatResponse(chatInput, context);
      const assistantMessage: ChatMessage = { role: 'assistant', content: fallbackResponse };
      setChatMessages(prev => [...prev, assistantMessage]);
    }
    
    setChatLoading(false);
  }, [chatInput, chatLoading, sessionId, isRunning, crashes, stats, uploadedBinary, config.target_path, aiSeedAnalysis, coverageAdvice, batchAnalysisResults, chatMessages]);
  
  // Generate local fallback response
  const generateLocalChatResponse = useCallback((query: string, context: any): string => {
    const q = query.toLowerCase();
    
    if (q.includes('summary') || q.includes('overview') || q.includes('status')) {
      return `## Fuzzing Session Summary\n\n` +
        `**Binary:** ${context.binaryName}\n` +
        `**Session Active:** ${context.sessionActive ? 'Yes' : 'No'}\n` +
        `**Status:** ${context.isRunning ? '🟢 Running' : '⚪ Stopped'}\n\n` +
        `### Statistics\n` +
        `- **Total Crashes:** ${context.totalCrashes}\n` +
        `- **Exploitable:** ${context.exploitableCrashes}\n` +
        (context.coverageStats ? 
          `- **Code Coverage:** ${context.coverageStats.coveragePct?.toFixed(2) || 0}%\n` +
          `- **Edges Discovered:** ${context.coverageStats.totalEdges?.toLocaleString() || 0}\n` +
          `- **Corpus Size:** ${context.coverageStats.corpusSize || 0}\n` +
          `- **Total Executions:** ${context.coverageStats.executions?.toLocaleString() || 0}\n`
          : '') +
        (context.hasBatchResults && context.batchSummary ?
          `\n### Batch Analysis Results\n` +
          `- 🔴 Critical: ${context.batchSummary.critical}\n` +
          `- 🟠 High: ${context.batchSummary.high}\n` +
          `- 🟡 Medium: ${context.batchSummary.medium}\n` +
          `- 🟢 Low: ${context.batchSummary.low}\n`
          : '');
    }
    
    if (q.includes('crash') || q.includes('vulnerab') || q.includes('bug')) {
      if (context.totalCrashes === 0) {
        return `## No Crashes Found Yet\n\n` +
          `The fuzzer hasn't discovered any crashes yet. Here are some suggestions:\n\n` +
          `1. **Let it run longer** - Some bugs take time to find\n` +
          `2. **Try AI Seed Generation** - Generate smarter test inputs\n` +
          `3. **Check Coverage Advisor** - See if you're hitting enough code paths\n` +
          `4. **Add custom seeds** - Provide valid input samples\n\n` +
          `Keep the fuzzer running to increase chances of finding vulnerabilities!`;
      }
      
      return `## Crash Analysis\n\n` +
        `Found **${context.totalCrashes}** crashes:\n\n` +
        `### Severity Breakdown\n` +
        `- 🔴 **Exploitable:** ${context.exploitableCrashes}\n` +
        `- Other severities: ${context.totalCrashes - context.exploitableCrashes}\n\n` +
        `### Crash Types Found\n` +
        context.crashTypes.map((t: string) => `- ${t}`).join('\n') +
        `\n\n**Recommendation:** ${context.exploitableCrashes > 0 ? 
          '⚠️ You have exploitable crashes! Review them in the Exploit Helper tab for detailed analysis.' :
          'Review crashes in the AI Analysis tab for detailed exploitability assessment.'}`;
    }
    
    if (q.includes('help') || q.includes('how') || q.includes('start') || q.includes('guide')) {
      return `## Binary Fuzzer Quick Guide\n\n` +
        `### Getting Started\n` +
        `1. **Upload Binary** - Click "Upload Binary" to select your target\n` +
        `2. **Add Seeds** - Upload sample inputs or use AI Seed Generator\n` +
        `3. **Start Fuzzing** - Click "Start Fuzzing" to begin\n\n` +
        `### AI Features\n` +
        `- **🧠 AI Seed Generator** - Analyzes your binary and generates smart test inputs\n` +
        `- **📊 Coverage Advisor** - Gives recommendations when coverage plateaus\n` +
        `- **🔐 Exploit Helper** - Deep analysis of crashes for exploitability\n\n` +
        `### Tips\n` +
        `- Let the fuzzer run for extended periods for best results\n` +
        `- Use batch analysis to triage all crashes at once\n` +
        `- Export reports for documentation\n\n` +
        `What would you like to know more about?`;
    }
    
    if (q.includes('seed') || q.includes('input')) {
      return `## Seed Generation\n\n` +
        `Seeds are the initial test inputs for fuzzing. Better seeds = better coverage.\n\n` +
        `### AI Seed Generator\n` +
        `The AI analyzes your binary to understand:\n` +
        `- Expected input format (text, binary, structured data)\n` +
        `- Input parsing functions\n` +
        `- Edge cases to target\n\n` +
        `**To use:**\n` +
        `1. Go to "AI Analysis" tab\n` +
        `2. Select "AI Seed Generator"\n` +
        `3. Click "Analyze Binary" then "Generate Seeds"\n\n` +
        (context.hasAISeedAnalysis ? 
          '✅ You already have AI seed analysis! Check the tab to generate seeds.' :
          '💡 Try analyzing your binary to get custom seeds!');
    }
    
    if (q.includes('coverage') || q.includes('stuck') || q.includes('plateau')) {
      return `## Coverage Analysis\n\n` +
        (context.coverageStats ?
          `Current coverage: **${context.coverageStats.coveragePct?.toFixed(2) || 0}%** with **${context.coverageStats.totalEdges?.toLocaleString() || 0}** edges\n\n` :
          'Start a fuzzing session to track coverage.\n\n') +
        `### Tips to Improve Coverage\n` +
        `1. **Add more seeds** - Different input formats\n` +
        `2. **Enable dictionary** - Add tokens from the binary\n` +
        `3. **Run longer** - Some paths take time to discover\n` +
        `4. **Use Coverage Advisor** - Get AI recommendations\n\n` +
        (context.hasCoverageAdvice ?
          '✅ You have coverage advice available! Check the Coverage Advisor tab.' :
          '💡 Try the Coverage Advisor for AI-powered suggestions!');
    }
    
    if (q.includes('exploit') || q.includes('poc') || q.includes('attack')) {
      return `## Exploit Analysis\n\n` +
        `The Exploit Helper provides:\n` +
        `- **Exploitability scoring** - How likely the crash is exploitable\n` +
        `- **Vulnerability type** - Buffer overflow, use-after-free, etc.\n` +
        `- **Root cause analysis** - What went wrong\n` +
        `- **PoC guidance** - Steps to develop an exploit\n` +
        `- **Similar CVEs** - Known vulnerabilities with similar patterns\n\n` +
        (context.totalCrashes > 0 ?
          `**You have ${context.totalCrashes} crashes to analyze!**\n\n` +
          `Use "Analyze All Crashes" for batch analysis, or select individual crashes for deep dive.` :
          'Find some crashes first, then use the Exploit Helper for analysis.');
    }
    
    // Default response
    return `I can help you with:\n\n` +
      `- **"summary"** - Get an overview of your fuzzing session\n` +
      `- **"crashes"** - Learn about found vulnerabilities\n` +
      `- **"coverage"** - Understand code coverage\n` +
      `- **"seeds"** - Tips on input generation\n` +
      `- **"exploit"** - Crash exploitability analysis\n` +
      `- **"help"** - Getting started guide\n\n` +
      `Just ask me anything about your fuzzing results!`;
  }, []);

  // ==========================================
  // File Upload Functions
  // ==========================================
  
  // Check AFL++ status
  const checkAflStatus = useCallback(async () => {
    try {
      const response = await fetch('/api/binary-fuzzer/afl-status');
      if (response.ok) {
        const data = await response.json();
        setAflStatus(data);
      }
    } catch (err) {
      console.error('Failed to check AFL status:', err);
    }
  }, []);

  // Fetch available binaries
  const fetchAvailableBinaries = useCallback(async () => {
    try {
      const response = await fetch('/api/binary-fuzzer/binaries', {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}` }
      });
      if (response.ok) {
        const data = await response.json();
        setAvailableBinaries(data);
      }
    } catch (err) {
      console.error('Failed to fetch binaries:', err);
    }
  }, []);

  // Upload binary file
  const handleBinaryUpload = useCallback(async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setBinaryUploading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('name', file.name);

      const response = await fetch('/api/binary-fuzzer/upload-binary', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}` },
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to upload binary');
      }

      const data = await response.json();
      setUploadedBinary(data);
      
      // Update config with the uploaded binary path
      setConfig(prev => ({
        ...prev,
        target_path: data.path,
      }));

      // Refresh available binaries list
      fetchAvailableBinaries();
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to upload binary');
    } finally {
      setBinaryUploading(false);
      // Reset the input
      if (binaryInputRef.current) {
        binaryInputRef.current.value = '';
      }
    }
  }, [fetchAvailableBinaries]);

  // Upload seed files
  const handleSeedsUpload = useCallback(async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    if (!uploadedBinary) {
      setError('Please upload a binary first before adding seeds');
      return;
    }

    setSeedsUploading(true);
    setError(null);

    try {
      const formData = new FormData();
      for (let i = 0; i < files.length; i++) {
        formData.append('files', files[i]);
      }
      formData.append('binary_id', uploadedBinary.binary_id);

      const response = await fetch('/api/binary-fuzzer/upload-seeds', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}` },
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to upload seeds');
      }

      const data = await response.json();
      setUploadedSeeds(prev => [...prev, ...data.seeds]);
      
      // Update config with the seeds directory
      setConfig(prev => ({
        ...prev,
        seed_dir: data.seeds_dir,
      }));
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to upload seeds');
    } finally {
      setSeedsUploading(false);
      // Reset the input
      if (seedsInputRef.current) {
        seedsInputRef.current.value = '';
      }
    }
  }, [uploadedBinary]);

  // Select an existing binary
  const selectExistingBinary = useCallback(async (binary: typeof availableBinaries[0]) => {
    setUploadedBinary({
      binary_id: binary.binary_id,
      name: binary.name,
      path: binary.path,
      size: binary.size,
      file_type: 'unknown',
    });
    
    setConfig(prev => ({
      ...prev,
      target_path: binary.path,
    }));

    // Fetch seeds for this binary
    try {
      const response = await fetch(`/api/binary-fuzzer/binaries/${binary.binary_id}/seeds`, {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}` }
      });
      if (response.ok) {
        const data = await response.json();
        if (data.seeds && data.seeds.length > 0) {
          setUploadedSeeds(data.seeds.map((s: any) => ({
            seed_id: s.name.split('_')[0],
            name: s.name,
            path: s.path,
            size: s.size,
          })));
          setConfig(prev => ({
            ...prev,
            seed_dir: data.seeds_dir,
          }));
        }
      }
    } catch (err) {
      console.error('Failed to fetch seeds:', err);
    }
  }, []);

  // Delete uploaded binary
  const deleteUploadedBinary = useCallback(async () => {
    if (!uploadedBinary) return;

    try {
      const response = await fetch(`/api/binary-fuzzer/binaries/${uploadedBinary.binary_id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}` },
      });

      if (response.ok) {
        setUploadedBinary(null);
        setUploadedSeeds([]);
        setConfig(prev => ({
          ...prev,
          target_path: '',
          seed_dir: '',
        }));
        fetchAvailableBinaries();
      }
    } catch (err) {
      setError('Failed to delete binary');
    }
  }, [uploadedBinary, fetchAvailableBinaries]);

  // Load initial data
  useEffect(() => {
    checkAflStatus();
    fetchAvailableBinaries();
  }, [checkAflStatus, fetchAvailableBinaries]);

  // Connect on mount
  useEffect(() => {
    connectWebSocket();
    return () => {
      wsRef.current?.close();
    };
  }, [connectWebSocket]);

  return (
    <Box sx={{ p: 3, maxWidth: 1600, mx: 'auto' }}>
      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
        <Box>
          <Typography variant="h4" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <BugReport fontSize="large" color="error" />
            Binary Vulnerability Fuzzer
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Coverage-guided fuzzing for native executables. Detects memory corruption, crashes, and security vulnerabilities.
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant={wizardMode ? 'contained' : 'outlined'}
            color="success"
            startIcon={<RocketLaunch />}
            onClick={() => {
              setWizardMode(!wizardMode);
              if (!wizardMode) setWizardStep(0);
            }}
            size="small"
          >
            {wizardMode ? 'Exit Wizard' : 'Beginner Wizard'}
          </Button>
          <Button
            variant={showGuide ? 'contained' : 'outlined'}
            startIcon={<School />}
            onClick={() => setShowGuide(!showGuide)}
            size="small"
          >
            {showGuide ? 'Hide Guide' : 'Quick Tips'}
          </Button>
        </Box>
      </Box>

      {/* Interactive Beginner Wizard */}
      <Collapse in={wizardMode}>
        <Card sx={{ mb: 3, bgcolor: alpha(theme.palette.success.main, 0.05), border: `2px solid ${theme.palette.success.main}` }}>
          <CardContent>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
              <Box sx={{ 
                bgcolor: theme.palette.success.main, 
                borderRadius: '50%', 
                p: 1, 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center' 
              }}>
                {WIZARD_STEPS[wizardStep]?.icon || <RocketLaunch sx={{ color: 'white' }} />}
              </Box>
              <Box sx={{ flexGrow: 1 }}>
                <Typography variant="h6" fontWeight={700}>
                  Step {wizardStep + 1} of {WIZARD_STEPS.length}: {WIZARD_STEPS[wizardStep]?.title}
                </Typography>
                <Box sx={{ display: 'flex', gap: 0.5, mt: 0.5 }}>
                  {WIZARD_STEPS.map((_, i) => (
                    <Box
                      key={i}
                      sx={{
                        width: 24,
                        height: 4,
                        borderRadius: 2,
                        bgcolor: i === wizardStep 
                          ? theme.palette.success.main 
                          : i < wizardStep 
                            ? alpha(theme.palette.success.main, 0.5)
                            : alpha(theme.palette.text.primary, 0.2),
                        cursor: 'pointer',
                        transition: 'all 0.2s ease',
                      }}
                      onClick={() => setWizardStep(i)}
                    />
                  ))}
                </Box>
              </Box>
            </Box>

            <Grid container spacing={3}>
              {/* Main Content */}
              <Grid item xs={12} md={8}>
                <Paper sx={{ p: 2, bgcolor: 'background.paper', minHeight: 300 }}>
                  <Typography 
                    variant="body1" 
                    sx={{ 
                      whiteSpace: 'pre-line',
                      '& strong': { color: theme.palette.primary.main },
                    }}
                    dangerouslySetInnerHTML={{
                      __html: WIZARD_STEPS[wizardStep]?.description
                        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                        .replace(/`(.*?)`/g, '<code style="background: rgba(0,0,0,0.1); padding: 2px 6px; border-radius: 4px; font-family: monospace;">$1</code>')
                    }}
                  />
                </Paper>
              </Grid>

              {/* Tips Sidebar */}
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.warning.main, 0.1) }}>
                  <Typography variant="subtitle2" fontWeight={700} sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    <Lightbulb color="warning" fontSize="small" />
                    Pro Tips
                  </Typography>
                  <List dense>
                    {WIZARD_STEPS[wizardStep]?.tips.map((tip, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircle color="success" sx={{ fontSize: 16 }} />
                        </ListItemIcon>
                        <ListItemText 
                          primary={tip}
                          primaryTypographyProps={{ variant: 'body2' }}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
                
                {/* Quick Actions */}
                {wizardStep === 1 && (
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <Typography variant="body2">
                      <strong>Try it:</strong> Enter a target path in the configuration panel on the left!
                    </Typography>
                  </Alert>
                )}
                {wizardStep === 2 && (
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <Typography variant="body2">
                      <strong>Try it:</strong> Set your seed directory path to continue.
                    </Typography>
                  </Alert>
                )}
                {wizardStep === 5 && config.target_path && config.seed_dir && (
                  <Alert severity="success" sx={{ mt: 2 }}>
                    <Typography variant="body2">
                      <strong>Ready!</strong> Your configuration looks good. Click "Start Fuzzing" below!
                    </Typography>
                  </Alert>
                )}
              </Grid>
            </Grid>

            {/* Navigation */}
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3, pt: 2, borderTop: `1px solid ${alpha('#000', 0.1)}` }}>
              <Button
                startIcon={<NavigateBefore />}
                onClick={() => setWizardStep(Math.max(0, wizardStep - 1))}
                disabled={wizardStep === 0}
              >
                Previous
              </Button>
              <Box sx={{ display: 'flex', gap: 1 }}>
                {wizardStep === WIZARD_STEPS.length - 1 ? (
                  <Button
                    variant="contained"
                    color="success"
                    startIcon={<Check />}
                    onClick={() => setWizardMode(false)}
                  >
                    Finish Tutorial
                  </Button>
                ) : (
                  <Button
                    variant="contained"
                    endIcon={<NavigateNext />}
                    onClick={() => setWizardStep(Math.min(WIZARD_STEPS.length - 1, wizardStep + 1))}
                  >
                    Next
                  </Button>
                )}
              </Box>
            </Box>
          </CardContent>
        </Card>
      </Collapse>

      {/* Quick Tips Guide */}
      <Collapse in={showGuide && !wizardMode}>
        <Paper sx={{ p: 2, mb: 3, bgcolor: alpha(theme.palette.info.main, 0.05), border: `1px solid ${alpha(theme.palette.info.main, 0.2)}` }}>
          <Typography variant="subtitle1" fontWeight={700} sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
            <Lightbulb color="info" />
            Quick Start Guide
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={3}>
              <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
                <Chip label="1" size="small" color="primary" />
                <Box>
                  <Typography variant="body2" fontWeight={600}>Set Target</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Point to an executable and use @@ for input file
                  </Typography>
                </Box>
              </Box>
            </Grid>
            <Grid item xs={12} md={3}>
              <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
                <Chip label="2" size="small" color="primary" />
                <Box>
                  <Typography variant="body2" fontWeight={600}>Add Seeds</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Provide sample input files in a seed directory
                  </Typography>
                </Box>
              </Box>
            </Grid>
            <Grid item xs={12} md={3}>
              <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
                <Chip label="3" size="small" color="primary" />
                <Box>
                  <Typography variant="body2" fontWeight={600}>Configure</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Set timeout, iterations, and scheduler strategy
                  </Typography>
                </Box>
              </Box>
            </Grid>
            <Grid item xs={12} md={3}>
              <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
                <Chip label="4" size="small" color="primary" />
                <Box>
                  <Typography variant="body2" fontWeight={600}>Start Fuzzing</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Click Start and monitor for crashes!
                  </Typography>
                </Box>
              </Box>
            </Grid>
          </Grid>
        </Paper>
      </Collapse>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Configuration Panel */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                <Terminal sx={{ mr: 1, verticalAlign: 'middle' }} />
                Target Configuration
              </Typography>

              {/* AFL++ Status Banner */}
              {aflStatus && (
                <Alert 
                  severity={aflStatus.installed ? "success" : "warning"} 
                  sx={{ mb: 2 }}
                  icon={aflStatus.installed ? <CheckCircle /> : <Warning />}
                >
                  {aflStatus.installed 
                    ? `AFL++ Ready: ${aflStatus.version || 'Installed'}`
                    : 'AFL++ not detected - using built-in fuzzer'
                  }
                </Alert>
              )}

              {/* Binary Upload Section */}
              <Paper sx={{ p: 2, mb: 2, bgcolor: 'background.default' }}>
                <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Upload fontSize="small" color="primary" />
                  Upload Binary
                </Typography>
                
                {uploadedBinary ? (
                  <Box>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, p: 1, bgcolor: 'success.dark', borderRadius: 1, mb: 1 }}>
                      <CheckCircle color="success" fontSize="small" />
                      <Box sx={{ flexGrow: 1 }}>
                        <Typography variant="body2" fontWeight={600}>
                          {uploadedBinary.name}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {uploadedBinary.file_type} • {(uploadedBinary.size / 1024).toFixed(1)} KB
                        </Typography>
                      </Box>
                      <Tooltip title="Remove binary">
                        <IconButton size="small" onClick={deleteUploadedBinary} disabled={isRunning}>
                          <Delete fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </Box>
                ) : (
                  <Box>
                    <input
                      ref={binaryInputRef}
                      type="file"
                      style={{ display: 'none' }}
                      onChange={handleBinaryUpload}
                      accept=".exe,.elf,.bin,.out,*"
                    />
                    <Button
                      fullWidth
                      variant="outlined"
                      startIcon={binaryUploading ? <CircularProgress size={16} /> : <Upload />}
                      onClick={() => binaryInputRef.current?.click()}
                      disabled={isRunning || binaryUploading}
                      sx={{ mb: 1 }}
                    >
                      {binaryUploading ? 'Uploading...' : 'Select Binary File'}
                    </Button>
                    
                    {availableBinaries.length > 0 && (
                      <Box>
                        <Typography variant="caption" color="text.secondary">
                          Or select existing:
                        </Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                          {availableBinaries.slice(0, 5).map((binary) => (
                            <Chip
                              key={binary.binary_id}
                              label={binary.name}
                              size="small"
                              onClick={() => selectExistingBinary(binary)}
                              variant="outlined"
                              sx={{ cursor: 'pointer' }}
                            />
                          ))}
                        </Box>
                      </Box>
                    )}
                  </Box>
                )}
              </Paper>

              {/* Seeds Upload Section */}
              <Paper sx={{ p: 2, mb: 2, bgcolor: 'background.default' }}>
                <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <FolderOpen fontSize="small" color="secondary" />
                  Seed Files
                </Typography>
                
                <input
                  ref={seedsInputRef}
                  type="file"
                  multiple
                  style={{ display: 'none' }}
                  onChange={handleSeedsUpload}
                />
                <Button
                  fullWidth
                  variant="outlined"
                  color="secondary"
                  startIcon={seedsUploading ? <CircularProgress size={16} /> : <Upload />}
                  onClick={() => seedsInputRef.current?.click()}
                  disabled={isRunning || seedsUploading || !uploadedBinary}
                  sx={{ mb: 1 }}
                >
                  {seedsUploading ? 'Uploading...' : 'Upload Seed Files'}
                </Button>
                
                {!uploadedBinary && (
                  <Typography variant="caption" color="text.secondary">
                    Upload a binary first
                  </Typography>
                )}
                
                {uploadedSeeds.length > 0 && (
                  <Box sx={{ mt: 1 }}>
                    <Typography variant="caption" color="text.secondary">
                      {uploadedSeeds.length} seed file(s):
                    </Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5, maxHeight: 80, overflow: 'auto' }}>
                      {uploadedSeeds.map((seed) => (
                        <Chip
                          key={seed.seed_id}
                          label={`${seed.name} (${seed.size}B)`}
                          size="small"
                          variant="outlined"
                          color="secondary"
                        />
                      ))}
                    </Box>
                  </Box>
                )}
              </Paper>

              <Divider sx={{ my: 2 }} />

              <TextField
                fullWidth
                label="Target Executable Path"
                placeholder="/fuzzing/binaries/xxx/target"
                value={config.target_path}
                onChange={(e) => setConfig((prev) => ({ ...prev, target_path: e.target.value }))}
                disabled={isRunning}
                margin="normal"
                size="small"
                helperText="Auto-filled from upload, or enter manually"
              />

              <TextField
                fullWidth
                label="Command Line Arguments"
                placeholder="@@"
                value={config.target_args}
                onChange={(e) => setConfig((prev) => ({ ...prev, target_args: e.target.value }))}
                disabled={isRunning}
                margin="normal"
                size="small"
                helperText="Use @@ as placeholder for input file path"
              />

              <TextField
                fullWidth
                label="Seed Directory"
                placeholder="/fuzzing/seeds/xxx/"
                value={config.seed_dir}
                onChange={(e) => setConfig((prev) => ({ ...prev, seed_dir: e.target.value }))}
                disabled={isRunning}
                margin="normal"
                size="small"
                helperText="Auto-filled from upload, or enter manually"
              />

              <Divider sx={{ my: 2 }} />

              <Typography variant="subtitle2" gutterBottom>
                Execution Limits
              </Typography>

              <TextField
                fullWidth
                label="Timeout (ms)"
                type="number"
                value={config.timeout_ms}
                onChange={(e) => setConfig((prev) => ({ ...prev, timeout_ms: parseInt(e.target.value) || 5000 }))}
                disabled={isRunning}
                margin="normal"
                InputProps={{ inputProps: { min: 100, max: 60000 } }}
              />

              <TextField
                fullWidth
                label="Max Iterations"
                type="number"
                value={config.max_iterations || ''}
                onChange={(e) =>
                  setConfig((prev) => ({
                    ...prev,
                    max_iterations: e.target.value ? parseInt(e.target.value) : null,
                  }))
                }
                disabled={isRunning}
                margin="normal"
                helperText="Leave empty for unlimited"
              />

              <TextField
                fullWidth
                label="Max Time (seconds)"
                type="number"
                value={config.max_time_seconds || ''}
                onChange={(e) =>
                  setConfig((prev) => ({
                    ...prev,
                    max_time_seconds: e.target.value ? parseInt(e.target.value) : null,
                  }))
                }
                disabled={isRunning}
                margin="normal"
                helperText="Leave empty for unlimited"
              />

              <Divider sx={{ my: 2 }} />

              <Typography variant="subtitle2" gutterBottom>
                <Science sx={{ mr: 1, verticalAlign: 'middle', fontSize: 18 }} />
                Coverage-Guided Options
              </Typography>

              <FormControlLabel
                control={
                  <Switch
                    checked={config.coverage_guided}
                    onChange={(e) => setConfig((prev) => ({ ...prev, coverage_guided: e.target.checked }))}
                    disabled={isRunning}
                  />
                }
                label="Enable Coverage Guidance"
              />
              <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1 }}>
                Track code coverage to prioritize inputs that explore new paths
              </Typography>

              <FormControl fullWidth margin="normal" disabled={isRunning || !config.coverage_guided}>
                <InputLabel>Scheduler Strategy</InputLabel>
                <Select
                  value={config.scheduler_strategy}
                  label="Scheduler Strategy"
                  onChange={(e) => setConfig((prev) => ({ ...prev, scheduler_strategy: e.target.value }))}
                >
                  {schedulerStrategies.map((s) => (
                    <MenuItem key={s.value} value={s.value}>
                      {s.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <Divider sx={{ my: 2 }} />

              <Typography variant="subtitle2" gutterBottom>
                Custom Dictionary
              </Typography>

              <Box sx={{ display: 'flex', gap: 1, mb: 1 }}>
                <TextField
                  size="small"
                  placeholder="Add dictionary entry..."
                  value={dictionaryInput}
                  onChange={(e) => setDictionaryInput(e.target.value)}
                  disabled={isRunning}
                  onKeyPress={(e) => e.key === 'Enter' && addDictionaryEntry()}
                />
                <Button onClick={addDictionaryEntry} disabled={isRunning}>
                  Add
                </Button>
              </Box>

              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                {config.dictionary.map((entry, idx) => (
                  <Chip
                    key={idx}
                    label={entry.substring(0, 20) + (entry.length > 20 ? '...' : '')}
                    size="small"
                    onDelete={() =>
                      setConfig((prev) => ({
                        ...prev,
                        dictionary: prev.dictionary.filter((_, i) => i !== idx),
                      }))
                    }
                    disabled={isRunning}
                  />
                ))}
              </Box>

              <Divider sx={{ my: 2 }} />

              <Box sx={{ display: 'flex', gap: 1 }}>
                {!isRunning ? (
                  <Button
                    variant="contained"
                    color="primary"
                    startIcon={<PlayArrow />}
                    onClick={startFuzzing}
                    disabled={!config.target_path}
                    fullWidth
                  >
                    Start Fuzzing
                  </Button>
                ) : (
                  <Button variant="contained" color="error" startIcon={<Stop />} onClick={stopFuzzing} fullWidth>
                    Stop
                  </Button>
                )}
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Stats & Results Panel */}
        <Grid item xs={12} md={8}>
          {/* Stats Cards - Row 1 */}
          <Grid container spacing={2} sx={{ mb: 2 }}>
            <Grid item xs={6} sm={3}>
              <Paper sx={{ p: 2, textAlign: 'center' }}>
                <Speed color="primary" />
                <Typography variant="h5">{stats.exec_per_sec.toFixed(1)}</Typography>
                <Typography variant="caption" color="text.secondary">
                  exec/sec
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Paper sx={{ p: 2, textAlign: 'center' }}>
                <Memory color="info" />
                <Typography variant="h5">{stats.total_executions.toLocaleString()}</Typography>
                <Typography variant="caption" color="text.secondary">
                  Total Executions
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Paper sx={{ p: 2, textAlign: 'center', bgcolor: stats.unique_crashes > 0 ? 'error.dark' : undefined }}>
                <BugReport color={stats.unique_crashes > 0 ? 'inherit' : 'error'} />
                <Typography variant="h5">{stats.unique_crashes}</Typography>
                <Typography variant="caption" color={stats.unique_crashes > 0 ? 'inherit' : 'text.secondary'}>
                  Unique Crashes
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Paper sx={{ p: 2, textAlign: 'center' }}>
                <Timer color="warning" />
                <Typography variant="h5">{Math.floor(stats.elapsed_seconds)}s</Typography>
                <Typography variant="caption" color="text.secondary">
                  Elapsed
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          {/* Stats Cards - Row 2: Coverage Stats (Phase 2) */}
          {config.coverage_guided && (
            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={6} sm={3}>
                <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'primary.dark' }}>
                  <TrendingUp sx={{ color: 'white' }} />
                  <Typography variant="h5" color="white">{stats.total_edges.toLocaleString()}</Typography>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                    Edges Discovered
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Paper sx={{ p: 2, textAlign: 'center' }}>
                  <Storage color="secondary" />
                  <Typography variant="h5">{stats.corpus_size}</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Corpus Size
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Paper sx={{ p: 2, textAlign: 'center' }}>
                  <Star color="warning" />
                  <Typography variant="h5">{stats.favored_inputs}</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Favored Inputs
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Paper sx={{ p: 2, textAlign: 'center', bgcolor: stats.new_coverage_inputs > 0 ? 'success.dark' : undefined }}>
                  <Science color={stats.new_coverage_inputs > 0 ? 'inherit' : 'success'} />
                  <Typography variant="h5" color={stats.new_coverage_inputs > 0 ? 'white' : undefined}>
                    {stats.new_coverage_inputs}
                  </Typography>
                  <Typography variant="caption" color={stats.new_coverage_inputs > 0 ? 'rgba(255,255,255,0.7)' : 'text.secondary'}>
                    New Coverage
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          )}

          {/* Stats Cards - Row 3: Memory Safety Stats (Phase 3) */}
          {config.coverage_guided && stats.memory_errors > 0 && (
            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={6} sm={3}>
                <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'error.dark' }}>
                  <Security sx={{ color: 'white' }} />
                  <Typography variant="h5" color="white">{stats.memory_errors}</Typography>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                    Memory Errors
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Paper sx={{ p: 2, textAlign: 'center', bgcolor: stats.heap_errors > 0 ? 'warning.dark' : undefined }}>
                  <Memory color={stats.heap_errors > 0 ? 'inherit' : 'warning'} />
                  <Typography variant="h5" color={stats.heap_errors > 0 ? 'white' : undefined}>
                    {stats.heap_errors}
                  </Typography>
                  <Typography variant="caption" color={stats.heap_errors > 0 ? 'rgba(255,255,255,0.7)' : 'text.secondary'}>
                    Heap Errors
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Paper sx={{ p: 2, textAlign: 'center', bgcolor: stats.stack_errors > 0 ? 'warning.dark' : undefined }}>
                  <Code color={stats.stack_errors > 0 ? 'inherit' : 'warning'} />
                  <Typography variant="h5" color={stats.stack_errors > 0 ? 'white' : undefined}>
                    {stats.stack_errors}
                  </Typography>
                  <Typography variant="caption" color={stats.stack_errors > 0 ? 'rgba(255,255,255,0.7)' : 'text.secondary'}>
                    Stack Errors
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Paper sx={{ p: 2, textAlign: 'center', bgcolor: stats.exploitable_errors > 0 ? 'error.main' : undefined }}>
                  <Warning color={stats.exploitable_errors > 0 ? 'inherit' : 'error'} />
                  <Typography variant="h5" color={stats.exploitable_errors > 0 ? 'white' : undefined}>
                    {stats.exploitable_errors}
                  </Typography>
                  <Typography variant="caption" color={stats.exploitable_errors > 0 ? 'rgba(255,255,255,0.7)' : 'text.secondary'}>
                    Exploitable
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          )}

          {/* Coverage Visualization Chart */}
          {config.coverage_guided && coverageHistory.length > 1 && (
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                  <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <ShowChart color="primary" />
                    Coverage Over Time
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <Box sx={{ width: 12, height: 3, bgcolor: theme.palette.primary.main, borderRadius: 1 }} />
                      <Typography variant="caption">Edges</Typography>
                    </Box>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <Box sx={{ width: 12, height: 3, bgcolor: theme.palette.secondary.main, borderRadius: 1 }} />
                      <Typography variant="caption">Corpus</Typography>
                    </Box>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <Box sx={{ width: 12, height: 3, bgcolor: theme.palette.error.main, borderRadius: 1 }} />
                      <Typography variant="caption">Crashes</Typography>
                    </Box>
                  </Box>
                </Box>

                {/* SVG Line Chart */}
                <Box 
                  ref={coverageChartRef}
                  sx={{ 
                    width: '100%', 
                    height: 200, 
                    position: 'relative',
                    bgcolor: alpha(theme.palette.background.default, 0.5),
                    borderRadius: 2,
                    p: 2,
                    overflow: 'hidden',
                  }}
                >
                  {(() => {
                    const width = 600;
                    const height = 160;
                    const padding = { top: 10, right: 10, bottom: 30, left: 50 };
                    const chartWidth = width - padding.left - padding.right;
                    const chartHeight = height - padding.top - padding.bottom;
                    
                    const data = coverageHistory;
                    const maxTime = Math.max(...data.map(d => d.time), 1);
                    const maxEdges = Math.max(...data.map(d => d.edges), 1);
                    const maxCorpus = Math.max(...data.map(d => d.corpus), 1);
                    const maxCrashes = Math.max(...data.map(d => d.crashes), 1);
                    
                    // Scale functions
                    const scaleX = (time: number) => padding.left + (time / maxTime) * chartWidth;
                    const scaleYEdges = (edges: number) => padding.top + chartHeight - (edges / maxEdges) * chartHeight;
                    const scaleYCorpus = (corpus: number) => padding.top + chartHeight - (corpus / maxCorpus) * chartHeight;
                    const scaleYCrashes = (crashes: number) => padding.top + chartHeight - (crashes / Math.max(maxCrashes, 5)) * chartHeight;
                    
                    // Generate path
                    const generatePath = (data: CoverageDataPoint[], yScale: (val: number) => number, getValue: (d: CoverageDataPoint) => number) => {
                      if (data.length < 2) return '';
                      return data.map((d, i) => 
                        `${i === 0 ? 'M' : 'L'} ${scaleX(d.time)} ${yScale(getValue(d))}`
                      ).join(' ');
                    };

                    const edgesPath = generatePath(data, scaleYEdges, d => d.edges);
                    const corpusPath = generatePath(data, scaleYCorpus, d => d.corpus);
                    const crashesPath = generatePath(data, scaleYCrashes, d => d.crashes);

                    return (
                      <svg width="100%" height="100%" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="xMidYMid meet">
                        {/* Grid lines */}
                        {[0, 0.25, 0.5, 0.75, 1].map((ratio, i) => (
                          <g key={i}>
                            <line
                              x1={padding.left}
                              y1={padding.top + chartHeight * (1 - ratio)}
                              x2={width - padding.right}
                              y2={padding.top + chartHeight * (1 - ratio)}
                              stroke={alpha(theme.palette.text.primary, 0.1)}
                              strokeDasharray="4 4"
                            />
                            <text
                              x={padding.left - 5}
                              y={padding.top + chartHeight * (1 - ratio) + 4}
                              textAnchor="end"
                              fontSize={10}
                              fill={theme.palette.text.secondary}
                            >
                              {Math.round(maxEdges * ratio)}
                            </text>
                          </g>
                        ))}

                        {/* X-axis labels */}
                        <text
                          x={padding.left}
                          y={height - 5}
                          fontSize={10}
                          fill={theme.palette.text.secondary}
                        >
                          0s
                        </text>
                        <text
                          x={width - padding.right}
                          y={height - 5}
                          textAnchor="end"
                          fontSize={10}
                          fill={theme.palette.text.secondary}
                        >
                          {Math.round(maxTime)}s
                        </text>

                        {/* Area fills */}
                        <path
                          d={`${edgesPath} L ${scaleX(data[data.length - 1]?.time || 0)} ${padding.top + chartHeight} L ${padding.left} ${padding.top + chartHeight} Z`}
                          fill={alpha(theme.palette.primary.main, 0.1)}
                        />

                        {/* Lines */}
                        <path
                          d={edgesPath}
                          fill="none"
                          stroke={theme.palette.primary.main}
                          strokeWidth={2}
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        />
                        <path
                          d={corpusPath}
                          fill="none"
                          stroke={theme.palette.secondary.main}
                          strokeWidth={2}
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeDasharray="4 2"
                        />
                        {maxCrashes > 0 && (
                          <path
                            d={crashesPath}
                            fill="none"
                            stroke={theme.palette.error.main}
                            strokeWidth={2}
                            strokeLinecap="round"
                            strokeLinejoin="round"
                          />
                        )}

                        {/* Data points for crashes */}
                        {data.filter(d => d.crashes > 0).map((d, i) => (
                          <circle
                            key={i}
                            cx={scaleX(d.time)}
                            cy={scaleYCrashes(d.crashes)}
                            r={4}
                            fill={theme.palette.error.main}
                          />
                        ))}

                        {/* Current values label */}
                        {data.length > 0 && (
                          <g>
                            <circle
                              cx={scaleX(data[data.length - 1].time)}
                              cy={scaleYEdges(data[data.length - 1].edges)}
                              r={5}
                              fill={theme.palette.primary.main}
                            />
                          </g>
                        )}
                      </svg>
                    );
                  })()}
                </Box>

                {/* Summary stats */}
                <Box sx={{ display: 'flex', gap: 3, mt: 2, pt: 2, borderTop: `1px solid ${alpha('#000', 0.1)}` }}>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Peak Edges</Typography>
                    <Typography variant="body2" fontWeight={600} color="primary.main">
                      {Math.max(...coverageHistory.map(d => d.edges)).toLocaleString()}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Growth Rate</Typography>
                    <Typography variant="body2" fontWeight={600}>
                      {coverageHistory.length > 5 
                        ? `${((coverageHistory[coverageHistory.length - 1].edges - coverageHistory[Math.max(0, coverageHistory.length - 6)].edges) / 5).toFixed(1)}/s`
                        : 'Calculating...'
                      }
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Corpus Efficiency</Typography>
                    <Typography variant="body2" fontWeight={600}>
                      {stats.corpus_size > 0 
                        ? `${(stats.total_edges / stats.corpus_size).toFixed(1)} edges/input`
                        : '-'
                      }
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Status</Typography>
                    <Typography variant="body2" fontWeight={600} color={
                      coverageHistory.length > 10 && 
                      coverageHistory[coverageHistory.length - 1].edges === coverageHistory[coverageHistory.length - 6]?.edges
                        ? 'warning.main'
                        : 'success.main'
                    }>
                      {coverageHistory.length > 10 && 
                       coverageHistory[coverageHistory.length - 1].edges === coverageHistory[coverageHistory.length - 6]?.edges
                        ? '⚠️ Plateau'
                        : '📈 Growing'
                      }
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          )}

          {/* Progress bar when running */}
          {isRunning && (
            <Box sx={{ mb: 2 }}>
              <LinearProgress variant="indeterminate" />
              <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
                Fuzzing in progress... {stats.total_crashes} crashes found ({stats.total_timeouts} timeouts)
                {config.coverage_guided && ` | ${stats.total_edges} edges discovered`}
              </Typography>
            </Box>
          )}

          {/* Tabs for Crashes / Events / Corpus */}
          <Card>
            <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)} variant="scrollable" scrollButtons="auto">
              <Tab
                label={
                  <Badge badgeContent={crashes.length} color="error">
                    Crashes
                  </Badge>
                }
                icon={<BugReport />}
                iconPosition="start"
              />
              <Tab
                label={
                  <Badge badgeContent={events.length} color="primary">
                    Events
                  </Badge>
                }
                icon={<Assessment />}
                iconPosition="start"
              />
              <Tab
                label={
                  <Badge badgeContent={corpusFiles.length} color="secondary">
                    Corpus
                  </Badge>
                }
                icon={<Inventory />}
                iconPosition="start"
              />
              <Tab
                label="AI Analysis"
                icon={<Psychology />}
                iconPosition="start"
              />
              <Tab
                label="QEMU Mode"
                icon={<DeveloperBoard />}
                iconPosition="start"
              />
            </Tabs>

            <CardContent sx={{ minHeight: 400 }}>
              {/* Crashes Tab */}
              {activeTab === 0 && (
                <>
                  {/* Export Button */}
                  {crashes.length > 0 && (
                    <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}>
                      <Button
                        variant="outlined"
                        startIcon={<Article />}
                        onClick={(e) => setExportMenuAnchor(e.currentTarget)}
                        disabled={exportLoading}
                      >
                        {exportLoading ? 'Exporting...' : 'Export Report'}
                      </Button>
                      <Menu
                        anchorEl={exportMenuAnchor}
                        open={Boolean(exportMenuAnchor)}
                        onClose={() => setExportMenuAnchor(null)}
                      >
                        <MenuItem onClick={exportMarkdown}>
                          <ListItemIcon><Article fontSize="small" /></ListItemIcon>
                          <ListItemText>Markdown Report</ListItemText>
                        </MenuItem>
                        <MenuItem onClick={exportPDF}>
                          <ListItemIcon><PictureAsPdf fontSize="small" /></ListItemIcon>
                          <ListItemText>PDF Report</ListItemText>
                        </MenuItem>
                      </Menu>
                    </Box>
                  )}
                  
                  {crashes.length === 0 ? (
                    <Box sx={{ textAlign: 'center', py: 8 }}>
                      <Security sx={{ fontSize: 64, color: 'text.disabled' }} />
                      <Typography color="text.secondary">No crashes detected yet</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {isRunning ? 'Fuzzing in progress...' : 'Start fuzzing to find vulnerabilities'}
                      </Typography>
                    </Box>
                  ) : (
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>Bucket</TableCell>
                            <TableCell>Type</TableCell>
                            <TableCell>Severity</TableCell>
                            <TableCell align="right">Count</TableCell>
                            <TableCell>First Seen</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {crashes.map((crash) => (
                            <TableRow 
                              key={crash.id} 
                              hover
                              onClick={() => openCrashDialog(crash)}
                              sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
                            >
                              <TableCell>
                                <Chip label={crash.id} size="small" variant="outlined" />
                              </TableCell>
                              <TableCell>
                                <Typography variant="body2">
                                  {crashTypeLabels[crash.crash_type] || crash.crash_type}
                                </Typography>
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={crash.severity.replace(/_/g, ' ')}
                                  size="small"
                                  color={severityColors[crash.severity] || 'default'}
                                />
                              </TableCell>
                              <TableCell align="right">
                                <Badge badgeContent={crash.sample_count} color="primary">
                                  <BugReport fontSize="small" />
                                </Badge>
                              </TableCell>
                              <TableCell>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                  <Typography variant="caption">
                                    {new Date(crash.first_seen).toLocaleTimeString()}
                                  </Typography>
                                  <Tooltip title="View Details">
                                    <Visibility fontSize="small" color="action" />
                                  </Tooltip>
                                </Box>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  )}
                </>
              )}

              {/* Events Tab */}
              {activeTab === 1 && (
                <Box sx={{ maxHeight: 400, overflow: 'auto' }}>
                  <List dense>
                    {events
                      .slice()
                      .reverse()
                      .map((event, idx) => (
                        <ListItem key={idx}>
                          <ListItemIcon>
                            {event.type === 'error' ? (
                              <ErrorIcon color="error" />
                            ) : event.type === 'new_crash' ? (
                              <BugReport color="error" />
                            ) : event.type === 'stats_update' ? (
                              <Assessment color="primary" />
                            ) : event.type === 'new_coverage' ? (
                              <TrendingUp color="success" />
                            ) : event.type === 'session_started' ? (
                              <PlayArrow color="success" />
                            ) : event.type === 'session_completed' ? (
                              <CheckCircle color="success" />
                            ) : (
                              <Info color="info" />
                            )}
                          </ListItemIcon>
                          <ListItemText
                            primary={event.type.replace(/_/g, ' ')}
                            secondary={
                              <Typography variant="caption" component="span" sx={{ fontFamily: 'monospace' }}>
                                {JSON.stringify(event, null, 0).substring(0, 100)}
                                {JSON.stringify(event).length > 100 ? '...' : ''}
                              </Typography>
                            }
                          />
                        </ListItem>
                      ))}
                  </List>
                </Box>
              )}

              {/* Corpus Browser Tab */}
              {activeTab === 2 && (
                <Box>
                  {/* Toolbar */}
                  <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap', alignItems: 'center' }}>
                    <TextField
                      size="small"
                      placeholder="Search files..."
                      value={corpusSearchQuery}
                      onChange={(e) => setCorpusSearchQuery(e.target.value)}
                      InputProps={{
                        startAdornment: <Search fontSize="small" sx={{ mr: 1, color: 'text.secondary' }} />,
                      }}
                      sx={{ minWidth: 200 }}
                    />
                    <FormControl size="small" sx={{ minWidth: 120 }}>
                      <InputLabel>Filter</InputLabel>
                      <Select
                        value={corpusFilter}
                        label="Filter"
                        onChange={(e) => setCorpusFilter(e.target.value as any)}
                      >
                        <MenuItem value="all">All Files</MenuItem>
                        <MenuItem value="seed">Seeds Only</MenuItem>
                        <MenuItem value="mutation">Mutations</MenuItem>
                        <MenuItem value="favored">Favored</MenuItem>
                      </Select>
                    </FormControl>
                    <FormControl size="small" sx={{ minWidth: 120 }}>
                      <InputLabel>Sort By</InputLabel>
                      <Select
                        value={corpusSortBy}
                        label="Sort By"
                        onChange={(e) => setCorpusSortBy(e.target.value as any)}
                      >
                        <MenuItem value="date">Date</MenuItem>
                        <MenuItem value="size">Size</MenuItem>
                        <MenuItem value="coverage">Coverage</MenuItem>
                      </Select>
                    </FormControl>
                    <Box sx={{ flexGrow: 1 }} />
                    <Button
                      size="small"
                      startIcon={<Refresh />}
                      onClick={refreshCorpusFiles}
                    >
                      Refresh
                    </Button>
                  </Box>

                  {/* Corpus Stats */}
                  <Paper sx={{ p: 2, mb: 2, bgcolor: 'background.default' }}>
                    <Grid container spacing={2}>
                      <Grid item xs={6} sm={3}>
                        <Typography variant="caption" color="text.secondary">Total Files</Typography>
                        <Typography variant="h6">{corpusFiles.length}</Typography>
                      </Grid>
                      <Grid item xs={6} sm={3}>
                        <Typography variant="caption" color="text.secondary">Seeds</Typography>
                        <Typography variant="h6">{corpusFiles.filter(f => f.source === 'seed').length}</Typography>
                      </Grid>
                      <Grid item xs={6} sm={3}>
                        <Typography variant="caption" color="text.secondary">Favored</Typography>
                        <Typography variant="h6">{corpusFiles.filter(f => f.is_favored).length}</Typography>
                      </Grid>
                      <Grid item xs={6} sm={3}>
                        <Typography variant="caption" color="text.secondary">Crash Inputs</Typography>
                        <Typography variant="h6" color="error.main">
                          {corpusFiles.filter(f => f.source === 'crash').length}
                        </Typography>
                      </Grid>
                    </Grid>
                  </Paper>

                  {/* File List */}
                  {filteredCorpusFiles.length === 0 ? (
                    <Box sx={{ textAlign: 'center', py: 6 }}>
                      <Inventory sx={{ fontSize: 64, color: 'text.disabled' }} />
                      <Typography color="text.secondary">
                        {corpusFiles.length === 0 ? 'No corpus files yet' : 'No files match your filter'}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {isRunning ? 'Files will appear as fuzzing discovers new inputs' : 'Start fuzzing to build a corpus'}
                      </Typography>
                    </Box>
                  ) : (
                    <TableContainer sx={{ maxHeight: 350 }}>
                      <Table size="small" stickyHeader>
                        <TableHead>
                          <TableRow>
                            <TableCell>Filename</TableCell>
                            <TableCell align="right">Size</TableCell>
                            <TableCell align="right">Coverage</TableCell>
                            <TableCell>Source</TableCell>
                            <TableCell>Time</TableCell>
                            <TableCell align="right">Actions</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {filteredCorpusFiles.map((file) => (
                            <TableRow
                              key={file.id}
                              hover
                              onClick={() => openCorpusPreview(file)}
                              sx={{ cursor: 'pointer' }}
                            >
                              <TableCell>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                  {file.is_favored && <Star fontSize="small" color="warning" />}
                                  {file.source === 'crash' ? (
                                    <BugReport fontSize="small" color="error" />
                                  ) : (
                                    <InsertDriveFile fontSize="small" color="action" />
                                  )}
                                  <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                                    {file.filename.length > 30 ? `${file.filename.substring(0, 27)}...` : file.filename}
                                  </Typography>
                                </Box>
                              </TableCell>
                              <TableCell align="right">
                                <Typography variant="caption">{file.size} B</Typography>
                              </TableCell>
                              <TableCell align="right">
                                <Chip
                                  size="small"
                                  label={`${file.coverage_edges} edges`}
                                  color={file.coverage_edges > 200 ? 'success' : file.coverage_edges > 50 ? 'primary' : 'default'}
                                  variant="outlined"
                                />
                              </TableCell>
                              <TableCell>
                                <Chip
                                  size="small"
                                  label={file.source}
                                  color={file.source === 'crash' ? 'error' : file.source === 'seed' ? 'info' : 'default'}
                                  variant="filled"
                                />
                              </TableCell>
                              <TableCell>
                                <Typography variant="caption">
                                  {new Date(file.created_at).toLocaleTimeString()}
                                </Typography>
                              </TableCell>
                              <TableCell align="right">
                                <Box sx={{ display: 'flex', gap: 0.5 }} onClick={(e) => e.stopPropagation()}>
                                  <Tooltip title={file.is_favored ? 'Unfavorite' : 'Favorite'}>
                                    <IconButton size="small" onClick={() => toggleFavorite(file.id)}>
                                      <Star fontSize="small" color={file.is_favored ? 'warning' : 'action'} />
                                    </IconButton>
                                  </Tooltip>
                                  <Tooltip title="Export">
                                    <IconButton size="small" onClick={() => exportCorpusFile(file)}>
                                      <Download fontSize="small" />
                                    </IconButton>
                                  </Tooltip>
                                  <Tooltip title="Delete">
                                    <IconButton size="small" onClick={() => deleteCorpusFile(file.id)}>
                                      <Delete fontSize="small" color="error" />
                                    </IconButton>
                                  </Tooltip>
                                </Box>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  )}
                </Box>
              )}

              {/* AI Analysis Tab - Enhanced with 3 AI Features */}
              {activeTab === 3 && (
                <Box>
                  {/* AI Feature Sub-Tabs */}
                  <Tabs
                    value={aiSubTab}
                    onChange={(_, newValue) => setAiSubTab(newValue)}
                    sx={{ mb: 2, borderBottom: 1, borderColor: 'divider' }}
                  >
                    <Tab 
                      label="AI Seed Generator" 
                      icon={<AutoAwesome fontSize="small" />}
                      iconPosition="start"
                    />
                    <Tab 
                      label="Coverage Advisor" 
                      icon={<Timeline fontSize="small" />}
                      iconPosition="start"
                    />
                    <Tab 
                      label="Exploit Helper" 
                      icon={<Security fontSize="small" />}
                      iconPosition="start"
                    />
                    <Tab 
                      label="Session Summary" 
                      icon={<Psychology fontSize="small" />}
                      iconPosition="start"
                    />
                  </Tabs>
                  
                  {/* AI Seed Generator Sub-Tab */}
                  {aiSubTab === 0 && (
                    <Box>
                      <Typography variant="subtitle1" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <AutoAwesome color="primary" />
                        AI-Powered Smart Seed Generation
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        Analyze your binary to automatically generate intelligent seed files optimized for fuzzing effectiveness.
                      </Typography>
                      
                      {!uploadedBinary ? (
                        <Alert severity="info" sx={{ mb: 2 }}>
                          Please upload a binary first to use AI seed generation
                        </Alert>
                      ) : (
                        <>
                          {/* Binary Analysis Section */}
                          <Paper sx={{ p: 2, mb: 2 }}>
                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                              <Typography variant="subtitle2" color="primary">
                                Binary Analysis
                              </Typography>
                              <Button
                                variant="outlined"
                                size="small"
                                startIcon={binaryAnalysisLoading ? <CircularProgress size={16} /> : <Search />}
                                onClick={analyzeBinary}
                                disabled={binaryAnalysisLoading}
                              >
                                Analyze Binary
                              </Button>
                            </Box>
                            
                            {binaryAnalysis && (
                              <Grid container spacing={2}>
                                <Grid item xs={6} sm={3}>
                                  <Typography variant="caption" color="text.secondary">Type</Typography>
                                  <Typography variant="body2">{binaryAnalysis.file_type}</Typography>
                                </Grid>
                                <Grid item xs={6} sm={3}>
                                  <Typography variant="caption" color="text.secondary">Architecture</Typography>
                                  <Typography variant="body2">{binaryAnalysis.architecture}</Typography>
                                </Grid>
                                <Grid item xs={6} sm={3}>
                                  <Typography variant="caption" color="text.secondary">Stripped</Typography>
                                  <Chip size="small" label={binaryAnalysis.is_stripped ? 'Yes' : 'No'} color={binaryAnalysis.is_stripped ? 'warning' : 'success'} />
                                </Grid>
                                <Grid item xs={6} sm={3}>
                                  <Typography variant="caption" color="text.secondary">Symbols</Typography>
                                  <Chip size="small" label={binaryAnalysis.has_symbols ? 'Yes' : 'No'} color={binaryAnalysis.has_symbols ? 'success' : 'warning'} />
                                </Grid>
                                {binaryAnalysis.input_functions.length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="caption" color="text.secondary">Input Functions Detected</Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mt: 0.5 }}>
                                      {binaryAnalysis.input_functions.map((fn, idx) => (
                                        <Chip key={idx} label={fn} size="small" variant="outlined" />
                                      ))}
                                    </Box>
                                  </Grid>
                                )}
                              </Grid>
                            )}
                          </Paper>
                          
                          {/* Seed Generation Controls */}
                          <Paper sx={{ p: 2, mb: 2 }}>
                            <Typography variant="subtitle2" color="primary" gutterBottom>
                              Generate Smart Seeds
                            </Typography>
                            <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', mb: 2 }}>
                              <TextField
                                label="Number of Seeds"
                                type="number"
                                size="small"
                                defaultValue={10}
                                inputProps={{ min: 1, max: 50 }}
                                sx={{ width: 150 }}
                                id="ai-seed-count"
                              />
                              <Button
                                variant="contained"
                                color="primary"
                                startIcon={aiSeedGenerating ? <CircularProgress size={20} color="inherit" /> : <AutoAwesome />}
                                onClick={() => {
                                  const input = document.getElementById('ai-seed-count') as HTMLInputElement;
                                  generateAISeeds(parseInt(input?.value || '10'));
                                }}
                                disabled={aiSeedGenerating}
                              >
                                {aiSeedGenerating ? 'Generating...' : 'Generate AI Seeds'}
                              </Button>
                            </Box>
                            <Typography variant="caption" color="text.secondary">
                              AI will analyze your binary structure and generate seeds optimized for discovering vulnerabilities
                            </Typography>
                          </Paper>
                          
                          {/* AI Analysis Results */}
                          {aiSeedAnalysis && (
                            <Paper sx={{ p: 2, mb: 2 }}>
                              <Typography variant="subtitle2" color="primary" gutterBottom>
                                AI Analysis
                              </Typography>
                              <Grid container spacing={2}>
                                <Grid item xs={12} md={6}>
                                  <Typography variant="caption" color="text.secondary">Detected Input Format</Typography>
                                  <Typography variant="body2">{aiSeedAnalysis.input_format_analysis}</Typography>
                                </Grid>
                                <Grid item xs={12} md={6}>
                                  <Typography variant="caption" color="text.secondary">Recommended Strategy</Typography>
                                  <Typography variant="body2">{aiSeedAnalysis.fuzzing_strategy}</Typography>
                                </Grid>
                                {aiSeedAnalysis.recommended_dictionary.length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="caption" color="text.secondary">Recommended Dictionary Tokens</Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mt: 0.5 }}>
                                      {aiSeedAnalysis.recommended_dictionary.slice(0, 20).map((token, idx) => (
                                        <Chip key={idx} label={token} size="small" sx={{ fontFamily: 'monospace' }} />
                                      ))}
                                      {aiSeedAnalysis.recommended_dictionary.length > 20 && (
                                        <Chip label={`+${aiSeedAnalysis.recommended_dictionary.length - 20} more`} size="small" variant="outlined" />
                                      )}
                                    </Box>
                                  </Grid>
                                )}
                              </Grid>
                            </Paper>
                          )}
                          
                          {/* Generated Seeds List */}
                          {aiSeeds.length > 0 && (
                            <Paper sx={{ p: 2 }}>
                              <Typography variant="subtitle2" color="primary" gutterBottom>
                                Generated Seeds ({aiSeeds.length})
                              </Typography>
                              <TableContainer sx={{ maxHeight: 300 }}>
                                <Table size="small" stickyHeader>
                                  <TableHead>
                                    <TableRow>
                                      <TableCell>Name</TableCell>
                                      <TableCell>Size</TableCell>
                                      <TableCell>Format</TableCell>
                                      <TableCell>Description</TableCell>
                                    </TableRow>
                                  </TableHead>
                                  <TableBody>
                                    {aiSeeds.map((seed, idx) => (
                                      <TableRow key={idx} hover>
                                        <TableCell sx={{ fontFamily: 'monospace' }}>{seed.name}</TableCell>
                                        <TableCell>{seed.size} B</TableCell>
                                        <TableCell>
                                          <Chip label={seed.format_type} size="small" />
                                        </TableCell>
                                        <TableCell>{seed.description}</TableCell>
                                      </TableRow>
                                    ))}
                                  </TableBody>
                                </Table>
                              </TableContainer>
                            </Paper>
                          )}
                        </>
                      )}
                    </Box>
                  )}
                  
                  {/* Coverage Advisor Sub-Tab */}
                  {aiSubTab === 1 && (
                    <Box>
                      <Typography variant="subtitle1" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Timeline color="primary" />
                        AI Coverage Advisor
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        Get AI-powered recommendations when your fuzzing campaign gets stuck or coverage plateaus.
                      </Typography>
                      
                      {!sessionId ? (
                        <Alert severity="info" sx={{ mb: 2 }}>
                          Start a fuzzing session first to use the coverage advisor
                        </Alert>
                      ) : (
                        <>
                          {/* Auto-Trigger Controls */}
                          <Paper sx={{ p: 2, mb: 2 }}>
                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 2 }}>
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                                <FormControlLabel
                                  control={
                                    <Switch
                                      checked={autoAdvisorEnabled}
                                      onChange={(e) => setAutoAdvisorEnabled(e.target.checked)}
                                      color="primary"
                                    />
                                  }
                                  label="Auto-trigger when stuck"
                                />
                                {autoAdvisorTriggered && (
                                  <Chip 
                                    label="Auto-triggered!" 
                                    color="warning" 
                                    size="small"
                                    onDelete={() => setAutoAdvisorTriggered(false)}
                                  />
                                )}
                              </Box>
                              <Button
                                variant="contained"
                                color="primary"
                                startIcon={coverageAdviceLoading ? <CircularProgress size={20} color="inherit" /> : <Psychology />}
                                onClick={getAICoverageAdvice}
                                disabled={coverageAdviceLoading}
                              >
                                {coverageAdviceLoading ? 'Analyzing...' : 'Get AI Advice'}
                              </Button>
                            </Box>
                          </Paper>
                          
                          {/* Coverage History Graph */}
                          {coverageHistory.length > 1 && (
                            <Paper sx={{ p: 2, mb: 2 }}>
                              <Typography variant="subtitle2" color="primary" gutterBottom>
                                Coverage Progress Over Time
                              </Typography>
                              <Box sx={{ height: 250 }}>
                                <ResponsiveContainer width="100%" height="100%">
                                  <AreaChart data={coverageHistory}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#444" />
                                    <XAxis 
                                      dataKey="time" 
                                      stroke="#888"
                                      tickFormatter={(v) => `${Math.floor(v / 60)}m`}
                                      label={{ value: 'Time', position: 'insideBottom', offset: -5 }}
                                    />
                                    <YAxis stroke="#888" />
                                    <RechartsTooltip 
                                      contentStyle={{ backgroundColor: '#1e1e1e', border: '1px solid #444' }}
                                      labelFormatter={(v) => `${Math.floor(Number(v) / 60)}m ${Number(v) % 60}s`}
                                    />
                                    <Area 
                                      type="monotone" 
                                      dataKey="edges" 
                                      stroke="#2196f3" 
                                      fill="#2196f3" 
                                      fillOpacity={0.3}
                                      name="Code Edges"
                                    />
                                    <Area 
                                      type="monotone" 
                                      dataKey="corpus" 
                                      stroke="#4caf50" 
                                      fill="#4caf50" 
                                      fillOpacity={0.2}
                                      name="Corpus Size"
                                    />
                                    <Line 
                                      type="monotone" 
                                      dataKey="crashes" 
                                      stroke="#f44336" 
                                      strokeWidth={2}
                                      dot={false}
                                      name="Crashes"
                                    />
                                  </AreaChart>
                                </ResponsiveContainer>
                              </Box>
                              <Box sx={{ display: 'flex', gap: 3, mt: 1, justifyContent: 'center' }}>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                  <Box sx={{ width: 12, height: 12, bgcolor: '#2196f3', borderRadius: 1 }} />
                                  <Typography variant="caption">Code Edges</Typography>
                                </Box>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                  <Box sx={{ width: 12, height: 12, bgcolor: '#4caf50', borderRadius: 1 }} />
                                  <Typography variant="caption">Corpus Size</Typography>
                                </Box>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                  <Box sx={{ width: 12, height: 12, bgcolor: '#f44336', borderRadius: 1 }} />
                                  <Typography variant="caption">Crashes</Typography>
                                </Box>
                              </Box>
                            </Paper>
                          )}
                          
                          {/* Current Stats */}
                          <Paper sx={{ p: 2, mb: 2 }}>
                            <Typography variant="subtitle2" color="primary" gutterBottom>
                              Current Session Stats
                            </Typography>
                            <Grid container spacing={2}>
                              <Grid item xs={6} sm={3}>
                                <Typography variant="caption" color="text.secondary">Executions</Typography>
                                <Typography variant="h6">{stats?.total_executions?.toLocaleString() || 0}</Typography>
                              </Grid>
                              <Grid item xs={6} sm={3}>
                                <Typography variant="caption" color="text.secondary">Total Edges</Typography>
                                <Typography variant="h6">{stats?.total_edges || 0}</Typography>
                              </Grid>
                              <Grid item xs={6} sm={3}>
                                <Typography variant="caption" color="text.secondary">Crashes</Typography>
                                <Typography variant="h6" color="error.main">{crashes.length}</Typography>
                              </Grid>
                              <Grid item xs={6} sm={3}>
                                <Typography variant="caption" color="text.secondary">Corpus Size</Typography>
                                <Typography variant="h6">{stats?.corpus_size || corpusFiles.length}</Typography>
                              </Grid>
                            </Grid>
                          </Paper>
                          
                          {/* Coverage Advice Results */}
                          {coverageAdvice && (
                            <>
                              {/* Status Banner */}
                              <Alert 
                                severity={coverageAdvice.is_stuck ? 'warning' : 'success'} 
                                sx={{ mb: 2 }}
                                icon={coverageAdvice.is_stuck ? <Warning /> : <Check />}
                              >
                                <Typography variant="subtitle2">
                                  {coverageAdvice.is_stuck ? 'Coverage Plateau Detected' : 'Fuzzing Progress Normal'}
                                </Typography>
                                <Typography variant="body2">
                                  Trend: {coverageAdvice.coverage_trend}
                                  {coverageAdvice.stuck_reason && ` - ${coverageAdvice.stuck_reason}`}
                                </Typography>
                              </Alert>
                              
                              {/* Recommendations */}
                              <Paper sx={{ p: 2, mb: 2 }}>
                                <Typography variant="subtitle2" color="primary" gutterBottom>
                                  AI Recommendations
                                </Typography>
                                <List dense>
                                  {coverageAdvice.recommendations.map((rec, idx) => (
                                    <ListItem key={idx}>
                                      <ListItemIcon>
                                        <Lightbulb color="warning" fontSize="small" />
                                      </ListItemIcon>
                                      <ListItemText primary={rec} />
                                    </ListItem>
                                  ))}
                                </List>
                              </Paper>
                              
                              {/* Priority Areas */}
                              {coverageAdvice.priority_areas.length > 0 && (
                                <Paper sx={{ p: 2, mb: 2 }}>
                                  <Typography variant="subtitle2" color="primary" gutterBottom>
                                    Priority Focus Areas
                                  </Typography>
                                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                                    {coverageAdvice.priority_areas.map((area, idx) => (
                                      <Chip key={idx} label={area} color="primary" variant="outlined" />
                                    ))}
                                  </Box>
                                </Paper>
                              )}
                              
                              {/* Mutation Adjustments */}
                              {Object.keys(coverageAdvice.mutation_adjustments).length > 0 && (
                                <Paper sx={{ p: 2 }}>
                                  <Typography variant="subtitle2" color="primary" gutterBottom>
                                    Suggested Mutation Adjustments
                                  </Typography>
                                  <Box sx={{ fontFamily: 'monospace', fontSize: '0.875rem', bgcolor: 'grey.900', p: 1, borderRadius: 1 }}>
                                    <pre style={{ margin: 0 }}>
                                      {JSON.stringify(coverageAdvice.mutation_adjustments, null, 2)}
                                    </pre>
                                  </Box>
                                </Paper>
                              )}
                            </>
                          )}
                        </>
                      )}
                    </Box>
                  )}
                  
                  {/* Exploit Helper Sub-Tab */}
                  {aiSubTab === 2 && (
                    <Box>
                      <Typography variant="subtitle1" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Security color="primary" />
                        AI Exploit Analysis Helper
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        Deep crash analysis with exploitability scoring and PoC generation guidance.
                      </Typography>
                      
                      {crashes.length === 0 ? (
                        <Alert severity="info" sx={{ mb: 2 }}>
                          No crashes found yet. Run fuzzing to discover crashes for exploit analysis.
                        </Alert>
                      ) : (
                        <>
                          {/* Batch Analysis Controls */}
                          <Paper sx={{ p: 2, mb: 2 }}>
                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 2 }}>
                              <Box>
                                <Typography variant="subtitle2" color="primary">
                                  Batch Analysis
                                </Typography>
                                <Typography variant="caption" color="text.secondary">
                                  Analyze all {crashes.length} crashes at once and prioritize by exploitability
                                </Typography>
                              </Box>
                              <Button
                                variant="contained"
                                color="secondary"
                                startIcon={batchAnalysisLoading ? <CircularProgress size={20} color="inherit" /> : <SelectAll />}
                                onClick={performBatchCrashAnalysis}
                                disabled={batchAnalysisLoading}
                              >
                                {batchAnalysisLoading ? `Analyzing ${batchAnalysisProgress}%` : 'Analyze All Crashes'}
                              </Button>
                            </Box>
                            {batchAnalysisLoading && (
                              <LinearProgress 
                                variant="determinate" 
                                value={batchAnalysisProgress} 
                                sx={{ mt: 2 }}
                              />
                            )}
                          </Paper>
                          
                          {/* Batch Analysis Results */}
                          {batchAnalysisResults.length > 0 && (
                            <Paper sx={{ p: 2, mb: 2 }}>
                              <Typography variant="subtitle2" color="primary" gutterBottom>
                                Prioritized Crash Triage ({batchAnalysisResults.length} analyzed)
                              </Typography>
                              <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                                <Chip 
                                  label={`Critical: ${batchAnalysisResults.filter(r => r.exploitability === 'critical').length}`} 
                                  color="error" 
                                  size="small" 
                                />
                                <Chip 
                                  label={`High: ${batchAnalysisResults.filter(r => r.exploitability === 'high').length}`} 
                                  color="warning" 
                                  size="small" 
                                />
                                <Chip 
                                  label={`Medium: ${batchAnalysisResults.filter(r => r.exploitability === 'medium').length}`} 
                                  color="info" 
                                  size="small" 
                                />
                                <Chip 
                                  label={`Low: ${batchAnalysisResults.filter(r => r.exploitability === 'low').length}`} 
                                  color="success" 
                                  size="small" 
                                />
                              </Box>
                              <TableContainer sx={{ maxHeight: 300 }}>
                                <Table size="small" stickyHeader>
                                  <TableHead>
                                    <TableRow>
                                      <TableCell>Crash ID</TableCell>
                                      <TableCell>Exploitability</TableCell>
                                      <TableCell>Score</TableCell>
                                      <TableCell>Vulnerability</TableCell>
                                      <TableCell>Action</TableCell>
                                    </TableRow>
                                  </TableHead>
                                  <TableBody>
                                    {batchAnalysisResults.map((result) => (
                                      <TableRow 
                                        key={result.crash_id} 
                                        hover
                                        sx={{ 
                                          bgcolor: result.exploitability === 'critical' ? alpha('#f44336', 0.1) : 
                                                   result.exploitability === 'high' ? alpha('#ff9800', 0.1) : 'inherit'
                                        }}
                                      >
                                        <TableCell sx={{ fontFamily: 'monospace' }}>{result.crash_id}</TableCell>
                                        <TableCell>
                                          <Chip 
                                            label={result.exploitability} 
                                            size="small"
                                            color={getExploitabilityColor(result.exploitability)}
                                          />
                                        </TableCell>
                                        <TableCell>
                                          <LinearProgress 
                                            variant="determinate" 
                                            value={result.exploitability_score * 100}
                                            color={getExploitabilityColor(result.exploitability)}
                                            sx={{ width: 60, height: 8, borderRadius: 4 }}
                                          />
                                          <Typography variant="caption">{Math.round(result.exploitability_score * 100)}%</Typography>
                                        </TableCell>
                                        <TableCell>{result.vulnerability_type}</TableCell>
                                        <TableCell>
                                          <Button 
                                            size="small"
                                            onClick={() => {
                                              const crash = crashes.find(c => c.id === result.crash_id);
                                              if (crash) performExploitAnalysis(crash);
                                            }}
                                          >
                                            Details
                                          </Button>
                                        </TableCell>
                                      </TableRow>
                                    ))}
                                  </TableBody>
                                </Table>
                              </TableContainer>
                            </Paper>
                          )}
                          
                          <Grid container spacing={3}>
                          {/* Crash Selection Panel */}
                          <Grid item xs={12} md={4}>
                            <Typography variant="subtitle2" gutterBottom>
                              Select a Crash for Deep Analysis
                            </Typography>
                            <Paper sx={{ maxHeight: 400, overflow: 'auto' }}>
                              <List dense>
                                {crashes.map((crash) => (
                                  <ListItem
                                    key={crash.id}
                                    button
                                    selected={exploitAnalysis?.crash_id === crash.id}
                                    onClick={() => performExploitAnalysis(crash)}
                                  >
                                    <ListItemIcon>
                                      <BugReport color={severityColors[crash.severity] || 'inherit'} />
                                    </ListItemIcon>
                                    <ListItemText
                                      primary={crash.id}
                                      secondary={crashTypeLabels[crash.crash_type] || crash.crash_type}
                                    />
                                    <Chip
                                      size="small"
                                      label={crash.severity.replace(/_/g, ' ')}
                                      color={severityColors[crash.severity] || 'default'}
                                    />
                                  </ListItem>
                                ))}
                              </List>
                            </Paper>
                          </Grid>
                          
                          {/* Exploit Analysis Results */}
                          <Grid item xs={12} md={8}>
                            {exploitAnalysisLoading ? (
                              <Box sx={{ textAlign: 'center', py: 6 }}>
                                <CircularProgress size={48} />
                                <Typography sx={{ mt: 2 }} color="text.secondary">
                                  <Security sx={{ mr: 1, verticalAlign: 'middle' }} />
                                  Performing deep exploit analysis...
                                </Typography>
                              </Box>
                            ) : exploitAnalysis ? (
                              <Box>
                                {/* Exploitability Score */}
                                <Alert
                                  severity={getExploitabilityColor(exploitAnalysis.exploitability)}
                                  icon={<Security />}
                                  sx={{ mb: 2 }}
                                >
                                  <Typography variant="subtitle2">
                                    Exploitability: {exploitAnalysis.exploitability.toUpperCase()} 
                                    ({Math.round(exploitAnalysis.exploitability_score * 100)}% confidence)
                                  </Typography>
                                  <Typography variant="body2">
                                    Vulnerability Type: {exploitAnalysis.vulnerability_type}
                                  </Typography>
                                </Alert>
                                
                                {/* Root Cause */}
                                <Paper sx={{ p: 2, mb: 2 }}>
                                  <Typography variant="subtitle2" color="primary" gutterBottom>
                                    Root Cause
                                  </Typography>
                                  <Typography variant="body2">{exploitAnalysis.root_cause}</Typography>
                                </Paper>
                                
                                {/* Affected Functions */}
                                {exploitAnalysis.affected_functions.length > 0 && (
                                  <Paper sx={{ p: 2, mb: 2 }}>
                                    <Typography variant="subtitle2" color="primary" gutterBottom>
                                      Affected Functions
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {exploitAnalysis.affected_functions.map((fn, idx) => (
                                        <Chip key={idx} label={fn} size="small" sx={{ fontFamily: 'monospace' }} />
                                      ))}
                                    </Box>
                                  </Paper>
                                )}
                                
                                {/* Exploitation Techniques */}
                                {exploitAnalysis.exploitation_techniques.length > 0 && (
                                  <Paper sx={{ p: 2, mb: 2 }}>
                                    <Typography variant="subtitle2" color="error" gutterBottom>
                                      Potential Exploitation Techniques
                                    </Typography>
                                    <List dense>
                                      {exploitAnalysis.exploitation_techniques.map((tech, idx) => (
                                        <ListItem key={idx}>
                                          <ListItemIcon>
                                            <Warning color="error" fontSize="small" />
                                          </ListItemIcon>
                                          <ListItemText primary={tech} />
                                        </ListItem>
                                      ))}
                                    </List>
                                  </Paper>
                                )}
                                
                                {/* PoC Guidance */}
                                {exploitAnalysis.poc_guidance && (
                                  <Paper sx={{ p: 2, mb: 2, bgcolor: 'error.dark', color: 'error.contrastText' }}>
                                    <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                      <Code /> PoC Development Guidance
                                    </Typography>
                                    <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                                      {exploitAnalysis.poc_guidance}
                                    </Typography>
                                  </Paper>
                                )}
                                
                                {/* Mitigation Bypass */}
                                {exploitAnalysis.mitigation_bypass.length > 0 && (
                                  <Paper sx={{ p: 2, mb: 2 }}>
                                    <Typography variant="subtitle2" color="warning.main" gutterBottom>
                                      Potential Mitigation Bypasses
                                    </Typography>
                                    <List dense>
                                      {exploitAnalysis.mitigation_bypass.map((bypass, idx) => (
                                        <ListItem key={idx}>
                                          <ListItemText primary={bypass} />
                                        </ListItem>
                                      ))}
                                    </List>
                                  </Paper>
                                )}
                                
                                {/* Similar CVEs */}
                                {exploitAnalysis.similar_cves.length > 0 && (
                                  <Paper sx={{ p: 2, mb: 2 }}>
                                    <Typography variant="subtitle2" color="primary" gutterBottom>
                                      Similar Known CVEs
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                                      {exploitAnalysis.similar_cves.map((cve, idx) => (
                                        <Chip
                                          key={idx}
                                          label={cve}
                                          size="small"
                                          variant="outlined"
                                          color="warning"
                                          onClick={() => window.open(`https://nvd.nist.gov/vuln/detail/${cve}`, '_blank')}
                                          sx={{ cursor: 'pointer' }}
                                        />
                                      ))}
                                    </Box>
                                  </Paper>
                                )}
                                
                                {/* Remediation */}
                                <Paper sx={{ p: 2 }}>
                                  <Typography variant="subtitle2" color="success.main" gutterBottom>
                                    Remediation Recommendations
                                  </Typography>
                                  <Typography variant="body2">{exploitAnalysis.remediation}</Typography>
                                </Paper>
                              </Box>
                            ) : (
                              <Box sx={{ textAlign: 'center', py: 6 }}>
                                <Security sx={{ fontSize: 64, color: 'text.disabled' }} />
                                <Typography color="text.secondary">
                                  Select a crash for deep exploit analysis
                                </Typography>
                                <Typography variant="caption" color="text.secondary">
                                  AI will analyze exploitability, suggest techniques, and provide PoC guidance
                                </Typography>
                              </Box>
                            )}
                          </Grid>
                        </Grid>
                        </>
                      )}
                    </Box>
                  )}
                  
                  {/* Session Summary Sub-Tab (Original AI Analysis) */}
                  {(aiSubTab as number) === 3 && (
                    <Box>
                      <Typography variant="subtitle1" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Psychology color="primary" />
                        AI Session Summary
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        Comprehensive AI analysis of your entire fuzzing session.
                      </Typography>
                      
                      {!sessionId ? (
                        <Alert severity="info" sx={{ mb: 2 }}>
                          Start a fuzzing session first to get an AI summary
                        </Alert>
                      ) : (
                        <>
                          <Box sx={{ mb: 2 }}>
                            <Button
                              variant="contained"
                              color="primary"
                              startIcon={aiAnalysisLoading ? <CircularProgress size={20} color="inherit" /> : <Psychology />}
                              onClick={getAISessionSummary}
                              disabled={aiAnalysisLoading}
                            >
                              {aiAnalysisLoading ? 'Generating Summary...' : 'Generate AI Summary'}
                            </Button>
                          </Box>
                          
                          {aiAnalysisError && (
                            <Alert severity="error" onClose={clearAIAnalysis} sx={{ mb: 2 }}>
                              {aiAnalysisError}
                            </Alert>
                          )}
                          
                          {aiAnalysis && (
                            <Box>
                              <Alert
                                severity={getExploitabilityColor(aiAnalysis.exploitability)}
                                icon={<Security />}
                                sx={{ mb: 2 }}
                              >
                                <Typography variant="subtitle2">
                                  Session Severity: {aiAnalysis.exploitability.toUpperCase()}
                                </Typography>
                              </Alert>
                              
                              <Paper sx={{ p: 2, mb: 2 }}>
                                <Typography variant="subtitle2" color="primary" gutterBottom>
                                  Summary
                                </Typography>
                                <Typography variant="body2">{aiAnalysis.summary}</Typography>
                              </Paper>
                              
                              <Paper sx={{ p: 2, mb: 2 }}>
                                <Typography variant="subtitle2" color="primary" gutterBottom>
                                  Key Findings
                                </Typography>
                                <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                                  {aiAnalysis.attack_vector}
                                </Typography>
                              </Paper>
                              
                              <Paper sx={{ p: 2, mb: 2 }}>
                                <Typography variant="subtitle2" color="primary" gutterBottom>
                                  Recommendations
                                </Typography>
                                <List dense>
                                  {aiAnalysis.recommendations.map((rec, idx) => (
                                    <ListItem key={idx}>
                                      <ListItemIcon>
                                        <Check fontSize="small" color="success" />
                                      </ListItemIcon>
                                      <ListItemText primary={rec} />
                                    </ListItem>
                                  ))}
                                </List>
                              </Paper>
                              
                              {aiAnalysis.affected_components.length > 0 && (
                                <Paper sx={{ p: 2 }}>
                                  <Typography variant="subtitle2" color="primary" gutterBottom>
                                    Priority Crashes
                                  </Typography>
                                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                                    {aiAnalysis.affected_components.map((crash, idx) => (
                                      <Chip key={idx} label={crash} color="error" variant="outlined" />
                                    ))}
                                  </Box>
                                </Paper>
                              )}
                              
                              {/* Export Buttons */}
                              <Paper sx={{ p: 2, mt: 2 }}>
                                <Typography variant="subtitle2" color="primary" gutterBottom>
                                  Export Report
                                </Typography>
                                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 2 }}>
                                  Generate a comprehensive report with all AI analysis, crash data, and recommendations
                                </Typography>
                                <Box sx={{ display: 'flex', gap: 2 }}>
                                  <Button
                                    variant="outlined"
                                    startIcon={<Article />}
                                    onClick={exportMarkdownReport}
                                  >
                                    Export as Markdown
                                  </Button>
                                  <Button
                                    variant="outlined"
                                    startIcon={<PdfIcon />}
                                    onClick={exportPdfReport}
                                  >
                                    Export as PDF
                                  </Button>
                                </Box>
                              </Paper>
                            </Box>
                          )}
                        </>
                      )}
                    </Box>
                  )}
                </Box>
              )}

              {/* QEMU Mode Tab */}
              {activeTab === 4 && (
                <Box>
                  {/* QEMU Feature Sub-Tabs */}
                  <Tabs
                    value={qemuSubTab}
                    onChange={(_, newValue) => setQemuSubTab(newValue)}
                    sx={{ mb: 2, borderBottom: 1, borderColor: 'divider' }}
                  >
                    <Tab
                      label="Overview"
                      icon={<Info fontSize="small" />}
                      iconPosition="start"
                    />
                    <Tab
                      label="Binary Analysis"
                      icon={<Architecture fontSize="small" />}
                      iconPosition="start"
                    />
                    <Tab
                      label="Trace Analysis"
                      icon={<Timeline fontSize="small" />}
                      iconPosition="start"
                    />
                    <Tab
                      label="Start QEMU Fuzzing"
                      icon={<FlashOn fontSize="small" />}
                      iconPosition="start"
                    />
                  </Tabs>

                  {/* QEMU Overview Sub-Tab */}
                  {qemuSubTab === 0 && (
                    <Box>
                      <Typography variant="subtitle1" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <DeveloperBoard color="primary" />
                        QEMU Mode for Closed-Source Binaries
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                        QEMU mode allows you to fuzz ANY binary without source code by running it inside a CPU emulator
                        that tracks code coverage. Perfect for proprietary software, firmware, and pre-compiled binaries.
                      </Typography>

                      {/* Capabilities Status */}
                      <Paper sx={{ p: 2, mb: 2 }}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                          <Typography variant="subtitle2" color="primary">
                            QEMU Capabilities
                          </Typography>
                          <Button
                            size="small"
                            startIcon={qemuCapabilitiesLoading ? <CircularProgress size={16} /> : <Refresh />}
                            onClick={fetchQemuCapabilities}
                            disabled={qemuCapabilitiesLoading}
                          >
                            Refresh
                          </Button>
                        </Box>

                        {qemuCapabilitiesLoading && !qemuCapabilities ? (
                          <Box sx={{ textAlign: 'center', py: 3 }}>
                            <CircularProgress size={32} />
                            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                              Checking QEMU capabilities...
                            </Typography>
                          </Box>
                        ) : qemuCapabilities ? (
                          <Box>
                            <Alert
                              severity={qemuCapabilities.available ? 'success' : 'warning'}
                              sx={{ mb: 2 }}
                              icon={qemuCapabilities.available ? <CheckCircle /> : <Warning />}
                            >
                              {qemuCapabilities.available
                                ? `QEMU Mode Ready${qemuCapabilities.version ? ` (${qemuCapabilities.version})` : ''}`
                                : 'QEMU mode not available'}
                            </Alert>

                            {qemuCapabilities.available && (
                              <Grid container spacing={2}>
                                <Grid item xs={12} md={6}>
                                  <Typography variant="subtitle2" gutterBottom>
                                    Supported Architectures
                                  </Typography>
                                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                    {qemuCapabilities.architectures?.map((arch) => (
                                      <Chip key={arch} label={arch} size="small" color="primary" variant="outlined" />
                                    ))}
                                  </Box>
                                </Grid>
                                <Grid item xs={12} md={6}>
                                  <Typography variant="subtitle2" gutterBottom>
                                    Features
                                  </Typography>
                                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                    <Chip
                                      label="Persistent Mode"
                                      size="small"
                                      color={qemuCapabilities.features?.persistent_qemu ? 'success' : 'default'}
                                      variant={qemuCapabilities.features?.persistent_qemu ? 'filled' : 'outlined'}
                                    />
                                    <Chip
                                      label="CompareCov"
                                      size="small"
                                      color={qemuCapabilities.features?.compcov ? 'success' : 'default'}
                                      variant={qemuCapabilities.features?.compcov ? 'filled' : 'outlined'}
                                    />
                                    <Chip
                                      label="Instrim"
                                      size="small"
                                      color={qemuCapabilities.features?.instrim ? 'success' : 'default'}
                                      variant={qemuCapabilities.features?.instrim ? 'filled' : 'outlined'}
                                    />
                                  </Box>
                                </Grid>
                              </Grid>
                            )}

                            {!qemuCapabilities.available && qemuCapabilities.how_to_fix && (
                              <Paper sx={{ p: 2, bgcolor: 'warning.dark', mt: 2 }}>
                                <Typography variant="subtitle2" gutterBottom>How to Enable QEMU Mode</Typography>
                                <Typography variant="body2">{qemuCapabilities.how_to_fix}</Typography>
                              </Paper>
                            )}
                          </Box>
                        ) : (
                          <Box sx={{ textAlign: 'center', py: 3 }}>
                            <Hub sx={{ fontSize: 48, color: 'text.disabled' }} />
                            <Typography variant="body2" color="text.secondary">
                              Click Refresh to check QEMU capabilities
                            </Typography>
                          </Box>
                        )}
                      </Paper>

                      {/* When to Use QEMU */}
                      <Paper sx={{ p: 2, mb: 2 }}>
                        <Typography variant="subtitle2" color="primary" gutterBottom>
                          When to Use QEMU Mode
                        </Typography>
                        <List dense>
                          <ListItem>
                            <ListItemIcon><Computer fontSize="small" color="primary" /></ListItemIcon>
                            <ListItemText primary="Proprietary/Closed-Source Software" secondary="No source code or recompilation needed" />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon><SettingsEthernet fontSize="small" color="primary" /></ListItemIcon>
                            <ListItemText primary="Firmware & IoT Devices" secondary="ARM, MIPS, and other embedded architectures" />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon><Security fontSize="small" color="primary" /></ListItemIcon>
                            <ListItemText primary="Suspicious Files" secondary="Analyze potential malware in isolation" />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon><Code fontSize="small" color="primary" /></ListItemIcon>
                            <ListItemText primary="Pre-compiled Binaries" secondary="Libraries, tools, and executables without instrumentation" />
                          </ListItem>
                        </List>
                      </Paper>

                      {/* QEMU Modes Explained */}
                      <Paper sx={{ p: 2 }}>
                        <Typography variant="subtitle2" color="primary" gutterBottom>
                          QEMU Fuzzing Modes
                        </Typography>
                        <Grid container spacing={2}>
                          <Grid item xs={12} md={4}>
                            <Paper sx={{ p: 2, bgcolor: 'background.default', height: '100%' }}>
                              <Typography variant="subtitle2" sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                                <PlayArrow color="success" fontSize="small" />
                                Standard Mode
                              </Typography>
                              <Typography variant="body2" color="text.secondary">
                                Works with any binary. Restarts the program for each test case.
                                Slower but most compatible.
                              </Typography>
                            </Paper>
                          </Grid>
                          <Grid item xs={12} md={4}>
                            <Paper sx={{ p: 2, bgcolor: 'background.default', height: '100%' }}>
                              <Typography variant="subtitle2" sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                                <FlashOn color="warning" fontSize="small" />
                                Persistent Mode
                              </Typography>
                              <Typography variant="body2" color="text.secondary">
                                10-20x faster! Loops execution at a specific address.
                                Requires finding a suitable entry point.
                              </Typography>
                            </Paper>
                          </Grid>
                          <Grid item xs={12} md={4}>
                            <Paper sx={{ p: 2, bgcolor: 'background.default', height: '100%' }}>
                              <Typography variant="subtitle2" sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                                <DataObject color="info" fontSize="small" />
                                CompareCov Mode
                              </Typography>
                              <Typography variant="body2" color="text.secondary">
                                Enhanced coverage for string/magic number comparisons.
                                Helps break through input validation.
                              </Typography>
                            </Paper>
                          </Grid>
                        </Grid>
                      </Paper>
                    </Box>
                  )}

                  {/* Binary Analysis Sub-Tab */}
                  {qemuSubTab === 1 && (
                    <Box>
                      <Typography variant="subtitle1" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Architecture color="primary" />
                        Binary Architecture Analysis
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                        Analyze your binary to detect its architecture, security features, and get optimal fuzzing recommendations.
                      </Typography>

                      {/* Binary Selection */}
                      <Paper sx={{ p: 2, mb: 2 }}>
                        <Typography variant="subtitle2" color="primary" gutterBottom>
                          Select Binary to Analyze
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-end', flexWrap: 'wrap' }}>
                          <TextField
                            label="Binary Path"
                            placeholder={uploadedBinary?.path || "/path/to/binary"}
                            value={uploadedBinary?.path || config.target_path}
                            onChange={(e) => setConfig(prev => ({ ...prev, target_path: e.target.value }))}
                            size="small"
                            sx={{ flexGrow: 1, minWidth: 300 }}
                          />
                          <Button
                            variant="contained"
                            startIcon={qemuBinaryAnalysisLoading ? <CircularProgress size={20} color="inherit" /> : <Search />}
                            onClick={() => analyzeQemuBinary(uploadedBinary?.path || config.target_path)}
                            disabled={qemuBinaryAnalysisLoading || !(uploadedBinary?.path || config.target_path)}
                          >
                            {qemuBinaryAnalysisLoading ? 'Analyzing...' : 'Analyze Binary'}
                          </Button>
                        </Box>
                        {uploadedBinary && (
                          <Typography variant="caption" color="success.main" sx={{ mt: 1, display: 'block' }}>
                            Using uploaded binary: {uploadedBinary.name}
                          </Typography>
                        )}
                      </Paper>

                      {/* Analysis Results */}
                      {qemuBinaryAnalysis ? (
                        <>
                          {/* Architecture Info */}
                          <Paper sx={{ p: 2, mb: 2 }}>
                            <Typography variant="subtitle2" color="primary" gutterBottom>
                              Architecture Information
                            </Typography>
                            <Grid container spacing={2}>
                              <Grid item xs={6} sm={3}>
                                <Typography variant="caption" color="text.secondary">Architecture</Typography>
                                <Typography variant="body1" fontWeight={600}>
                                  {qemuBinaryAnalysis.architecture.architecture}
                                </Typography>
                              </Grid>
                              <Grid item xs={6} sm={3}>
                                <Typography variant="caption" color="text.secondary">Bits</Typography>
                                <Typography variant="body1" fontWeight={600}>
                                  {qemuBinaryAnalysis.architecture.bits}-bit
                                </Typography>
                              </Grid>
                              <Grid item xs={6} sm={3}>
                                <Typography variant="caption" color="text.secondary">Endianness</Typography>
                                <Typography variant="body1" fontWeight={600}>
                                  {qemuBinaryAnalysis.architecture.endian}
                                </Typography>
                              </Grid>
                              <Grid item xs={6} sm={3}>
                                <Typography variant="caption" color="text.secondary">File Type</Typography>
                                <Typography variant="body1" fontWeight={600}>
                                  {qemuBinaryAnalysis.architecture.file_type}
                                </Typography>
                              </Grid>
                              <Grid item xs={6} sm={3}>
                                <Typography variant="caption" color="text.secondary">Stripped</Typography>
                                <Chip
                                  size="small"
                                  label={qemuBinaryAnalysis.architecture.is_stripped ? 'Yes' : 'No'}
                                  color={qemuBinaryAnalysis.architecture.is_stripped ? 'warning' : 'success'}
                                />
                              </Grid>
                              <Grid item xs={6} sm={3}>
                                <Typography variant="caption" color="text.secondary">PIE</Typography>
                                <Chip
                                  size="small"
                                  label={qemuBinaryAnalysis.architecture.is_pie ? 'Yes' : 'No'}
                                  color={qemuBinaryAnalysis.architecture.is_pie ? 'info' : 'default'}
                                />
                              </Grid>
                              <Grid item xs={6} sm={3}>
                                <Typography variant="caption" color="text.secondary">QEMU Support</Typography>
                                <Chip
                                  size="small"
                                  label={qemuBinaryAnalysis.qemu_supported ? 'Supported' : 'Not Supported'}
                                  color={qemuBinaryAnalysis.qemu_supported ? 'success' : 'error'}
                                />
                              </Grid>
                            </Grid>
                          </Paper>

                          {/* Beginner Summary */}
                          {qemuBinaryAnalysis.beginner_summary && (
                            <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.info.main, 0.1) }}>
                              <Typography variant="subtitle2" color="info.main" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                <School fontSize="small" />
                                What This Means
                              </Typography>
                              <Typography variant="body2" sx={{ mb: 1 }}>
                                <strong>{qemuBinaryAnalysis.beginner_summary.what_is_this_binary}</strong>
                              </Typography>
                              <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                                <Chip
                                  size="small"
                                  label={qemuBinaryAnalysis.beginner_summary.can_we_fuzz_it ? 'Can be fuzzed' : 'Cannot be fuzzed'}
                                  color={qemuBinaryAnalysis.beginner_summary.can_we_fuzz_it ? 'success' : 'error'}
                                />
                                <Chip
                                  size="small"
                                  label={`Difficulty: ${qemuBinaryAnalysis.beginner_summary.difficulty}`}
                                  color={qemuBinaryAnalysis.beginner_summary.difficulty === 'easy' ? 'success' : qemuBinaryAnalysis.beginner_summary.difficulty === 'medium' ? 'warning' : 'error'}
                                />
                              </Box>
                              {qemuBinaryAnalysis.beginner_summary.things_to_know.length > 0 && (
                                <List dense>
                                  {qemuBinaryAnalysis.beginner_summary.things_to_know.map((item, idx) => (
                                    <ListItem key={idx}>
                                      <ListItemIcon><Info fontSize="small" color="info" /></ListItemIcon>
                                      <ListItemText primary={item} primaryTypographyProps={{ variant: 'body2' }} />
                                    </ListItem>
                                  ))}
                                </List>
                              )}
                            </Paper>
                          )}

                          {/* Recommendations */}
                          {qemuBinaryAnalysis.recommendations && (
                            <Paper sx={{ p: 2 }}>
                              <Typography variant="subtitle2" color="primary" gutterBottom>
                                Fuzzing Recommendations
                              </Typography>
                              <Box sx={{ mb: 2 }}>
                                <Typography variant="caption" color="text.secondary">Recommended Mode</Typography>
                                <Chip label={qemuBinaryAnalysis.recommendations.mode} color="primary" sx={{ ml: 1 }} />
                              </Box>
                              {qemuBinaryAnalysis.recommendations.tips.length > 0 && (
                                <>
                                  <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                    <Lightbulb fontSize="small" color="warning" />
                                    Tips
                                  </Typography>
                                  <List dense>
                                    {qemuBinaryAnalysis.recommendations.tips.map((tip, idx) => (
                                      <ListItem key={idx}>
                                        <ListItemText primary={tip} primaryTypographyProps={{ variant: 'body2' }} />
                                      </ListItem>
                                    ))}
                                  </List>
                                </>
                              )}
                              {qemuBinaryAnalysis.recommendations.warnings.length > 0 && (
                                <>
                                  <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 2 }}>
                                    <Warning fontSize="small" color="warning" />
                                    Warnings
                                  </Typography>
                                  <List dense>
                                    {qemuBinaryAnalysis.recommendations.warnings.map((warning, idx) => (
                                      <ListItem key={idx}>
                                        <ListItemText primary={warning} primaryTypographyProps={{ variant: 'body2', color: 'warning.main' }} />
                                      </ListItem>
                                    ))}
                                  </List>
                                </>
                              )}
                            </Paper>
                          )}
                        </>
                      ) : (
                        <Box sx={{ textAlign: 'center', py: 6 }}>
                          <Architecture sx={{ fontSize: 64, color: 'text.disabled' }} />
                          <Typography color="text.secondary">
                            Upload or specify a binary to analyze its architecture
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            Analysis will detect CPU architecture, security features, and provide fuzzing recommendations
                          </Typography>
                        </Box>
                      )}
                    </Box>
                  )}

                  {/* Trace Analysis Sub-Tab */}
                  {qemuSubTab === 2 && (
                    <Box>
                      <Typography variant="subtitle1" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Timeline color="primary" />
                        QEMU Trace Analysis
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                        Run a single execution with QEMU tracing to analyze code coverage and find good entry points for persistent mode.
                      </Typography>

                      {/* Trace Configuration */}
                      <Paper sx={{ p: 2, mb: 2 }}>
                        <Typography variant="subtitle2" color="primary" gutterBottom>
                          Trace Configuration
                        </Typography>
                        <Grid container spacing={2}>
                          <Grid item xs={12}>
                            <TextField
                              fullWidth
                              label="Binary Path"
                              placeholder={uploadedBinary?.path || "/path/to/binary"}
                              value={uploadedBinary?.path || config.target_path}
                              onChange={(e) => setConfig(prev => ({ ...prev, target_path: e.target.value }))}
                              size="small"
                            />
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <TextField
                              fullWidth
                              label="Input File Path (optional)"
                              placeholder="/path/to/input.bin"
                              value={qemuTraceInputFile}
                              onChange={(e) => setQemuTraceInputFile(e.target.value)}
                              size="small"
                              helperText="Path to a test input file"
                            />
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <TextField
                              fullWidth
                              label="Input Data (Base64, optional)"
                              placeholder="QUFBQQo="
                              value={qemuTraceInputData}
                              onChange={(e) => setQemuTraceInputData(e.target.value)}
                              size="small"
                              helperText="Base64-encoded input if no file"
                            />
                          </Grid>
                          <Grid item xs={12}>
                            <Button
                              variant="contained"
                              color="secondary"
                              startIcon={qemuTraceLoading ? <CircularProgress size={20} color="inherit" /> : <PlayArrow />}
                              onClick={() => runQemuTrace(
                                uploadedBinary?.path || config.target_path,
                                qemuTraceInputFile || undefined,
                                qemuTraceInputData || undefined
                              )}
                              disabled={qemuTraceLoading || !(uploadedBinary?.path || config.target_path)}
                            >
                              {qemuTraceLoading ? 'Running Trace...' : 'Run QEMU Trace'}
                            </Button>
                          </Grid>
                        </Grid>
                      </Paper>

                      {/* Trace Results */}
                      {qemuTraceAnalysis ? (
                        <Paper sx={{ p: 2 }}>
                          <Typography variant="subtitle2" color="primary" gutterBottom>
                            Trace Results
                          </Typography>
                          <Grid container spacing={2}>
                            <Grid item xs={6} sm={3}>
                              <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'primary.dark' }}>
                                <Typography variant="h4" color="white">
                                  {qemuTraceAnalysis.unique_basic_blocks.toLocaleString()}
                                </Typography>
                                <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                                  Unique Basic Blocks
                                </Typography>
                              </Paper>
                            </Grid>
                            <Grid item xs={6} sm={3}>
                              <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'secondary.dark' }}>
                                <Typography variant="h4" color="white">
                                  {qemuTraceAnalysis.total_basic_blocks.toLocaleString()}
                                </Typography>
                                <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                                  Total Executions
                                </Typography>
                              </Paper>
                            </Grid>
                            <Grid item xs={6} sm={3}>
                              <Paper sx={{ p: 2, textAlign: 'center' }}>
                                <Typography variant="h4">
                                  {qemuTraceAnalysis.execution_time_ms.toFixed(1)}
                                </Typography>
                                <Typography variant="caption" color="text.secondary">
                                  Execution Time (ms)
                                </Typography>
                              </Paper>
                            </Grid>
                            <Grid item xs={6} sm={3}>
                              <Paper sx={{ p: 2, textAlign: 'center' }}>
                                <Typography variant="h4">
                                  {qemuTraceAnalysis.total_basic_blocks > 0
                                    ? (qemuTraceAnalysis.total_basic_blocks / qemuTraceAnalysis.unique_basic_blocks).toFixed(1)
                                    : '0'}
                                </Typography>
                                <Typography variant="caption" color="text.secondary">
                                  Avg Executions/Block
                                </Typography>
                              </Paper>
                            </Grid>
                          </Grid>

                          {qemuTraceAnalysis.hot_spots && qemuTraceAnalysis.hot_spots.length > 0 && (
                            <Box sx={{ mt: 2 }}>
                              <Typography variant="subtitle2" gutterBottom>
                                Hot Spots (Most Executed)
                              </Typography>
                              <TableContainer>
                                <Table size="small">
                                  <TableHead>
                                    <TableRow>
                                      <TableCell>Address</TableCell>
                                      <TableCell align="right">Execution Count</TableCell>
                                    </TableRow>
                                  </TableHead>
                                  <TableBody>
                                    {qemuTraceAnalysis.hot_spots.slice(0, 10).map((spot, idx) => (
                                      <TableRow key={idx}>
                                        <TableCell sx={{ fontFamily: 'monospace' }}>{spot.address}</TableCell>
                                        <TableCell align="right">{spot.count.toLocaleString()}</TableCell>
                                      </TableRow>
                                    ))}
                                  </TableBody>
                                </Table>
                              </TableContainer>
                              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
                                Hot spots are good candidates for persistent mode entry points
                              </Typography>
                            </Box>
                          )}
                        </Paper>
                      ) : (
                        <Box sx={{ textAlign: 'center', py: 6 }}>
                          <Timeline sx={{ fontSize: 64, color: 'text.disabled' }} />
                          <Typography color="text.secondary">
                            Run a trace to analyze code coverage
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            Trace analysis helps understand which code paths an input exercises
                          </Typography>
                        </Box>
                      )}
                    </Box>
                  )}

                  {/* Start QEMU Fuzzing Sub-Tab */}
                  {qemuSubTab === 3 && (
                    <Box>
                      <Typography variant="subtitle1" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <FlashOn color="primary" />
                        Start QEMU Mode Fuzzing
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                        Configure and start a QEMU-mode fuzzing session for your closed-source binary.
                      </Typography>

                      {/* Prerequisites Check */}
                      <Paper sx={{ p: 2, mb: 2 }}>
                        <Typography variant="subtitle2" color="primary" gutterBottom>
                          Prerequisites
                        </Typography>
                        <List dense>
                          <ListItem>
                            <ListItemIcon>
                              {qemuCapabilities?.available ? <CheckCircle color="success" /> : <Warning color="warning" />}
                            </ListItemIcon>
                            <ListItemText
                              primary="QEMU Mode Available"
                              secondary={qemuCapabilities?.available ? 'AFL++ QEMU mode is ready' : 'QEMU mode not detected'}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon>
                              {(uploadedBinary?.path || config.target_path) ? <CheckCircle color="success" /> : <ErrorIcon color="error" />}
                            </ListItemIcon>
                            <ListItemText
                              primary="Target Binary"
                              secondary={(uploadedBinary?.path || config.target_path) || 'No binary selected'}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon>
                              {config.seed_dir || uploadedSeeds.length > 0 ? <CheckCircle color="success" /> : <Warning color="warning" />}
                            </ListItemIcon>
                            <ListItemText
                              primary="Seed Files"
                              secondary={uploadedSeeds.length > 0 ? `${uploadedSeeds.length} seeds uploaded` : config.seed_dir || 'No seeds configured (will use defaults)'}
                            />
                          </ListItem>
                        </List>
                      </Paper>

                      {/* QEMU Configuration */}
                      <Paper sx={{ p: 2, mb: 2 }}>
                        <Typography variant="subtitle2" color="primary" gutterBottom>
                          QEMU Configuration
                        </Typography>
                        <Grid container spacing={2}>
                          <Grid item xs={12} md={6}>
                            <FormControl fullWidth size="small">
                              <InputLabel>QEMU Mode</InputLabel>
                              <Select
                                value={qemuFuzzConfig.mode}
                                label="QEMU Mode"
                                onChange={(e) => setQemuFuzzConfig(prev => ({ ...prev, mode: e.target.value as 'standard' | 'persistent' | 'compcov' }))}
                              >
                                <MenuItem value="standard">Standard Mode (Most Compatible)</MenuItem>
                                <MenuItem value="persistent">Persistent Mode (10-20x Faster)</MenuItem>
                                <MenuItem value="compcov">CompareCov Mode (Better Coverage)</MenuItem>
                              </Select>
                            </FormControl>
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <FormControlLabel
                              control={
                                <Switch
                                  checked={qemuFuzzConfig.enable_compcov}
                                  onChange={(e) => setQemuFuzzConfig(prev => ({ ...prev, enable_compcov: e.target.checked }))}
                                />
                              }
                              label="Enable CompareCoverage"
                            />
                          </Grid>

                          {qemuFuzzConfig.mode === 'persistent' && (
                            <>
                              <Grid item xs={12} md={6}>
                                <TextField
                                  fullWidth
                                  label="Persistent Address (Hex)"
                                  placeholder="0x400000"
                                  value={qemuFuzzConfig.persistent_address}
                                  onChange={(e) => setQemuFuzzConfig(prev => ({ ...prev, persistent_address: e.target.value }))}
                                  size="small"
                                  helperText="Entry point for persistent loop"
                                />
                              </Grid>
                              <Grid item xs={12} md={6}>
                                <TextField
                                  fullWidth
                                  label="Persistent Count"
                                  type="number"
                                  value={qemuFuzzConfig.persistent_count}
                                  onChange={(e) => setQemuFuzzConfig(prev => ({ ...prev, persistent_count: parseInt(e.target.value) || 10000 }))}
                                  size="small"
                                  inputProps={{ min: 1, max: 1000000 }}
                                  helperText="Iterations per fork"
                                />
                              </Grid>
                            </>
                          )}

                          <Grid item xs={12} md={6}>
                            <TextField
                              fullWidth
                              label="Timeout (ms)"
                              type="number"
                              value={qemuFuzzConfig.timeout_ms}
                              onChange={(e) => setQemuFuzzConfig(prev => ({ ...prev, timeout_ms: parseInt(e.target.value) || 10000 }))}
                              size="small"
                              inputProps={{ min: 100, max: 120000 }}
                              helperText="QEMU is slower - use longer timeouts"
                            />
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <TextField
                              fullWidth
                              label="Memory Limit (MB)"
                              type="number"
                              value={qemuFuzzConfig.memory_limit_mb}
                              onChange={(e) => setQemuFuzzConfig(prev => ({ ...prev, memory_limit_mb: parseInt(e.target.value) || 512 }))}
                              size="small"
                              inputProps={{ min: 64, max: 8192 }}
                            />
                          </Grid>
                        </Grid>
                      </Paper>

                      {/* Binary Analysis Summary */}
                      {qemuBinaryAnalysis && (
                        <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.success.main, 0.1) }}>
                          <Typography variant="subtitle2" color="success.main" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <CheckCircle fontSize="small" />
                            Binary Analyzed
                          </Typography>
                          <Typography variant="body2">
                            {qemuBinaryAnalysis.architecture.architecture} {qemuBinaryAnalysis.architecture.bits}-bit {qemuBinaryAnalysis.architecture.endian} binary
                            {qemuBinaryAnalysis.recommendations?.mode && ` • Recommended: ${qemuBinaryAnalysis.recommendations.mode} mode`}
                          </Typography>
                        </Paper>
                      )}

                      {/* Start Button */}
                      <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                        <Button
                          variant="contained"
                          color="error"
                          size="large"
                          startIcon={qemuFuzzLoading ? <CircularProgress size={24} color="inherit" /> : <PlayArrow />}
                          onClick={startQemuFuzzing}
                          disabled={qemuFuzzLoading || !qemuCapabilities?.available || !(uploadedBinary?.path || config.target_path)}
                          sx={{ minWidth: 200 }}
                        >
                          {qemuFuzzLoading ? 'Starting...' : 'Start QEMU Fuzzing'}
                        </Button>
                        {!qemuBinaryAnalysis && (uploadedBinary?.path || config.target_path) && (
                          <Button
                            variant="outlined"
                            onClick={() => analyzeQemuBinary(uploadedBinary?.path || config.target_path)}
                          >
                            Analyze Binary First (Recommended)
                          </Button>
                        )}
                      </Box>

                      {/* Tips */}
                      <Paper sx={{ p: 2, mt: 2, bgcolor: alpha(theme.palette.warning.main, 0.1) }}>
                        <Typography variant="subtitle2" color="warning.main" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Lightbulb fontSize="small" />
                          QEMU Fuzzing Tips
                        </Typography>
                        <List dense>
                          <ListItem>
                            <ListItemText
                              primary="QEMU mode is 2-10x slower than native fuzzing"
                              secondary="This is normal - you're trading speed for the ability to fuzz any binary"
                              primaryTypographyProps={{ variant: 'body2' }}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemText
                              primary="Use persistent mode for 10-20x speedup"
                              secondary="Run trace analysis to find good entry points"
                              primaryTypographyProps={{ variant: 'body2' }}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemText
                              primary="Enable CompareCov for better coverage"
                              secondary="Helps break through string comparisons and magic bytes"
                              primaryTypographyProps={{ variant: 'body2' }}
                            />
                          </ListItem>
                        </List>
                      </Paper>
                    </Box>
                  )}
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Feature Info */}
      <Card sx={{ mt: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            <Info sx={{ mr: 1, verticalAlign: 'middle' }} />
            About Binary Fuzzing
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={3}>
              <Typography variant="subtitle2" color="primary">
                Mutation Strategies
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Bit flips, byte flips, arithmetic mutations, interesting boundary values, dictionary-based mutations,
                and AFL-style havoc mode.
              </Typography>
            </Grid>
            <Grid item xs={12} md={3}>
              <Typography variant="subtitle2" color="primary">
                Coverage Guidance
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Track edge coverage to prioritize inputs that explore new code paths. AFL-style power scheduling
                optimizes mutation energy.
              </Typography>
            </Grid>
            <Grid item xs={12} md={3}>
              <Typography variant="subtitle2" color="primary">
                Crash Detection
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Automatically detects crashes via exit codes and signals. Supports AddressSanitizer output parsing for
                enhanced crash classification.
              </Typography>
            </Grid>
            <Grid item xs={12} md={3}>
              <Typography variant="subtitle2" color="primary">
                AI-Powered Analysis
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Smart seed generation, coverage optimization advice, deep exploit analysis with PoC guidance, and 
                comprehensive session summaries.
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Crash Details Dialog */}
      <Dialog
        open={crashDialogOpen}
        onClose={closeCrashDialog}
        maxWidth="md"
        fullWidth
        PaperProps={{ sx: { minHeight: '60vh' } }}
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <BugReportOutlined color="error" />
            <Typography variant="h6">
              Crash Details - {selectedCrash?.id}
            </Typography>
            {selectedCrash && (
              <Chip
                label={selectedCrash.severity.replace(/_/g, ' ')}
                size="small"
                color={severityColors[selectedCrash.severity] || 'default'}
              />
            )}
          </Box>
          <IconButton onClick={closeCrashDialog} size="small">
            <Close />
          </IconButton>
        </DialogTitle>
        <DialogContent dividers>
          {selectedCrash && (
            <>
              <Tabs
                value={crashDialogTab}
                onChange={(_, newValue) => setCrashDialogTab(newValue)}
                sx={{ mb: 2, borderBottom: 1, borderColor: 'divider' }}
              >
                <Tab label="Overview" icon={<Info fontSize="small" />} iconPosition="start" />
                <Tab label="Stack Trace" icon={<DataObject fontSize="small" />} iconPosition="start" />
                <Tab label="Registers" icon={<MemoryOutlined fontSize="small" />} iconPosition="start" />
                <Tab label="Hex Dump" icon={<Code fontSize="small" />} iconPosition="start" />
              </Tabs>

              {/* Overview Tab */}
              {crashDialogTab === 0 && (
                <Box>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="subtitle2" color="text.secondary">Crash Type</Typography>
                      <Typography variant="body1" sx={{ fontWeight: 500 }}>
                        {crashTypeLabels[selectedCrash.crash_type] || selectedCrash.crash_type}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="subtitle2" color="text.secondary">Severity</Typography>
                      <Chip
                        label={selectedCrash.severity.replace(/_/g, ' ')}
                        color={severityColors[selectedCrash.severity] || 'default'}
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="subtitle2" color="text.secondary">First Seen</Typography>
                      <Typography variant="body1">
                        {new Date(selectedCrash.first_seen).toLocaleString()}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="subtitle2" color="text.secondary">Sample Count</Typography>
                      <Typography variant="body1">{selectedCrash.sample_count} occurrences</Typography>
                    </Grid>
                    {selectedCrash.crash_address && (
                      <Grid item xs={12} sm={6}>
                        <Typography variant="subtitle2" color="text.secondary">Crash Address</Typography>
                        <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                          {selectedCrash.crash_address}
                        </Typography>
                      </Grid>
                    )}
                    {selectedCrash.faulting_instruction && (
                      <Grid item xs={12}>
                        <Typography variant="subtitle2" color="text.secondary">Faulting Instruction</Typography>
                        <Paper sx={{ p: 1, bgcolor: 'grey.900' }}>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace', color: 'error.light' }}>
                            {selectedCrash.faulting_instruction}
                          </Typography>
                        </Paper>
                      </Grid>
                    )}
                    {selectedCrash.input_file && (
                      <Grid item xs={12}>
                        <Typography variant="subtitle2" color="text.secondary">Input File</Typography>
                        <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                          {selectedCrash.input_file}
                        </Typography>
                      </Grid>
                    )}
                  </Grid>
                  
                  {/* Quick Actions */}
                  <Box sx={{ mt: 3, pt: 2, borderTop: 1, borderColor: 'divider' }}>
                    <Typography variant="subtitle2" gutterBottom>Quick Actions</Typography>
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={<Code />}
                        onClick={() => exportCrashGDB(selectedCrash)}
                      >
                        Export GDB Script
                      </Button>
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={<ContentCopy />}
                        onClick={() => copyToClipboard(JSON.stringify(selectedCrash, null, 2))}
                      >
                        Copy as JSON
                      </Button>
                    </Box>
                  </Box>
                </Box>
              )}

              {/* Stack Trace Tab */}
              {crashDialogTab === 1 && (
                <Box>
                  <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 1 }}>
                    <Tooltip title="Copy Stack Trace">
                      <IconButton
                        size="small"
                        onClick={() => copyToClipboard(selectedCrash.stack_trace?.join('\n') || 'No stack trace available')}
                      >
                        <ContentCopy fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </Box>
                  <Paper
                    sx={{
                      p: 2,
                      bgcolor: 'grey.900',
                      maxHeight: 400,
                      overflow: 'auto',
                    }}
                  >
                    {selectedCrash.stack_trace && selectedCrash.stack_trace.length > 0 ? (
                      selectedCrash.stack_trace.map((frame, idx) => (
                        <Typography
                          key={idx}
                          variant="body2"
                          sx={{
                            fontFamily: 'monospace',
                            fontSize: '0.8rem',
                            color: idx === 0 ? 'error.light' : 'grey.300',
                            mb: 0.5,
                          }}
                        >
                          #{idx} {frame}
                        </Typography>
                      ))
                    ) : (
                      <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                        No stack trace available. Enable AddressSanitizer for detailed stack traces.
                      </Typography>
                    )}
                  </Paper>
                </Box>
              )}

              {/* Registers Tab */}
              {crashDialogTab === 2 && (
                <Box>
                  {selectedCrash.registers && Object.keys(selectedCrash.registers).length > 0 ? (
                    <Grid container spacing={1}>
                      {Object.entries(selectedCrash.registers).map(([reg, value]) => (
                        <Grid item xs={6} sm={4} md={3} key={reg}>
                          <Paper sx={{ p: 1, bgcolor: 'grey.900' }}>
                            <Typography variant="caption" color="primary.light">
                              {reg}
                            </Typography>
                            <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                              {value}
                            </Typography>
                          </Paper>
                        </Grid>
                      ))}
                    </Grid>
                  ) : (
                    <Box sx={{ textAlign: 'center', py: 4 }}>
                      <MemoryOutlined sx={{ fontSize: 48, color: 'text.disabled' }} />
                      <Typography color="text.secondary">
                        Register dump not available
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Use a debugger or GDB script to capture register state
                      </Typography>
                    </Box>
                  )}
                </Box>
              )}

              {/* Hex Dump Tab */}
              {crashDialogTab === 3 && (
                <Box>
                  <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 1 }}>
                    <Tooltip title="Copy Hex Dump">
                      <IconButton
                        size="small"
                        onClick={() => copyToClipboard(generateHexDump(selectedCrash.input_data || '').join('\n'))}
                      >
                        <ContentCopy fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </Box>
                  <Paper
                    sx={{
                      p: 2,
                      bgcolor: 'grey.900',
                      maxHeight: 400,
                      overflow: 'auto',
                    }}
                  >
                    {selectedCrash.input_data ? (
                      <Typography
                        variant="body2"
                        component="pre"
                        sx={{
                          fontFamily: 'monospace',
                          fontSize: '0.75rem',
                          color: 'grey.300',
                          whiteSpace: 'pre',
                          m: 0,
                        }}
                      >
                        {generateHexDump(selectedCrash.input_data).join('\n')}
                      </Typography>
                    ) : (
                      <Box sx={{ textAlign: 'center', py: 4 }}>
                        <DataObject sx={{ fontSize: 48, color: 'text.disabled' }} />
                        <Typography color="text.secondary">
                          Input data not available
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          Crash input file may be available in the corpus directory
                        </Typography>
                      </Box>
                    )}
                  </Paper>
                </Box>
              )}
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={closeCrashDialog}>Close</Button>
          <Button
            variant="contained"
            startIcon={<Code />}
            onClick={() => selectedCrash && exportCrashGDB(selectedCrash)}
          >
            Export GDB Script
          </Button>
        </DialogActions>
      </Dialog>

      {/* Corpus File Preview Dialog */}
      <Dialog
        open={corpusDialogOpen}
        onClose={closeCorpusDialog}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            {selectedCorpusFile?.source === 'crash' ? (
              <BugReport color="error" />
            ) : (
              <InsertDriveFile color="primary" />
            )}
            <Typography variant="h6">Corpus File Preview</Typography>
            {selectedCorpusFile?.is_favored && (
              <Chip icon={<Star />} label="Favored" size="small" color="warning" />
            )}
          </Box>
          <IconButton onClick={closeCorpusDialog} size="small">
            <Close />
          </IconButton>
        </DialogTitle>
        <DialogContent dividers>
          {selectedCorpusFile && (
            <Box>
              {/* File Info */}
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12} sm={6}>
                  <Typography variant="caption" color="text.secondary">Filename</Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    {selectedCorpusFile.filename}
                  </Typography>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Typography variant="caption" color="text.secondary">Size</Typography>
                  <Typography variant="body2">{selectedCorpusFile.size} bytes</Typography>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Typography variant="caption" color="text.secondary">Coverage</Typography>
                  <Typography variant="body2">{selectedCorpusFile.coverage_edges} edges</Typography>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Typography variant="caption" color="text.secondary">Source</Typography>
                  <Chip
                    size="small"
                    label={selectedCorpusFile.source}
                    color={selectedCorpusFile.source === 'crash' ? 'error' : selectedCorpusFile.source === 'seed' ? 'info' : 'default'}
                  />
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Typography variant="caption" color="text.secondary">Created</Typography>
                  <Typography variant="body2">
                    {new Date(selectedCorpusFile.created_at).toLocaleString()}
                  </Typography>
                </Grid>
              </Grid>

              {/* Hex Preview */}
              <Typography variant="subtitle2" gutterBottom>
                <DataObject sx={{ mr: 1, verticalAlign: 'middle', fontSize: 'small' }} />
                Hex Preview
              </Typography>
              <Paper
                sx={{
                  p: 2,
                  bgcolor: 'grey.900',
                  maxHeight: 300,
                  overflow: 'auto',
                  mb: 2,
                }}
              >
                <Typography
                  variant="body2"
                  component="pre"
                  sx={{
                    fontFamily: 'monospace',
                    fontSize: '0.75rem',
                    color: 'grey.300',
                    m: 0,
                    whiteSpace: 'pre-wrap',
                  }}
                >
                  {selectedCorpusFile.preview || 'No preview available'}
                </Typography>
              </Paper>

              {/* ASCII Preview */}
              <Typography variant="subtitle2" gutterBottom>
                <TextSnippet sx={{ mr: 1, verticalAlign: 'middle', fontSize: 'small' }} />
                ASCII Preview
              </Typography>
              <Paper
                sx={{
                  p: 2,
                  bgcolor: 'grey.900',
                  maxHeight: 150,
                  overflow: 'auto',
                }}
              >
                <Typography
                  variant="body2"
                  component="pre"
                  sx={{
                    fontFamily: 'monospace',
                    fontSize: '0.75rem',
                    color: 'grey.300',
                    m: 0,
                    whiteSpace: 'pre-wrap',
                  }}
                >
                  {selectedCorpusFile.preview
                    ?.split(' ')
                    .map(hex => {
                      const byte = parseInt(hex, 16);
                      return byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';
                    })
                    .join('') || 'No preview available'}
                </Typography>
              </Paper>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={closeCorpusDialog}>Close</Button>
          <Button
            variant="outlined"
            startIcon={selectedCorpusFile?.is_favored ? <Star /> : <Star />}
            color={selectedCorpusFile?.is_favored ? 'warning' : 'inherit'}
            onClick={() => {
              if (selectedCorpusFile) {
                toggleFavorite(selectedCorpusFile.id);
                setSelectedCorpusFile({ ...selectedCorpusFile, is_favored: !selectedCorpusFile.is_favored });
              }
            }}
          >
            {selectedCorpusFile?.is_favored ? 'Unfavorite' : 'Add to Favorites'}
          </Button>
          <Button
            variant="contained"
            startIcon={<Download />}
            onClick={() => selectedCorpusFile && exportCorpusFile(selectedCorpusFile)}
          >
            Export File
          </Button>
        </DialogActions>
      </Dialog>

      {/* AI Chat Panel - Floating */}
      <Paper
        elevation={6}
        sx={{
          position: 'fixed',
          bottom: 16,
          right: 16,
          left: chatMaximized ? { xs: 16, md: 256 } : 'auto',
          width: chatMaximized ? 'auto' : { xs: 'calc(100% - 32px)', sm: 400 },
          maxWidth: chatMaximized ? 'none' : 400,
          zIndex: 1200,
          borderRadius: 3,
          overflow: 'hidden',
          boxShadow: '0 4px 30px rgba(0,0,0,0.3)',
          transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
        }}
      >
        {/* Chat Header */}
        <Box
          onClick={() => !chatMaximized && setChatOpen(!chatOpen)}
          sx={{
            p: 1.5,
            background: 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)',
            color: 'white',
            cursor: chatMaximized ? 'default' : 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            '&:hover': { filter: chatMaximized ? 'none' : 'brightness(1.1)' },
          }}
        >
          <Box
            onClick={() => chatMaximized && setChatOpen(!chatOpen)}
            sx={{ display: 'flex', alignItems: 'center', gap: 1, cursor: 'pointer', flex: 1 }}
          >
            <ChatIcon fontSize="small" />
            <Typography variant="body2" sx={{ fontWeight: 600 }}>
              AI Chat
            </Typography>
            {crashes.length > 0 && (
              <Chip
                label={crashes.length}
                size="small"
                sx={{ bgcolor: 'rgba(255,255,255,0.2)', color: 'white', height: 20, '& .MuiChip-label': { px: 1, fontSize: '0.7rem' } }}
              />
            )}
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <IconButton
              size="small"
              sx={{ color: 'white', p: 0.5 }}
              onClick={(e) => {
                e.stopPropagation();
                if (!chatOpen) setChatOpen(true);
                setChatMaximized(!chatMaximized);
              }}
            >
              {chatMaximized ? <CloseFullscreen fontSize="small" /> : <OpenInFull fontSize="small" />}
            </IconButton>
            <IconButton
              size="small"
              sx={{ color: 'white', p: 0.5 }}
              onClick={(e) => {
                e.stopPropagation();
                setChatOpen(!chatOpen);
              }}
            >
              {chatOpen ? <ExpandMore fontSize="small" /> : <ExpandLess fontSize="small" />}
            </IconButton>
          </Box>
        </Box>

        {/* Chat Content */}
        <Collapse in={chatOpen}>
          {/* Messages Area */}
          <Box
            sx={{
              height: chatMaximized ? 'calc(66vh - 120px)' : 280,
              overflowY: 'auto',
              p: 2,
              bgcolor: alpha(theme.palette.background.default, 0.98),
              transition: 'height 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
            }}
          >
            {/* Welcome message */}
            {chatMessages.length === 0 && (
              <Box sx={{ textAlign: 'center', py: chatMaximized ? 6 : 2 }}>
                <SmartToyIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 1 }} />
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  I can help you understand your fuzzing results, analyze crashes, and optimize your testing!
                </Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, alignItems: 'center' }}>
                  {[
                    'Give me a summary of the session',
                    'What crashes did you find?',
                    'How do I improve coverage?',
                    'Help me generate better seeds',
                    'Explain the exploitability of crashes',
                  ].map((suggestion, i) => (
                    <Chip
                      key={i}
                      label={suggestion}
                      variant="outlined"
                      size="small"
                      onClick={() => setChatInput(suggestion)}
                      sx={{ cursor: 'pointer', '&:hover': { bgcolor: alpha(theme.palette.primary.main, 0.1) } }}
                    />
                  ))}
                </Box>
              </Box>
            )}

            {/* Chat Messages */}
            {chatMessages.map((msg, i) => (
              <Box
                key={i}
                sx={{
                  display: 'flex',
                  justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start',
                  mb: 2,
                }}
              >
                <Box
                  sx={{
                    maxWidth: '85%',
                    display: 'flex',
                    gap: 1,
                    flexDirection: msg.role === 'user' ? 'row-reverse' : 'row',
                  }}
                >
                  <Box
                    sx={{
                      width: 32,
                      height: 32,
                      borderRadius: '50%',
                      bgcolor: msg.role === 'user' ? '#dc2626' : '#8b5cf6',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                    }}
                  >
                    {msg.role === 'user' ? (
                      <PersonIcon sx={{ fontSize: 18, color: 'white' }} />
                    ) : (
                      <SmartToyIcon sx={{ fontSize: 18, color: 'white' }} />
                    )}
                  </Box>
                  <Paper
                    sx={{
                      p: 1.5,
                      bgcolor: msg.role === 'user' ? '#dc2626' : theme.palette.background.paper,
                      color: msg.role === 'user' ? 'white' : 'text.primary',
                      borderRadius: 2,
                      '& p': { m: 0 },
                      '& p:not(:last-child)': { mb: 1 },
                      '& h2': { fontSize: '1.1rem', fontWeight: 700, mb: 1 },
                      '& h3': { fontSize: '1rem', fontWeight: 600, mb: 0.5 },
                      '& ul, & ol': { pl: 2, m: 0 },
                      '& li': { mb: 0.5 },
                      '& strong': { fontWeight: 600 },
                    }}
                  >
                    <ReactMarkdown
                      components={{
                        code: ({ className, children }) => (
                          <ChatCodeBlock className={className} theme={theme}>
                            {children}
                          </ChatCodeBlock>
                        ),
                      }}
                    >
                      {msg.content}
                    </ReactMarkdown>
                  </Paper>
                </Box>
              </Box>
            ))}

            {/* Loading indicator */}
            {chatLoading && (
              <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                <Box
                  sx={{
                    width: 32,
                    height: 32,
                    borderRadius: '50%',
                    bgcolor: '#8b5cf6',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <SmartToyIcon sx={{ fontSize: 18, color: 'white' }} />
                </Box>
                <Paper sx={{ p: 1.5, borderRadius: 2 }}>
                  <CircularProgress size={16} />
                </Paper>
              </Box>
            )}

            <div ref={chatEndRef} />
          </Box>

          {/* Input Area */}
          <Box
            sx={{
              p: 2,
              borderTop: `1px solid ${theme.palette.divider}`,
              bgcolor: theme.palette.background.paper,
              display: 'flex',
              gap: 1,
            }}
          >
            <TextField
              fullWidth
              size="small"
              placeholder="Ask about your fuzzing results, crashes, coverage..."
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && sendChatMessage()}
              disabled={chatLoading}
            />
            <Button
              variant="contained"
              onClick={sendChatMessage}
              disabled={!chatInput.trim() || chatLoading}
              sx={{
                background: 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)',
                '&:hover': {
                  background: 'linear-gradient(135deg, #b91c1c 0%, #991b1b 100%)',
                },
              }}
            >
              <SendIcon />
            </Button>
          </Box>
        </Collapse>
      </Paper>
    </Box>
  );
};

export default BinaryFuzzerPage;
