import { useEffect, useState, useRef } from "react";
import {
  Box,
  LinearProgress,
  Paper,
  Typography,
  alpha,
  useTheme,
  Chip,
  Stack,
  keyframes,
  Collapse,
  IconButton,
  Tooltip,
  Divider,
  Theme,
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import RadioButtonUncheckedIcon from "@mui/icons-material/RadioButtonUnchecked";
import HourglassEmptyIcon from "@mui/icons-material/HourglassEmpty";

// Success animation
const celebrateAnimation = keyframes`
  0% { transform: scale(0.8); opacity: 0; }
  50% { transform: scale(1.1); }
  100% { transform: scale(1); opacity: 1; }
`;

const pulseGlow = keyframes`
  0%, 100% { box-shadow: 0 0 20px rgba(34, 197, 94, 0.3); }
  50% { box-shadow: 0 0 40px rgba(34, 197, 94, 0.6), 0 0 60px rgba(34, 197, 94, 0.3); }
`;

const spinAnimation = keyframes`
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
`;

interface ScanProgress {
  scan_run_id: number;
  phase: string;
  progress: number;
  message: string;
  timestamp: string;
}

interface ScanProgressProps {
  scanRunId: number | null;
  onComplete?: () => void;
}

// Phase categories for organized display - EXACT ORDER matching backend execution
interface PhaseCategory {
  name: string;
  icon: string;
  phases: string[];
  description: string;
}

const PHASE_CATEGORIES: PhaseCategory[] = [
  {
    name: "Setup",
    icon: "📦",
    phases: ["initializing", "extracting", "parsing"],
    description: "Extracting and parsing source code (0-30%)",
  },
  {
    name: "Embeddings",
    icon: "🧠",
    phases: ["embedding"],
    description: "Generating code embeddings for AI analysis (30-45%)",
  },
  {
    name: "Parallel Scanning",
    icon: "🔍",
    phases: ["parallel_scanning", "scanning", "sast", "secrets", "eslint", "semgrep", "bandit", "gosec", "spotbugs", "clangtidy", "cppcheck", "php", "brakeman", "cargo_audit", "docker", "iac"],
    description: "SAST, Docker, IaC scanners in parallel (45-70%)",
  },
  {
    name: "Deduplication",
    icon: "🔗",
    phases: ["deduplication"],
    description: "Merging duplicate findings across scanners (70-72%)",
  },
  {
    name: "Dependency Parsing",
    icon: "📦",
    phases: ["dependencies"],
    description: "Parsing project dependencies (72-75%)",
  },
  {
    name: "Dependency Trees",
    icon: "📚",
    phases: ["transitive_deps"],
    description: "Analyzing transitive dependency trees (75-78%)",
  },
  {
    name: "CVE Lookup",
    icon: "🛡️",
    phases: ["cve_lookup"],
    description: "Looking up known vulnerabilities (78-82%)",
  },
  {
    name: "Transitive Analysis",
    icon: "🔀",
    phases: ["transitive_analysis"],
    description: "Analyzing transitive vulnerability paths (82-84%)",
  },
  {
    name: "Reachability Analysis",
    icon: "🎯",
    phases: ["reachability"],
    description: "Determining if vulnerable code is reachable (84-86%)",
  },
  {
    name: "Enrichment",
    icon: "📊",
    phases: ["enrichment", "epss", "nvd"],
    description: "Enriching with EPSS, NVD, and KEV data (86-89%)",
  },
  {
    name: "AI File Triage",
    icon: "🔍",
    phases: ["agentic_scan", "agentic_initializing", "agentic_file_triage"],
    description: "AI examines all files to select security-relevant ones (89-90%)",
  },
  {
    name: "Multi-Pass Analysis",
    icon: "🤖",
    phases: ["agentic_initial_analysis", "agentic_focused_analysis", "agentic_deep_analysis"],
    description: "AI analyzes files with progressively increasing depth (89.5-90%)",
  },
  {
    name: "Entry Point Detection",
    icon: "🎯",
    phases: ["agentic_chunking", "agentic_entry_points"],
    description: "Finding user input sources and API endpoints (90-90.2%)",
  },
  {
    name: "Flow Tracing",
    icon: "🔀",
    phases: ["agentic_flow_tracing"],
    description: "Tracing data flows from inputs to dangerous sinks (90.2-90.5%)",
  },
  {
    name: "Vulnerability Analysis",
    icon: "⚠️",
    phases: ["agentic_analyzing", "agentic_fp_filtering"],
    description: "Analyzing vulnerabilities and filtering false positives (90.5-90.8%)",
  },
  {
    name: "Synthesis",
    icon: "🧠",
    phases: ["agentic_synthesis", "agentic_reporting", "agentic_complete", "agentic_error", "agentic_scanning"],
    description: "AI synthesizes findings across all passes (90.8-91%)",
  },
  {
    name: "Final Deduplication",
    icon: "🔗",
    phases: ["deduplication_final"],
    description: "Merging agentic findings with SAST results (91-92%)",
  },
  {
    name: "AI Analysis",
    icon: "✨",
    phases: ["ai_analysis"],
    description: "False positive detection & attack chain discovery (92-98%)",
  },
  {
    name: "Report",
    icon: "📝",
    phases: ["reporting", "complete"],
    description: "Generating final security report (99-100%)",
  },
];

// Phase display names
const PHASE_LABELS: Record<string, string> = {
  initializing: "Initializing",
  extracting: "Extracting Archive",
  parsing: "Parsing Source Files",
  embedding: "Generating Embeddings",
  parallel_scanning: "Parallel Scanning",
  scanning: "Security Scanning",
  sast: "SAST Analysis",
  secrets: "Secret Detection",
  eslint: "ESLint (JS/TS)",
  semgrep: "Semgrep Analysis",
  bandit: "Bandit (Python)",
  gosec: "Gosec (Go)",
  spotbugs: "SpotBugs (Java)",
  clangtidy: "Clang-Tidy (C/C++)",
  cppcheck: "Cppcheck (C/C++)",
  php: "PHP Security Scanner",
  brakeman: "Brakeman (Ruby)",
  cargo_audit: "Cargo Audit (Rust)",
  docker: "Docker Scanning",
  iac: "IaC Scanning",
  deduplication: "Deduplicating Findings",
  deduplication_final: "Final Deduplication (Post-AI)",
  dependencies: "Parsing Dependencies",
  transitive_deps: "Building Dependency Trees",
  cve_lookup: "CVE Lookup",
  transitive_analysis: "Transitive Analysis",
  reachability: "Reachability Analysis",
  enrichment: "Vulnerability Enrichment",
  epss: "EPSS Scoring",
  nvd: "NVD Enrichment",
  ai_analysis: "AI Analysis",
  reporting: "Generating Report",
  complete: "Complete",
  failed: "Failed",
  // Agentic AI phases - unified pipeline with CVE/SAST context
  agentic_scan: "🤖 AI-Guided Analysis",
  agentic_initializing: "Initializing Agentic AI",
  agentic_file_triage: "🔍 AI File Triage",
  agentic_initial_analysis: "📋 Pass 1: Scanning Files",
  agentic_focused_analysis: "🔬 Pass 2: Focused Analysis",
  agentic_deep_analysis: "🎯 Pass 3: Deep Analysis",
  agentic_chunking: "Breaking Code into Chunks",
  agentic_entry_points: "Detecting Entry Points",
  agentic_flow_tracing: "🔀 Data Flow Tracing",
  agentic_analyzing: "Analyzing Vulnerabilities",
  agentic_fp_filtering: "Filtering False Positives",
  agentic_synthesis: "🧠 Synthesizing Findings",
  agentic_reporting: "Generating AI Report",
  agentic_complete: "Agentic Scan Complete",
  agentic_error: "Agentic Scan Error",
  agentic_scanning: "Agentic AI Scanning",
};

export default function ScanProgress({ scanRunId, onComplete }: ScanProgressProps) {
  const theme = useTheme();
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [connected, setConnected] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const [reconnectAttempt, setReconnectAttempt] = useState(0);
  const [phaseHistory, setPhaseHistory] = useState<string[]>([]);  // Track completed phases from server
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const heartbeatIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const isCompleteRef = useRef(false);
  const maxReconnectAttempts = 10;
  const baseReconnectDelay = 1000; // 1 second

  useEffect(() => {
    if (!scanRunId) return;

    const connectWebSocket = () => {
      // Don't reconnect if scan is complete
      if (isCompleteRef.current) return;

      setReconnecting(reconnectAttemptsRef.current > 0);

      // Connect to WebSocket
      const wsUrl = `ws://${window.location.hostname}:8000/ws/scans/${scanRunId}`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        setReconnecting(false);
        setReconnectAttempt(0);
        reconnectAttemptsRef.current = 0; // Reset on successful connection

        // Start heartbeat - send ping every 25 seconds to keep connection alive
        heartbeatIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send("ping");
          }
        }, 25000);
      };

      ws.onmessage = (event) => {
        try {
          // Handle pong response (keep-alive)
          if (event.data === "pong") {
            return;
          }

          const rawData = JSON.parse(event.data);
          
          // Handle phase history message (sent on connect for late-joining clients)
          if (rawData.type === "phase_history" && rawData.completed_phases) {
            // Store history phases - they'll be used by PhaseProgressCategories
            setPhaseHistory(rawData.completed_phases);
            return;
          }

          const data = rawData as ScanProgress;
          setProgress(data);

          // Notify parent when complete
          if (data.phase === "complete" || data.phase === "failed") {
            isCompleteRef.current = true;
            if (onComplete) {
              onComplete();
            }
            // Close connection gracefully on completion
            ws.close(1000, "Scan complete");
          }
        } catch (e) {
          console.error("Failed to parse WebSocket message:", e);
        }
      };

      ws.onerror = (error) => {
        console.error("WebSocket error:", error);
        setConnected(false);
      };

      ws.onclose = (event) => {
        setConnected(false);

        // Clear heartbeat
        if (heartbeatIntervalRef.current) {
          clearInterval(heartbeatIntervalRef.current);
          heartbeatIntervalRef.current = null;
        }

        // Only reconnect if scan is not complete and we haven't exceeded max attempts
        if (!isCompleteRef.current && reconnectAttemptsRef.current < maxReconnectAttempts) {
          // Exponential backoff: 1s, 2s, 4s, 8s, 16s, max 30s
          const delay = Math.min(baseReconnectDelay * Math.pow(2, reconnectAttemptsRef.current), 30000);
          reconnectAttemptsRef.current += 1;
          setReconnectAttempt(reconnectAttemptsRef.current);
          setReconnecting(true);
          
          reconnectTimeoutRef.current = setTimeout(() => {
            connectWebSocket();
          }, delay);
        } else if (reconnectAttemptsRef.current >= maxReconnectAttempts) {
          console.error("Max reconnection attempts reached, giving up");
          setReconnecting(false);
        }
      };
    };

    connectWebSocket();

    return () => {
      // Cleanup on unmount
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (heartbeatIntervalRef.current) {
        clearInterval(heartbeatIntervalRef.current);
      }
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
      }
      if (wsRef.current) {
        isCompleteRef.current = true; // Prevent reconnection during cleanup
        wsRef.current.close();
      }
    };
  }, [scanRunId, onComplete]);

  // Fallback polling when WebSocket fails completely
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  
  useEffect(() => {
    if (!scanRunId || connected || isCompleteRef.current) {
      // Clear polling if connected or complete
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
      return;
    }

    // Start polling only after max reconnect attempts
    if (reconnectAttempt >= maxReconnectAttempts && !pollingIntervalRef.current) {
      const pollStatus = async () => {
        try {
          // Use the progress endpoint which returns WebSocket-compatible format
          const response = await fetch(`/api/scans/scan-runs/${scanRunId}/progress`);
          if (response.ok) {
            const data = await response.json();
            setProgress({
              scan_run_id: data.scan_run_id || scanRunId,
              phase: data.phase || "unknown",
              progress: data.progress ?? data.overall_progress ?? 50,
              message: data.message || `Status: ${data.phase}`,
              timestamp: data.timestamp || new Date().toISOString(),
            });
            
            if (data.phase === "complete" || data.phase === "failed") {
              isCompleteRef.current = true;
              if (pollingIntervalRef.current) {
                clearInterval(pollingIntervalRef.current);
              }
              if (onComplete) {
                onComplete();
              }
            }
          }
        } catch (e) {
          console.error("Polling failed:", e);
        }
      };

      // Poll immediately and then every 5 seconds
      pollStatus();
      pollingIntervalRef.current = setInterval(pollStatus, 5000);
    }

    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
    };
  }, [scanRunId, connected, reconnectAttempt, onComplete]);

  if (!scanRunId) return null;

  const isComplete = progress?.phase === "complete";
  const isFailed = progress?.phase === "failed";
  const currentProgress = progress?.progress ?? 0;
  const currentPhase = progress?.phase ?? "initializing";
  const currentMessage = progress?.message ?? "Starting scan...";

  return (
    <Paper
      sx={{
        p: 3,
        mt: 2,
        bgcolor: isComplete
          ? alpha(theme.palette.success.main, 0.08)
          : isFailed
          ? alpha(theme.palette.error.main, 0.05)
          : alpha(theme.palette.primary.main, 0.05),
        border: `1px solid ${
          isComplete
            ? alpha(theme.palette.success.main, 0.4)
            : isFailed
            ? alpha(theme.palette.error.main, 0.3)
            : alpha(theme.palette.primary.main, 0.2)
        }`,
        ...(isComplete && {
          animation: `${pulseGlow} 2s ease-in-out infinite`,
        }),
      }}
    >
      {/* Success Banner when complete */}
      {isComplete && (
        <Box
          sx={{
            mb: 3,
            p: 2,
            borderRadius: 2,
            background: `linear-gradient(135deg, ${alpha(theme.palette.success.main, 0.15)} 0%, ${alpha(theme.palette.success.dark, 0.1)} 100%)`,
            border: `1px solid ${alpha(theme.palette.success.main, 0.3)}`,
            display: "flex",
            alignItems: "center",
            gap: 2,
            animation: `${celebrateAnimation} 0.5s ease-out`,
          }}
        >
          <Box
            sx={{
              fontSize: "2.5rem",
              animation: `${celebrateAnimation} 0.6s ease-out`,
            }}
          >
            🎉
          </Box>
          <Box>
            <Typography variant="h6" fontWeight={700} color="success.main">
              Security Scan Complete!
            </Typography>
            <Typography variant="body2" color="text.secondary">
              All security checks have finished. Your report is now available.
            </Typography>
          </Box>
        </Box>
      )}

      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
        <Typography variant="h6" fontWeight={600}>
          Scan Progress
        </Typography>
        <Tooltip title={
          connected 
            ? "Live connection to scan worker" 
            : reconnecting 
            ? `Reconnecting... attempt ${reconnectAttempt}/${maxReconnectAttempts}` 
            : "Disconnected"
        }>
          <Chip
            label={
              connected 
                ? "Live" 
                : reconnecting 
                ? `Reconnecting (${reconnectAttempt})` 
                : "Disconnected"
            }
            color={connected ? "success" : reconnecting ? "warning" : "error"}
            size="small"
            sx={{ fontWeight: 600 }}
          />
        </Tooltip>
      </Stack>

      <Box sx={{ mb: 2 }}>
        <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
          <Typography variant="body2" fontWeight={600}>
            {PHASE_LABELS[currentPhase] || currentPhase}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {currentProgress}%
          </Typography>
        </Stack>
        <LinearProgress
          variant="determinate"
          value={currentProgress}
          sx={{
            height: 8,
            borderRadius: 4,
            bgcolor: alpha(
              isComplete
                ? theme.palette.success.main
                : isFailed
                ? theme.palette.error.main
                : theme.palette.primary.main,
              0.15
            ),
            "& .MuiLinearProgress-bar": {
              borderRadius: 4,
              bgcolor: isComplete
                ? theme.palette.success.main
                : isFailed
                ? theme.palette.error.main
                : theme.palette.primary.main,
            },
          }}
        />
      </Box>

      {/* Current Message - Handle multi-line for agentic stats */}
      {currentPhase.startsWith("agentic_") ? (
        <AgenticStatsDisplay message={currentMessage} theme={theme} />
      ) : (
        <Typography variant="body2" color="text.secondary">
          {currentMessage}
        </Typography>
      )}

      {/* Phase Category Display */}
      <PhaseProgressCategories currentPhase={currentPhase} theme={theme} initialPhaseHistory={phaseHistory} />
    </Paper>
  );
}

// Helper component to display agentic scan stats nicely
interface AgenticStatsDisplayProps {
  message: string;
  theme: Theme;
}

function AgenticStatsDisplay({ message, theme }: AgenticStatsDisplayProps) {
  // Parse the message to extract stats (format: "🤖 Message\n📄 x/y chunks | 🎯 n entry points | ...")
  const lines = message.split("\n");
  const mainMessage = lines[0] || "";
  const statsLine = lines[1] || "";
  
  // Parse individual stats
  const stats = statsLine.split("|").map(s => s.trim()).filter(Boolean);
  
  return (
    <Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: stats.length > 0 ? 1 : 0 }}>
        {mainMessage}
      </Typography>
      {stats.length > 0 && (
        <Stack 
          direction="row" 
          spacing={1.5} 
          flexWrap="wrap"
          sx={{ 
            gap: 1,
            p: 1.5,
            bgcolor: alpha(theme.palette.info.main, 0.08),
            borderRadius: 1,
            border: `1px solid ${alpha(theme.palette.info.main, 0.2)}`,
          }}
        >
          {stats.map((stat, index) => (
            <Chip
              key={index}
              label={stat}
              size="small"
              sx={{
                fontWeight: 500,
                bgcolor: alpha(theme.palette.background.paper, 0.8),
                border: `1px solid ${alpha(theme.palette.divider, 0.3)}`,
                "& .MuiChip-label": {
                  px: 1,
                },
              }}
            />
          ))}
        </Stack>
      )}
    </Box>
  );
}

// Helper component to show categorized progress
interface PhaseProgressCategoriesProps {
  currentPhase: string;
  theme: Theme;
  initialPhaseHistory?: string[];  // Phases already completed (received from server on connect)
}

function PhaseProgressCategories({ currentPhase, theme, initialPhaseHistory = [] }: PhaseProgressCategoriesProps) {
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());
  const [seenPhases, setSeenPhases] = useState<Set<string>>(new Set());
  
  // Initialize seenPhases with history when we get it from server
  useEffect(() => {
    if (initialPhaseHistory.length > 0) {
      setSeenPhases(prev => {
        const newSet = new Set(prev);
        initialPhaseHistory.forEach(phase => newSet.add(phase));
        return newSet;
      });
    }
  }, [initialPhaseHistory]);
  
  // Track phases we've seen to determine what's been completed
  useEffect(() => {
    if (currentPhase) {
      setSeenPhases(prev => new Set([...prev, currentPhase]));
    }
  }, [currentPhase]);

  // Build a flat list of all phases in order
  const allPhases = PHASE_CATEGORIES.flatMap((cat) => cat.phases);
  const currentPhaseIndex = allPhases.indexOf(currentPhase);

  // Determine which category the current phase belongs to
  const getCurrentCategoryIndex = () => {
    return PHASE_CATEGORIES.findIndex((cat) => cat.phases.includes(currentPhase));
  };

  const currentCategoryIndex = getCurrentCategoryIndex();

  const toggleCategory = (categoryName: string) => {
    setExpandedCategories((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(categoryName)) {
        newSet.delete(categoryName);
      } else {
        newSet.add(categoryName);
      }
      return newSet;
    });
  };

  // Check if any phase in a category has been seen (meaning it ran)
  const categoryHasBeenSeen = (category: PhaseCategory) => {
    return category.phases.some(phase => seenPhases.has(phase));
  };

  const getCategoryStatus = (categoryIndex: number, category: PhaseCategory) => {
    // If current phase is in this category, it's active
    if (category.phases.includes(currentPhase)) {
      return "active";
    }
    
    // If we've seen phases from this category, it's complete
    if (categoryHasBeenSeen(category)) {
      return "complete";
    }
    
    // If current category index is higher and this category hasn't been seen, it was skipped
    if (categoryIndex < currentCategoryIndex && !categoryHasBeenSeen(category)) {
      return "skipped";
    }
    
    // Otherwise pending
    return "pending";
  };

  const getPhaseStatus = (phase: string) => {
    if (phase === currentPhase) {
      return "active";
    }
    if (seenPhases.has(phase)) {
      return "complete";
    }
    const phaseIndex = allPhases.indexOf(phase);
    if (phaseIndex < currentPhaseIndex) {
      // Phase was before current but not seen - skipped
      return "skipped";
    }
    return "pending";
  };

  return (
    <Box sx={{ mt: 3 }}>
      <Divider sx={{ mb: 2 }} />
      <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2 }}>
        Scan Phases
      </Typography>
      <Stack spacing={1}>
        {PHASE_CATEGORIES.map((category, categoryIndex) => {
          const status = getCategoryStatus(categoryIndex, category);
          const isExpanded = expandedCategories.has(category.name) || status === "active";
          const hasMultiplePhases = category.phases.length > 1;

          return (
            <Box key={category.name}>
              <Box
                sx={{
                  display: "flex",
                  alignItems: "center",
                  gap: 1,
                  py: 0.75,
                  px: 1.5,
                  borderRadius: 1,
                  cursor: hasMultiplePhases ? "pointer" : "default",
                  bgcolor:
                    status === "active"
                      ? alpha(theme.palette.primary.main, 0.1)
                      : status === "complete"
                        ? alpha(theme.palette.success.main, 0.05)
                        : status === "skipped"
                          ? alpha(theme.palette.grey[500], 0.05)
                          : "transparent",
                  border: `1px solid ${
                    status === "active"
                      ? alpha(theme.palette.primary.main, 0.3)
                      : status === "complete"
                        ? alpha(theme.palette.success.main, 0.2)
                        : status === "skipped"
                          ? alpha(theme.palette.grey[500], 0.15)
                          : "transparent"
                  }`,
                  opacity: status === "skipped" ? 0.6 : 1,
                  "&:hover": hasMultiplePhases
                    ? {
                        bgcolor: alpha(theme.palette.primary.main, 0.05),
                      }
                    : {},
                }}
                onClick={() => hasMultiplePhases && toggleCategory(category.name)}
              >
                {/* Status Icon */}
                {status === "complete" ? (
                  <CheckCircleIcon
                    sx={{ fontSize: 18, color: theme.palette.success.main }}
                  />
                ) : status === "active" ? (
                  <HourglassEmptyIcon
                    sx={{
                      fontSize: 18,
                      color: theme.palette.primary.main,
                      animation: `${spinAnimation} 2s linear infinite`,
                    }}
                  />
                ) : status === "skipped" ? (
                  <CheckCircleIcon
                    sx={{ fontSize: 18, color: theme.palette.grey[400] }}
                  />
                ) : (
                  <RadioButtonUncheckedIcon
                    sx={{ fontSize: 18, color: theme.palette.text.disabled }}
                  />
                )}

                {/* Category Icon */}
                <Typography sx={{ fontSize: "1rem", opacity: status === "skipped" ? 0.5 : 1 }}>{category.icon}</Typography>

                {/* Category Name */}
                <Typography
                  variant="body2"
                  sx={{
                    flex: 1,
                    fontWeight: status === "active" ? 600 : 500,
                    color:
                      status === "active"
                        ? theme.palette.primary.main
                        : status === "complete"
                          ? theme.palette.success.main
                          : status === "skipped"
                            ? theme.palette.grey[500]
                            : theme.palette.text.secondary,
                  }}
                >
                  {category.name}
                  {status === "skipped" && (
                    <Typography component="span" variant="caption" sx={{ ml: 1, color: theme.palette.grey[500] }}>
                      (skipped)
                    </Typography>
                  )}
                </Typography>

                {/* Phase count badge for categories with multiple phases */}
                {hasMultiplePhases && (
                  <>
                    <Chip
                      label={`${category.phases.length} steps`}
                      size="small"
                      sx={{
                        fontSize: "0.65rem",
                        height: 18,
                        bgcolor: alpha(theme.palette.grey[500], 0.1),
                        color: theme.palette.text.secondary,
                      }}
                    />
                    <Tooltip title={isExpanded ? "Collapse" : "Expand"}>
                      <IconButton size="small" sx={{ p: 0.25 }}>
                        {isExpanded ? (
                          <ExpandLessIcon sx={{ fontSize: 16 }} />
                        ) : (
                          <ExpandMoreIcon sx={{ fontSize: 16 }} />
                        )}
                      </IconButton>
                    </Tooltip>
                  </>
                )}
              </Box>

              {/* Expanded sub-phases */}
              <Collapse in={isExpanded && hasMultiplePhases}>
                <Stack spacing={0.5} sx={{ ml: 4, mt: 0.5, mb: 1 }}>
                  {category.phases.map((phase) => {
                    const phaseStatus = getPhaseStatus(phase);
                    const phaseLabel = PHASE_LABELS[phase] || phase;

                    return (
                      <Box
                        key={phase}
                        sx={{
                          display: "flex",
                          alignItems: "center",
                          gap: 1,
                          py: 0.5,
                          px: 1,
                          borderRadius: 0.5,
                          bgcolor:
                            phaseStatus === "active"
                              ? alpha(theme.palette.primary.main, 0.08)
                              : "transparent",
                        }}
                      >
                        {phaseStatus === "complete" ? (
                          <CheckCircleIcon
                            sx={{ fontSize: 14, color: theme.palette.success.main }}
                          />
                        ) : phaseStatus === "active" ? (
                          <HourglassEmptyIcon
                            sx={{
                              fontSize: 14,
                              color: theme.palette.primary.main,
                              animation: `${spinAnimation} 2s linear infinite`,
                            }}
                          />
                        ) : (
                          <RadioButtonUncheckedIcon
                            sx={{ fontSize: 14, color: theme.palette.text.disabled }}
                          />
                        )}
                        <Typography
                          variant="caption"
                          sx={{
                            color:
                              phaseStatus === "active"
                                ? theme.palette.primary.main
                                : phaseStatus === "complete"
                                  ? theme.palette.success.main
                                  : theme.palette.text.disabled,
                            fontWeight: phaseStatus === "active" ? 600 : 400,
                          }}
                        >
                          {phaseLabel}
                        </Typography>
                      </Box>
                    );
                  })}
                </Stack>
              </Collapse>
            </Box>
          );
        })}
      </Stack>
    </Box>
  );
}
