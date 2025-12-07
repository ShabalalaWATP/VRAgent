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

// Phase categories for organized display
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
    description: "Extracting and parsing source code",
  },
  {
    name: "Embeddings",
    icon: "🧠",
    phases: ["embedding"],
    description: "Generating code embeddings for AI analysis",
  },
  {
    name: "Security Scanners",
    icon: "🔍",
    phases: ["parallel_scanning", "scanning", "sast", "secrets", "eslint", "semgrep", "bandit", "gosec", "spotbugs", "clangtidy"],
    description: "Running SAST security scanners",
  },
  {
    name: "Docker Security",
    icon: "🐳",
    phases: ["docker"],
    description: "Scanning Dockerfiles and container images",
  },
  {
    name: "Infrastructure as Code",
    icon: "☁️",
    phases: ["iac"],
    description: "Scanning Terraform, Kubernetes, CloudFormation",
  },
  {
    name: "Deduplication",
    icon: "🔗",
    phases: ["deduplication"],
    description: "Merging duplicate findings across scanners",
  },
  {
    name: "Dependencies",
    icon: "📚",
    phases: ["dependencies", "transitive_deps"],
    description: "Analyzing direct and transitive dependencies",
  },
  {
    name: "Vulnerability Lookup",
    icon: "🛡️",
    phases: ["cve_lookup", "transitive_analysis", "reachability"],
    description: "Looking up CVEs and analyzing reachability",
  },
  {
    name: "Enrichment",
    icon: "📊",
    phases: ["enrichment", "epss", "nvd"],
    description: "Enriching with EPSS, NVD, and KEV data",
  },
  {
    name: "AI Analysis",
    icon: "🤖",
    phases: ["ai_analysis"],
    description: "AI-powered vulnerability analysis",
  },
  {
    name: "Report",
    icon: "📝",
    phases: ["reporting", "complete"],
    description: "Generating final security report",
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
  docker: "Docker Scanning",
  iac: "IaC Scanning",
  deduplication: "Deduplicating Findings",
  dependencies: "Parsing Dependencies",
  transitive_deps: "Transitive Dependencies",
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
};

export default function ScanProgress({ scanRunId, onComplete }: ScanProgressProps) {
  const theme = useTheme();
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!scanRunId) return;

    // Connect to WebSocket
    const wsUrl = `ws://${window.location.hostname}:8000/ws/scans/${scanRunId}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log("WebSocket connected for scan", scanRunId);
      setConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as ScanProgress;
        setProgress(data);

        // Notify parent when complete
        if (data.phase === "complete" && onComplete) {
          onComplete();
        }
      } catch (e) {
        console.error("Failed to parse WebSocket message:", e);
      }
    };

    ws.onerror = (error) => {
      console.error("WebSocket error:", error);
      setConnected(false);
    };

    ws.onclose = () => {
      console.log("WebSocket disconnected");
      setConnected(false);
    };

    return () => {
      ws.close();
    };
  }, [scanRunId, onComplete]);

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
        <Chip
          label={connected ? "Live" : "Connecting..."}
          color={connected ? "success" : "default"}
          size="small"
          sx={{ fontWeight: 600 }}
        />
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

      <Typography variant="body2" color="text.secondary">
        {currentMessage}
      </Typography>

      {/* Phase Category Display */}
      <PhaseProgressCategories currentPhase={currentPhase} theme={theme} />
    </Paper>
  );
}

// Helper component to show categorized progress
interface PhaseProgressCategoriesProps {
  currentPhase: string;
  theme: Theme;
}

function PhaseProgressCategories({ currentPhase, theme }: PhaseProgressCategoriesProps) {
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());

  // Determine which category the current phase belongs to
  const getCurrentCategoryIndex = () => {
    return PHASE_CATEGORIES.findIndex((cat) => cat.phases.includes(currentPhase));
  };

  const currentCategoryIndex = getCurrentCategoryIndex();

  // Find all completed phases
  const allPhases = PHASE_CATEGORIES.flatMap((cat) => cat.phases);
  const currentPhaseIndex = allPhases.indexOf(currentPhase);

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

  const getCategoryStatus = (categoryIndex: number, category: PhaseCategory) => {
    if (categoryIndex < currentCategoryIndex) {
      return "complete";
    } else if (categoryIndex === currentCategoryIndex) {
      return "active";
    }
    return "pending";
  };

  const getPhaseStatus = (phase: string) => {
    const phaseIndex = allPhases.indexOf(phase);
    if (phaseIndex < currentPhaseIndex) {
      return "complete";
    } else if (phase === currentPhase) {
      return "active";
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
                        : "transparent",
                  border: `1px solid ${
                    status === "active"
                      ? alpha(theme.palette.primary.main, 0.3)
                      : status === "complete"
                        ? alpha(theme.palette.success.main, 0.2)
                        : "transparent"
                  }`,
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
                ) : (
                  <RadioButtonUncheckedIcon
                    sx={{ fontSize: 18, color: theme.palette.text.disabled }}
                  />
                )}

                {/* Category Icon */}
                <Typography sx={{ fontSize: "1rem" }}>{category.icon}</Typography>

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
                          : theme.palette.text.secondary,
                  }}
                >
                  {category.name}
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
