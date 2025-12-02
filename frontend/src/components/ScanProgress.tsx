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
} from "@mui/material";

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

// Phase display names and icons
const PHASE_LABELS: Record<string, string> = {
  initializing: "Initializing",
  extracting: "Extracting Archive",
  parsing: "Parsing Source Files",
  embedding: "Generating Embeddings",
  secrets: "Secret Detection",
  eslint: "ESLint (JS/TS)",
  semgrep: "Semgrep Analysis",
  bandit: "Bandit (Python)",
  gosec: "Gosec (Go)",
  spotbugs: "SpotBugs (Java)",
  clangtidy: "Clang-Tidy (C/C++)",
  dependencies: "Parsing Dependencies",
  cve_lookup: "CVE Lookup",
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

      {/* Phase indicators */}
      <Box sx={{ mt: 2, display: "flex", flexWrap: "wrap", gap: 0.5 }}>
        {Object.entries(PHASE_LABELS).map(([key, label]) => {
          if (key === "failed") return null;
          const phaseOrder = [
            "initializing",
            "extracting",
            "parsing",
            "embedding",
            "secrets",
            "eslint",
            "semgrep",
            "bandit",
            "gosec",
            "spotbugs",
            "clangtidy",
            "dependencies",
            "cve_lookup",
            "epss",
            "nvd",
            "ai_analysis",
            "reporting",
            "complete",
          ];
          const currentIndex = phaseOrder.indexOf(currentPhase);
          const thisIndex = phaseOrder.indexOf(key);
          const isActive = key === currentPhase;
          const isPast = thisIndex < currentIndex;

          return (
            <Chip
              key={key}
              label={label}
              size="small"
              sx={{
                fontSize: "0.65rem",
                height: 20,
                bgcolor: isActive
                  ? alpha(theme.palette.primary.main, 0.2)
                  : isPast
                  ? alpha(theme.palette.success.main, 0.15)
                  : alpha(theme.palette.grey[500], 0.1),
                color: isActive
                  ? theme.palette.primary.main
                  : isPast
                  ? theme.palette.success.main
                  : theme.palette.text.disabled,
                fontWeight: isActive ? 700 : 500,
                border: isActive ? `1px solid ${theme.palette.primary.main}` : "none",
              }}
            />
          );
        })}
      </Box>
    </Paper>
  );
}
