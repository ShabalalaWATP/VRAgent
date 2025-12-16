/**
 * Advanced Binary Analysis Components
 * 
 * Features:
 * - Entropy Visualization with Heat Map
 * - Packing Detection Analysis
 * - Section-by-Section Entropy Breakdown
 */

import React, { useState, useEffect, useMemo } from "react";
import {
  Box,
  Typography,
  Paper,
  Grid,
  Button,
  Alert,
  CircularProgress,
  Tabs,
  Tab,
  Chip,
  IconButton,
  Tooltip,
  alpha,
  useTheme,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Slider,
  LinearProgress,
  Card,
  CardContent,
  Stack,
} from "@mui/material";
import {
  BarChart as ChartIcon,
  Warning as WarningIcon,
  Security as SecurityIcon,
  Info as InfoIcon,
  Lock as LockIcon,
  Code as CodeIcon,
  Memory as MemoryIcon,
  Compress as PackedIcon,
  Refresh as RefreshIcon,
} from "@mui/icons-material";
import {
  reverseEngineeringClient,
  type EntropyAnalysisResult,
  type EntropyDataPoint,
  type EntropyRegion,
  type SectionEntropy,
} from "../api/client";

// ================== Entropy Heat Map Visualization ==================

interface EntropyHeatMapProps {
  dataPoints: EntropyDataPoint[];
  regions: EntropyRegion[];
  fileSize: number;
}

/**
 * Visual heat map showing entropy distribution across the file
 */
function EntropyHeatMap({ dataPoints, regions, fileSize }: EntropyHeatMapProps) {
  const theme = useTheme();
  const containerRef = React.useRef<HTMLDivElement>(null);
  const [hoveredPoint, setHoveredPoint] = useState<EntropyDataPoint | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  // Calculate color for entropy value (0-8 scale)
  const getEntropyColor = (entropy: number): string => {
    // Low entropy (0-3): Blue (structured/code)
    // Medium entropy (3-5): Green (normal data)
    // High entropy (5-7): Yellow/Orange (possibly compressed)
    // Very high entropy (7-8): Red (encrypted/packed)
    if (entropy < 3) {
      return `hsl(210, 80%, ${60 - entropy * 10}%)`;
    } else if (entropy < 5) {
      return `hsl(${180 - (entropy - 3) * 45}, 70%, 50%)`;
    } else if (entropy < 7) {
      return `hsl(${90 - (entropy - 5) * 30}, 80%, 50%)`;
    } else {
      return `hsl(${30 - (entropy - 7) * 15}, 90%, ${55 - (entropy - 7) * 10}%)`;
    }
  };

  // Group data points into rows for rendering
  const POINTS_PER_ROW = 64;
  const rows = useMemo(() => {
    const result: EntropyDataPoint[][] = [];
    for (let i = 0; i < dataPoints.length; i += POINTS_PER_ROW) {
      result.push(dataPoints.slice(i, i + POINTS_PER_ROW));
    }
    return result;
  }, [dataPoints]);

  const handleMouseMove = (e: React.MouseEvent, point: EntropyDataPoint) => {
    const rect = containerRef.current?.getBoundingClientRect();
    if (rect) {
      setTooltipPos({
        x: e.clientX - rect.left,
        y: e.clientY - rect.top - 60,
      });
    }
    setHoveredPoint(point);
  };

  return (
    <Box ref={containerRef} sx={{ position: "relative" }}>
      {/* Legend */}
      <Box sx={{ mb: 2, display: "flex", alignItems: "center", gap: 2 }}>
        <Typography variant="caption" color="text.secondary">Entropy Scale:</Typography>
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
          {[0, 2, 4, 6, 8].map((val) => (
            <Box key={val} sx={{ display: "flex", alignItems: "center" }}>
              <Box
                sx={{
                  width: 16,
                  height: 16,
                  bgcolor: getEntropyColor(val),
                  borderRadius: 0.5,
                }}
              />
              <Typography variant="caption" sx={{ ml: 0.5, mr: 1 }}>{val}</Typography>
            </Box>
          ))}
        </Box>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, ml: "auto" }}>
          <Chip icon={<CodeIcon />} label="Code" size="small" sx={{ bgcolor: alpha(getEntropyColor(2), 0.3) }} />
          <Chip icon={<MemoryIcon />} label="Data" size="small" sx={{ bgcolor: alpha(getEntropyColor(4), 0.3) }} />
          <Chip icon={<PackedIcon />} label="Packed/Encrypted" size="small" sx={{ bgcolor: alpha(getEntropyColor(7.5), 0.3) }} />
        </Box>
      </Box>

      {/* Heat Map Grid */}
      <Box
        sx={{
          display: "flex",
          flexDirection: "column",
          gap: "1px",
          bgcolor: alpha(theme.palette.divider, 0.3),
          p: 0.5,
          borderRadius: 1,
          overflow: "hidden",
        }}
      >
        {rows.map((row, rowIdx) => (
          <Box key={rowIdx} sx={{ display: "flex", gap: "1px" }}>
            {row.map((point, colIdx) => (
              <Tooltip
                key={`${rowIdx}-${colIdx}`}
                title=""
                open={false}
              >
                <Box
                  onMouseEnter={(e) => handleMouseMove(e, point)}
                  onMouseLeave={() => setHoveredPoint(null)}
                  sx={{
                    width: 8,
                    height: 8,
                    bgcolor: getEntropyColor(point.entropy),
                    cursor: "pointer",
                    transition: "transform 0.1s",
                    "&:hover": {
                      transform: "scale(1.5)",
                      zIndex: 1,
                    },
                  }}
                />
              </Tooltip>
            ))}
          </Box>
        ))}
      </Box>

      {/* Custom Tooltip */}
      {hoveredPoint && (
        <Paper
          elevation={8}
          sx={{
            position: "absolute",
            left: tooltipPos.x,
            top: tooltipPos.y,
            transform: "translateX(-50%)",
            p: 1.5,
            zIndex: 10,
            pointerEvents: "none",
            minWidth: 180,
          }}
        >
          <Typography variant="caption" display="block" fontWeight={600}>
            Offset: 0x{hoveredPoint.offset.toString(16).toUpperCase()}
          </Typography>
          <Typography variant="body2" color="primary" fontWeight={600}>
            Entropy: {hoveredPoint.entropy.toFixed(3)} / 8.0
          </Typography>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mt: 0.5 }}>
            <Box
              sx={{
                width: 12,
                height: 12,
                bgcolor: getEntropyColor(hoveredPoint.entropy),
                borderRadius: 0.5,
              }}
            />
            <Typography variant="caption">
              {hoveredPoint.entropy < 3
                ? "Low (Structured/Code)"
                : hoveredPoint.entropy < 5
                ? "Medium (Normal Data)"
                : hoveredPoint.entropy < 7
                ? "High (Compressed)"
                : "Very High (Encrypted/Packed)"}
            </Typography>
          </Box>
        </Paper>
      )}

      {/* File offset markers */}
      <Box sx={{ display: "flex", justifyContent: "space-between", mt: 1 }}>
        <Typography variant="caption" color="text.secondary">0x0</Typography>
        <Typography variant="caption" color="text.secondary">
          0x{Math.floor(fileSize / 4).toString(16).toUpperCase()}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          0x{Math.floor(fileSize / 2).toString(16).toUpperCase()}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          0x{Math.floor((fileSize * 3) / 4).toString(16).toUpperCase()}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          0x{fileSize.toString(16).toUpperCase()}
        </Typography>
      </Box>
    </Box>
  );
}

// ================== Section Entropy Table ==================

interface SectionEntropyTableProps {
  sections: SectionEntropy[];
}

function SectionEntropyTable({ sections }: SectionEntropyTableProps) {
  const theme = useTheme();

  const getEntropyLevel = (entropy: number): { label: string; color: string } => {
    if (entropy < 3) return { label: "Low", color: theme.palette.info.main };
    if (entropy < 5) return { label: "Medium", color: theme.palette.success.main };
    if (entropy < 7) return { label: "High", color: theme.palette.warning.main };
    return { label: "Very High", color: theme.palette.error.main };
  };

  // Classify entropy level
  const classifyEntropy = (entropy: number): string => {
    if (entropy < 3) return "Code/Structured";
    if (entropy < 5) return "Normal Data";
    if (entropy < 7) return "Compressed";
    return "Encrypted/Packed";
  };

  return (
    <TableContainer component={Paper} variant="outlined">
      <Table size="small">
        <TableHead>
          <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
            <TableCell><strong>Section</strong></TableCell>
            <TableCell align="right"><strong>Address</strong></TableCell>
            <TableCell align="right"><strong>Size</strong></TableCell>
            <TableCell align="center"><strong>Entropy</strong></TableCell>
            <TableCell><strong>Classification</strong></TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {sections.map((section, idx) => {
            const level = getEntropyLevel(section.entropy);
            const offset = section.virtual_address ?? section.address ?? 0;
            const size = section.raw_size ?? section.virtual_size ?? section.size ?? 0;
            return (
              <TableRow key={idx} hover>
                <TableCell>
                  <Typography variant="body2" fontFamily="monospace" fontWeight={600}>
                    {section.name}
                  </Typography>
                </TableCell>
                <TableCell align="right">
                  <Typography variant="body2" fontFamily="monospace">
                    0x{offset.toString(16).toUpperCase()}
                  </Typography>
                </TableCell>
                <TableCell align="right">
                  <Typography variant="body2" fontFamily="monospace">
                    {(size / 1024).toFixed(1)} KB
                  </Typography>
                </TableCell>
                <TableCell align="center">
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <LinearProgress
                      variant="determinate"
                      value={(section.entropy / 8) * 100}
                      sx={{
                        width: 60,
                        height: 8,
                        borderRadius: 4,
                        bgcolor: alpha(level.color, 0.2),
                        "& .MuiLinearProgress-bar": {
                          bgcolor: level.color,
                          borderRadius: 4,
                        },
                      }}
                    />
                    <Typography variant="body2" fontWeight={600}>
                      {section.entropy.toFixed(2)}
                    </Typography>
                  </Box>
                </TableCell>
                <TableCell>
                  <Chip
                    label={classifyEntropy(section.entropy)}
                    size="small"
                    sx={{
                      bgcolor: alpha(level.color, 0.15),
                      color: level.color,
                      fontWeight: 600,
                    }}
                  />
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

// ================== Entropy Regions Display ==================

interface EntropyRegionsProps {
  regions: EntropyRegion[];
}

function EntropyRegions({ regions }: EntropyRegionsProps) {
  const theme = useTheme();

  const getRegionIcon = (classification: string) => {
    switch (classification.toLowerCase()) {
      case "packed":
      case "encrypted":
        return <LockIcon fontSize="small" />;
      case "code":
        return <CodeIcon fontSize="small" />;
      case "data":
        return <MemoryIcon fontSize="small" />;
      default:
        return <InfoIcon fontSize="small" />;
    }
  };

  const getRegionColor = (classification: string) => {
    switch (classification.toLowerCase()) {
      case "packed":
      case "encrypted":
        return theme.palette.error.main;
      case "code":
        return theme.palette.info.main;
      case "data":
        return theme.palette.success.main;
      default:
        return theme.palette.grey[500];
    }
  };

  return (
    <Box>
      <Typography variant="subtitle2" gutterBottom color="text.secondary">
        High-entropy regions detected that may indicate packing or encryption:
      </Typography>
      <Grid container spacing={2}>
        {regions.map((region, idx) => (
          <Grid item xs={12} md={6} key={idx}>
            <Card variant="outlined" sx={{ borderColor: alpha(getRegionColor(region.classification), 0.5) }}>
              <CardContent sx={{ py: 1.5 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <Box sx={{ color: getRegionColor(region.classification) }}>
                    {getRegionIcon(region.classification)}
                  </Box>
                  <Typography variant="subtitle2" fontWeight={600}>
                    {region.classification}
                  </Typography>
                  <Chip
                    label={`${region.avg_entropy.toFixed(2)} entropy`}
                    size="small"
                    sx={{
                      ml: "auto",
                      bgcolor: alpha(getRegionColor(region.classification), 0.15),
                      color: getRegionColor(region.classification),
                    }}
                  />
                </Box>
                <Box sx={{ display: "flex", gap: 3 }}>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Start</Typography>
                    <Typography variant="body2" fontFamily="monospace">
                      0x{region.start_offset.toString(16).toUpperCase()}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">End</Typography>
                    <Typography variant="body2" fontFamily="monospace">
                      0x{region.end_offset.toString(16).toUpperCase()}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Size</Typography>
                    <Typography variant="body2">
                      {((region.end_offset - region.start_offset) / 1024).toFixed(1)} KB
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
      {regions.length === 0 && (
        <Alert severity="success" icon={<SecurityIcon />}>
          No high-entropy regions detected. Binary appears to be unobfuscated.
        </Alert>
      )}
    </Box>
  );
}

// ================== Packing Detection Card ==================

interface PackingDetectionProps {
  isPacked: boolean;
  packerName?: string;
  confidence: number;
  overallEntropy: number;
  sections: SectionEntropy[];
}

function PackingDetection({
  isPacked,
  packerName,
  confidence,
  overallEntropy,
  sections,
}: PackingDetectionProps) {
  const theme = useTheme();

  return (
    <Paper
      sx={{
        p: 3,
        bgcolor: isPacked
          ? alpha(theme.palette.error.main, 0.05)
          : alpha(theme.palette.success.main, 0.05),
        border: 1,
        borderColor: isPacked
          ? alpha(theme.palette.error.main, 0.3)
          : alpha(theme.palette.success.main, 0.3),
      }}
    >
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
        {isPacked ? (
          <PackedIcon sx={{ fontSize: 40, color: theme.palette.error.main }} />
        ) : (
          <SecurityIcon sx={{ fontSize: 40, color: theme.palette.success.main }} />
        )}
        <Box>
          <Typography variant="h6">
            {isPacked ? "🔒 Packing Detected" : "✅ No Packing Detected"}
          </Typography>
          {packerName && (
            <Typography variant="body2" color="text.secondary">
              Detected Packer: <strong>{packerName}</strong>
            </Typography>
          )}
        </Box>
        <Box sx={{ ml: "auto", textAlign: "right" }}>
          <Typography variant="caption" color="text.secondary">Confidence</Typography>
          <Typography variant="h5" color={isPacked ? "error" : "success"} fontWeight={600}>
            {(confidence * 100).toFixed(0)}%
          </Typography>
        </Box>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} sm={6}>
          <Box>
            <Typography variant="caption" color="text.secondary">Overall Entropy</Typography>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <LinearProgress
                variant="determinate"
                value={(overallEntropy / 8) * 100}
                sx={{
                  flex: 1,
                  height: 12,
                  borderRadius: 6,
                  bgcolor: alpha(theme.palette.grey[500], 0.2),
                  "& .MuiLinearProgress-bar": {
                    bgcolor:
                      overallEntropy > 7
                        ? theme.palette.error.main
                        : overallEntropy > 5
                        ? theme.palette.warning.main
                        : theme.palette.success.main,
                    borderRadius: 6,
                  },
                }}
              />
              <Typography variant="h6" fontWeight={600}>
                {overallEntropy.toFixed(2)} / 8.0
              </Typography>
            </Box>
          </Box>
        </Grid>
        <Grid item xs={12} sm={6}>
          <Box>
            <Typography variant="caption" color="text.secondary">
              High Entropy Sections ({sections.filter((s) => s.entropy > 7).length} of {sections.length})
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
              {sections
                .filter((s) => s.entropy > 7)
                .slice(0, 5)
                .map((s, idx) => (
                  <Chip
                    key={idx}
                    label={`${s.name}: ${s.entropy.toFixed(1)}`}
                    size="small"
                    color="error"
                    variant="outlined"
                  />
                ))}
              {sections.filter((s) => s.entropy > 7).length === 0 && (
                <Typography variant="body2" color="text.secondary">None</Typography>
              )}
            </Box>
          </Box>
        </Grid>
      </Grid>

      {isPacked && (
        <Alert severity="warning" sx={{ mt: 2 }}>
          <Typography variant="body2">
            <strong>Analysis Recommendation:</strong> This binary appears to be packed or protected.
            Consider using unpacking tools like UPX, or dynamic analysis with a debugger to analyze
            the unpacked code at runtime.
          </Typography>
        </Alert>
      )}
    </Paper>
  );
}

// ================== Main Entropy Visualizer Component ==================

interface EntropyVisualizerProps {
  file: File | null;
}

/**
 * EntropyVisualizer - Full entropy analysis component for binary files
 * 
 * Shows:
 * - Overall packing detection status
 * - Heat map visualization
 * - Section-by-section entropy breakdown
 * - High-entropy region analysis
 */
export function EntropyVisualizer({ file }: EntropyVisualizerProps) {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<EntropyAnalysisResult | null>(null);
  const [windowSize, setWindowSize] = useState(256);
  const [stepSize, setStepSize] = useState(128);

  const analyzeEntropy = async () => {
    if (!file) return;

    setLoading(true);
    setError(null);

    try {
      const data = await reverseEngineeringClient.analyzeBinaryEntropy(file, windowSize, stepSize);
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to analyze entropy");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (file) {
      analyzeEntropy();
    }
  }, [file]);

  if (!file) {
    return (
      <Alert severity="info">
        Upload a binary file to analyze its entropy distribution.
      </Alert>
    );
  }

  return (
    <Box>
      {/* Analysis Controls */}
      <Paper sx={{ p: 2, mb: 3, bgcolor: alpha(theme.palette.background.paper, 0.7) }}>
        <Grid container spacing={3} alignItems="center">
          <Grid item xs={12} sm={4}>
            <Typography variant="subtitle2" gutterBottom>Window Size: {windowSize} bytes</Typography>
            <Slider
              value={windowSize}
              onChange={(_, value) => setWindowSize(value as number)}
              min={64}
              max={1024}
              step={64}
              marks={[
                { value: 64, label: "64" },
                { value: 256, label: "256" },
                { value: 512, label: "512" },
                { value: 1024, label: "1024" },
              ]}
              disabled={loading}
            />
          </Grid>
          <Grid item xs={12} sm={4}>
            <Typography variant="subtitle2" gutterBottom>Step Size: {stepSize} bytes</Typography>
            <Slider
              value={stepSize}
              onChange={(_, value) => setStepSize(value as number)}
              min={32}
              max={512}
              step={32}
              marks={[
                { value: 32, label: "32" },
                { value: 128, label: "128" },
                { value: 256, label: "256" },
                { value: 512, label: "512" },
              ]}
              disabled={loading}
            />
          </Grid>
          <Grid item xs={12} sm={4}>
            <Button
              variant="contained"
              startIcon={loading ? <CircularProgress size={20} /> : <RefreshIcon />}
              onClick={analyzeEntropy}
              disabled={loading}
              fullWidth
            >
              {loading ? "Analyzing..." : "Re-analyze"}
            </Button>
          </Grid>
        </Grid>
      </Paper>

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Loading State */}
      {loading && (
        <Box sx={{ textAlign: "center", py: 4 }}>
          <CircularProgress />
          <Typography variant="body2" sx={{ mt: 2 }}>
            Calculating entropy distribution...
          </Typography>
        </Box>
      )}

      {/* Results */}
      {result && !loading && (
        <>
          {/* Packing Detection Summary */}
          <PackingDetection
            isPacked={result.is_likely_packed}
            packerName={result.detected_packers?.[0]}
            confidence={result.packing_confidence}
            overallEntropy={result.overall_entropy}
            sections={result.section_entropy}
          />

          {/* Tabs */}
          <Box sx={{ mt: 3 }}>
            <Tabs
              value={activeTab}
              onChange={(_, value) => setActiveTab(value)}
              variant="fullWidth"
              sx={{
                bgcolor: alpha(theme.palette.background.paper, 0.7),
                borderRadius: 1,
                mb: 2,
              }}
            >
              <Tab icon={<ChartIcon />} label="Heat Map" />
              <Tab icon={<MemoryIcon />} label="Sections" />
              <Tab icon={<WarningIcon />} label={`Regions (${result.regions.length})`} />
            </Tabs>

            {/* Heat Map Tab */}
            {activeTab === 0 && (
              <Paper sx={{ p: 3, bgcolor: alpha(theme.palette.background.paper, 0.7) }}>
                <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <ChartIcon color="primary" /> Entropy Heat Map
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Visual representation of entropy distribution across the file.
                  Higher entropy (red) may indicate encrypted or compressed data.
                </Typography>
                <EntropyHeatMap
                  dataPoints={result.entropy_data}
                  regions={result.regions}
                  fileSize={result.file_size}
                />
              </Paper>
            )}

            {/* Sections Tab */}
            {activeTab === 1 && (
              <Paper sx={{ p: 3, bgcolor: alpha(theme.palette.background.paper, 0.7) }}>
                <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <MemoryIcon color="primary" /> Section Entropy Analysis
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Entropy breakdown by binary section. High entropy in code sections (.text) may indicate obfuscation.
                </Typography>
                <SectionEntropyTable sections={result.section_entropy} />
              </Paper>
            )}

            {/* Regions Tab */}
            {activeTab === 2 && (
              <Paper sx={{ p: 3, bgcolor: alpha(theme.palette.background.paper, 0.7) }}>
                <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <WarningIcon color="warning" /> High Entropy Regions
                </Typography>
                <EntropyRegions regions={result.regions} />
              </Paper>
            )}
          </Box>
        </>
      )}
    </Box>
  );
}

export default EntropyVisualizer;
