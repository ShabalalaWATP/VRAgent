import React, { useCallback, useMemo, useRef, useEffect, useState } from "react";
import ForceGraph2D, { ForceGraphMethods } from "react-force-graph-2d";
import {
  Box,
  Paper,
  Typography,
  IconButton,
  Tooltip,
  Chip,
  Slider,
  FormControlLabel,
  Switch,
  alpha,
  useTheme,
} from "@mui/material";
import {
  ZoomIn as ZoomInIcon,
  ZoomOut as ZoomOutIcon,
  CenterFocusStrong as CenterIcon,
  Fullscreen as FullscreenIcon,
  FullscreenExit as FullscreenExitIcon,
} from "@mui/icons-material";

// Types for the graph
interface NmapHost {
  ip: string;
  hostname?: string;
  status?: string;
  os_guess?: string;
  ports?: Array<{
    port: number;
    protocol: string;
    state: string;
    service?: string;
    product?: string;
    version?: string;
  }>;
}

interface NmapFinding {
  severity: string;
  title: string;
  host?: string;
  port?: number;
}

interface NmapNetworkGraphProps {
  hosts: NmapHost[];
  findings?: NmapFinding[];
  onHostClick?: (host: NmapHost) => void;
  height?: number;
}

interface GraphNode {
  id: string;
  label: string;
  ip: string;
  hostname?: string;
  os?: string;
  openPorts: number;
  riskLevel: "critical" | "high" | "medium" | "low" | "info";
  nodeType: "host" | "gateway" | "server";
  ports: NmapHost["ports"];
  x?: number;
  y?: number;
  fx?: number;
  fy?: number;
}

interface GraphLink {
  source: string;
  target: string;
  value: number;
}

// OS detection patterns for icons
const detectOSType = (osGuess?: string): "windows" | "linux" | "mac" | "network" | "unknown" => {
  if (!osGuess) return "unknown";
  const os = osGuess.toLowerCase();
  if (os.includes("windows")) return "windows";
  if (os.includes("linux") || os.includes("ubuntu") || os.includes("debian") || os.includes("centos") || os.includes("redhat")) return "linux";
  if (os.includes("mac") || os.includes("darwin") || os.includes("apple")) return "mac";
  if (os.includes("cisco") || os.includes("router") || os.includes("switch") || os.includes("juniper")) return "network";
  return "unknown";
};

// Get risk color based on severity
const getRiskColor = (riskLevel: string): string => {
  switch (riskLevel) {
    case "critical": return "#dc2626";
    case "high": return "#ea580c";
    case "medium": return "#ca8a04";
    case "low": return "#2563eb";
    default: return "#22c55e";
  }
};

// Get OS color
const getOSColor = (osType: string): string => {
  switch (osType) {
    case "windows": return "#0078d4";
    case "linux": return "#f97316";
    case "mac": return "#a3a3a3";
    case "network": return "#8b5cf6";
    default: return "#6b7280";
  }
};

export const NmapNetworkGraph: React.FC<NmapNetworkGraphProps> = ({
  hosts,
  findings = [],
  onHostClick,
  height = 500,
}) => {
  const theme = useTheme();
  const graphRef = useRef<ForceGraphMethods<any, any>>();
  const containerRef = useRef<HTMLDivElement>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showLabels, setShowLabels] = useState(true);
  const [nodeSize, setNodeSize] = useState(8);
  const [colorBy, setColorBy] = useState<"risk" | "os">("risk");
  const [dimensions, setDimensions] = useState({ width: 800, height: height });

  // Calculate risk level for a host based on findings
  const getHostRiskLevel = useCallback((ip: string): "critical" | "high" | "medium" | "low" | "info" => {
    const hostFindings = findings.filter(f => f.host === ip);
    if (hostFindings.some(f => f.severity === "critical")) return "critical";
    if (hostFindings.some(f => f.severity === "high")) return "high";
    if (hostFindings.some(f => f.severity === "medium")) return "medium";
    if (hostFindings.some(f => f.severity === "low")) return "low";
    return "info";
  }, [findings]);

  // Build graph data from hosts
  const graphData = useMemo(() => {
    const nodes: GraphNode[] = [];
    const links: GraphLink[] = [];

    // Add a central gateway node if we have multiple hosts
    if (hosts.length > 1) {
      nodes.push({
        id: "gateway",
        label: "Network",
        ip: "Network",
        nodeType: "gateway",
        openPorts: 0,
        riskLevel: "info",
        ports: [],
      });
    }

    // Add host nodes
    hosts.forEach((host) => {
      const openPorts = host.ports?.filter(p => p.state === "open").length || 0;
      const riskLevel = getHostRiskLevel(host.ip);
      
      // Determine node type based on services
      let nodeType: "host" | "gateway" | "server" = "host";
      if (host.ports?.some(p => ["http", "https", "ssh", "ftp", "mysql", "postgresql", "mongodb", "redis"].includes(p.service || ""))) {
        nodeType = "server";
      }

      nodes.push({
        id: host.ip,
        label: host.hostname || host.ip,
        ip: host.ip,
        hostname: host.hostname,
        os: host.os_guess,
        openPorts,
        riskLevel,
        nodeType,
        ports: host.ports || [],
      });

      // Connect to gateway if multiple hosts
      if (hosts.length > 1) {
        links.push({
          source: "gateway",
          target: host.ip,
          value: 1,
        });
      }
    });

    return { nodes, links };
  }, [hosts, getHostRiskLevel]);

  // Update dimensions on resize
  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        setDimensions({
          width: rect.width || 800,
          height: isFullscreen ? window.innerHeight - 100 : height,
        });
      }
    };

    updateDimensions();
    window.addEventListener("resize", updateDimensions);
    return () => window.removeEventListener("resize", updateDimensions);
  }, [height, isFullscreen]);

  // Handle node click
  const handleNodeClick = useCallback((node: GraphNode) => {
    if (node.nodeType === "gateway") return;
    const host = hosts.find(h => h.ip === node.ip);
    if (host && onHostClick) {
      onHostClick(host);
    }
  }, [hosts, onHostClick]);

  // Custom node rendering
  const nodeCanvasObject = useCallback((node: GraphNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
    const size = nodeSize * (node.nodeType === "gateway" ? 1.5 : 1);
    const fontSize = 12 / globalScale;
    
    // Get colors
    const osType = detectOSType(node.os);
    const baseColor = colorBy === "risk" ? getRiskColor(node.riskLevel) : getOSColor(osType);
    
    // Draw node circle with glow for high-risk
    if (node.riskLevel === "critical" || node.riskLevel === "high") {
      ctx.beginPath();
      ctx.arc(node.x!, node.y!, size + 4, 0, 2 * Math.PI);
      ctx.fillStyle = `${baseColor}4D`; // 30% opacity
      ctx.fill();
    }

    // Main node
    ctx.beginPath();
    ctx.arc(node.x!, node.y!, size, 0, 2 * Math.PI);
    ctx.fillStyle = baseColor;
    ctx.fill();
    
    // Border
    ctx.strokeStyle = theme.palette.mode === "dark" ? "#fff" : "#000";
    ctx.lineWidth = 1.5 / globalScale;
    ctx.stroke();

    // Icon inside (simplified)
    ctx.fillStyle = "#fff";
    ctx.font = `${size}px sans-serif`;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    
    let icon = "●";
    if (node.nodeType === "gateway") icon = "◆";
    else if (node.nodeType === "server") icon = "■";
    
    ctx.fillText(icon, node.x!, node.y!);

    // Label
    if (showLabels && globalScale > 0.5) {
      ctx.font = `${fontSize}px sans-serif`;
      ctx.fillStyle = theme.palette.text.primary;
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      
      const label = node.hostname || node.ip;
      ctx.fillText(label.length > 20 ? label.substring(0, 17) + "..." : label, node.x!, node.y! + size + 4);
      
      // Port count badge
      if (node.openPorts > 0) {
        const badgeText = `${node.openPorts} ports`;
        ctx.font = `${fontSize * 0.8}px sans-serif`;
        ctx.fillStyle = theme.palette.text.secondary;
        ctx.fillText(badgeText, node.x!, node.y! + size + 4 + fontSize);
      }
    }
  }, [nodeSize, colorBy, showLabels, theme]);

  // Zoom controls
  const handleZoomIn = () => graphRef.current?.zoom(graphRef.current.zoom() * 1.3, 300);
  const handleZoomOut = () => graphRef.current?.zoom(graphRef.current.zoom() / 1.3, 300);
  const handleCenter = () => graphRef.current?.zoomToFit(400, 50);

  // Fullscreen toggle
  const toggleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
  };

  // Risk legend
  const riskLegend = [
    { level: "critical", label: "Critical", color: "#dc2626" },
    { level: "high", label: "High", color: "#ea580c" },
    { level: "medium", label: "Medium", color: "#ca8a04" },
    { level: "low", label: "Low", color: "#2563eb" },
    { level: "info", label: "Info", color: "#22c55e" },
  ];

  const osLegend = [
    { type: "windows", label: "Windows", color: "#0078d4" },
    { type: "linux", label: "Linux", color: "#f97316" },
    { type: "mac", label: "macOS", color: "#a3a3a3" },
    { type: "network", label: "Network", color: "#8b5cf6" },
    { type: "unknown", label: "Unknown", color: "#6b7280" },
  ];

  if (hosts.length === 0) {
    return (
      <Paper sx={{ p: 4, textAlign: "center" }}>
        <Typography color="text.secondary">No hosts to display</Typography>
      </Paper>
    );
  }

  return (
    <Box
      ref={containerRef}
      sx={{
        position: isFullscreen ? "fixed" : "relative",
        top: isFullscreen ? 0 : "auto",
        left: isFullscreen ? 0 : "auto",
        right: isFullscreen ? 0 : "auto",
        bottom: isFullscreen ? 0 : "auto",
        zIndex: isFullscreen ? 9999 : "auto",
        bgcolor: "background.paper",
        borderRadius: isFullscreen ? 0 : 2,
        overflow: "hidden",
        border: `1px solid ${theme.palette.divider}`,
      }}
    >
      {/* Controls */}
      <Box
        sx={{
          position: "absolute",
          top: 8,
          left: 8,
          zIndex: 10,
          display: "flex",
          flexDirection: "column",
          gap: 1,
        }}
      >
        <Paper sx={{ p: 0.5, display: "flex", gap: 0.5 }}>
          <Tooltip title="Zoom In">
            <IconButton size="small" onClick={handleZoomIn}>
              <ZoomInIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title="Zoom Out">
            <IconButton size="small" onClick={handleZoomOut}>
              <ZoomOutIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title="Fit to View">
            <IconButton size="small" onClick={handleCenter}>
              <CenterIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title={isFullscreen ? "Exit Fullscreen" : "Fullscreen"}>
            <IconButton size="small" onClick={toggleFullscreen}>
              {isFullscreen ? <FullscreenExitIcon fontSize="small" /> : <FullscreenIcon fontSize="small" />}
            </IconButton>
          </Tooltip>
        </Paper>

        <Paper sx={{ p: 1 }}>
          <FormControlLabel
            control={<Switch checked={showLabels} onChange={(e) => setShowLabels(e.target.checked)} size="small" />}
            label={<Typography variant="caption">Labels</Typography>}
            sx={{ m: 0 }}
          />
        </Paper>

        <Paper sx={{ p: 1, width: 120 }}>
          <Typography variant="caption" color="text.secondary">Node Size</Typography>
          <Slider
            value={nodeSize}
            onChange={(_, v) => setNodeSize(v as number)}
            min={4}
            max={16}
            size="small"
          />
        </Paper>

        <Paper sx={{ p: 1 }}>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>Color By</Typography>
          <Box sx={{ display: "flex", gap: 0.5 }}>
            <Chip
              label="Risk"
              size="small"
              variant={colorBy === "risk" ? "filled" : "outlined"}
              onClick={() => setColorBy("risk")}
              color={colorBy === "risk" ? "error" : "default"}
            />
            <Chip
              label="OS"
              size="small"
              variant={colorBy === "os" ? "filled" : "outlined"}
              onClick={() => setColorBy("os")}
              color={colorBy === "os" ? "primary" : "default"}
            />
          </Box>
        </Paper>
      </Box>

      {/* Legend */}
      <Box
        sx={{
          position: "absolute",
          top: 8,
          right: 8,
          zIndex: 10,
        }}
      >
        <Paper sx={{ p: 1 }}>
          <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
            {colorBy === "risk" ? "Risk Level" : "Operating System"}
          </Typography>
          <Box sx={{ mt: 0.5 }}>
            {(colorBy === "risk" ? riskLegend : osLegend).map((item: any) => (
              <Box key={item.level || item.type} sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                <Box
                  sx={{
                    width: 10,
                    height: 10,
                    borderRadius: "50%",
                    bgcolor: item.color,
                  }}
                />
                <Typography variant="caption">{item.label}</Typography>
              </Box>
            ))}
          </Box>
        </Paper>
      </Box>

      {/* Stats */}
      <Box
        sx={{
          position: "absolute",
          bottom: 8,
          left: 8,
          zIndex: 10,
        }}
      >
        <Paper sx={{ p: 1, display: "flex", gap: 2 }}>
          <Box sx={{ textAlign: "center" }}>
            <Typography variant="h6" sx={{ lineHeight: 1 }}>{hosts.length}</Typography>
            <Typography variant="caption" color="text.secondary">Hosts</Typography>
          </Box>
          <Box sx={{ textAlign: "center" }}>
            <Typography variant="h6" sx={{ lineHeight: 1, color: "error.main" }}>
              {findings.filter(f => f.severity === "critical" || f.severity === "high").length}
            </Typography>
            <Typography variant="caption" color="text.secondary">High Risk</Typography>
          </Box>
          <Box sx={{ textAlign: "center" }}>
            <Typography variant="h6" sx={{ lineHeight: 1, color: "warning.main" }}>
              {hosts.reduce((sum, h) => sum + (h.ports?.filter(p => p.state === "open").length || 0), 0)}
            </Typography>
            <Typography variant="caption" color="text.secondary">Open Ports</Typography>
          </Box>
        </Paper>
      </Box>

      {/* Graph */}
      <ForceGraph2D
        ref={graphRef}
        graphData={graphData}
        width={dimensions.width}
        height={dimensions.height}
        nodeCanvasObject={nodeCanvasObject}
        nodePointerAreaPaint={(node: any, color, ctx) => {
          ctx.beginPath();
          ctx.arc(node.x!, node.y!, nodeSize + 5, 0, 2 * Math.PI);
          ctx.fillStyle = color;
          ctx.fill();
        }}
        onNodeClick={(node: any) => handleNodeClick(node)}
        linkColor={() => `${theme.palette.text.secondary}4D`}
        linkWidth={1}
        linkDirectionalParticles={2}
        linkDirectionalParticleWidth={2}
        linkDirectionalParticleSpeed={0.005}
        backgroundColor={theme.palette.background.paper}
        cooldownTicks={100}
        onEngineStop={() => graphRef.current?.zoomToFit(400, 50)}
      />
    </Box>
  );
};

export default NmapNetworkGraph;
