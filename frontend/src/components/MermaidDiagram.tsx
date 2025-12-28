/**
 * MermaidDiagram Component
 * 
 * Renders Mermaid diagrams directly in the app (works 100% offline).
 * No external CDN dependencies - mermaid.js is bundled with the app.
 * 
 * ============================================================================
 * AVAILABLE ICON PACKS (use in diagrams with prefix:icon-name syntax)
 * ============================================================================
 * 
 * FONT AWESOME 6 SOLID (fa6-solid:) - General purpose icons
 *   Security:    fa6-solid:shield, fa6-solid:lock, fa6-solid:key, fa6-solid:bug, 
 *                fa6-solid:shield-halved, fa6-solid:user-shield, fa6-solid:fingerprint
 *   UI/Actions:  fa6-solid:gear, fa6-solid:check, fa6-solid:xmark, fa6-solid:plus,
 *                fa6-solid:play, fa6-solid:stop, fa6-solid:trash, fa6-solid:pen
 *   Files:       fa6-solid:file, fa6-solid:folder, fa6-solid:database, fa6-solid:code
 *   Network:     fa6-solid:server, fa6-solid:network-wired, fa6-solid:cloud, fa6-solid:globe
 *   Alerts:      fa6-solid:triangle-exclamation, fa6-solid:circle-info, fa6-solid:bell
 *   People:      fa6-solid:user, fa6-solid:users, fa6-solid:user-secret
 *   Mobile:      fa6-solid:mobile, fa6-solid:tablet, fa6-solid:laptop
 * 
 * FONT AWESOME 6 BRANDS (fa6-brands:) - Brand/platform icons
 *   Platforms:   fa6-brands:android, fa6-brands:apple, fa6-brands:windows, fa6-brands:linux
 *   Dev:         fa6-brands:github, fa6-brands:docker, fa6-brands:python, fa6-brands:java
 *   Cloud:       fa6-brands:aws, fa6-brands:google, fa6-brands:microsoft
 * 
 * MATERIAL DESIGN ICONS (mdi:) - 7000+ icons, excellent coverage
 *   Security:    mdi:shield, mdi:lock, mdi:key, mdi:bug, mdi:security, mdi:incognito
 *   Files:       mdi:file, mdi:folder, mdi:database, mdi:code-braces, mdi:file-code
 *   Network:     mdi:server, mdi:lan, mdi:cloud, mdi:web, mdi:api, mdi:webhook
 *   Android:     mdi:android, mdi:cellphone, mdi:application, mdi:package-variant
 *   Alerts:      mdi:alert, mdi:information, mdi:check-circle, mdi:close-circle
 *   Actions:     mdi:play, mdi:stop, mdi:refresh, mdi:download, mdi:upload, mdi:send
 *   Data:        mdi:chart-bar, mdi:table, mdi:format-list-bulleted, mdi:graph
 * 
 * LUCIDE (lucide:) - Clean modern icons
 *   Security:    lucide:shield, lucide:lock, lucide:key, lucide:bug, lucide:scan
 *   Files:       lucide:file, lucide:folder, lucide:database, lucide:code
 *   Network:     lucide:server, lucide:wifi, lucide:cloud, lucide:globe
 *   UI:          lucide:check, lucide:x, lucide:plus, lucide:minus, lucide:search
 * 
 * TABLER (tabler:) - UI/Developer focused
 *   Security:    tabler:shield, tabler:lock, tabler:key, tabler:bug, tabler:spy
 *   Dev:         tabler:code, tabler:terminal, tabler:git-branch, tabler:api
 *   Network:     tabler:server, tabler:cloud, tabler:world, tabler:network
 * 
 * CARBON (carbon:) - IBM design system icons
 *   Security:    carbon:security, carbon:locked, carbon:password, carbon:fingerprint
 *   Enterprise:  carbon:enterprise, carbon:application, carbon:api, carbon:data-base
 *   Cloud:       carbon:cloud, carbon:kubernetes, carbon:container-software
 * 
 * ============================================================================
 * USAGE EXAMPLES IN MERMAID DIAGRAMS:
 * ============================================================================
 * 
 *   flowchart LR
 *     A[fa6-solid:shield Security] --> B[fa6-solid:bug Vulnerability]
 *     B --> C[fa6-brands:android Android App]
 *     C --> D[mdi:database Data Store]
 * 
 *   flowchart TD
 *     subgraph Security[mdi:security Security Layer]
 *       A[fa6-solid:lock Auth]
 *       B[fa6-solid:key Crypto]
 *     end
 */

import React, { useEffect, useRef, useState, useCallback } from "react";
import mermaid from "mermaid";

// Import icon packs for Mermaid
import { icons as fa6SolidIcons } from "@iconify-json/fa6-solid";
import { icons as fa6BrandsIcons } from "@iconify-json/fa6-brands";
import { icons as mdiIcons } from "@iconify-json/mdi";
import { icons as lucideIcons } from "@iconify-json/lucide";
import { icons as tablerIcons } from "@iconify-json/tabler";
import { icons as carbonIcons } from "@iconify-json/carbon";
import {
  Box,
  Paper,
  IconButton,
  Tooltip,
  CircularProgress,
  Alert,
  useTheme,
  alpha,
  Typography,
  Button,
  ButtonGroup,
} from "@mui/material";
import {
  ContentCopy as CopyIcon,
  Fullscreen as FullscreenIcon,
  FullscreenExit as FullscreenExitIcon,
  Code as CodeIcon,
  Image as ImageIcon,
  Download as DownloadIcon,
  ZoomIn as ZoomInIcon,
  ZoomOut as ZoomOutIcon,
  RestartAlt as ResetIcon,
  Close as CloseIcon,
} from "@mui/icons-material";

// Initialize mermaid with dark theme settings and register icon packs
// Register with BOTH long names (fa6-solid) and short names (fa, fab) for maximum compatibility
// The short names are needed for Mermaid's icon shape syntax: @{ icon: "fa:user" }
mermaid.registerIconPacks([
  // Short names for Mermaid icon shape syntax (fa:icon-name, fab:icon-name)
  {
    name: "fa",
    icons: fa6SolidIcons,
  },
  {
    name: "fas", // FontAwesome solid alias
    icons: fa6SolidIcons,
  },
  {
    name: "fab", // FontAwesome brands
    icons: fa6BrandsIcons,
  },
  // Long names for backward compatibility
  {
    name: "fa6-solid",
    icons: fa6SolidIcons,
  },
  {
    name: "fa6-brands", 
    icons: fa6BrandsIcons,
  },
  {
    name: "mdi",
    icons: mdiIcons,
  },
  {
    name: "lucide",
    icons: lucideIcons,
  },
  {
    name: "tabler",
    icons: tablerIcons,
  },
  {
    name: "carbon",
    icons: carbonIcons,
  },
]);

mermaid.initialize({
  startOnLoad: false,
  theme: "dark",
  securityLevel: "loose",
  fontFamily: "inherit",
  flowchart: {
    useMaxWidth: true,
    htmlLabels: true,
    curve: "basis",
    nodeSpacing: 50,
    rankSpacing: 50,
  },
  themeVariables: {
    // Primary nodes (blue)
    primaryColor: "#3b82f6",
    primaryTextColor: "#ffffff",
    primaryBorderColor: "#60a5fa",
    // Lines and connections
    lineColor: "#94a3b8",
    // Secondary (darker blue-gray)
    secondaryColor: "#1e3a5f",
    secondaryTextColor: "#ffffff",
    secondaryBorderColor: "#3b82f6",
    // Tertiary (even darker)
    tertiaryColor: "#1e293b",
    tertiaryTextColor: "#e2e8f0",
    tertiaryBorderColor: "#475569",
    // Background colors
    background: "#0f172a",
    mainBkg: "#1e293b",
    // Node styling
    nodeBorder: "#3b82f6",
    nodeTextColor: "#ffffff",
    // Cluster/subgraph styling - IMPORTANT for contrast
    clusterBkg: "#1e293b",
    clusterBorder: "#475569",
    // Title and labels
    titleColor: "#f1f5f9",
    edgeLabelBackground: "#1e293b",
    // Ensure text is always readable
    textColor: "#f1f5f9",
    // Note styling
    noteBkgColor: "#334155",
    noteTextColor: "#f1f5f9",
    noteBorderColor: "#475569",
  },
});

interface MermaidDiagramProps {
  code: string;
  title?: string;
  maxHeight?: number | string;
  showControls?: boolean;
  showCodeToggle?: boolean;
}

export function MermaidDiagram({
  code,
  title,
  maxHeight = 500,
  showControls = true,
  showCodeToggle = true,
}: MermaidDiagramProps) {
  const theme = useTheme();
  const containerRef = useRef<HTMLDivElement>(null);
  const diagramRef = useRef<HTMLDivElement>(null);
  const [svg, setSvg] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [showCode, setShowCode] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  // Generate unique ID for each diagram
  const diagramId = useRef(`mermaid-${Math.random().toString(36).substr(2, 9)}`);

  const renderDiagram = useCallback(async () => {
    if (!code || !code.trim()) {
      setError("No diagram code provided");
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Clean up the code - remove any existing diagram type declarations if duplicated
      let cleanCode = code.trim();
      
      // Validate and render
      const { svg: renderedSvg } = await mermaid.render(
        diagramId.current,
        cleanCode
      );
      setSvg(renderedSvg);
    } catch (err) {
      console.error("Mermaid rendering error:", err);
      setError(
        err instanceof Error
          ? `Diagram rendering failed: ${err.message}`
          : "Failed to render diagram"
      );
    } finally {
      setLoading(false);
    }
  }, [code]);

  useEffect(() => {
    renderDiagram();
  }, [renderDiagram]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const downloadSvg = () => {
    if (!svg) return;
    const blob = new Blob([svg], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${title || "diagram"}.svg`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const downloadPng = async () => {
    if (!svg) return;
    
    // Create canvas and draw SVG
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const img = new Image();
    const svgBlob = new Blob([svg], { type: "image/svg+xml;charset=utf-8" });
    const url = URL.createObjectURL(svgBlob);

    img.onload = () => {
      canvas.width = img.width * 2; // 2x for better quality
      canvas.height = img.height * 2;
      ctx.scale(2, 2);
      ctx.fillStyle = "#0f172a";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0);
      
      const pngUrl = canvas.toDataURL("image/png");
      const a = document.createElement("a");
      a.href = pngUrl;
      a.download = `${title || "diagram"}.png`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    };

    img.src = url;
  };

  const toggleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  // Handle escape key to exit fullscreen
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isFullscreen) {
        setIsFullscreen(false);
        setZoom(1);
        setPan({ x: 0, y: 0 });
      }
    };

    if (isFullscreen) {
      document.addEventListener("keydown", handleKeyDown);
      // Prevent body scrolling when fullscreen
      document.body.style.overflow = "hidden";
    }

    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = "";
    };
  }, [isFullscreen]);

  const handleZoom = (delta: number) => {
    setZoom((prev) => Math.max(0.1, Math.min(5, prev + delta)));
  };

  // Mouse wheel zoom
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -0.1 : 0.1;
    setZoom((prev) => Math.max(0.1, Math.min(5, prev + delta)));
  }, []);

  // Mouse drag for panning
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return; // Only left click
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  }, [pan]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!isDragging) return;
    setPan({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  }, [isDragging, dragStart]);

  const handleMouseUp = useCallback(() => {
    setIsDragging(false);
  }, []);

  const handleMouseLeave = useCallback(() => {
    setIsDragging(false);
  }, []);

  const resetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  const containerStyle = isFullscreen
    ? {
        position: "fixed" as const,
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        width: "100vw",
        height: "100vh",
        zIndex: 9999,
        bgcolor: "#0f172a",
        p: 0,
        display: "flex",
        flexDirection: "column" as const,
      }
    : {};

  return (
    <Paper
      sx={{
        overflow: "hidden",
        ...containerStyle,
      }}
    >
      {/* Prominent close button for fullscreen mode */}
      {isFullscreen && (
        <IconButton
          onClick={toggleFullscreen}
          sx={{
            position: "fixed",
            top: 16,
            right: 16,
            zIndex: 10000,
            bgcolor: "error.main",
            color: "white",
            width: 48,
            height: 48,
            "&:hover": {
              bgcolor: "error.dark",
              transform: "scale(1.1)",
            },
            boxShadow: 4,
            transition: "all 0.2s",
          }}
        >
          <CloseIcon />
        </IconButton>
      )}

      {/* ESC hint in fullscreen */}
      {isFullscreen && (
        <Typography
          variant="caption"
          sx={{
            position: "fixed",
            top: 20,
            right: 80,
            zIndex: 10000,
            color: "text.secondary",
            bgcolor: alpha(theme.palette.background.paper, 0.8),
            px: 1.5,
            py: 0.5,
            borderRadius: 1,
          }}
        >
          Press ESC to exit
        </Typography>
      )}

      {/* Header with controls */}
      {showControls && (
        <Box
          sx={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            p: 1,
            borderBottom: `1px solid ${theme.palette.divider}`,
            bgcolor: alpha(theme.palette.primary.main, 0.05),
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            {title && (
              <Typography variant="subtitle2" sx={{ mr: 2 }}>
                {title}
              </Typography>
            )}
            {showCodeToggle && (
              <ButtonGroup size="small" variant="outlined">
                <Button
                  startIcon={<ImageIcon />}
                  variant={!showCode ? "contained" : "outlined"}
                  onClick={() => setShowCode(false)}
                >
                  Diagram
                </Button>
                <Button
                  startIcon={<CodeIcon />}
                  variant={showCode ? "contained" : "outlined"}
                  onClick={() => setShowCode(true)}
                >
                  Code
                </Button>
              </ButtonGroup>
            )}
          </Box>

          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            {!showCode && svg && (
              <>
                <Tooltip title="Zoom Out">
                  <IconButton size="small" onClick={() => handleZoom(-0.25)}>
                    <ZoomOutIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
                <Typography variant="caption" sx={{ mx: 0.5, minWidth: 40, textAlign: "center" }}>
                  {Math.round(zoom * 100)}%
                </Typography>
                <Tooltip title="Zoom In">
                  <IconButton size="small" onClick={() => handleZoom(0.25)}>
                    <ZoomInIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Reset View">
                  <IconButton size="small" onClick={resetView}>
                    <ResetIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
                <Box sx={{ width: 1, height: 20, bgcolor: "divider", mx: 1 }} />
                <Tooltip title="Download SVG">
                  <IconButton size="small" onClick={downloadSvg}>
                    <DownloadIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
              </>
            )}
            <Tooltip title="Copy Mermaid Code">
              <IconButton size="small" onClick={() => copyToClipboard(code)}>
                <CopyIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            <Tooltip title={isFullscreen ? "Exit Fullscreen" : "Fullscreen"}>
              <IconButton size="small" onClick={toggleFullscreen}>
                {isFullscreen ? (
                  <FullscreenExitIcon fontSize="small" />
                ) : (
                  <FullscreenIcon fontSize="small" />
                )}
              </IconButton>
            </Tooltip>
          </Box>
        </Box>
      )}

      {/* Content */}
      <Box
        ref={containerRef}
        onWheel={!showCode ? handleWheel : undefined}
        onMouseDown={!showCode ? handleMouseDown : undefined}
        onMouseMove={!showCode ? handleMouseMove : undefined}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseLeave}
        sx={{
          p: 2,
          overflow: "hidden",
          height: isFullscreen ? "calc(100vh - 60px)" : "auto",
          maxHeight: isFullscreen ? "none" : maxHeight,
          minHeight: isFullscreen ? "calc(100vh - 60px)" : 200,
          flex: isFullscreen ? 1 : undefined,
          bgcolor: "#0f172a",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          cursor: isDragging ? "grabbing" : (svg && !showCode ? "grab" : "default"),
          userSelect: "none",
        }}
      >
        {loading ? (
          <Box sx={{ textAlign: "center", py: 4 }}>
            <CircularProgress size={40} />
            <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
              Rendering diagram...
            </Typography>
          </Box>
        ) : error ? (
          <Alert severity="error" sx={{ width: "100%" }}>
            {error}
            <Box
              component="pre"
              sx={{
                mt: 1,
                fontSize: "0.75rem",
                overflow: "auto",
                maxHeight: 200,
                bgcolor: "rgba(0,0,0,0.2)",
                p: 1,
                borderRadius: 1,
              }}
            >
              {code}
            </Box>
          </Alert>
        ) : showCode ? (
          <Box
            component="pre"
            sx={{
              m: 0,
              p: 2,
              width: "100%",
              fontSize: "0.85rem",
              fontFamily: "monospace",
              color: "#98c379",
              whiteSpace: "pre-wrap",
              bgcolor: "transparent",
            }}
          >
            {code}
          </Box>
        ) : (
          <Box
            ref={diagramRef}
            sx={{
              transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
              transformOrigin: "center center",
              transition: isDragging ? "none" : "transform 0.1s ease-out",
              "& svg": {
                maxWidth: isFullscreen ? "none" : "100%",
                width: isFullscreen ? "auto" : undefined,
                height: "auto",
                minWidth: isFullscreen ? "800px" : undefined,
              },
              // Force readable text colors on all node types
              "& .node rect, & .node polygon, & .node circle, & .node ellipse": {
                stroke: "#60a5fa !important",
              },
              "& .node .label, & .nodeLabel, & .label": {
                color: "#f1f5f9 !important",
                fill: "#f1f5f9 !important",
              },
              "& .cluster rect": {
                fill: "#1e293b !important",
                stroke: "#475569 !important",
              },
              "& .cluster .nodeLabel, & .cluster-label": {
                fill: "#f1f5f9 !important",
              },
              // Subgraph title styling
              "& .cluster text, & text.cluster-label": {
                fill: "#f1f5f9 !important",
                fontWeight: 600,
              },
              // Edge labels
              "& .edgeLabel": {
                backgroundColor: "#1e293b",
                color: "#e2e8f0",
              },
              "& .edgeLabel rect": {
                fill: "#1e293b !important",
              },
              "& .edgeLabel span": {
                color: "#e2e8f0 !important",
              },
            }}
            dangerouslySetInnerHTML={{ __html: svg }}
          />
        )}
      </Box>
    </Paper>
  );
}

export default MermaidDiagram;
