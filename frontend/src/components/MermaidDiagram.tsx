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
      
      // Post-process SVG to fix white backgrounds and black text
      // This handles inline styles that CSS can't override
      let processedSvg = renderedSvg;
      
      // Use DOMParser to properly manipulate the SVG
      const parser = new DOMParser();
      const doc = parser.parseFromString(processedSvg, 'image/svg+xml');
      const svgElement = doc.querySelector('svg');
      
      if (svgElement) {
        // Fix all rect elements with white/light fills
        const rects = svgElement.querySelectorAll('rect');
        rects.forEach((rect) => {
          const fill = rect.getAttribute('fill');
          const style = rect.getAttribute('style') || '';
          
          // Check for white fills in attribute
          if (fill && /^(#fff|#ffffff|white|#f[0-9a-f]{5}|rgb\s*\(\s*255|rgba?\s*\(\s*255)$/i.test(fill.trim())) {
            rect.setAttribute('fill', '#1e3a5f');
          }
          // Check for white fills in style attribute
          if (style.includes('fill') && /fill\s*:\s*(#fff|#ffffff|white|rgb\s*\(\s*255)/i.test(style)) {
            rect.setAttribute('style', style.replace(/fill\s*:\s*[^;]+/i, 'fill: #1e3a5f'));
          }
          // Add stroke if missing or none
          const stroke = rect.getAttribute('stroke');
          if (!stroke || stroke === 'none') {
            rect.setAttribute('stroke', '#60a5fa');
            rect.setAttribute('stroke-width', '1');
          }
        });
        
        // Fix all polygon elements (diamond shapes, etc.)
        const polygons = svgElement.querySelectorAll('polygon');
        polygons.forEach((poly) => {
          const fill = poly.getAttribute('fill');
          if (fill && /^(#fff|#ffffff|white|#f[0-9a-f]{5}|rgb\s*\(\s*255)/i.test(fill.trim())) {
            poly.setAttribute('fill', '#1e3a5f');
          }
        });
        
        // Fix all path elements that might be node backgrounds
        const paths = svgElement.querySelectorAll('path');
        paths.forEach((path) => {
          const fill = path.getAttribute('fill');
          const className = path.getAttribute('class') || '';
          // Only fix paths that are likely backgrounds (not arrows/lines)
          if (fill && /^(#fff|#ffffff|white|#f[0-9a-f]{5}|rgb\s*\(\s*255)/i.test(fill.trim())) {
            if (!className.includes('arrowhead') && !className.includes('marker')) {
              path.setAttribute('fill', '#1e3a5f');
            }
          }
        });
        
        // Fix text and tspan elements with black fill
        const textElements = svgElement.querySelectorAll('text, tspan');
        textElements.forEach((text) => {
          const fill = text.getAttribute('fill');
          const style = text.getAttribute('style') || '';
          
          if (fill && /^(#000|#000000|black|rgb\s*\(\s*0\s*,\s*0\s*,\s*0)/i.test(fill.trim())) {
            text.setAttribute('fill', '#ffffff');
          }
          if (style.includes('fill') && /fill\s*:\s*(#000|#000000|black|rgb\s*\(\s*0)/i.test(style)) {
            text.setAttribute('style', style.replace(/fill\s*:\s*[^;]+/i, 'fill: #ffffff'));
          }
        });
        
        // Fix foreignObject divs and spans (HTML labels in SVG)
        const foreignObjects = svgElement.querySelectorAll('foreignObject');
        foreignObjects.forEach((fo) => {
          const divs = fo.querySelectorAll('div, span');
          divs.forEach((div) => {
            const style = div.getAttribute('style') || '';
            // Fix black text color
            if (style.includes('color') && /color\s*:\s*(#000|#000000|black|rgb\s*\(\s*0)/i.test(style)) {
              div.setAttribute('style', style.replace(/color\s*:\s*[^;]+/i, 'color: #ffffff'));
            }
            // Fix white background
            if (style.includes('background') && /background[^:]*:\s*(#fff|#ffffff|white|rgb\s*\(\s*255)/i.test(style)) {
              div.setAttribute('style', style.replace(/background[^:]*:\s*[^;]+/i, 'background: transparent'));
            }
          });
        });
        
        // Fix g elements that might have problematic fills
        const gElements = svgElement.querySelectorAll('g.node, g.cluster');
        gElements.forEach((g) => {
          const childRects = g.querySelectorAll('rect');
          childRects.forEach((rect) => {
            const fill = rect.getAttribute('fill');
            if (!fill || fill === 'none' || /^(#fff|#ffffff|white)/i.test(fill.trim())) {
              rect.setAttribute('fill', '#1e3a5f');
              rect.setAttribute('stroke', '#60a5fa');
            }
          });
        });
        
        // Serialize back to string
        const serializer = new XMLSerializer();
        processedSvg = serializer.serializeToString(svgElement);
      }
      
      setSvg(processedSvg);
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
              // ============================================================
              // COMPREHENSIVE NODE STYLING - Fix white/invisible boxes
              // ============================================================
              
              // DEFAULT NODE BACKGROUNDS - catch any node without explicit style
              "& .node rect, & .node polygon, & .node circle, & .node ellipse": {
                fill: "#1e3a5f !important",
                stroke: "#60a5fa !important",
                strokeWidth: "2px !important",
              },
              // Basic shapes (database cylinders, etc)
              "& .node path:not(.arrowheadPath)": {
                fill: "#1e3a5f !important",
                stroke: "#60a5fa !important",
              },
              // Flowchart specific nodes
              "& .flowchart-label rect, & .basic.label-container rect": {
                fill: "#1e3a5f !important",
                stroke: "#60a5fa !important",
              },
              // Stadium/pill shapes
              "& .node .label-container": {
                fill: "#1e3a5f !important",
              },
              // Rhombus/diamond shapes
              "& .node polygon.label-container": {
                fill: "#1e3a5f !important",
                stroke: "#60a5fa !important",
              },
              
              // ============================================================
              // TEXT COLORS - Force white/light on ALL text elements
              // ============================================================
              "& .node .label, & .nodeLabel, & .label": {
                color: "#ffffff !important",
                fill: "#ffffff !important",
                fontWeight: "500 !important",
              },
              "& text": {
                fill: "#ffffff !important",
              },
              "& foreignObject div, & foreignObject span": {
                color: "#ffffff !important",
              },
              "& span.nodeLabel, & .node span": {
                color: "#ffffff !important",
                fill: "#ffffff !important",
              },
              // Flowchart specific labels
              "& .flowchart-label .nodeLabel, & .flowchart-label span": {
                color: "#ffffff !important",
              },
              
              // ============================================================
              // SUBGRAPH/CLUSTER STYLING - Fix nested subgraph visibility
              // ============================================================
              "& .cluster rect, & g.cluster > rect": {
                fill: "#0f172a !important",
                stroke: "#3b82f6 !important",
                strokeWidth: "2px !important",
                rx: "8px",
                ry: "8px",
              },
              // Nested subgraphs - slightly lighter for visual hierarchy
              "& .cluster .cluster rect": {
                fill: "#1e293b !important",
                stroke: "#475569 !important",
              },
              "& .cluster .cluster .cluster rect": {
                fill: "#334155 !important",
                stroke: "#64748b !important",
              },
              // Cluster/subgraph titles
              "& .cluster .nodeLabel, & .cluster-label, & .cluster text, & g.cluster text": {
                fill: "#ffffff !important",
                color: "#ffffff !important",
                fontWeight: "700 !important",
                fontSize: "14px !important",
              },
              // Cluster title backgrounds (some Mermaid versions add these)
              "& .cluster .cluster-label rect": {
                fill: "transparent !important",
              },
              
              // ============================================================
              // NODES INSIDE SUBGRAPHS - Ensure they're visible
              // ============================================================
              "& .cluster .node rect, & .cluster .node polygon": {
                fill: "#1e3a5f !important",
                stroke: "#60a5fa !important",
              },
              "& .cluster .node .nodeLabel": {
                color: "#ffffff !important",
                fill: "#ffffff !important",
              },
              
              // ============================================================
              // EDGE LABELS AND CONNECTIONS
              // ============================================================
              "& .edgeLabel": {
                backgroundColor: "#1e293b !important",
              },
              "& .edgeLabel rect, & .labelBkg": {
                fill: "#1e293b !important",
                stroke: "none !important",
              },
              "& .edgeLabel span, & .edgeLabel text, & .edgeLabel .nodeLabel": {
                color: "#e2e8f0 !important",
                fill: "#e2e8f0 !important",
                backgroundColor: "#1e293b !important",
              },
              
              // ============================================================
              // LINES AND ARROWS
              // ============================================================
              "& .flowchart-link, & path.flowchart-link, & .edge-pattern-solid": {
                stroke: "#60a5fa !important",
                strokeWidth: "2px !important",
              },
              "& .arrowheadPath, & .marker, & marker path": {
                fill: "#60a5fa !important",
                stroke: "#60a5fa !important",
              },
              "& .edge-thickness-normal": {
                strokeWidth: "2px !important",
              },
              
              // ============================================================
              // OVERRIDE CLASSDEFS - Handle AI-generated custom styles
              // These override the diagram's built-in classDef styles
              // ============================================================
              // Critical (red) - keep color but ensure readable
              "& .critical rect, & .critical polygon, & [class*='critical'] rect": {
                fill: "#dc2626 !important",
                stroke: "#ef4444 !important",
              },
              "& .critical .nodeLabel, & [class*='critical'] .nodeLabel, & .critical span": {
                color: "#ffffff !important",
                fill: "#ffffff !important",
              },
              // High (orange)
              "& .high rect, & .high polygon, & [class*='high'] rect": {
                fill: "#ea580c !important",
                stroke: "#f97316 !important",
              },
              "& .high .nodeLabel, & [class*='high'] .nodeLabel, & .high span": {
                color: "#ffffff !important",
                fill: "#ffffff !important",
              },
              // Medium (yellow/amber) - ensure text is visible
              "& .medium rect, & .medium polygon, & [class*='medium'] rect": {
                fill: "#d97706 !important",
                stroke: "#f59e0b !important",
              },
              "& .medium .nodeLabel, & [class*='medium'] .nodeLabel, & .medium span": {
                color: "#ffffff !important",
                fill: "#ffffff !important",
              },
              // Low (green)
              "& .low rect, & .low polygon, & [class*='low'] rect": {
                fill: "#16a34a !important",
                stroke: "#22c55e !important",
              },
              "& .low .nodeLabel, & [class*='low'] .nodeLabel, & .low span": {
                color: "#ffffff !important",
                fill: "#ffffff !important",
              },
              // Attacker (purple)
              "& .attacker rect, & .attacker polygon, & [class*='attacker'] rect": {
                fill: "#7c3aed !important",
                stroke: "#8b5cf6 !important",
              },
              "& .attacker .nodeLabel, & [class*='attacker'] .nodeLabel, & .attacker span": {
                color: "#ffffff !important",
                fill: "#ffffff !important",
              },
              // Info (blue)
              "& .info rect, & .info polygon, & [class*='info'] rect": {
                fill: "#0284c7 !important",
                stroke: "#0ea5e9 !important",
              },
              "& .info .nodeLabel, & [class*='info'] .nodeLabel": {
                color: "#ffffff !important",
                fill: "#ffffff !important",
              },
              
              // ============================================================
              // SPECIAL ELEMENTS
              // ============================================================
              // Database cylinders
              "& .node .er.entityBox, & .node.database rect": {
                fill: "#1e3a5f !important",
              },
              // Notes
              "& .note rect, & .noteText": {
                fill: "#334155 !important",
                stroke: "#475569 !important",
              },
              "& .noteText, & .note span": {
                color: "#f1f5f9 !important",
                fill: "#f1f5f9 !important",
              },
              
              // ============================================================
              // CATCH-ALL for any remaining white/blank boxes
              // ============================================================
              "& rect:not(.labelBkg):not(.er)": {
                fill: "#1e3a5f",
              },
              "& g > rect[class='']": {
                fill: "#1e3a5f !important",
                stroke: "#60a5fa !important",
              },
            }}
            dangerouslySetInnerHTML={{ __html: svg }}
          />
        )}
      </Box>

      {/* Global styles for Mermaid diagram readability */}
      <style>
        {`
          /* ============================================================
           * COMPREHENSIVE MERMAID DARK THEME FIXES
           * Ensures ALL diagram elements are visible with proper contrast
           * ============================================================ */
          
          /* === TEXT COLORS === */
          .mermaid .node .label,
          .mermaid .nodeLabel,
          .mermaid .label,
          .mermaid foreignObject div,
          .mermaid .node foreignObject div,
          .mermaid .node text,
          .mermaid text.nodeLabel,
          .mermaid .label-container,
          .mermaid g.node text,
          .mermaid g.cluster text,
          .mermaid span.nodeLabel,
          .mermaid .flowchart-label,
          .mermaid .flowchart-label span,
          .mermaid .actor,
          .mermaid .messageText,
          .mermaid .loopText,
          .mermaid .noteText,
          .mermaid foreignObject span,
          .mermaid .node span {
            color: #ffffff !important;
            fill: #ffffff !important;
            font-weight: 500 !important;
          }
          
          /* === SUBGRAPH/CLUSTER TITLES === */
          .mermaid .cluster text,
          .mermaid text.cluster-label,
          .mermaid .cluster-label span,
          .mermaid g.cluster text.nodeLabel,
          .mermaid .cluster .nodeLabel,
          .mermaid g.cluster > text {
            fill: #ffffff !important;
            color: #ffffff !important;
            font-weight: 700 !important;
            font-size: 14px !important;
          }
          
          /* === DEFAULT NODE BACKGROUNDS === */
          .mermaid .node rect,
          .mermaid .node polygon,
          .mermaid .node circle,
          .mermaid .node ellipse,
          .mermaid .node path:not(.arrowheadPath),
          .mermaid .flowchart-label rect,
          .mermaid .basic.label-container rect {
            fill: #1e3a5f !important;
            stroke: #60a5fa !important;
            stroke-width: 2px !important;
          }
          
          /* === CLUSTER/SUBGRAPH BACKGROUNDS === */
          .mermaid .cluster rect,
          .mermaid g.cluster rect,
          .mermaid g.cluster > rect {
            fill: #0f172a !important;
            stroke: #3b82f6 !important;
            stroke-width: 2px !important;
            rx: 8px !important;
            ry: 8px !important;
          }
          
          /* Nested clusters - visual hierarchy */
          .mermaid .cluster .cluster rect {
            fill: #1e293b !important;
            stroke: #475569 !important;
          }
          
          .mermaid .cluster .cluster .cluster rect {
            fill: #334155 !important;
            stroke: #64748b !important;
          }
          
          /* === NODES INSIDE SUBGRAPHS === */
          .mermaid .cluster .node rect,
          .mermaid .cluster .node polygon,
          .mermaid g.cluster .node rect {
            fill: #1e3a5f !important;
            stroke: #60a5fa !important;
          }
          
          .mermaid .cluster .node .nodeLabel,
          .mermaid .cluster .node span {
            color: #ffffff !important;
            fill: #ffffff !important;
          }
          
          /* === EDGE/ARROW LABELS === */
          .mermaid .edgeLabel,
          .mermaid .edgeLabel span,
          .mermaid .edgeLabel rect,
          .mermaid .labelBkg {
            background-color: #1e293b !important;
            fill: #1e293b !important;
            color: #e2e8f0 !important;
          }
          
          .mermaid .edgeLabel span,
          .mermaid .edgeLabel .nodeLabel {
            color: #e2e8f0 !important;
            fill: #e2e8f0 !important;
          }
          
          /* === LINES AND ARROWS === */
          .mermaid .flowchart-link,
          .mermaid .marker,
          .mermaid path.flowchart-link,
          .mermaid .edge-pattern-solid {
            stroke: #60a5fa !important;
            stroke-width: 2px !important;
          }
          
          .mermaid .arrowheadPath,
          .mermaid .marker,
          .mermaid marker path {
            fill: #60a5fa !important;
            stroke: #60a5fa !important;
          }
          
          /* === CLASSDEFS - Risk Level Colors === */
          /* Critical (red) */
          .mermaid .critical rect,
          .mermaid .critical polygon,
          .mermaid [class*="critical"] rect {
            fill: #dc2626 !important;
            stroke: #ef4444 !important;
          }
          .mermaid .critical .nodeLabel,
          .mermaid .critical span,
          .mermaid [class*="critical"] .nodeLabel {
            color: #ffffff !important;
            fill: #ffffff !important;
          }
          
          /* High (orange) */
          .mermaid .high rect,
          .mermaid .high polygon,
          .mermaid [class*="high"] rect {
            fill: #ea580c !important;
            stroke: #f97316 !important;
          }
          .mermaid .high .nodeLabel,
          .mermaid .high span,
          .mermaid [class*="high"] .nodeLabel {
            color: #ffffff !important;
            fill: #ffffff !important;
          }
          
          /* Medium (amber/yellow) - IMPORTANT: white text for visibility */
          .mermaid .medium rect,
          .mermaid .medium polygon,
          .mermaid [class*="medium"] rect {
            fill: #d97706 !important;
            stroke: #f59e0b !important;
          }
          .mermaid .medium .nodeLabel,
          .mermaid .medium span,
          .mermaid [class*="medium"] .nodeLabel {
            color: #ffffff !important;
            fill: #ffffff !important;
          }
          
          /* Low (green) */
          .mermaid .low rect,
          .mermaid .low polygon,
          .mermaid [class*="low"] rect {
            fill: #16a34a !important;
            stroke: #22c55e !important;
          }
          .mermaid .low .nodeLabel,
          .mermaid .low span,
          .mermaid [class*="low"] .nodeLabel {
            color: #ffffff !important;
            fill: #ffffff !important;
          }
          
          /* Attacker (purple) */
          .mermaid .attacker rect,
          .mermaid .attacker polygon,
          .mermaid [class*="attacker"] rect {
            fill: #7c3aed !important;
            stroke: #8b5cf6 !important;
          }
          .mermaid .attacker .nodeLabel,
          .mermaid .attacker span,
          .mermaid [class*="attacker"] .nodeLabel {
            color: #ffffff !important;
            fill: #ffffff !important;
          }
          
          /* Info (blue) */
          .mermaid .info rect,
          .mermaid .info polygon,
          .mermaid [class*="info"] rect {
            fill: #0284c7 !important;
            stroke: #0ea5e9 !important;
          }
          .mermaid .info .nodeLabel,
          .mermaid .info span,
          .mermaid [class*="info"] .nodeLabel {
            color: #ffffff !important;
            fill: #ffffff !important;
          }
          
          /* === SPECIAL ELEMENTS === */
          /* Notes */
          .mermaid .note rect,
          .mermaid .noteText {
            fill: #334155 !important;
            stroke: #475569 !important;
          }
          .mermaid .noteText,
          .mermaid .note span {
            color: #f1f5f9 !important;
            fill: #f1f5f9 !important;
          }
          
          /* === CATCH-ALL FOR BLANK/WHITE BOXES === */
          /* These target elements that might slip through */
          .mermaid rect:not(.labelBkg):not(.er)[fill="#ffffff"],
          .mermaid rect:not(.labelBkg):not(.er)[fill="white"],
          .mermaid rect:not(.labelBkg):not(.er)[fill="#fff"],
          .mermaid rect:not(.labelBkg):not(.er):not([fill]),
          .mermaid g > rect[class=""] {
            fill: #1e3a5f !important;
            stroke: #60a5fa !important;
          }
          
          /* Force dark fills on inline styles */
          .mermaid rect[style*="fill: rgb(255, 255, 255)"],
          .mermaid rect[style*="fill:#ffffff"],
          .mermaid rect[style*="fill: white"],
          .mermaid rect[style*="fill:#fff"] {
            fill: #1e3a5f !important;
          }
          
          /* Override any black text */
          .mermaid [fill="#000"],
          .mermaid [fill="black"],
          .mermaid [fill="#000000"],
          .mermaid [style*="fill: rgb(0, 0, 0)"],
          .mermaid [style*="fill:#000"],
          .mermaid [style*="color:#000"],
          .mermaid [style*="color: black"] {
            fill: #ffffff !important;
            color: #ffffff !important;
          }
        `}
      </style>
    </Paper>
  );
}

export default MermaidDiagram;
