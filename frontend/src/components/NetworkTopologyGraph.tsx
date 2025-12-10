import React, { useEffect, useRef, useState } from "react";
import {
  Box,
  Typography,
  Paper,
  alpha,
  Chip,
  FormControlLabel,
  Switch,
  Slider,
  IconButton,
  Tooltip,
} from "@mui/material";
import ZoomInIcon from "@mui/icons-material/ZoomIn";
import ZoomOutIcon from "@mui/icons-material/ZoomOut";
import CenterFocusStrongIcon from "@mui/icons-material/CenterFocusStrong";
import * as d3 from "d3";

export interface TopologyNode {
  id: string;
  ip: string;
  type: "host" | "server" | "router" | "unknown";
  hostname?: string;
  services?: string[];
  ports?: number[];
  packets?: number;
  bytes?: number;
  riskLevel?: "critical" | "high" | "medium" | "low" | "none";
}

export interface TopologyLink {
  source: string;
  target: string;
  protocol?: string;
  port?: number;
  packets?: number;
  bytes?: number;
  bidirectional?: boolean;
}

interface NetworkTopologyGraphProps {
  nodes: TopologyNode[];
  links: TopologyLink[];
  title?: string;
  height?: number;
  onNodeClick?: (node: TopologyNode) => void;
}

const NetworkTopologyGraph: React.FC<NetworkTopologyGraphProps> = ({
  nodes,
  links,
  title = "Network Topology",
  height = 500,
  onNodeClick,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [showLabels, setShowLabels] = useState(true);
  const [linkStrength, setLinkStrength] = useState(0.5);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const getNodeColor = (node: TopologyNode) => {
    if (node.riskLevel) {
      switch (node.riskLevel) {
        case "critical":
          return "#dc2626";
        case "high":
          return "#ea580c";
        case "medium":
          return "#ca8a04";
        case "low":
          return "#16a34a";
        default:
          return "#6b7280";
      }
    }
    switch (node.type) {
      case "server":
        return "#8b5cf6";
      case "router":
        return "#06b6d4";
      case "host":
        return "#10b981";
      default:
        return "#6b7280";
    }
  };

  const getNodeSize = (node: TopologyNode) => {
    const baseSize = 20;
    if (node.packets) {
      return Math.min(baseSize + Math.log10(node.packets + 1) * 5, 50);
    }
    return baseSize;
  };

  const getNodeShape = (node: TopologyNode) => {
    switch (node.type) {
      case "server":
        return "rect";
      case "router":
        return "diamond";
      default:
        return "circle";
    }
  };

  useEffect(() => {
    if (!svgRef.current || !containerRef.current || nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = containerRef.current.clientWidth;
    const svgHeight = height;

    // Create zoom behavior
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });

    svg.call(zoom);

    const g = svg.append("g");

    // Create arrow marker for directed links
    svg
      .append("defs")
      .append("marker")
      .attr("id", "arrowhead")
      .attr("viewBox", "-0 -5 10 10")
      .attr("refX", 25)
      .attr("refY", 0)
      .attr("orient", "auto")
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .append("path")
      .attr("d", "M 0,-5 L 10,0 L 0,5")
      .attr("fill", "#6b7280");

    // Process nodes and links
    const nodeMap = new Map(nodes.map((n) => [n.id, n]));
    const processedLinks = links.map((link) => ({
      ...link,
      source: link.source,
      target: link.target,
    }));

    // Create force simulation
    const simulation = d3
      .forceSimulation(nodes as any)
      .force(
        "link",
        d3
          .forceLink(processedLinks)
          .id((d: any) => d.id)
          .distance(100)
          .strength(linkStrength)
      )
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, svgHeight / 2))
      .force("collision", d3.forceCollide().radius(50));

    // Draw links
    const link = g
      .append("g")
      .attr("class", "links")
      .selectAll("line")
      .data(processedLinks)
      .enter()
      .append("line")
      .attr("stroke", "#6b7280")
      .attr("stroke-opacity", 0.6)
      .attr("stroke-width", (d) => Math.max(1, Math.min(Math.log10((d.packets || 1) + 1), 5)))
      .attr("marker-end", (d) => (d.bidirectional ? "" : "url(#arrowhead)"));

    // Link labels (protocol/port)
    const linkLabel = g
      .append("g")
      .attr("class", "link-labels")
      .selectAll("text")
      .data(processedLinks)
      .enter()
      .append("text")
      .attr("font-size", "10px")
      .attr("fill", "#9ca3af")
      .attr("text-anchor", "middle")
      .text((d) => (d.protocol ? `${d.protocol}${d.port ? `:${d.port}` : ""}` : ""))
      .style("display", showLabels ? "block" : "none");

    // Draw nodes
    const node = g
      .append("g")
      .attr("class", "nodes")
      .selectAll("g")
      .data(nodes)
      .enter()
      .append("g")
      .attr("cursor", "pointer")
      .call(
        d3
          .drag<any, TopologyNode>()
          .on("start", (event, d: any) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d: any) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event, d: any) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      )
      .on("click", (event, d) => {
        setSelectedNode(d.id === selectedNode ? null : d.id);
        if (onNodeClick) onNodeClick(d);
      });

    // Add shapes based on node type
    node.each(function (d) {
      const el = d3.select(this);
      const size = getNodeSize(d);
      const color = getNodeColor(d);

      if (getNodeShape(d) === "rect") {
        el.append("rect")
          .attr("width", size * 1.5)
          .attr("height", size)
          .attr("x", (-size * 1.5) / 2)
          .attr("y", -size / 2)
          .attr("rx", 4)
          .attr("fill", color)
          .attr("stroke", "#fff")
          .attr("stroke-width", 2);
      } else if (getNodeShape(d) === "diamond") {
        el.append("polygon")
          .attr("points", `0,${-size} ${size},0 0,${size} ${-size},0`)
          .attr("fill", color)
          .attr("stroke", "#fff")
          .attr("stroke-width", 2);
      } else {
        el.append("circle")
          .attr("r", size / 2)
          .attr("fill", color)
          .attr("stroke", "#fff")
          .attr("stroke-width", 2);
      }

      // Add icon based on type
      el.append("text")
        .attr("text-anchor", "middle")
        .attr("dominant-baseline", "central")
        .attr("fill", "#fff")
        .attr("font-size", "12px")
        .attr("font-weight", "bold")
        .text(() => {
          switch (d.type) {
            case "server":
              return "S";
            case "router":
              return "R";
            case "host":
              return "H";
            default:
              return "?";
          }
        });
    });

    // Node labels
    node
      .append("text")
      .attr("dy", (d) => getNodeSize(d) / 2 + 15)
      .attr("text-anchor", "middle")
      .attr("font-size", "11px")
      .attr("fill", "#e5e7eb")
      .attr("font-weight", "500")
      .text((d) => d.hostname || d.ip)
      .style("display", showLabels ? "block" : "none");

    // Service badges
    node
      .filter((d): boolean => !!(d.services && d.services.length > 0))
      .append("text")
      .attr("dy", (d) => getNodeSize(d) / 2 + 28)
      .attr("text-anchor", "middle")
      .attr("font-size", "9px")
      .attr("fill", "#9ca3af")
      .text((d) => (d.services || []).slice(0, 3).join(", "))
      .style("display", showLabels ? "block" : "none");

    // Tooltip
    const tooltip = d3
      .select("body")
      .append("div")
      .attr("class", "network-topology-tooltip")
      .style("position", "absolute")
      .style("visibility", "hidden")
      .style("background", "rgba(0, 0, 0, 0.9)")
      .style("color", "white")
      .style("padding", "10px")
      .style("border-radius", "8px")
      .style("font-size", "12px")
      .style("max-width", "250px")
      .style("z-index", "10000")
      .style("pointer-events", "none");

    node
      .on("mouseover", (event, d) => {
        tooltip
          .style("visibility", "visible")
          .html(
            `
            <strong>${d.hostname || d.ip}</strong><br/>
            <span style="color: #9ca3af">Type:</span> ${d.type}<br/>
            ${d.services ? `<span style="color: #9ca3af">Services:</span> ${d.services.join(", ")}<br/>` : ""}
            ${d.ports ? `<span style="color: #9ca3af">Ports:</span> ${d.ports.join(", ")}<br/>` : ""}
            ${d.packets ? `<span style="color: #9ca3af">Packets:</span> ${d.packets.toLocaleString()}<br/>` : ""}
            ${d.bytes ? `<span style="color: #9ca3af">Bytes:</span> ${(d.bytes / 1024).toFixed(2)} KB<br/>` : ""}
            ${d.riskLevel ? `<span style="color: ${getNodeColor(d)}">Risk: ${d.riskLevel.toUpperCase()}</span>` : ""}
          `
          );
      })
      .on("mousemove", (event) => {
        tooltip
          .style("top", event.pageY - 10 + "px")
          .style("left", event.pageX + 10 + "px");
      })
      .on("mouseout", () => {
        tooltip.style("visibility", "hidden");
      });

    // Update positions on tick
    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);

      linkLabel
        .attr("x", (d: any) => (d.source.x + d.target.x) / 2)
        .attr("y", (d: any) => (d.source.y + d.target.y) / 2);

      node.attr("transform", (d: any) => `translate(${d.x},${d.y})`);
    });

    // Cleanup
    return () => {
      simulation.stop();
      tooltip.remove();
    };
  }, [nodes, links, showLabels, linkStrength, height, onNodeClick, selectedNode]);

  const handleZoomIn = () => {
    if (svgRef.current) {
      const svg = d3.select(svgRef.current);
      svg.transition().call(
        d3.zoom<SVGSVGElement, unknown>().scaleBy as any,
        1.3
      );
    }
  };

  const handleZoomOut = () => {
    if (svgRef.current) {
      const svg = d3.select(svgRef.current);
      svg.transition().call(
        d3.zoom<SVGSVGElement, unknown>().scaleBy as any,
        0.7
      );
    }
  };

  const handleReset = () => {
    if (svgRef.current && containerRef.current) {
      const svg = d3.select(svgRef.current);
      const width = containerRef.current.clientWidth;
      svg.transition().call(
        d3.zoom<SVGSVGElement, unknown>().transform as any,
        d3.zoomIdentity.translate(width / 2 - width / 2, height / 2 - height / 2)
      );
    }
  };

  if (nodes.length === 0) {
    return (
      <Paper sx={{ p: 3, textAlign: "center" }}>
        <Typography color="text.secondary">
          No network topology data available. Upload a PCAP or Nmap scan to visualize the network.
        </Typography>
      </Paper>
    );
  }

  return (
    <Paper
      sx={{
        p: 2,
        background: alpha("#000", 0.3),
        border: "1px solid",
        borderColor: "divider",
      }}
    >
      {/* Header */}
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          mb: 2,
        }}
      >
        <Typography variant="h6" fontWeight={600}>
          {title}
        </Typography>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
          <FormControlLabel
            control={
              <Switch
                checked={showLabels}
                onChange={(e) => setShowLabels(e.target.checked)}
                size="small"
              />
            }
            label="Labels"
          />
          <Box sx={{ width: 150 }}>
            <Typography variant="caption" color="text.secondary">
              Link Strength
            </Typography>
            <Slider
              value={linkStrength}
              onChange={(_, v) => setLinkStrength(v as number)}
              min={0.1}
              max={1}
              step={0.1}
              size="small"
            />
          </Box>
          <Box>
            <Tooltip title="Zoom In">
              <IconButton size="small" onClick={handleZoomIn}>
                <ZoomInIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Zoom Out">
              <IconButton size="small" onClick={handleZoomOut}>
                <ZoomOutIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Reset View">
              <IconButton size="small" onClick={handleReset}>
                <CenterFocusStrongIcon />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>
      </Box>

      {/* Legend */}
      <Box sx={{ display: "flex", gap: 2, mb: 2 }}>
        <Chip
          size="small"
          label="Host"
          sx={{ bgcolor: alpha("#10b981", 0.2), color: "#10b981" }}
        />
        <Chip
          size="small"
          label="Server"
          sx={{ bgcolor: alpha("#8b5cf6", 0.2), color: "#8b5cf6" }}
        />
        <Chip
          size="small"
          label="Router"
          sx={{ bgcolor: alpha("#06b6d4", 0.2), color: "#06b6d4" }}
        />
        <Box sx={{ flexGrow: 1 }} />
        <Typography variant="caption" color="text.secondary">
          {nodes.length} nodes, {links.length} connections
        </Typography>
      </Box>

      {/* Graph Container */}
      <Box
        ref={containerRef}
        sx={{
          width: "100%",
          height,
          border: "1px solid",
          borderColor: "divider",
          borderRadius: 1,
          overflow: "hidden",
          bgcolor: alpha("#000", 0.5),
        }}
      >
        <svg
          ref={svgRef}
          width="100%"
          height={height}
          style={{ display: "block" }}
        />
      </Box>
    </Paper>
  );
};

export default NetworkTopologyGraph;
