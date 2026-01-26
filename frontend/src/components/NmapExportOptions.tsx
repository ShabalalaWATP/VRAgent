import React, { useState } from "react";
import {
  Button,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  CircularProgress,
  Divider,
} from "@mui/material";
import {
  FileDownload as DownloadIcon,
  PictureAsPdf as PdfIcon,
  Description as CsvIcon,
  Code as JsonIcon,
  TableChart as ExcelIcon,
} from "@mui/icons-material";

interface NmapHost {
  ip: string;
  hostname?: string;
  status?: string;
  os_guess?: string;
  os_accuracy?: number;
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
  category: string;
  severity: string;
  title: string;
  description: string;
  host?: string;
  port?: number;
  service?: string;
  evidence?: string;
  cve_ids?: string[];
}

interface ScanSummary {
  scan_time?: string;
  hosts_up?: number;
  hosts_down?: number;
  total_open_ports?: number;
  scan_type?: string;
  command?: string;
}

interface NmapExportOptionsProps {
  hosts: NmapHost[];
  findings: NmapFinding[];
  summary?: ScanSummary;
  rawXml?: string;
  scanTarget?: string;
}

export const NmapExportOptions: React.FC<NmapExportOptionsProps> = ({
  hosts,
  findings,
  summary,
  rawXml,
  scanTarget,
}) => {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [exporting, setExporting] = useState(false);

  const handleClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const downloadFile = (content: string, filename: string, mimeType: string) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const generateCSV = (type: "hosts" | "ports" | "findings") => {
    let csv = "";
    const timestamp = new Date().toISOString().split("T")[0];

    if (type === "hosts") {
      csv = "IP,Hostname,Status,OS,OS Accuracy,Open Ports\n";
      hosts.forEach((host) => {
        const openPorts = host.ports?.filter((p) => p.state === "open").length || 0;
        csv += `"${host.ip}","${host.hostname || ""}","${host.status || "up"}","${host.os_guess || ""}","${host.os_accuracy || ""}","${openPorts}"\n`;
      });
      downloadFile(csv, `nmap-hosts-${timestamp}.csv`, "text/csv");
    } else if (type === "ports") {
      csv = "Host,Port,Protocol,State,Service,Product,Version\n";
      hosts.forEach((host) => {
        host.ports?.forEach((port) => {
          csv += `"${host.ip}","${port.port}","${port.protocol}","${port.state}","${port.service || ""}","${port.product || ""}","${port.version || ""}"\n`;
        });
      });
      downloadFile(csv, `nmap-ports-${timestamp}.csv`, "text/csv");
    } else if (type === "findings") {
      csv = "Severity,Host,Port,Service,Category,Title,Description,CVEs\n";
      findings.forEach((f) => {
        csv += `"${f.severity}","${f.host}","${f.port || ""}","${f.service || ""}","${f.category}","${f.title}","${f.description.replace(/"/g, '""')}","${f.cve_ids?.join(", ") || ""}"\n`;
      });
      downloadFile(csv, `nmap-findings-${timestamp}.csv`, "text/csv");
    }
  };

  const generateJSON = () => {
    const data = {
      exportedAt: new Date().toISOString(),
      target: scanTarget,
      summary,
      hosts,
      findings,
    };
    const timestamp = new Date().toISOString().split("T")[0];
    downloadFile(JSON.stringify(data, null, 2), `nmap-export-${timestamp}.json`, "application/json");
  };

  const generateMarkdown = () => {
    const timestamp = new Date().toISOString().split("T")[0];
    let md = `# Nmap Scan Report\n\n`;
    md += `**Generated:** ${new Date().toLocaleString()}\n\n`;
    
    if (scanTarget) {
      md += `**Target:** ${scanTarget}\n\n`;
    }

    if (summary) {
      md += `## Summary\n\n`;
      md += `| Metric | Value |\n`;
      md += `|--------|-------|\n`;
      if (summary.scan_time) md += `| Scan Duration | ${summary.scan_time} |\n`;
      if (summary.hosts_up !== undefined) md += `| Hosts Up | ${summary.hosts_up} |\n`;
      if (summary.total_open_ports !== undefined) md += `| Open Ports | ${summary.total_open_ports} |\n`;
      md += `\n`;
    }

    // Findings summary
    if (findings.length > 0) {
      md += `## Security Findings\n\n`;
      const severityCounts: Record<string, number> = {};
      findings.forEach((f) => {
        severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
      });
      md += `| Severity | Count |\n`;
      md += `|----------|-------|\n`;
      ["critical", "high", "medium", "low", "info"].forEach((sev) => {
        if (severityCounts[sev]) {
          md += `| ${sev.toUpperCase()} | ${severityCounts[sev]} |\n`;
        }
      });
      md += `\n`;

      findings.forEach((f, idx) => {
        md += `### ${idx + 1}. ${f.title}\n\n`;
        md += `- **Severity:** ${f.severity.toUpperCase()}\n`;
        md += `- **Host:** ${f.host}\n`;
        if (f.port) md += `- **Port:** ${f.port}\n`;
        if (f.service) md += `- **Service:** ${f.service}\n`;
        md += `- **Category:** ${f.category}\n\n`;
        md += `${f.description}\n\n`;
        if (f.cve_ids?.length) {
          md += `**CVEs:** ${f.cve_ids.join(", ")}\n\n`;
        }
      });
    }

    // Hosts
    md += `## Discovered Hosts\n\n`;
    hosts.forEach((host) => {
      md += `### ${host.hostname || host.ip}\n\n`;
      md += `- **IP:** ${host.ip}\n`;
      if (host.hostname) md += `- **Hostname:** ${host.hostname}\n`;
      if (host.os_guess) md += `- **OS:** ${host.os_guess}\n`;
      
      const openPorts = host.ports?.filter((p) => p.state === "open") || [];
      if (openPorts.length > 0) {
        md += `\n| Port | Service | Product | Version |\n`;
        md += `|------|---------|---------|--------|\n`;
        openPorts.forEach((p) => {
          md += `| ${p.port}/${p.protocol} | ${p.service || "-"} | ${p.product || "-"} | ${p.version || "-"} |\n`;
        });
      }
      md += `\n`;
    });

    downloadFile(md, `nmap-report-${timestamp}.md`, "text/markdown");
  };

  const generateHTML = async () => {
    setExporting(true);
    try {
      const timestamp = new Date().toISOString().split("T")[0];
      let html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Nmap Scan Report - ${scanTarget || "Unknown Target"}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; color: #333; }
    h1 { color: #1976d2; border-bottom: 2px solid #1976d2; padding-bottom: 10px; }
    h2 { color: #424242; margin-top: 30px; }
    h3 { color: #616161; }
    table { border-collapse: collapse; width: 100%; margin: 15px 0; }
    th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
    th { background: #f5f5f5; font-weight: 600; }
    tr:hover { background: #fafafa; }
    .severity-critical { background: #ffebee; color: #c62828; font-weight: bold; }
    .severity-high { background: #fff3e0; color: #e65100; font-weight: bold; }
    .severity-medium { background: #fff8e1; color: #f57f17; }
    .severity-low { background: #e3f2fd; color: #1565c0; }
    .summary-box { background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }
    .finding { margin: 15px 0; padding: 15px; border-radius: 8px; border-left: 4px solid; }
    .finding-critical { border-color: #c62828; background: #ffebee; }
    .finding-high { border-color: #e65100; background: #fff3e0; }
    .finding-medium { border-color: #f57f17; background: #fff8e1; }
    .finding-low { border-color: #1565c0; background: #e3f2fd; }
    .chip { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; margin: 2px; }
    .chip-service { background: #e3f2fd; color: #1565c0; }
    code { background: #f5f5f5; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
    @media print { body { margin: 20px; } }
  </style>
</head>
<body>
  <h1>🔍 Nmap Scan Report</h1>
  <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
  ${scanTarget ? `<p><strong>Target:</strong> <code>${scanTarget}</code></p>` : ""}
  
  ${summary ? `
  <div class="summary-box">
    <h2>📊 Summary</h2>
    <table>
      <tr><th>Metric</th><th>Value</th></tr>
      ${summary.scan_time ? `<tr><td>Scan Duration</td><td>${summary.scan_time}</td></tr>` : ""}
      ${summary.hosts_up !== undefined ? `<tr><td>Hosts Up</td><td>${summary.hosts_up}</td></tr>` : ""}
      ${summary.hosts_down !== undefined ? `<tr><td>Hosts Down</td><td>${summary.hosts_down}</td></tr>` : ""}
      ${summary.total_open_ports !== undefined ? `<tr><td>Total Open Ports</td><td>${summary.total_open_ports}</td></tr>` : ""}
    </table>
  </div>
  ` : ""}

  ${findings.length > 0 ? `
  <h2>🚨 Security Findings (${findings.length})</h2>
  ${findings.map((f, idx) => `
    <div class="finding finding-${f.severity}">
      <h3>${idx + 1}. ${f.title}</h3>
      <p><strong>Severity:</strong> <span class="severity-${f.severity}">${f.severity.toUpperCase()}</span></p>
      <p><strong>Host:</strong> <code>${f.host}</code>${f.port ? ` | <strong>Port:</strong> ${f.port}` : ""}${f.service ? ` | <strong>Service:</strong> ${f.service}` : ""}</p>
      <p><strong>Category:</strong> ${f.category}</p>
      <p>${f.description}</p>
      ${f.cve_ids?.length ? `<p><strong>CVEs:</strong> ${f.cve_ids.map(c => `<code>${c}</code>`).join(", ")}</p>` : ""}
    </div>
  `).join("")}
  ` : ""}

  <h2>🖥️ Discovered Hosts (${hosts.length})</h2>
  ${hosts.map(host => `
    <h3>${host.hostname || host.ip}</h3>
    <p><strong>IP:</strong> <code>${host.ip}</code>${host.hostname ? ` | <strong>Hostname:</strong> ${host.hostname}` : ""}${host.os_guess ? ` | <strong>OS:</strong> ${host.os_guess}` : ""}</p>
    ${(host.ports?.filter(p => p.state === "open") || []).length > 0 ? `
    <table>
      <tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>
      ${host.ports?.filter(p => p.state === "open").map(p => `
        <tr>
          <td><code>${p.port}/${p.protocol}</code></td>
          <td>${p.service ? `<span class="chip chip-service">${p.service}</span>` : "-"}</td>
          <td>${p.product || "-"}</td>
          <td>${p.version || "-"}</td>
        </tr>
      `).join("")}
    </table>
    ` : "<p>No open ports detected</p>"}
  `).join("")}

</body>
</html>`;

      downloadFile(html, `nmap-report-${timestamp}.html`, "text/html");
    } finally {
      setExporting(false);
    }
  };

  return (
    <>
      <Button
        variant="outlined"
        startIcon={exporting ? <CircularProgress size={16} /> : <DownloadIcon />}
        onClick={handleClick}
        disabled={exporting}
      >
        Export
      </Button>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        <MenuItem
          onClick={() => {
            generateHTML();
            handleClose();
          }}
        >
          <ListItemIcon>
            <PdfIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText primary="HTML Report" secondary="Full report with styling" />
        </MenuItem>
        <MenuItem
          onClick={() => {
            generateMarkdown();
            handleClose();
          }}
        >
          <ListItemIcon>
            <Description fontSize="small" />
          </ListItemIcon>
          <ListItemText primary="Markdown Report" secondary="Documentation format" />
        </MenuItem>
        <Divider />
        <MenuItem
          onClick={() => {
            generateCSV("hosts");
            handleClose();
          }}
        >
          <ListItemIcon>
            <CsvIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText primary="Hosts CSV" secondary="Host summary data" />
        </MenuItem>
        <MenuItem
          onClick={() => {
            generateCSV("ports");
            handleClose();
          }}
        >
          <ListItemIcon>
            <ExcelIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText primary="Ports CSV" secondary="All port details" />
        </MenuItem>
        {findings.length > 0 && (
          <MenuItem
            onClick={() => {
              generateCSV("findings");
              handleClose();
            }}
          >
            <ListItemIcon>
              <CsvIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText primary="Findings CSV" secondary="Security findings" />
          </MenuItem>
        )}
        <Divider />
        <MenuItem
          onClick={() => {
            generateJSON();
            handleClose();
          }}
        >
          <ListItemIcon>
            <JsonIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText primary="JSON Export" secondary="Raw data export" />
        </MenuItem>
        {rawXml && (
          <MenuItem
            onClick={() => {
              const timestamp = new Date().toISOString().split("T")[0];
              downloadFile(rawXml, `nmap-raw-${timestamp}.xml`, "application/xml");
              handleClose();
            }}
          >
            <ListItemIcon>
              <JsonIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText primary="Raw XML" secondary="Original Nmap output" />
          </MenuItem>
        )}
      </Menu>
    </>
  );
};

// Fix missing import
import { Description } from "@mui/icons-material";

export default NmapExportOptions;
