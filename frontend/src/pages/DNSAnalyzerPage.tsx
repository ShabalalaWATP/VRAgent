import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  Button,
  CircularProgress,
  Alert,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  LinearProgress,
  Tooltip,
  Card,
  CardContent,
  Grid,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormHelperText,
  Tabs,
  Tab,
  IconButton,
  Breadcrumbs,
  Link as MuiLink,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Snackbar,
  Collapse,
} from "@mui/material";
import { Link } from "react-router-dom";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import DnsIcon from "@mui/icons-material/Dns";
import SearchIcon from "@mui/icons-material/Search";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ErrorIcon from "@mui/icons-material/Error";
import InfoIcon from "@mui/icons-material/Info";
import HubIcon from "@mui/icons-material/Hub";
import HistoryIcon from "@mui/icons-material/History";
import DeleteIcon from "@mui/icons-material/Delete";
import VisibilityIcon from "@mui/icons-material/Visibility";
import NavigateNextIcon from "@mui/icons-material/NavigateNext";
import EmailIcon from "@mui/icons-material/Email";
import StorageIcon from "@mui/icons-material/Storage";
import PublicIcon from "@mui/icons-material/Public";
import SendIcon from "@mui/icons-material/Send";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import PersonIcon from "@mui/icons-material/Person";
import ChatIcon from "@mui/icons-material/Chat";
import OpenInFullIcon from "@mui/icons-material/OpenInFull";
import CloseFullscreenIcon from "@mui/icons-material/CloseFullscreen";
import LanguageIcon from "@mui/icons-material/Language";
import GppBadIcon from "@mui/icons-material/GppBad";
import GppGoodIcon from "@mui/icons-material/GppGood";
import SubdirectoryArrowRightIcon from "@mui/icons-material/SubdirectoryArrowRight";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import StopIcon from "@mui/icons-material/Stop";
import ManageSearchIcon from "@mui/icons-material/ManageSearch";
import BusinessIcon from "@mui/icons-material/Business";
import CalendarTodayIcon from "@mui/icons-material/CalendarToday";
import RouterIcon from "@mui/icons-material/Router";
import CloudIcon from "@mui/icons-material/Cloud";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import LinkOffIcon from "@mui/icons-material/LinkOff";
import VerifiedUserIcon from "@mui/icons-material/VerifiedUser";
import DeviceHubIcon from "@mui/icons-material/DeviceHub";
import ReactMarkdown from "react-markdown";
import { ChatCodeBlock } from "../components/ChatCodeBlock";
import ForceGraph2D from "react-force-graph-2d";
import DownloadIcon from "@mui/icons-material/Download";
import { jsPDF } from "jspdf";
import {
  Document as DocxDocument,
  Packer,
  Paragraph,
  TextRun,
  HeadingLevel,
  Table as DocxTable,
  TableRow as DocxTableRow,
  TableCell as DocxTableCell,
  WidthType,
  AlignmentType,
  ISectionOptions,
} from "docx";
import { saveAs } from "file-saver";
import {
  apiClient,
  DNSScanType,
  DNSReconResult,
  SavedDNSReport,
  WhoisDomainResult,
  WhoisIPResult,
} from "../api/client";

// Severity colors
const severityColors: Record<string, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#3b82f6",
};

// Record type colors
const recordTypeColors: Record<string, string> = {
  A: "#3b82f6",
  AAAA: "#06b6d4",
  MX: "#8b5cf6",
  NS: "#f59e0b",
  TXT: "#10b981",
  SOA: "#ec4899",
  CNAME: "#6366f1",
  SRV: "#f97316",
  CAA: "#dc2626",
  PTR: "#84cc16",
};

// Phase labels for progress
const phaseLabels: Record<string, string> = {
  records: "Querying DNS Records",
  subdomains: "Enumerating Subdomains",
  zone_transfer: "Testing Zone Transfer",
  security: "Analyzing Security",
  reverse_dns: "Reverse DNS Lookups",
  ai_analysis: "AI Analysis",
  complete: "Complete",
};

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

interface ScanProgress {
  phase: string;
  progress: number;
  message: string;
}

// Simple copy to clipboard utility (for inline handlers)
async function copyToClipboard(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Fallback for older browsers
    const textarea = document.createElement("textarea");
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
  }
}

// Copy to clipboard hook (for components that need copy state)
function useCopyToClipboard() {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for older browsers
      const textarea = document.createElement("textarea");
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, []);

  return { copy, copied };
}

// Copy button component
function CopyButton({ text, size = "small" }: { text: string; size?: "small" | "medium" }) {
  const { copy, copied } = useCopyToClipboard();
  
  return (
    <Tooltip title={copied ? "Copied!" : "Copy to clipboard"}>
      <IconButton
        size={size}
        onClick={(e) => {
          e.stopPropagation();
          copy(text);
        }}
        sx={{ 
          opacity: 0.6, 
          "&:hover": { opacity: 1 },
          color: copied ? "success.main" : "inherit",
        }}
      >
        <ContentCopyIcon fontSize={size === "small" ? "small" : "medium"} />
      </IconButton>
    </Tooltip>
  );
}

// =============================================================================
// EXPORT FUNCTIONS
// =============================================================================

/**
 * Generate comprehensive Markdown report from DNS reconnaissance results
 */
function generateDNSMarkdown(result: DNSReconResult): string {
  const lines: string[] = [];
  const timestamp = new Date().toLocaleString();

  // Title and metadata
  lines.push(`# DNS Reconnaissance Report: ${result.domain}`);
  lines.push("");
  lines.push(`**Generated:** ${timestamp}`);
  lines.push(`**Scan Duration:** ${result.scan_duration_seconds.toFixed(2)} seconds`);
  lines.push(`**Report ID:** ${result.report_id || "N/A"}`);
  lines.push("");

  // Executive Summary
  lines.push("---");
  lines.push("");
  lines.push("## Executive Summary");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("|--------|-------|");
  lines.push(`| **DNS Records** | ${result.total_records} |`);
  lines.push(`| **Subdomains Found** | ${result.total_subdomains} |`);
  lines.push(`| **Unique IPs** | ${result.unique_ips.length} |`);
  lines.push(`| **Nameservers** | ${result.nameservers.length} |`);
  lines.push(`| **Mail Servers** | ${result.mail_servers.length} |`);
  lines.push(`| **Zone Transfer** | ${result.zone_transfer_possible ? "⚠️ **VULNERABLE**" : "✅ Protected"} |`);
  if (result.security) {
    lines.push(`| **Mail Security Score** | ${result.security.mail_security_score}/100 |`);
  }
  if (result.takeover_risks && result.takeover_risks.length > 0) {
    lines.push(`| **Takeover Risks** | ⚠️ ${result.takeover_risks.length} found |`);
  }
  if (result.has_wildcard) {
    lines.push(`| **Wildcard DNS** | ⚡ Detected |`);
  }
  lines.push("");

  // Zone Transfer Warning
  if (result.zone_transfer_possible) {
    lines.push("### ⚠️ CRITICAL: Zone Transfer Vulnerability");
    lines.push("");
    lines.push("> **This domain allows DNS zone transfers (AXFR), exposing all DNS records to attackers.**");
    lines.push("> This is a serious misconfiguration that should be fixed immediately.");
    lines.push("");
  }

  // Email Security Analysis
  if (result.security) {
    lines.push("---");
    lines.push("");
    lines.push("## Email Security Analysis");
    lines.push("");
    lines.push(`**Mail Security Score:** ${result.security.mail_security_score}/100`);
    lines.push("");
    lines.push("### Security Controls Status");
    lines.push("");
    lines.push("| Control | Status | Details |");
    lines.push("|---------|--------|---------|");
    lines.push(`| **SPF** | ${result.security.has_spf ? "✅ Present" : "❌ Missing"} | ${result.security.spf_record || "Not configured"} |`);
    lines.push(`| **DMARC** | ${result.security.has_dmarc ? "✅ Present" : "❌ Missing"} | ${result.security.dmarc_record || "Not configured"} |`);
    lines.push(`| **DKIM** | ${result.security.has_dkim ? "✅ Found" : "❌ Not found"} | Selectors: ${result.security.dkim_selectors_found?.join(", ") || "None"} |`);
    lines.push(`| **DNSSEC** | ${result.security.has_dnssec ? "✅ Enabled" : "⚠️ Not enabled"} | ${result.security.dnssec_details || "-"} |`);
    lines.push(`| **CAA** | ${result.security.has_caa ? "✅ Present" : "⚠️ Missing"} | ${result.security.caa_records?.join(", ") || "Not configured"} |`);
    lines.push(`| **BIMI** | ${result.security.has_bimi ? "✅ Present" : "⚠️ Missing"} | ${result.security.bimi_record || "-"} |`);
    lines.push(`| **MTA-STS** | ${result.security.has_mta_sts ? "✅ Present" : "⚠️ Missing"} | ${result.security.mta_sts_record || "-"} |`);
    lines.push("");

    // Security Issues
    if (result.security.overall_issues && result.security.overall_issues.length > 0) {
      lines.push("### ⚠️ Security Issues");
      lines.push("");
      result.security.overall_issues.forEach(issue => {
        lines.push(`- ${issue}`);
      });
      lines.push("");
    }

    // Recommendations
    if (result.security.recommendations && result.security.recommendations.length > 0) {
      lines.push("### 💡 Recommendations");
      lines.push("");
      result.security.recommendations.forEach(rec => {
        lines.push(`- ${rec}`);
      });
      lines.push("");
    }
  }

  // DNS Records
  lines.push("---");
  lines.push("");
  lines.push("## DNS Records");
  lines.push("");
  if (result.records && result.records.length > 0) {
    lines.push("| Type | Name | Value | TTL | Priority |");
    lines.push("|------|------|-------|-----|----------|");
    result.records.forEach(record => {
      const value = record.value.length > 60 ? record.value.substring(0, 57) + "..." : record.value;
      lines.push(`| \`${record.record_type}\` | ${record.name} | \`${value}\` | ${record.ttl || "-"} | ${record.priority ?? "-"} |`);
    });
    lines.push("");
  } else {
    lines.push("*No DNS records found.*");
    lines.push("");
  }

  // Nameservers
  if (result.nameservers && result.nameservers.length > 0) {
    lines.push("### Nameservers");
    lines.push("");
    result.nameservers.forEach(ns => {
      lines.push(`- \`${ns}\``);
    });
    lines.push("");
  }

  // Mail Servers
  if (result.mail_servers && result.mail_servers.length > 0) {
    lines.push("### Mail Servers");
    lines.push("");
    lines.push("| Priority | Server |");
    lines.push("|----------|--------|");
    result.mail_servers.forEach(mx => {
      lines.push(`| ${mx.priority} | \`${mx.server}\` |`);
    });
    lines.push("");
  }

  // Subdomains
  lines.push("---");
  lines.push("");
  lines.push("## Subdomains");
  lines.push("");
  if (result.subdomains && result.subdomains.length > 0) {
    lines.push(`**Total Found:** ${result.total_subdomains}`);
    lines.push("");
    lines.push("| Subdomain | Full Domain | IP Addresses | CNAME |");
    lines.push("|-----------|-------------|--------------|-------|");
    result.subdomains.slice(0, 100).forEach(sub => {
      const ips = sub.ip_addresses?.join(", ") || "-";
      lines.push(`| ${sub.subdomain} | \`${sub.full_domain}\` | ${ips} | ${sub.cname || "-"} |`);
    });
    if (result.subdomains.length > 100) {
      lines.push("");
      lines.push(`*... and ${result.subdomains.length - 100} more subdomains*`);
    }
    lines.push("");
  } else {
    lines.push("*No subdomains found.*");
    lines.push("");
  }

  // Subdomain Takeover Risks
  if (result.takeover_risks && result.takeover_risks.length > 0) {
    lines.push("---");
    lines.push("");
    lines.push("## ⚠️ Subdomain Takeover Risks");
    lines.push("");
    lines.push("| Subdomain | CNAME Target | Provider | Risk Level | Vulnerable |");
    lines.push("|-----------|--------------|----------|------------|------------|");
    result.takeover_risks.forEach(risk => {
      const vulnStatus = risk.is_vulnerable ? "**YES**" : "No";
      lines.push(`| \`${risk.subdomain}\` | \`${risk.cname_target}\` | ${risk.provider} | **${risk.risk_level.toUpperCase()}** | ${vulnStatus} |`);
    });
    lines.push("");
  }

  // Dangling CNAMEs
  if (result.dangling_cnames && result.dangling_cnames.length > 0) {
    lines.push("---");
    lines.push("");
    lines.push("## 🔗 Dangling CNAMEs");
    lines.push("");
    lines.push("*These CNAMEs point to non-resolving targets and may be vulnerable to takeover.*");
    lines.push("");
    result.dangling_cnames.forEach(dc => {
      lines.push(`- \`${dc.subdomain}\` → \`${dc.cname}\``);
    });
    lines.push("");
  }

  // Cloud Providers
  if (result.cloud_providers && result.cloud_providers.length > 0) {
    lines.push("---");
    lines.push("");
    lines.push("## ☁️ Cloud Infrastructure Detected");
    lines.push("");
    const providerGroups: Record<string, typeof result.cloud_providers> = {};
    result.cloud_providers.forEach(cp => {
      const key = cp.provider.toUpperCase();
      if (!providerGroups[key]) providerGroups[key] = [];
      providerGroups[key].push(cp);
    });

    Object.entries(providerGroups).forEach(([provider, items]) => {
      lines.push(`### ${provider}`);
      lines.push("");
      items.slice(0, 10).forEach(item => {
        const cdn = item.is_cdn ? " (CDN)" : "";
        const service = item.service ? ` - ${item.service}` : "";
        lines.push(`- \`${item.ip_or_domain}\`${service}${cdn}`);
      });
      if (items.length > 10) {
        lines.push(`- *... and ${items.length - 10} more*`);
      }
      lines.push("");
    });
  }

  // ASN Information
  if (result.asn_info && result.asn_info.length > 0) {
    lines.push("---");
    lines.push("");
    lines.push("## 🌐 ASN/Network Information");
    lines.push("");
    lines.push("| IP Address | ASN | Organization | Country |");
    lines.push("|------------|-----|--------------|---------|");
    result.asn_info.forEach(asn => {
      lines.push(`| \`${asn.ip_address}\` | ${asn.asn || "-"} | ${asn.asn_name || "-"} | ${asn.country || "-"} |`);
    });
    lines.push("");
  }

  // Unique IPs
  if (result.unique_ips && result.unique_ips.length > 0) {
    lines.push("---");
    lines.push("");
    lines.push("## 📍 Unique IP Addresses");
    lines.push("");
    lines.push("```");
    result.unique_ips.forEach(ip => {
      const rdns = result.reverse_dns?.[ip];
      lines.push(rdns ? `${ip} (${rdns})` : ip);
    });
    lines.push("```");
    lines.push("");
  }

  // AI Analysis
  if (result.ai_analysis && typeof result.ai_analysis === "object" && !result.ai_analysis.error) {
    lines.push("---");
    lines.push("");
    lines.push("## 🤖 AI Security Analysis");
    lines.push("");

    if (result.ai_analysis.risk_level) {
      lines.push(`**Overall Risk Level:** ${result.ai_analysis.risk_level.toUpperCase()}`);
      lines.push("");
    }

    if (result.ai_analysis.executive_summary) {
      lines.push("### Executive Summary");
      lines.push("");
      lines.push(result.ai_analysis.executive_summary);
      lines.push("");
    }

    if (result.ai_analysis.key_findings && result.ai_analysis.key_findings.length > 0) {
      lines.push("### Key Findings");
      lines.push("");
      result.ai_analysis.key_findings.forEach((finding: any, i: number) => {
        lines.push(`#### ${i + 1}. ${finding.finding} [${finding.severity?.toUpperCase()}]`);
        lines.push("");
        if (finding.description) lines.push(finding.description);
        if (finding.impact) lines.push(`\n**Impact:** ${finding.impact}`);
        if (finding.recommendation) lines.push(`\n**Recommendation:** ${finding.recommendation}`);
        lines.push("");
      });
    }
  }

  // Footer
  lines.push("---");
  lines.push("");
  lines.push("*Report generated by VRAgent DNS Reconnaissance Tool*");
  lines.push("");

  return lines.join("\n");
}

/**
 * Generate PDF report from DNS reconnaissance results
 */
function generateDNSPDF(result: DNSReconResult): void {
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  const contentWidth = pageWidth - 2 * margin;
  let y = margin;

  // Helper functions
  const addPage = () => {
    doc.addPage();
    y = margin;
  };

  const checkPageBreak = (height: number) => {
    if (y + height > pageHeight - margin) {
      addPage();
    }
  };

  const addTitle = (text: string, size: number = 20, color: [number, number, number] = [0, 100, 200]) => {
    checkPageBreak(15);
    doc.setFontSize(size);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(color[0], color[1], color[2]);
    doc.text(text, margin, y);
    y += size * 0.5 + 5;
  };

  const addSubtitle = (text: string, size: number = 14) => {
    checkPageBreak(12);
    doc.setFontSize(size);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(60, 60, 60);
    doc.text(text, margin, y);
    y += size * 0.4 + 4;
  };

  const addText = (text: string, size: number = 10, bold: boolean = false) => {
    doc.setFontSize(size);
    doc.setFont("helvetica", bold ? "bold" : "normal");
    doc.setTextColor(40, 40, 40);
    const lines = doc.splitTextToSize(text, contentWidth);
    lines.forEach((line: string) => {
      checkPageBreak(size * 0.4 + 2);
      doc.text(line, margin, y);
      y += size * 0.4 + 2;
    });
  };

  const addBullet = (text: string, indent: number = 5) => {
    checkPageBreak(8);
    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(40, 40, 40);
    const lines = doc.splitTextToSize(text, contentWidth - indent - 5);
    doc.text("•", margin + indent, y);
    lines.forEach((line: string, i: number) => {
      doc.text(line, margin + indent + 5, y);
      y += 5;
    });
  };

  const addKeyValue = (key: string, value: string) => {
    checkPageBreak(8);
    doc.setFontSize(10);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(60, 60, 60);
    doc.text(key + ":", margin, y);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(40, 40, 40);
    doc.text(value, margin + 50, y);
    y += 6;
  };

  // Title
  addTitle(`DNS Reconnaissance Report`, 22, [0, 80, 180]);
  addTitle(result.domain, 18, [0, 120, 200]);
  y += 5;

  // Metadata
  doc.setFontSize(9);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(100, 100, 100);
  doc.text(`Generated: ${new Date().toLocaleString()}`, margin, y);
  y += 5;
  doc.text(`Scan Duration: ${result.scan_duration_seconds.toFixed(2)} seconds`, margin, y);
  y += 10;

  // Executive Summary Box
  doc.setFillColor(240, 248, 255);
  doc.rect(margin, y, contentWidth, 45, "F");
  doc.setDrawColor(0, 100, 200);
  doc.rect(margin, y, contentWidth, 45, "S");
  y += 8;

  doc.setFontSize(12);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(0, 80, 160);
  doc.text("Executive Summary", margin + 5, y);
  y += 8;

  doc.setFontSize(10);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(40, 40, 40);
  doc.text(`DNS Records: ${result.total_records}`, margin + 5, y);
  doc.text(`Subdomains: ${result.total_subdomains}`, margin + 70, y);
  doc.text(`Unique IPs: ${result.unique_ips.length}`, margin + 130, y);
  y += 7;
  doc.text(`Nameservers: ${result.nameservers.length}`, margin + 5, y);
  doc.text(`Mail Servers: ${result.mail_servers.length}`, margin + 70, y);
  y += 7;

  // Zone Transfer Status
  if (result.zone_transfer_possible) {
    doc.setTextColor(220, 38, 38);
    doc.setFont("helvetica", "bold");
    doc.text("⚠ ZONE TRANSFER VULNERABLE", margin + 5, y);
  } else {
    doc.setTextColor(34, 197, 94);
    doc.text("✓ Zone Transfer Protected", margin + 5, y);
  }

  // Mail Security Score
  if (result.security) {
    doc.setTextColor(40, 40, 40);
    doc.setFont("helvetica", "normal");
    doc.text(`Mail Security: ${result.security.mail_security_score}/100`, margin + 100, y);
  }
  y += 15;

  // Email Security Section
  if (result.security) {
    addSubtitle("Email Security Analysis");

    const securityItems = [
      { name: "SPF", status: result.security.has_spf, detail: result.security.spf_record },
      { name: "DMARC", status: result.security.has_dmarc, detail: result.security.dmarc_record },
      { name: "DKIM", status: result.security.has_dkim, detail: result.security.dkim_selectors_found?.join(", ") },
      { name: "DNSSEC", status: result.security.has_dnssec, detail: result.security.dnssec_details },
      { name: "CAA", status: result.security.has_caa, detail: result.security.caa_records?.join(", ") },
    ];

    securityItems.forEach(item => {
      checkPageBreak(8);
      doc.setFontSize(10);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(item.status ? 34 : 220, item.status ? 197 : 38, item.status ? 94 : 38);
      doc.text(item.status ? "✓" : "✗", margin, y);
      doc.setTextColor(60, 60, 60);
      doc.text(item.name + ":", margin + 8, y);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(80, 80, 80);
      const detail = item.detail ? (item.detail.length > 60 ? item.detail.substring(0, 57) + "..." : item.detail) : "Not configured";
      doc.text(detail, margin + 35, y);
      y += 6;
    });
    y += 5;

    // Security Issues
    if (result.security.overall_issues && result.security.overall_issues.length > 0) {
      addSubtitle("Security Issues", 12);
      result.security.overall_issues.forEach(issue => {
        addBullet(issue);
      });
      y += 5;
    }
  }

  // DNS Records Section
  addSubtitle("DNS Records");
  if (result.records && result.records.length > 0) {
    result.records.slice(0, 30).forEach(record => {
      checkPageBreak(6);
      doc.setFontSize(9);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(0, 100, 200);
      doc.text(record.record_type, margin, y);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(60, 60, 60);
      const value = record.value.length > 80 ? record.value.substring(0, 77) + "..." : record.value;
      doc.text(value, margin + 20, y);
      y += 5;
    });
    if (result.records.length > 30) {
      addText(`... and ${result.records.length - 30} more records`);
    }
  }
  y += 5;

  // Subdomains Section
  if (result.subdomains && result.subdomains.length > 0) {
    addSubtitle("Subdomains Found");
    addText(`Total: ${result.total_subdomains} subdomains discovered`);
    y += 3;

    result.subdomains.slice(0, 25).forEach(sub => {
      checkPageBreak(6);
      doc.setFontSize(9);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(40, 40, 40);
      const ips = sub.ip_addresses?.slice(0, 2).join(", ") || "No IP";
      doc.text(`• ${sub.full_domain} → ${ips}`, margin, y);
      y += 5;
    });
    if (result.subdomains.length > 25) {
      addText(`... and ${result.subdomains.length - 25} more subdomains`);
    }
    y += 5;
  }

  // Takeover Risks Section
  if (result.takeover_risks && result.takeover_risks.length > 0) {
    addSubtitle("⚠ Subdomain Takeover Risks", 14);
    result.takeover_risks.forEach(risk => {
      checkPageBreak(10);
      doc.setFontSize(10);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(risk.is_vulnerable ? 220 : 245, risk.is_vulnerable ? 38 : 158, risk.is_vulnerable ? 38 : 11);
      doc.text(`${risk.subdomain} [${risk.risk_level.toUpperCase()}]`, margin, y);
      y += 5;
      doc.setFont("helvetica", "normal");
      doc.setTextColor(80, 80, 80);
      doc.setFontSize(9);
      doc.text(`→ ${risk.cname_target} (${risk.provider})`, margin + 5, y);
      y += 6;
    });
    y += 5;
  }

  // Footer
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    doc.text(`Page ${i} of ${totalPages}`, pageWidth / 2, pageHeight - 10, { align: "center" });
    doc.text("Generated by VRAgent DNS Reconnaissance", pageWidth / 2, pageHeight - 5, { align: "center" });
  }

  // Save
  doc.save(`dns-report-${result.domain}-${new Date().toISOString().split("T")[0]}.pdf`);
}

/**
 * Generate Word document from DNS reconnaissance results
 */
async function generateDNSWord(result: DNSReconResult): Promise<void> {
  const children: (Paragraph | DocxTable)[] = [];
  const timestamp = new Date().toLocaleString();

  // Title
  children.push(
    new Paragraph({
      children: [
        new TextRun({ text: "DNS Reconnaissance Report", bold: true, size: 48, color: "0066CC" }),
      ],
      heading: HeadingLevel.TITLE,
      spacing: { after: 200 },
    }),
    new Paragraph({
      children: [
        new TextRun({ text: result.domain, bold: true, size: 36, color: "0088DD" }),
      ],
      spacing: { after: 400 },
    }),
    new Paragraph({
      children: [
        new TextRun({ text: `Generated: ${timestamp}`, italics: true, size: 20, color: "666666" }),
      ],
      spacing: { after: 100 },
    }),
    new Paragraph({
      children: [
        new TextRun({ text: `Scan Duration: ${result.scan_duration_seconds.toFixed(2)} seconds`, italics: true, size: 20, color: "666666" }),
      ],
      spacing: { after: 400 },
    })
  );

  // Executive Summary
  children.push(
    new Paragraph({
      children: [new TextRun({ text: "Executive Summary", bold: true, size: 32, color: "0066CC" })],
      heading: HeadingLevel.HEADING_1,
      spacing: { before: 400, after: 200 },
    })
  );

  // Summary Table
  const summaryRows = [
    new DocxTableRow({
      children: [
        new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "Metric", bold: true })] })], width: { size: 40, type: WidthType.PERCENTAGE } }),
        new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "Value", bold: true })] })], width: { size: 60, type: WidthType.PERCENTAGE } }),
      ],
      tableHeader: true,
    }),
    new DocxTableRow({
      children: [
        new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "DNS Records" })] })] }),
        new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: `${result.total_records}`, bold: true })] })] }),
      ],
    }),
    new DocxTableRow({
      children: [
        new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "Subdomains Found" })] })] }),
        new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: `${result.total_subdomains}`, bold: true })] })] }),
      ],
    }),
    new DocxTableRow({
      children: [
        new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "Unique IPs" })] })] }),
        new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: `${result.unique_ips.length}`, bold: true })] })] }),
      ],
    }),
    new DocxTableRow({
      children: [
        new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "Zone Transfer" })] })] }),
        new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: result.zone_transfer_possible ? "⚠️ VULNERABLE" : "✅ Protected", bold: true, color: result.zone_transfer_possible ? "DC2626" : "22C55E" })] })] }),
      ],
    }),
  ];

  if (result.security) {
    summaryRows.push(
      new DocxTableRow({
        children: [
          new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "Mail Security Score" })] })] }),
          new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: `${result.security.mail_security_score}/100`, bold: true })] })] }),
        ],
      })
    );
  }

  children.push(
    new DocxTable({
      rows: summaryRows,
      width: { size: 100, type: WidthType.PERCENTAGE },
    })
  );

  // Zone Transfer Warning
  if (result.zone_transfer_possible) {
    children.push(
      new Paragraph({
        children: [
          new TextRun({ text: "⚠️ CRITICAL: Zone Transfer Vulnerability Detected!", bold: true, size: 24, color: "DC2626" }),
        ],
        spacing: { before: 300, after: 100 },
        shading: { fill: "FEE2E2" },
      }),
      new Paragraph({
        children: [
          new TextRun({ text: "This domain allows DNS zone transfers (AXFR), exposing all DNS records to attackers. This is a serious misconfiguration that should be fixed immediately.", color: "991B1B" }),
        ],
        spacing: { after: 300 },
        shading: { fill: "FEE2E2" },
      })
    );
  }

  // Email Security Section
  if (result.security) {
    children.push(
      new Paragraph({
        children: [new TextRun({ text: "Email Security Analysis", bold: true, size: 32, color: "0066CC" })],
        heading: HeadingLevel.HEADING_1,
        spacing: { before: 400, after: 200 },
      }),
      new Paragraph({
        children: [
          new TextRun({ text: "Mail Security Score: ", bold: true }),
          new TextRun({ text: `${result.security.mail_security_score}/100`, bold: true, size: 28, color: result.security.mail_security_score >= 70 ? "22C55E" : result.security.mail_security_score >= 40 ? "F59E0B" : "DC2626" }),
        ],
        spacing: { after: 200 },
      })
    );

    // Security Controls
    const controls = [
      { name: "SPF", status: result.security.has_spf, detail: result.security.spf_record || "Not configured" },
      { name: "DMARC", status: result.security.has_dmarc, detail: result.security.dmarc_record || "Not configured" },
      { name: "DKIM", status: result.security.has_dkim, detail: result.security.dkim_selectors_found?.join(", ") || "Not found" },
      { name: "DNSSEC", status: result.security.has_dnssec, detail: result.security.dnssec_details || "Not enabled" },
      { name: "CAA", status: result.security.has_caa, detail: result.security.caa_records?.join(", ") || "Not configured" },
      { name: "BIMI", status: result.security.has_bimi, detail: result.security.bimi_record || "Not configured" },
      { name: "MTA-STS", status: result.security.has_mta_sts, detail: result.security.mta_sts_record || "Not configured" },
    ];

    controls.forEach(ctrl => {
      children.push(
        new Paragraph({
          children: [
            new TextRun({ text: ctrl.status ? "✅ " : "❌ ", color: ctrl.status ? "22C55E" : "DC2626" }),
            new TextRun({ text: ctrl.name + ": ", bold: true }),
            new TextRun({ text: ctrl.detail.length > 80 ? ctrl.detail.substring(0, 77) + "..." : ctrl.detail, font: "Courier New", size: 18 }),
          ],
          spacing: { after: 100 },
        })
      );
    });

    // Security Issues
    if (result.security.overall_issues && result.security.overall_issues.length > 0) {
      children.push(
        new Paragraph({
          children: [new TextRun({ text: "Security Issues", bold: true, size: 26, color: "DC2626" })],
          heading: HeadingLevel.HEADING_2,
          spacing: { before: 300, after: 150 },
        })
      );
      result.security.overall_issues.forEach(issue => {
        children.push(
          new Paragraph({
            children: [new TextRun({ text: `• ${issue}` })],
            indent: { left: 300 },
            spacing: { after: 80 },
          })
        );
      });
    }

    // Recommendations
    if (result.security.recommendations && result.security.recommendations.length > 0) {
      children.push(
        new Paragraph({
          children: [new TextRun({ text: "💡 Recommendations", bold: true, size: 26, color: "0066CC" })],
          heading: HeadingLevel.HEADING_2,
          spacing: { before: 300, after: 150 },
        })
      );
      result.security.recommendations.forEach(rec => {
        children.push(
          new Paragraph({
            children: [new TextRun({ text: `• ${rec}` })],
            indent: { left: 300 },
            spacing: { after: 80 },
          })
        );
      });
    }
  }

  // DNS Records Section
  children.push(
    new Paragraph({
      children: [new TextRun({ text: "DNS Records", bold: true, size: 32, color: "0066CC" })],
      heading: HeadingLevel.HEADING_1,
      spacing: { before: 400, after: 200 },
    }),
    new Paragraph({
      children: [new TextRun({ text: `Total: ${result.total_records} records found` })],
      spacing: { after: 200 },
    })
  );

  if (result.records && result.records.length > 0) {
    const recordRows = [
      new DocxTableRow({
        children: [
          new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "Type", bold: true })] })], width: { size: 15, type: WidthType.PERCENTAGE } }),
          new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "Name", bold: true })] })], width: { size: 25, type: WidthType.PERCENTAGE } }),
          new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "Value", bold: true })] })], width: { size: 45, type: WidthType.PERCENTAGE } }),
          new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "TTL", bold: true })] })], width: { size: 15, type: WidthType.PERCENTAGE } }),
        ],
        tableHeader: true,
      }),
      ...result.records.slice(0, 50).map(record =>
        new DocxTableRow({
          children: [
            new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: record.record_type, bold: true, color: "0066CC" })] })] }),
            new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: record.name, font: "Courier New", size: 18 })] })] }),
            new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: record.value.length > 50 ? record.value.substring(0, 47) + "..." : record.value, font: "Courier New", size: 18 })] })] }),
            new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: `${record.ttl || "-"}` })] })] }),
          ],
        })
      ),
    ];

    children.push(
      new DocxTable({
        rows: recordRows,
        width: { size: 100, type: WidthType.PERCENTAGE },
      })
    );

    if (result.records.length > 50) {
      children.push(
        new Paragraph({
          children: [new TextRun({ text: `... and ${result.records.length - 50} more records`, italics: true, color: "666666" })],
          spacing: { before: 100 },
        })
      );
    }
  }

  // Subdomains Section
  if (result.subdomains && result.subdomains.length > 0) {
    children.push(
      new Paragraph({
        children: [new TextRun({ text: "Subdomains", bold: true, size: 32, color: "0066CC" })],
        heading: HeadingLevel.HEADING_1,
        spacing: { before: 400, after: 200 },
      }),
      new Paragraph({
        children: [new TextRun({ text: `Total: ${result.total_subdomains} subdomains discovered` })],
        spacing: { after: 200 },
      })
    );

    const subdomainRows = [
      new DocxTableRow({
        children: [
          new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "Subdomain", bold: true })] })], width: { size: 30, type: WidthType.PERCENTAGE } }),
          new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "IP Addresses", bold: true })] })], width: { size: 40, type: WidthType.PERCENTAGE } }),
          new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "CNAME", bold: true })] })], width: { size: 30, type: WidthType.PERCENTAGE } }),
        ],
        tableHeader: true,
      }),
      ...result.subdomains.slice(0, 50).map(sub =>
        new DocxTableRow({
          children: [
            new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: sub.full_domain, font: "Courier New", size: 18 })] })] }),
            new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: sub.ip_addresses?.join(", ") || "-", font: "Courier New", size: 18 })] })] }),
            new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: sub.cname || "-", font: "Courier New", size: 18 })] })] }),
          ],
        })
      ),
    ];

    children.push(
      new DocxTable({
        rows: subdomainRows,
        width: { size: 100, type: WidthType.PERCENTAGE },
      })
    );
  }

  // Takeover Risks Section
  if (result.takeover_risks && result.takeover_risks.length > 0) {
    children.push(
      new Paragraph({
        children: [new TextRun({ text: "⚠️ Subdomain Takeover Risks", bold: true, size: 32, color: "DC2626" })],
        heading: HeadingLevel.HEADING_1,
        spacing: { before: 400, after: 200 },
      })
    );

    result.takeover_risks.forEach(risk => {
      children.push(
        new Paragraph({
          children: [
            new TextRun({ text: risk.subdomain, bold: true }),
            new TextRun({ text: ` [${risk.risk_level.toUpperCase()}]`, bold: true, color: risk.risk_level === "critical" ? "DC2626" : "F59E0B" }),
            risk.is_vulnerable ? new TextRun({ text: " - VULNERABLE", bold: true, color: "DC2626" }) : new TextRun({ text: "" }),
          ],
          spacing: { before: 150, after: 50 },
        }),
        new Paragraph({
          children: [
            new TextRun({ text: "CNAME: ", bold: true }),
            new TextRun({ text: risk.cname_target, font: "Courier New", size: 18 }),
          ],
          indent: { left: 300 },
        }),
        new Paragraph({
          children: [
            new TextRun({ text: "Provider: ", bold: true }),
            new TextRun({ text: risk.provider }),
          ],
          indent: { left: 300 },
          spacing: { after: 150 },
        })
      );
    });
  }

  // Footer
  children.push(
    new Paragraph({
      children: [
        new TextRun({ text: "Report generated by VRAgent DNS Reconnaissance Tool", italics: true, size: 18, color: "999999" }),
      ],
      alignment: AlignmentType.CENTER,
      spacing: { before: 600 },
    })
  );

  // Create document
  const doc = new DocxDocument({
    sections: [{
      properties: {},
      children: children,
    }],
  });

  // Save
  const blob = await Packer.toBlob(doc);
  saveAs(blob, `dns-report-${result.domain}-${new Date().toISOString().split("T")[0]}.docx`);
}

// Network graph component
function DNSNetworkGraph({ result }: { result: DNSReconResult }) {
  const theme = useTheme();
  const graphRef = useRef<any>();
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 500 });
  
  // Update dimensions on resize
  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        const { width } = containerRef.current.getBoundingClientRect();
        setDimensions({ width: width || 800, height: 500 });
      }
    };
    
    updateDimensions();
    window.addEventListener("resize", updateDimensions);
    return () => window.removeEventListener("resize", updateDimensions);
  }, []);
  
  // Build graph data
  const graphData = useMemo(() => {
    const nodes: Array<{ id: string; name: string; type: string; color: string; size: number }> = [];
    const links: Array<{ source: string; target: string; label?: string }> = [];
    const nodeSet = new Set<string>();
    
    // Add domain as central node
    const domainId = `domain:${result.domain}`;
    nodes.push({
      id: domainId,
      name: result.domain,
      type: "domain",
      color: "#f59e0b",
      size: 20,
    });
    nodeSet.add(domainId);
    
    // Add nameservers
    result.nameservers.forEach((ns) => {
      const nsId = `ns:${ns}`;
      if (!nodeSet.has(nsId)) {
        nodes.push({
          id: nsId,
          name: ns,
          type: "nameserver",
          color: "#f59e0b",
          size: 12,
        });
        nodeSet.add(nsId);
      }
      links.push({ source: domainId, target: nsId, label: "NS" });
    });
    
    // Add mail servers
    result.mail_servers.forEach((mx) => {
      const mxId = `mx:${mx.server}`;
      if (!nodeSet.has(mxId)) {
        nodes.push({
          id: mxId,
          name: mx.server,
          type: "mail",
          color: "#8b5cf6",
          size: 12,
        });
        nodeSet.add(mxId);
      }
      links.push({ source: domainId, target: mxId, label: `MX:${mx.priority}` });
    });
    
    // Add IPs from main domain
    result.records
      .filter((r) => r.record_type === "A" || r.record_type === "AAAA")
      .forEach((record) => {
        const ipId = `ip:${record.value}`;
        if (!nodeSet.has(ipId)) {
          nodes.push({
            id: ipId,
            name: record.value,
            type: "ip",
            color: "#10b981",
            size: 10,
          });
          nodeSet.add(ipId);
        }
        links.push({ source: domainId, target: ipId, label: record.record_type });
      });
    
    // Add subdomains (limit to 30 for performance)
    result.subdomains.slice(0, 30).forEach((sub) => {
      const subId = `subdomain:${sub.full_domain}`;
      if (!nodeSet.has(subId)) {
        nodes.push({
          id: subId,
          name: sub.subdomain,
          type: "subdomain",
          color: "#3b82f6",
          size: 8,
        });
        nodeSet.add(subId);
        links.push({ source: domainId, target: subId });
      }
      
      // Add IPs for subdomain
      sub.ip_addresses.forEach((ip) => {
        const ipId = `ip:${ip}`;
        if (!nodeSet.has(ipId)) {
          nodes.push({
            id: ipId,
            name: ip,
            type: "ip",
            color: "#10b981",
            size: 10,
          });
          nodeSet.add(ipId);
        }
        links.push({ source: subId, target: ipId });
      });
      
      // Add CNAME
      if (sub.cname) {
        const cnameId = `cname:${sub.cname}`;
        if (!nodeSet.has(cnameId)) {
          nodes.push({
            id: cnameId,
            name: sub.cname,
            type: "cname",
            color: "#6366f1",
            size: 8,
          });
          nodeSet.add(cnameId);
        }
        links.push({ source: subId, target: cnameId, label: "CNAME" });
      }
    });
    
    return { nodes, links };
  }, [result]);
  
  // Zoom to fit on load
  useEffect(() => {
    if (graphRef.current && graphData.nodes.length > 0) {
      setTimeout(() => {
        graphRef.current?.zoomToFit(400, 50);
      }, 500);
    }
  }, [graphData, dimensions]);
  
  return (
    <Box 
      ref={containerRef}
      sx={{ height: 500, border: `1px solid ${alpha(theme.palette.divider, 0.2)}`, borderRadius: 2, overflow: "hidden", position: "relative" }}
    >
      {dimensions.width > 0 && (
        <ForceGraph2D
          ref={graphRef}
          graphData={graphData}
          nodeLabel={(node: any) => `${node.type}: ${node.name}`}
          nodeColor={(node: any) => node.color}
          nodeVal={(node: any) => node.size}
          linkColor={() => alpha(theme.palette.text.primary, 0.2)}
          linkWidth={1}
          linkDirectionalParticles={1}
          linkDirectionalParticleWidth={2}
          nodeCanvasObject={(node: any, ctx, globalScale) => {
            const label = node.name.length > 20 ? node.name.slice(0, 18) + "..." : node.name;
            const fontSize = Math.max(10 / globalScale, 3);
            ctx.font = `${fontSize}px Sans-Serif`;
            
            // Draw node
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.size / 2, 0, 2 * Math.PI);
            ctx.fillStyle = node.color;
            ctx.fill();
            
            // Draw label
            ctx.fillStyle = theme.palette.text.primary;
            ctx.textAlign = "center";
            ctx.textBaseline = "top";
            ctx.fillText(label, node.x, node.y + node.size / 2 + 2);
          }}
          backgroundColor="transparent"
          width={dimensions.width}
          height={dimensions.height}
        />
      )}
      
      {/* Legend */}
      <Box sx={{ position: "absolute", bottom: 16, left: 16, display: "flex", gap: 2, flexWrap: "wrap", bgcolor: alpha(theme.palette.background.paper, 0.9), p: 1, borderRadius: 1 }}>
        {[
          { type: "Domain", color: "#f59e0b" },
          { type: "Subdomain", color: "#3b82f6" },
          { type: "IP", color: "#10b981" },
          { type: "Mail", color: "#8b5cf6" },
          { type: "NS", color: "#f59e0b" },
          { type: "CNAME", color: "#6366f1" },
        ].map((item) => (
          <Box key={item.type} sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <Box sx={{ width: 12, height: 12, borderRadius: "50%", bgcolor: item.color }} />
            <Typography variant="caption">{item.type}</Typography>
          </Box>
        ))}
      </Box>
    </Box>
  );
}

export default function DNSAnalyzerPage() {
  const theme = useTheme();
  
  // State
  const [activeTab, setActiveTab] = useState(0);
  const [domain, setDomain] = useState("");
  const [domainValid, setDomainValid] = useState<boolean | null>(null);
  const [domainError, setDomainError] = useState<string | null>(null);
  const [scanTypes, setScanTypes] = useState<DNSScanType[]>([]);
  const [selectedScanType, setSelectedScanType] = useState("standard");
  const [customSubdomains, setCustomSubdomains] = useState("");
  const [scanTitle, setScanTitle] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<DNSReconResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  // Progress state
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const scanControllerRef = useRef<AbortController | null>(null);
  
  // Snackbar for copy feedback
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string }>({ open: false, message: "" });
  
  // Saved reports
  const [savedReports, setSavedReports] = useState<SavedDNSReport[]>([]);
  const [savedReportsTotal, setSavedReportsTotal] = useState(0);
  const [loadingReports, setLoadingReports] = useState(false);
  
  // AI Chat
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMaximized, setChatMaximized] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);
  
  // Graph view
  const [showGraph, setShowGraph] = useState(false);

  // WHOIS Lookup state
  const [whoisTarget, setWhoisTarget] = useState("");
  const [whoisType, setWhoisType] = useState<"domain" | "ip">("domain");
  const [whoisLoading, setWhoisLoading] = useState(false);
  const [whoisDomainResult, setWhoisDomainResult] = useState<WhoisDomainResult | null>(null);
  const [whoisIPResult, setWhoisIPResult] = useState<WhoisIPResult | null>(null);
  const [whoisError, setWhoisError] = useState<string | null>(null);
  const [showRawWhois, setShowRawWhois] = useState(false);

  // Load scan types on mount
  useEffect(() => {
    const loadScanTypes = async () => {
      try {
        const types = await apiClient.getDnsScanTypes();
        setScanTypes(types);
      } catch (err) {
        console.error("Failed to load scan types:", err);
      }
    };
    loadScanTypes();
  }, []);

  // Load saved reports when tab changes
  const loadSavedReports = useCallback(async () => {
    setLoadingReports(true);
    try {
      const response = await apiClient.getDnsReports(0, 20);
      setSavedReports(response.reports);
      setSavedReportsTotal(response.total);
    } catch (err) {
      console.error("Failed to load reports:", err);
    } finally {
      setLoadingReports(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === 1) {
      loadSavedReports();
    }
  }, [activeTab, loadSavedReports]);

  // Auto-scroll chat to bottom when new messages arrive
  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [chatMessages]);

  // Validate domain
  const validateDomain = async (value: string) => {
    if (!value.trim()) {
      setDomainValid(null);
      setDomainError(null);
      return;
    }
    try {
      const result = await apiClient.validateDomain(value);
      setDomainValid(result.valid);
      setDomainError(result.error || null);
    } catch {
      setDomainValid(false);
      setDomainError("Validation failed");
    }
  };

  useEffect(() => {
    const timeout = setTimeout(() => {
      if (domain) validateDomain(domain);
    }, 500);
    return () => clearTimeout(timeout);
  }, [domain]);

  // Run scan with streaming progress
  const handleRunScan = () => {
    if (!domainValid || !domain.trim()) return;
    
    setScanning(true);
    setError(null);
    setResult(null);
    setChatMessages([]);
    setProgress({ phase: "starting", progress: 0, message: "Starting scan..." });
    
    const customSubs = customSubdomains
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    scanControllerRef.current = apiClient.runDnsScanWithProgress(
      {
        domain: domain.trim(),
        scan_type: selectedScanType,
        custom_subdomains: customSubs.length > 0 ? customSubs : undefined,
        save_report: true,
        report_title: scanTitle || undefined,
        run_ai_analysis: true,
      },
      // Progress callback
      (phase, progressValue, message) => {
        setProgress({ phase, progress: progressValue, message });
      },
      // Result callback
      (scanResult) => {
        setResult(scanResult);
        setScanning(false);
        setProgress(null);
        scanControllerRef.current = null;
      },
      // Error callback
      (errorMessage) => {
        setError(errorMessage);
        setScanning(false);
        setProgress(null);
        scanControllerRef.current = null;
      }
    );
  };

  // Cancel scan
  const handleCancelScan = () => {
    if (scanControllerRef.current) {
      scanControllerRef.current.abort();
      scanControllerRef.current = null;
      setScanning(false);
      setProgress(null);
      setError("Scan cancelled");
    }
  };

  // Load saved report
  const handleLoadReport = async (reportId: number) => {
    setScanning(true);
    setError(null);
    try {
      const report = await apiClient.getDnsReport(reportId);
      setResult(report);
      setActiveTab(0);
    } catch (err: any) {
      setError(err.message || "Failed to load report");
    } finally {
      setScanning(false);
    }
  };

  // Delete report
  const handleDeleteReport = async (reportId: number) => {
    try {
      await apiClient.deleteDnsReport(reportId);
      loadSavedReports();
    } catch (err) {
      console.error("Failed to delete report:", err);
    }
  };

  // Copy all data
  const handleCopyAll = async (dataType: "records" | "subdomains" | "ips") => {
    if (!result) return;
    
    let text = "";
    if (dataType === "records") {
      text = (result.records || []).map((r) => `${r.record_type}\t${r.name}\t${r.value}`).join("\n");
    } else if (dataType === "subdomains") {
      text = (result.subdomains || []).map((s) => s.full_domain).join("\n");
    } else if (dataType === "ips") {
      text = (result.unique_ips || []).join("\n");
    }
    
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Fallback for older browsers
      const textarea = document.createElement("textarea");
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
    }
    setSnackbar({ open: true, message: `Copied ${dataType} to clipboard!` });
  };

  // AI Chat
  const handleSendChat = async () => {
    if (!chatInput.trim() || !result || chatLoading) return;
    
    const userMessage = chatInput.trim();
    setChatInput("");
    setChatMessages((prev) => [...prev, { role: "user", content: userMessage }]);
    setChatLoading(true);
    setChatError(null);
    
    try {
      const response = await apiClient.chatAboutDns(
        userMessage,
        {
          domain: result.domain,
          total_records: result.total_records,
          total_subdomains: result.total_subdomains,
          nameservers: result.nameservers,
          mail_servers: result.mail_servers,
          zone_transfer_possible: result.zone_transfer_possible,
          security: result.security,
          subdomains: result.subdomains.slice(0, 20),
          unique_ips: result.unique_ips.slice(0, 20),
          ai_analysis: result.ai_analysis,
          // Advanced reconnaissance data
          takeover_risks: result.takeover_risks?.slice(0, 10),
          dangling_cnames: result.dangling_cnames?.slice(0, 10),
          cloud_providers: result.cloud_providers?.slice(0, 10),
          asn_info: result.asn_info?.slice(0, 10),
          has_wildcard: result.has_wildcard,
          infrastructure_summary: result.infrastructure_summary,
        },
        chatMessages.map((m) => ({ role: m.role, content: m.content }))
      );
      
      setChatMessages((prev) => [
        ...prev,
        { role: "assistant", content: response.response },
      ]);
    } catch (err: any) {
      setChatError(err.message || "Failed to send message");
    } finally {
      setChatLoading(false);
    }
  };

  // Handle Enter key in chat
  const handleChatKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendChat();
    }
  };

  // WHOIS Lookup handler
  const handleWhoisLookup = async () => {
    if (!whoisTarget.trim()) return;
    
    setWhoisLoading(true);
    setWhoisError(null);
    setWhoisDomainResult(null);
    setWhoisIPResult(null);
    
    try {
      if (whoisType === "domain") {
        const result = await apiClient.whoisDomain(whoisTarget.trim());
        if (result.error) {
          setWhoisError(result.error);
        } else {
          setWhoisDomainResult(result);
        }
      } else {
        const result = await apiClient.whoisIP(whoisTarget.trim());
        if (result.error) {
          setWhoisError(result.error);
        } else {
          setWhoisIPResult(result);
        }
      }
    } catch (err: any) {
      setWhoisError(err.message || "WHOIS lookup failed");
    } finally {
      setWhoisLoading(false);
    }
  };

  // Copy WHOIS data to clipboard
  const handleCopyWhoisData = async () => {
    let text = "";
    if (whoisDomainResult) {
      text = `Domain: ${whoisDomainResult.domain}\n`;
      if (whoisDomainResult.registrar) text += `Registrar: ${whoisDomainResult.registrar}\n`;
      if (whoisDomainResult.creation_date) text += `Created: ${whoisDomainResult.creation_date}\n`;
      if (whoisDomainResult.expiration_date) text += `Expires: ${whoisDomainResult.expiration_date}\n`;
      if (whoisDomainResult.registrant_organization) text += `Organization: ${whoisDomainResult.registrant_organization}\n`;
      if ((whoisDomainResult.name_servers || []).length) text += `Name Servers: ${whoisDomainResult.name_servers.join(", ")}\n`;
    } else if (whoisIPResult) {
      text = `IP: ${whoisIPResult.ip_address}\n`;
      if (whoisIPResult.organization) text += `Organization: ${whoisIPResult.organization}\n`;
      if (whoisIPResult.network_name) text += `Network: ${whoisIPResult.network_name}\n`;
      if (whoisIPResult.cidr) text += `CIDR: ${whoisIPResult.cidr}\n`;
      if (whoisIPResult.asn) text += `ASN: ${whoisIPResult.asn}\n`;
      if (whoisIPResult.country) text += `Country: ${whoisIPResult.country}\n`;
    }
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Fallback for older browsers
      const textarea = document.createElement("textarea");
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
    }
    setSnackbar({ open: true, message: "WHOIS data copied to clipboard!" });
  };

  return (
    <Container maxWidth="xl" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Breadcrumbs separator={<NavigateNextIcon fontSize="small" />} sx={{ mb: 2 }}>
          <MuiLink component={Link} to="/dynamic" color="inherit" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <HubIcon fontSize="small" />
            Network Analysis
          </MuiLink>
          <Typography color="text.primary" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <DnsIcon fontSize="small" />
            DNS Reconnaissance
          </Typography>
        </Breadcrumbs>
        
        <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
          DNS Reconnaissance
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Enumerate DNS records, discover subdomains, test zone transfers, and analyze email security (SPF, DMARC, DKIM).
        </Typography>
      </Box>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={activeTab}
          onChange={(_, v) => setActiveTab(v)}
          sx={{ borderBottom: 1, borderColor: "divider" }}
        >
          <Tab icon={<SearchIcon />} iconPosition="start" label="New Scan" />
          <Tab
            icon={<HistoryIcon />}
            iconPosition="start"
            label={`Saved Reports${savedReportsTotal > 0 ? ` (${savedReportsTotal})` : ""}`}
          />
          <Tab icon={<ManageSearchIcon />} iconPosition="start" label="WHOIS Lookup" />
        </Tabs>
      </Paper>

      {/* Tab 0: New Scan */}
      {activeTab === 0 && (
        <>
          {/* Scan Configuration */}
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" sx={{ mb: 3, fontWeight: 600 }}>
              Scan Configuration
            </Typography>
            
            <Grid container spacing={3}>
              {/* Domain Input */}
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Target Domain"
                  placeholder="example.com"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  error={domainValid === false}
                  helperText={domainError || "Enter a domain name to scan"}
                  InputProps={{
                    startAdornment: <LanguageIcon sx={{ mr: 1, color: "text.secondary" }} />,
                    endAdornment: domainValid === true ? (
                      <Chip label="Valid" size="small" color="success" />
                    ) : null,
                  }}
                  disabled={scanning}
                />
              </Grid>

              {/* Scan Type */}
              <Grid item xs={12} md={6}>
                <FormControl fullWidth disabled={scanning}>
                  <InputLabel>Scan Type</InputLabel>
                  <Select
                    value={selectedScanType}
                    label="Scan Type"
                    onChange={(e) => setSelectedScanType(e.target.value)}
                  >
                    {scanTypes.map((type) => (
                      <MenuItem key={type.id} value={type.id}>
                        <Box sx={{ display: "flex", justifyContent: "space-between", width: "100%", alignItems: "center" }}>
                          <Box>
                            <Typography variant="body1" fontWeight={500}>{type.name}</Typography>
                            <Typography variant="caption" color="text.secondary">
                              {type.description}
                            </Typography>
                          </Box>
                          <Chip
                            label={type.estimated_time}
                            size="small"
                            variant="outlined"
                            sx={{ ml: 2, minWidth: 80 }}
                          />
                        </Box>
                      </MenuItem>
                    ))}
                  </Select>
                  <FormHelperText>
                    {scanTypes.find((t) => t.id === selectedScanType)?.description}
                  </FormHelperText>
                </FormControl>
              </Grid>

              {/* Custom Subdomains */}
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Custom Subdomains (optional)"
                  placeholder="api, dev, staging, admin..."
                  value={customSubdomains}
                  onChange={(e) => setCustomSubdomains(e.target.value)}
                  helperText="Comma-separated list of additional subdomains to check"
                  multiline
                  rows={2}
                  disabled={scanning}
                />
              </Grid>

              {/* Report Title */}
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Report Title (optional)"
                  placeholder="My DNS Scan"
                  value={scanTitle}
                  onChange={(e) => setScanTitle(e.target.value)}
                  helperText="Custom title for the saved report"
                  disabled={scanning}
                />
              </Grid>
            </Grid>

            {/* Scan Type Info */}
            {selectedScanType && !scanning && (
              <Alert severity="info" sx={{ mt: 3 }} icon={<DnsIcon />}>
                <Typography variant="body2">
                  <strong>{scanTypes.find((t) => t.id === selectedScanType)?.name}:</strong>{" "}
                  {scanTypes.find((t) => t.id === selectedScanType)?.description}
                  <br />
                  <Typography component="span" variant="caption" color="text.secondary">
                    Record types: {scanTypes.find((t) => t.id === selectedScanType)?.record_types.join(", ")}
                    {" • "}
                    Subdomains: {scanTypes.find((t) => t.id === selectedScanType)?.subdomain_count || "None"}
                    {" • "}
                    Security check: {scanTypes.find((t) => t.id === selectedScanType)?.check_security ? "Yes" : "No"}
                  </Typography>
                </Typography>
              </Alert>
            )}

            {/* Buttons */}
            <Box sx={{ mt: 3, display: "flex", gap: 2 }}>
              <Button
                variant="contained"
                size="large"
                onClick={handleRunScan}
                disabled={scanning || !domainValid || !domain.trim()}
                sx={{
                  py: 1.5,
                  px: 4,
                  background: `linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)`,
                  "&:hover": {
                    background: `linear-gradient(135deg, #0891b2 0%, #0e7490 100%)`,
                  },
                }}
                startIcon={scanning ? <CircularProgress size={20} color="inherit" /> : <PlayArrowIcon />}
              >
                {scanning ? "Scanning..." : "Start DNS Scan"}
              </Button>
              
              {scanning && (
                <Button
                  variant="outlined"
                  color="error"
                  size="large"
                  onClick={handleCancelScan}
                  startIcon={<StopIcon />}
                >
                  Cancel
                </Button>
              )}
            </Box>
          </Paper>

          {/* Error */}
          {error && (
            <Alert severity="error" sx={{ mb: 3 }}>
              {error}
            </Alert>
          )}

          {/* Scanning Progress */}
          {scanning && progress && (
            <Paper sx={{ p: 3, mb: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <CircularProgress size={24} />
                <Box sx={{ flex: 1 }}>
                  <Typography variant="h6">Scanning {domain}...</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {phaseLabels[progress.phase] || progress.phase}: {progress.message}
                  </Typography>
                </Box>
                <Typography variant="h6" sx={{ minWidth: 60, textAlign: "right" }}>
                  {progress.progress}%
                </Typography>
              </Box>
              
              <LinearProgress 
                variant="determinate" 
                value={progress.progress} 
                sx={{ 
                  height: 8, 
                  borderRadius: 4,
                  bgcolor: alpha(theme.palette.primary.main, 0.1),
                  "& .MuiLinearProgress-bar": {
                    borderRadius: 4,
                    background: `linear-gradient(90deg, #06b6d4 0%, #0891b2 50%, #0e7490 100%)`,
                  },
                }} 
              />
              
              {/* Phase indicators */}
              <Box sx={{ display: "flex", justifyContent: "space-between", mt: 2, flexWrap: "wrap", gap: 1 }}>
                {["records", "subdomains", "zone_transfer", "security", "ai_analysis"].map((phase) => {
                  const isActive = progress.phase === phase;
                  const phaseOrder = ["records", "subdomains", "zone_transfer", "security", "ai_analysis"];
                  const isPast = phaseOrder.indexOf(progress.phase) > phaseOrder.indexOf(phase);
                  return (
                    <Chip
                      key={phase}
                      label={phaseLabels[phase]}
                      size="small"
                      color={isActive ? "primary" : isPast ? "success" : "default"}
                      variant={isActive ? "filled" : "outlined"}
                      icon={isPast ? <CheckCircleIcon /> : undefined}
                    />
                  );
                })}
              </Box>
            </Paper>
          )}

          {/* Results */}
          {result && !scanning && (
            <Box>
              {/* Summary Cards */}
              <Grid container spacing={3} sx={{ mb: 3 }}>
                <Grid item xs={6} sm={3}>
                  <Card sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                    <CardContent sx={{ textAlign: "center" }}>
                      <StorageIcon sx={{ fontSize: 40, color: theme.palette.primary.main, mb: 1 }} />
                      <Typography variant="h4" fontWeight={700}>{result.total_records}</Typography>
                      <Typography variant="body2" color="text.secondary">DNS Records</Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Card sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                    <CardContent sx={{ textAlign: "center" }}>
                      <SubdirectoryArrowRightIcon sx={{ fontSize: 40, color: "#8b5cf6", mb: 1 }} />
                      <Typography variant="h4" fontWeight={700}>{result.total_subdomains}</Typography>
                      <Typography variant="body2" color="text.secondary">Subdomains Found</Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Card sx={{ bgcolor: alpha("#10b981", 0.1) }}>
                    <CardContent sx={{ textAlign: "center" }}>
                      <PublicIcon sx={{ fontSize: 40, color: "#10b981", mb: 1 }} />
                      <Typography variant="h4" fontWeight={700}>{result.unique_ips.length}</Typography>
                      <Typography variant="body2" color="text.secondary">Unique IPs</Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Card sx={{ bgcolor: result.zone_transfer_possible ? alpha("#dc2626", 0.1) : alpha("#22c55e", 0.1) }}>
                    <CardContent sx={{ textAlign: "center" }}>
                      {result.zone_transfer_possible ? (
                        <GppBadIcon sx={{ fontSize: 40, color: "#dc2626", mb: 1 }} />
                      ) : (
                        <GppGoodIcon sx={{ fontSize: 40, color: "#22c55e", mb: 1 }} />
                      )}
                      <Typography variant="h6" fontWeight={700}>
                        {result.zone_transfer_possible ? "VULNERABLE" : "Protected"}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">Zone Transfer</Typography>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>

              {/* Export Buttons */}
              <Paper sx={{ p: 2, mb: 3 }}>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 2 }}>
                  <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <DownloadIcon />
                    Export Report
                  </Typography>
                  <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                    <Button
                      variant="outlined"
                      startIcon={<DownloadIcon />}
                      onClick={() => {
                        const markdown = generateDNSMarkdown(result);
                        const blob = new Blob([markdown], { type: "text/markdown;charset=utf-8" });
                        saveAs(blob, `dns-report-${result.domain}-${new Date().toISOString().split("T")[0]}.md`);
                        setSnackbar({ open: true, message: "Markdown report downloaded!" });
                      }}
                      sx={{
                        borderColor: "#6366f1",
                        color: "#6366f1",
                        "&:hover": { borderColor: "#4f46e5", bgcolor: alpha("#6366f1", 0.1) },
                      }}
                    >
                      📝 Markdown
                    </Button>
                    <Button
                      variant="outlined"
                      startIcon={<DownloadIcon />}
                      onClick={() => {
                        generateDNSPDF(result);
                        setSnackbar({ open: true, message: "PDF report downloaded!" });
                      }}
                      sx={{
                        borderColor: "#dc2626",
                        color: "#dc2626",
                        "&:hover": { borderColor: "#b91c1c", bgcolor: alpha("#dc2626", 0.1) },
                      }}
                    >
                      📄 PDF
                    </Button>
                    <Button
                      variant="outlined"
                      startIcon={<DownloadIcon />}
                      onClick={async () => {
                        await generateDNSWord(result);
                        setSnackbar({ open: true, message: "Word document downloaded!" });
                      }}
                      sx={{
                        borderColor: "#2563eb",
                        color: "#2563eb",
                        "&:hover": { borderColor: "#1d4ed8", bgcolor: alpha("#2563eb", 0.1) },
                      }}
                    >
                      📃 Word
                    </Button>
                  </Box>
                </Box>
              </Paper>

              {/* Zone Transfer Warning */}
              {result.zone_transfer_possible && (
                <Alert severity="error" sx={{ mb: 3 }}>
                  <Typography variant="subtitle2" fontWeight={700}>⚠️ CRITICAL: Zone Transfer Allowed!</Typography>
                  <Typography variant="body2">
                    This domain allows DNS zone transfers (AXFR), exposing all DNS records to attackers.
                    This is a serious misconfiguration that should be fixed immediately.
                  </Typography>
                </Alert>
              )}

              {/* Network Graph Toggle */}
              <Paper sx={{ p: 2, mb: 3 }}>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <AccountTreeIcon />
                    DNS Network Graph
                  </Typography>
                  <Button
                    variant={showGraph ? "contained" : "outlined"}
                    onClick={() => setShowGraph(!showGraph)}
                    startIcon={<AccountTreeIcon />}
                  >
                    {showGraph ? "Hide Graph" : "Show Graph"}
                  </Button>
                </Box>
                
                {showGraph && (
                  <Box sx={{ mt: 2 }}>
                    <DNSNetworkGraph result={result} />
                  </Box>
                )}
              </Paper>

              {/* Email Security Score */}
              {result.security && (
                <Paper sx={{ p: 3, mb: 3 }}>
                  <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                    <EmailIcon />
                    Email Security Score
                  </Typography>
                  
                  <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
                    <Box sx={{ position: "relative", display: "inline-flex" }}>
                      <CircularProgress
                        variant="determinate"
                        value={result.security.mail_security_score}
                        size={100}
                        thickness={8}
                        sx={{
                          color: result.security.mail_security_score >= 70 ? "#22c55e" :
                                 result.security.mail_security_score >= 40 ? "#eab308" : "#dc2626"
                        }}
                      />
                      <Box
                        sx={{
                          position: "absolute",
                          top: 0, left: 0, bottom: 0, right: 0,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                        }}
                      >
                        <Typography variant="h5" fontWeight={700}>
                          {result.security.mail_security_score}
                        </Typography>
                      </Box>
                    </Box>
                    
                    <Box sx={{ flex: 1 }}>
                      <Grid container spacing={2}>
                        <Grid item xs={6} sm={3}>
                          <Chip
                            icon={result.security.has_spf ? <CheckCircleIcon /> : <ErrorIcon />}
                            label="SPF"
                            color={result.security.has_spf ? "success" : "error"}
                            variant={result.security.has_spf ? "filled" : "outlined"}
                          />
                        </Grid>
                        <Grid item xs={6} sm={3}>
                          <Chip
                            icon={result.security.has_dmarc ? <CheckCircleIcon /> : <ErrorIcon />}
                            label="DMARC"
                            color={result.security.has_dmarc ? "success" : "error"}
                            variant={result.security.has_dmarc ? "filled" : "outlined"}
                          />
                        </Grid>
                        <Grid item xs={6} sm={3}>
                          <Chip
                            icon={result.security.has_dkim ? <CheckCircleIcon /> : <ErrorIcon />}
                            label="DKIM"
                            color={result.security.has_dkim ? "success" : "error"}
                            variant={result.security.has_dkim ? "filled" : "outlined"}
                          />
                        </Grid>
                        <Grid item xs={6} sm={3}>
                          <Chip
                            icon={result.security.has_dnssec ? <CheckCircleIcon /> : <WarningIcon />}
                            label="DNSSEC"
                            color={result.security.has_dnssec ? "success" : "warning"}
                            variant={result.security.has_dnssec ? "filled" : "outlined"}
                          />
                        </Grid>
                      </Grid>
                    </Box>
                  </Box>

                  {/* Security Issues */}
                  {result.security.overall_issues.length > 0 && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600, color: "#dc2626" }}>
                        Issues Found:
                      </Typography>
                      <List dense>
                        {result.security.overall_issues.map((issue, i) => (
                          <ListItem key={i}>
                            <ListItemIcon sx={{ minWidth: 32 }}>
                              <WarningIcon fontSize="small" color="error" />
                            </ListItemIcon>
                            <ListItemText primary={issue} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}

                  {/* Recommendations */}
                  {result.security.recommendations.length > 0 && (
                    <Box>
                      <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600, color: "#3b82f6" }}>
                        Recommendations:
                      </Typography>
                      <List dense>
                        {result.security.recommendations.map((rec, i) => (
                          <ListItem key={i}>
                            <ListItemIcon sx={{ minWidth: 32 }}>
                              <InfoIcon fontSize="small" color="info" />
                            </ListItemIcon>
                            <ListItemText primary={rec} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}
                </Paper>
              )}

              {/* DNS Records */}
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, flex: 1 }}>
                    <Typography variant="h6" fontWeight={600}>
                      DNS Records ({result.total_records})
                    </Typography>
                    <Button
                      size="small"
                      startIcon={<ContentCopyIcon />}
                      onClick={(e) => {
                        e.stopPropagation();
                        handleCopyAll("records");
                      }}
                    >
                      Copy All
                    </Button>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Type</TableCell>
                          <TableCell>Name</TableCell>
                          <TableCell>Value</TableCell>
                          <TableCell>TTL</TableCell>
                          <TableCell>Priority</TableCell>
                          <TableCell width={50}></TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {result.records.map((record, i) => (
                          <TableRow key={i} hover>
                            <TableCell>
                              <Chip
                                label={record.record_type}
                                size="small"
                                sx={{
                                  bgcolor: alpha(recordTypeColors[record.record_type] || "#888", 0.15),
                                  color: recordTypeColors[record.record_type] || "#888",
                                  fontWeight: 700,
                                  fontFamily: "monospace",
                                }}
                              />
                            </TableCell>
                            <TableCell sx={{ fontFamily: "monospace" }}>{record.name}</TableCell>
                            <TableCell sx={{ fontFamily: "monospace", maxWidth: 400, wordBreak: "break-all" }}>
                              {record.value}
                            </TableCell>
                            <TableCell>{record.ttl || "-"}</TableCell>
                            <TableCell>{record.priority ?? "-"}</TableCell>
                            <TableCell>
                              <CopyButton text={record.value} />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              {/* Nameservers & Mail */}
              <Grid container spacing={3} sx={{ mt: 0 }}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2 }}>
                    <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                        <DnsIcon fontSize="small" />
                        Nameservers ({result.nameservers.length})
                      </Typography>
                      <CopyButton text={result.nameservers.join("\n")} />
                    </Box>
                    {result.nameservers.map((ns, i) => (
                      <Box key={i} sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 0.5 }}>
                        <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                          {ns}
                        </Typography>
                        <CopyButton text={ns} />
                      </Box>
                    ))}
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2 }}>
                    <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                        <EmailIcon fontSize="small" />
                        Mail Servers ({result.mail_servers.length})
                      </Typography>
                      <CopyButton text={result.mail_servers.map((mx) => mx.server).join("\n")} />
                    </Box>
                    {result.mail_servers.map((mx, i) => (
                      <Box key={i} sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 0.5 }}>
                        <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                          {mx.priority} {mx.server}
                        </Typography>
                        <CopyButton text={mx.server} />
                      </Box>
                    ))}
                  </Paper>
                </Grid>
              </Grid>

              {/* Unique IPs */}
              {result.unique_ips.length > 0 && (
                <Paper sx={{ p: 2, mt: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                      <PublicIcon fontSize="small" />
                      Unique IP Addresses ({result.unique_ips.length})
                    </Typography>
                    <Button
                      size="small"
                      startIcon={<ContentCopyIcon />}
                      onClick={() => handleCopyAll("ips")}
                    >
                      Copy All
                    </Button>
                  </Box>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {(result.unique_ips || []).map((ip, i) => (
                      <Chip
                        key={i}
                        label={ip}
                        size="small"
                        sx={{ fontFamily: "monospace" }}
                        onDelete={() => copyToClipboard(ip)}
                        deleteIcon={<ContentCopyIcon fontSize="small" />}
                      />
                    ))}
                  </Box>
                </Paper>
              )}

              {/* Subdomains */}
              {result.subdomains.length > 0 && (
                <Accordion sx={{ mt: 3 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, flex: 1 }}>
                      <Typography variant="h6" fontWeight={600}>
                        Subdomains Found ({result.total_subdomains})
                      </Typography>
                      <Button
                        size="small"
                        startIcon={<ContentCopyIcon />}
                        onClick={(e) => {
                          e.stopPropagation();
                          handleCopyAll("subdomains");
                        }}
                      >
                        Copy All
                      </Button>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TableContainer sx={{ maxHeight: 400 }}>
                      <Table size="small" stickyHeader>
                        <TableHead>
                          <TableRow>
                            <TableCell>Subdomain</TableCell>
                            <TableCell>IP Addresses</TableCell>
                            <TableCell>CNAME</TableCell>
                            <TableCell width={50}></TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {result.subdomains.map((sub, i) => (
                            <TableRow key={i} hover>
                              <TableCell sx={{ fontFamily: "monospace", fontWeight: 500 }}>
                                {sub.full_domain}
                              </TableCell>
                              <TableCell sx={{ fontFamily: "monospace" }}>
                                {sub.ip_addresses.join(", ") || "-"}
                              </TableCell>
                              <TableCell sx={{ fontFamily: "monospace" }}>
                                {sub.cname || "-"}
                              </TableCell>
                              <TableCell>
                                <CopyButton text={sub.full_domain} />
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* AI Analysis */}
              {result.ai_analysis && !result.ai_analysis.error && (
                <Accordion sx={{ mt: 3 }} defaultExpanded>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, flex: 1 }}>
                      <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <SmartToyIcon />
                        AI Security Analysis
                      </Typography>
                      {result.ai_analysis.risk_level && (
                        <Chip
                          label={result.ai_analysis.risk_level.toUpperCase()}
                          size="small"
                          sx={{
                            bgcolor: alpha(severityColors[result.ai_analysis.risk_level] || "#888", 0.15),
                            color: severityColors[result.ai_analysis.risk_level] || "#888",
                            fontWeight: 700,
                          }}
                        />
                      )}
                      {result.ai_analysis.overall_risk_score !== undefined && (
                        <Chip
                          label={`Risk Score: ${result.ai_analysis.overall_risk_score}/100`}
                          size="small"
                          variant="outlined"
                        />
                      )}
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    {/* Executive Summary */}
                    {result.ai_analysis.executive_summary && (
                      <Paper sx={{ p: 2, mb: 3, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
                        <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600 }}>📋 Executive Summary</Typography>
                        <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>{result.ai_analysis.executive_summary}</Typography>
                      </Paper>
                    )}

                    {/* Key Findings */}
                    {result.ai_analysis.key_findings && result.ai_analysis.key_findings.length > 0 && (
                      <Box sx={{ mb: 3 }}>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600 }}>🔍 Key Findings</Typography>
                        {result.ai_analysis.key_findings.map((finding: any, i: number) => (
                          <Paper key={i} sx={{ p: 2, mb: 1, borderLeft: `4px solid ${severityColors[finding.severity] || "#888"}` }}>
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                              <Typography variant="subtitle2" fontWeight={600}>{finding.finding}</Typography>
                              {finding.cvss_estimate && (
                                <Chip label={`CVSS: ${finding.cvss_estimate}`} size="small" variant="outlined" />
                              )}
                              {finding.effort && (
                                <Chip label={`Effort: ${finding.effort}`} size="small" variant="outlined" />
                              )}
                            </Box>
                            <Typography variant="body2" color="text.secondary">{finding.description}</Typography>
                            {finding.impact && (
                              <Typography variant="body2" sx={{ mt: 1, color: "#dc2626" }}>
                                ⚠️ Impact: {finding.impact}
                              </Typography>
                            )}
                            {finding.recommendation && (
                              <Typography variant="body2" sx={{ mt: 1, color: "#3b82f6" }}>
                                💡 {finding.recommendation}
                              </Typography>
                            )}
                          </Paper>
                        ))}
                      </Box>
                    )}

                    {/* Attack Surface Analysis */}
                    {result.ai_analysis.attack_surface && (
                      <Accordion sx={{ mb: 2 }}>
                        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                          <Typography variant="subtitle2" fontWeight={600}>🎯 Attack Surface Analysis</Typography>
                        </AccordionSummary>
                        <AccordionDetails>
                          {/* Reconnaissance Value */}
                          {result.ai_analysis.attack_surface.reconnaissance_value && (
                            <Alert severity="warning" sx={{ mb: 2 }}>
                              <Typography variant="body2">
                                <strong>What an attacker learned:</strong> {result.ai_analysis.attack_surface.reconnaissance_value}
                              </Typography>
                            </Alert>
                          )}
                          
                          {/* High Value Targets */}
                          {result.ai_analysis.attack_surface.high_value_targets && result.ai_analysis.attack_surface.high_value_targets.length > 0 && (
                            <Box sx={{ mb: 2 }}>
                              <Typography variant="body2" fontWeight={600} sx={{ mb: 1 }}>High Value Targets:</Typography>
                              <Grid container spacing={1}>
                                {result.ai_analysis.attack_surface.high_value_targets.map((target: any, i: number) => (
                                  <Grid item xs={12} sm={6} key={i}>
                                    <Paper sx={{ p: 1.5, bgcolor: alpha("#dc2626", 0.05) }}>
                                      <Typography variant="body2" fontWeight={600}>{target.target}</Typography>
                                      <Typography variant="caption" color="text.secondary">{target.reason}</Typography>
                                      {target.attack_vector && (
                                        <Typography variant="caption" display="block" sx={{ color: "#f59e0b", mt: 0.5 }}>
                                          Vector: {target.attack_vector}
                                        </Typography>
                                      )}
                                    </Paper>
                                  </Grid>
                                ))}
                              </Grid>
                            </Box>
                          )}

                          {/* Attack Paths */}
                          {result.ai_analysis.attack_surface.attack_paths && result.ai_analysis.attack_surface.attack_paths.length > 0 && (
                            <Box sx={{ mb: 2 }}>
                              <Typography variant="body2" fontWeight={600} sx={{ mb: 1 }}>Potential Attack Paths:</Typography>
                              {result.ai_analysis.attack_surface.attack_paths.map((path: any, i: number) => (
                                <Paper key={i} sx={{ p: 1.5, mb: 1, bgcolor: alpha("#8b5cf6", 0.05) }}>
                                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                                    <Typography variant="body2" fontWeight={600}>{path.name}</Typography>
                                    <Chip label={`Likelihood: ${path.likelihood}`} size="small" />
                                    <Chip label={`Impact: ${path.impact}`} size="small" />
                                  </Box>
                                  <Box sx={{ pl: 2 }}>
                                    {path.steps && path.steps.map((step: string, j: number) => (
                                      <Typography key={j} variant="caption" display="block" color="text.secondary">
                                        {j + 1}. {step}
                                      </Typography>
                                    ))}
                                  </Box>
                                </Paper>
                              ))}
                            </Box>
                          )}

                          {/* Exposed Services */}
                          {result.ai_analysis.attack_surface.exposed_services && result.ai_analysis.attack_surface.exposed_services.length > 0 && (
                            <Box>
                              <Typography variant="body2" fontWeight={600} sx={{ mb: 1 }}>Exposed Services:</Typography>
                              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                                {result.ai_analysis.attack_surface.exposed_services.map((service: any, i: number) => (
                                  <Tooltip key={i} title={typeof service === 'object' ? `${service.location}: ${service.risk}` : service}>
                                    <Chip 
                                      label={typeof service === 'object' ? service.service : service} 
                                      size="small" 
                                      variant="outlined"
                                    />
                                  </Tooltip>
                                ))}
                              </Box>
                            </Box>
                          )}
                        </AccordionDetails>
                      </Accordion>
                    )}

                    {/* Predicted Subdomains */}
                    {result.ai_analysis.predicted_subdomains && result.ai_analysis.predicted_subdomains.length > 0 && (
                      <Paper sx={{ p: 2, mb: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                        <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600, color: "#10b981" }}>
                          🔮 AI Predicted Subdomains (based on naming patterns)
                        </Typography>
                        <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1 }}>
                          These subdomains may exist based on patterns found in the scan. Consider probing them:
                        </Typography>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                          {result.ai_analysis.predicted_subdomains.map((subdomain: string, i: number) => (
                            <Chip
                              key={i}
                              label={subdomain}
                              size="small"
                              sx={{ fontFamily: "monospace" }}
                              onDelete={() => copyToClipboard(`${subdomain}.${result.domain}`)}
                              deleteIcon={<ContentCopyIcon fontSize="small" />}
                            />
                          ))}
                        </Box>
                      </Paper>
                    )}

                    {/* Remediation Roadmap */}
                    {result.ai_analysis.remediation_roadmap && (
                      <Accordion sx={{ mb: 2 }}>
                        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                          <Typography variant="subtitle2" fontWeight={600}>🗺️ Remediation Roadmap</Typography>
                        </AccordionSummary>
                        <AccordionDetails>
                          <Grid container spacing={2}>
                            {/* Immediate Actions */}
                            {result.ai_analysis.remediation_roadmap.immediate && result.ai_analysis.remediation_roadmap.immediate.length > 0 && (
                              <Grid item xs={12} md={4}>
                                <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.05), height: "100%" }}>
                                  <Typography variant="body2" fontWeight={700} sx={{ color: "#dc2626", mb: 1 }}>
                                    🚨 IMMEDIATE (P1)
                                  </Typography>
                                  {result.ai_analysis.remediation_roadmap.immediate.map((item: any, i: number) => (
                                    <Box key={i} sx={{ mb: 1 }}>
                                      <Typography variant="body2" fontWeight={500}>{item.action}</Typography>
                                      <Typography variant="caption" color="text.secondary">
                                        {item.effort} • Addresses: {item.finding}
                                      </Typography>
                                    </Box>
                                  ))}
                                </Paper>
                              </Grid>
                            )}
                            {/* Short Term */}
                            {result.ai_analysis.remediation_roadmap.short_term && result.ai_analysis.remediation_roadmap.short_term.length > 0 && (
                              <Grid item xs={12} md={4}>
                                <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), height: "100%" }}>
                                  <Typography variant="body2" fontWeight={700} sx={{ color: "#f59e0b", mb: 1 }}>
                                    📅 SHORT TERM (P2)
                                  </Typography>
                                  {result.ai_analysis.remediation_roadmap.short_term.map((item: any, i: number) => (
                                    <Box key={i} sx={{ mb: 1 }}>
                                      <Typography variant="body2" fontWeight={500}>{item.action}</Typography>
                                      <Typography variant="caption" color="text.secondary">
                                        {item.effort} • Addresses: {item.finding}
                                      </Typography>
                                    </Box>
                                  ))}
                                </Paper>
                              </Grid>
                            )}
                            {/* Long Term */}
                            {result.ai_analysis.remediation_roadmap.long_term && result.ai_analysis.remediation_roadmap.long_term.length > 0 && (
                              <Grid item xs={12} md={4}>
                                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), height: "100%" }}>
                                  <Typography variant="body2" fontWeight={700} sx={{ color: "#3b82f6", mb: 1 }}>
                                    📆 LONG TERM (P3)
                                  </Typography>
                                  {result.ai_analysis.remediation_roadmap.long_term.map((item: any, i: number) => (
                                    <Box key={i} sx={{ mb: 1 }}>
                                      <Typography variant="body2" fontWeight={500}>{item.action}</Typography>
                                      <Typography variant="caption" color="text.secondary">
                                        {item.effort} • Addresses: {item.finding}
                                      </Typography>
                                    </Box>
                                  ))}
                                </Paper>
                              </Grid>
                            )}
                          </Grid>
                        </AccordionDetails>
                      </Accordion>
                    )}

                    {/* Threat Intel Correlation */}
                    {result.ai_analysis.threat_intel_correlation && (
                      <Accordion sx={{ mb: 2 }}>
                        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                          <Typography variant="subtitle2" fontWeight={600}>🛡️ Threat Intelligence Correlation</Typography>
                        </AccordionSummary>
                        <AccordionDetails>
                          {result.ai_analysis.threat_intel_correlation.known_attack_patterns && 
                           result.ai_analysis.threat_intel_correlation.known_attack_patterns.length > 0 && (
                            <Box sx={{ mb: 2 }}>
                              <Typography variant="body2" fontWeight={600} sx={{ mb: 1 }}>Known Attack Patterns (TTPs):</Typography>
                              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                                {result.ai_analysis.threat_intel_correlation.known_attack_patterns.map((pattern: string, i: number) => (
                                  <Chip key={i} label={pattern} size="small" color="warning" variant="outlined" />
                                ))}
                              </Box>
                            </Box>
                          )}
                          {result.ai_analysis.threat_intel_correlation.relevant_cves && 
                           result.ai_analysis.threat_intel_correlation.relevant_cves.length > 0 && (
                            <Box sx={{ mb: 2 }}>
                              <Typography variant="body2" fontWeight={600} sx={{ mb: 1 }}>Potentially Relevant CVEs:</Typography>
                              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                                {result.ai_analysis.threat_intel_correlation.relevant_cves.map((cve: string, i: number) => (
                                  <Chip key={i} label={cve} size="small" color="error" variant="outlined" />
                                ))}
                              </Box>
                            </Box>
                          )}
                          {result.ai_analysis.threat_intel_correlation.apt_relevance && (
                            <Alert severity="info">
                              <Typography variant="body2">
                                <strong>APT Relevance:</strong> {result.ai_analysis.threat_intel_correlation.apt_relevance}
                              </Typography>
                            </Alert>
                          )}
                        </AccordionDetails>
                      </Accordion>
                    )}

                    {/* Next Steps with Tools */}
                    {result.ai_analysis.next_steps && result.ai_analysis.next_steps.length > 0 && (
                      <Box>
                        <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600 }}>🚀 Recommended Next Steps</Typography>
                        <List dense>
                          {result.ai_analysis.next_steps.map((step: any, i: number) => (
                            <ListItem key={i} sx={{ flexDirection: "column", alignItems: "flex-start" }}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
                                <ListItemIcon sx={{ minWidth: 32 }}>
                                  <CheckCircleIcon fontSize="small" color="success" />
                                </ListItemIcon>
                                <ListItemText 
                                  primary={typeof step === 'object' ? step.action : step}
                                  secondary={typeof step === 'object' && step.reason ? step.reason : null}
                                />
                              </Box>
                              {typeof step === 'object' && step.tools && step.tools.length > 0 && (
                                <Box sx={{ pl: 5, mt: 0.5 }}>
                                  <Typography variant="caption" color="text.secondary">
                                    Tools: {step.tools.join(", ")}
                                  </Typography>
                                </Box>
                              )}
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    )}
                  </AccordionDetails>
                </Accordion>
              )}

              {/* ===== ADVANCED RECONNAISSANCE SECTION ===== */}
              
              {/* Infrastructure Summary Card */}
              {result.infrastructure_summary && Object.keys(result.infrastructure_summary).length > 0 && (
                <Paper sx={{ p: 3, mt: 3, bgcolor: alpha("#6366f1", 0.05), border: `1px solid ${alpha("#6366f1", 0.2)}` }}>
                  <Typography variant="h6" sx={{ mb: 3, fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                    <DeviceHubIcon sx={{ color: "#6366f1" }} />
                    Infrastructure Summary
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={6} sm={4} md={2}>
                      <Box sx={{ textAlign: "center" }}>
                        <Typography variant="h4" fontWeight={700} color="primary">
                          {result.infrastructure_summary.total_unique_ips || 0}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">Unique IPs</Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6} sm={4} md={2}>
                      <Box sx={{ textAlign: "center" }}>
                        <Typography variant="h4" fontWeight={700} color="secondary">
                          {result.infrastructure_summary.total_asns || 0}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">ASNs Detected</Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6} sm={4} md={2}>
                      <Box sx={{ textAlign: "center" }}>
                        <Typography variant="h4" fontWeight={700} sx={{ color: "#dc2626" }}>
                          {result.infrastructure_summary.potential_takeovers || 0}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">Takeover Risks</Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6} sm={4} md={2}>
                      <Box sx={{ textAlign: "center" }}>
                        <Typography variant="h4" fontWeight={700} sx={{ color: "#f59e0b" }}>
                          {result.infrastructure_summary.dangling_records || 0}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">Dangling CNAMEs</Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6} sm={4} md={2}>
                      <Box sx={{ textAlign: "center" }}>
                        {result.infrastructure_summary.cdn_usage ? (
                          <CheckCircleIcon sx={{ fontSize: 40, color: "#22c55e" }} />
                        ) : (
                          <ErrorIcon sx={{ fontSize: 40, color: "#888" }} />
                        )}
                        <Typography variant="caption" color="text.secondary" display="block">CDN Detected</Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6} sm={4} md={2}>
                      <Box sx={{ textAlign: "center" }}>
                        {result.infrastructure_summary.has_wildcard ? (
                          <WarningIcon sx={{ fontSize: 40, color: "#f59e0b" }} />
                        ) : (
                          <CheckCircleIcon sx={{ fontSize: 40, color: "#22c55e" }} />
                        )}
                        <Typography variant="caption" color="text.secondary" display="block">
                          {result.infrastructure_summary.has_wildcard ? "Wildcard DNS" : "No Wildcard"}
                        </Typography>
                      </Box>
                    </Grid>
                  </Grid>
                  {result.infrastructure_summary.cloud_providers_detected && result.infrastructure_summary.cloud_providers_detected.length > 0 && (
                    <Box sx={{ mt: 2, display: "flex", gap: 1, flexWrap: "wrap", alignItems: "center" }}>
                      <Typography variant="body2" color="text.secondary">Cloud Providers:</Typography>
                      {result.infrastructure_summary.cloud_providers_detected.map((provider: string, i: number) => (
                        <Chip key={i} label={provider} size="small" icon={<CloudIcon />} sx={{ bgcolor: alpha("#3b82f6", 0.1) }} />
                      ))}
                    </Box>
                  )}
                </Paper>
              )}

              {/* Subdomain Takeover Risks */}
              {result.takeover_risks && result.takeover_risks.length > 0 && (
                <Accordion sx={{ mt: 3 }} defaultExpanded>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, flex: 1 }}>
                      <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <BugReportIcon sx={{ color: "#dc2626" }} />
                        Subdomain Takeover Risks ({result.takeover_risks.length})
                      </Typography>
                      {result.takeover_risks.some(r => r.is_vulnerable) && (
                        <Chip label="VULNERABLE" size="small" color="error" />
                      )}
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Alert severity="warning" sx={{ mb: 2 }}>
                      Subdomain takeover occurs when a subdomain points to an unclaimed external service. Attackers can claim these services and serve malicious content.
                    </Alert>
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>Subdomain</TableCell>
                            <TableCell>CNAME Target</TableCell>
                            <TableCell>Provider</TableCell>
                            <TableCell>Risk Level</TableCell>
                            <TableCell>Status</TableCell>
                            <TableCell>Reason</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {result.takeover_risks.map((risk, i) => (
                            <TableRow key={i} hover sx={{ bgcolor: risk.is_vulnerable ? alpha("#dc2626", 0.05) : "inherit" }}>
                              <TableCell sx={{ fontFamily: "monospace", fontWeight: 500 }}>
                                {risk.subdomain}
                              </TableCell>
                              <TableCell sx={{ fontFamily: "monospace" }}>
                                {risk.cname_target}
                              </TableCell>
                              <TableCell>
                                <Chip label={risk.provider} size="small" />
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={risk.risk_level.toUpperCase()}
                                  size="small"
                                  sx={{
                                    bgcolor: alpha(severityColors[risk.risk_level] || "#888", 0.15),
                                    color: severityColors[risk.risk_level] || "#888",
                                    fontWeight: 700,
                                  }}
                                />
                              </TableCell>
                              <TableCell>
                                {risk.is_vulnerable ? (
                                  <Chip label="VULNERABLE" size="small" color="error" icon={<WarningIcon />} />
                                ) : (
                                  <Chip label="Potential Risk" size="small" color="warning" variant="outlined" />
                                )}
                              </TableCell>
                              <TableCell>{risk.reason}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Dangling CNAMEs */}
              {result.dangling_cnames && result.dangling_cnames.length > 0 && (
                <Accordion sx={{ mt: 3 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <LinkOffIcon sx={{ color: "#f59e0b" }} />
                      Dangling CNAMEs ({result.dangling_cnames.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Alert severity="warning" sx={{ mb: 2 }}>
                      Dangling CNAMEs point to targets that do not resolve. These can indicate misconfiguration or potential takeover opportunities.
                    </Alert>
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>Subdomain</TableCell>
                            <TableCell>CNAME Target</TableCell>
                            <TableCell>Error</TableCell>
                            <TableCell></TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {result.dangling_cnames.map((cname, i) => (
                            <TableRow key={i} hover>
                              <TableCell sx={{ fontFamily: "monospace", fontWeight: 500 }}>
                                {cname.subdomain}
                              </TableCell>
                              <TableCell sx={{ fontFamily: "monospace" }}>
                                {cname.cname}
                              </TableCell>
                              <TableCell sx={{ color: "error.main" }}>
                                {cname.error}
                              </TableCell>
                              <TableCell>
                                <CopyButton text={cname.subdomain} />
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Cloud Providers Detected */}
              {result.cloud_providers && result.cloud_providers.length > 0 && (
                <Accordion sx={{ mt: 3 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <CloudIcon sx={{ color: "#3b82f6" }} />
                      Cloud Providers Detected ({result.cloud_providers.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Grid container spacing={2}>
                      {result.cloud_providers.map((cp, i) => (
                        <Grid item xs={12} sm={6} md={4} key={i}>
                          <Card sx={{ bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                            <CardContent sx={{ pb: "16px !important" }}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                                <CloudIcon sx={{ color: "#3b82f6" }} />
                                <Typography variant="subtitle2" fontWeight={600}>
                                  {cp.provider.toUpperCase()}
                                </Typography>
                                {cp.is_cdn && <Chip label="CDN" size="small" color="info" />}
                              </Box>
                              <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 0.5 }}>
                                {cp.ip_or_domain}
                              </Typography>
                              {cp.service && (
                                <Typography variant="caption" color="text.secondary">
                                  Service: {cp.service}
                                </Typography>
                              )}
                              {cp.region && (
                                <Typography variant="caption" color="text.secondary" display="block">
                                  Region: {cp.region}
                                </Typography>
                              )}
                            </CardContent>
                          </Card>
                        </Grid>
                      ))}
                    </Grid>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* ASN Information */}
              {result.asn_info && result.asn_info.length > 0 && (
                <Accordion sx={{ mt: 3 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <HubIcon sx={{ color: "#10b981" }} />
                      ASN / BGP Information ({result.asn_info.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>IP Address</TableCell>
                            <TableCell>ASN</TableCell>
                            <TableCell>Organization</TableCell>
                            <TableCell>Country</TableCell>
                            <TableCell>Network Range</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {result.asn_info.map((asn, i) => (
                            <TableRow key={i} hover>
                              <TableCell sx={{ fontFamily: "monospace", fontWeight: 500 }}>
                                {asn.ip_address}
                              </TableCell>
                              <TableCell>
                                {asn.asn ? (
                                  <Chip label={asn.asn} size="small" sx={{ fontFamily: "monospace" }} />
                                ) : "-"}
                              </TableCell>
                              <TableCell>
                                <Box>
                                  {asn.asn_name && <Typography variant="body2" fontWeight={500}>{asn.asn_name}</Typography>}
                                  {asn.organization && asn.organization !== asn.asn_name && (
                                    <Typography variant="caption" color="text.secondary">{asn.organization}</Typography>
                                  )}
                                </Box>
                              </TableCell>
                              <TableCell>{asn.country || "-"}</TableCell>
                              <TableCell sx={{ fontFamily: "monospace" }}>
                                {asn.network_range || "-"}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Certificate Transparency Logs */}
              {result.ct_logs && result.ct_logs.length > 0 && (
                <Accordion sx={{ mt: 3 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <VerifiedUserIcon sx={{ color: "#8b5cf6" }} />
                      Certificate Transparency Logs ({result.ct_logs.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Alert severity="info" sx={{ mb: 2 }}>
                      CT logs reveal SSL certificates issued for this domain, which can help discover subdomains and track certificate issuance.
                    </Alert>
                    <TableContainer sx={{ maxHeight: 400 }}>
                      <Table size="small" stickyHeader>
                        <TableHead>
                          <TableRow>
                            <TableCell>Common Name</TableCell>
                            <TableCell>Issuer</TableCell>
                            <TableCell>Valid From</TableCell>
                            <TableCell>Valid Until</TableCell>
                            <TableCell>SAN Entries</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {result.ct_logs.map((cert, i) => (
                            <TableRow key={i} hover>
                              <TableCell sx={{ fontFamily: "monospace", fontWeight: 500 }}>
                                {cert.common_name}
                              </TableCell>
                              <TableCell>{cert.issuer}</TableCell>
                              <TableCell>{cert.not_before}</TableCell>
                              <TableCell>{cert.not_after}</TableCell>
                              <TableCell>
                                <Tooltip title={cert.san_names.join(", ")}>
                                  <Chip label={`${cert.san_names.length} names`} size="small" variant="outlined" />
                                </Tooltip>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Wildcard DNS Detection */}
              {result.has_wildcard && (
                <Alert 
                  severity="warning" 
                  sx={{ mt: 3 }}
                  icon={<SecurityIcon />}
                >
                  <Typography variant="subtitle2" fontWeight={700}>Wildcard DNS Detected</Typography>
                  <Typography variant="body2">
                    This domain has wildcard DNS configured, meaning any subdomain will resolve.
                    This can make subdomain enumeration less reliable and may indicate a catch-all configuration.
                  </Typography>
                  {result.wildcard_ips && result.wildcard_ips.length > 0 && (
                    <Box sx={{ mt: 1 }}>
                      <Typography variant="caption" color="text.secondary">
                        Wildcard resolves to: {result.wildcard_ips.join(", ")}
                      </Typography>
                    </Box>
                  )}
                </Alert>
              )}

              {/* BIMI and MTA-STS indicators in Email Security */}
              {result.security && (result.security.has_bimi || result.security.has_mta_sts) && (
                <Paper sx={{ p: 2, mt: 3, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#10b981", display: "flex", alignItems: "center", gap: 1 }}>
                    <EmailIcon fontSize="small" />
                    Advanced Email Security
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Chip
                          icon={result.security.has_bimi ? <CheckCircleIcon /> : <ErrorIcon />}
                          label="BIMI"
                          color={result.security.has_bimi ? "success" : "default"}
                          variant={result.security.has_bimi ? "filled" : "outlined"}
                        />
                        <Typography variant="caption" color="text.secondary">
                          Brand Indicators for Message Identification
                        </Typography>
                      </Box>
                      {result.security.bimi_record && (
                        <Typography variant="caption" sx={{ fontFamily: "monospace", mt: 1, display: "block" }}>
                          {result.security.bimi_record}
                        </Typography>
                      )}
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Chip
                          icon={result.security.has_mta_sts ? <CheckCircleIcon /> : <ErrorIcon />}
                          label="MTA-STS"
                          color={result.security.has_mta_sts ? "success" : "default"}
                          variant={result.security.has_mta_sts ? "filled" : "outlined"}
                        />
                        <Typography variant="caption" color="text.secondary">
                          Mail Transfer Agent Strict Transport Security
                        </Typography>
                      </Box>
                      {result.security.mta_sts_record && (
                        <Typography variant="caption" sx={{ fontFamily: "monospace", mt: 1, display: "block" }}>
                          {result.security.mta_sts_record}
                        </Typography>
                      )}
                    </Grid>
                  </Grid>
                </Paper>
              )}
            </Box>
          )}
        </>
      )}

      {/* Tab 1: Saved Reports */}
      {activeTab === 1 && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" sx={{ mb: 3, fontWeight: 600 }}>
            Saved DNS Reports
          </Typography>

          {loadingReports ? (
            <Box sx={{ textAlign: "center", py: 4 }}>
              <CircularProgress />
            </Box>
          ) : savedReports.length === 0 ? (
            <Alert severity="info">
              No saved DNS reports yet. Run a scan to create one.
            </Alert>
          ) : (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Domain</TableCell>
                    <TableCell>Title</TableCell>
                    <TableCell>Records</TableCell>
                    <TableCell>Subdomains</TableCell>
                    <TableCell>Zone Transfer</TableCell>
                    <TableCell>Email Score</TableCell>
                    <TableCell>Date</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {savedReports.map((report) => (
                    <TableRow key={report.id} hover>
                      <TableCell sx={{ fontFamily: "monospace", fontWeight: 500 }}>
                        {report.domain}
                      </TableCell>
                      <TableCell>{report.title || "-"}</TableCell>
                      <TableCell>{report.total_records}</TableCell>
                      <TableCell>{report.total_subdomains}</TableCell>
                      <TableCell>
                        {report.zone_transfer_possible ? (
                          <Chip label="VULNERABLE" size="small" color="error" />
                        ) : (
                          <Chip label="Protected" size="small" color="success" variant="outlined" />
                        )}
                      </TableCell>
                      <TableCell>
                        {report.mail_security_score !== undefined ? (
                          <Chip
                            label={`${report.mail_security_score}/100`}
                            size="small"
                            sx={{
                              bgcolor: alpha(
                                report.mail_security_score >= 70 ? "#22c55e" :
                                report.mail_security_score >= 40 ? "#eab308" : "#dc2626",
                                0.15
                              ),
                              color: report.mail_security_score >= 70 ? "#22c55e" :
                                     report.mail_security_score >= 40 ? "#eab308" : "#dc2626",
                            }}
                          />
                        ) : "-"}
                      </TableCell>
                      <TableCell>
                        {new Date(report.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell>
                        <Tooltip title="View Report">
                          <IconButton size="small" onClick={() => handleLoadReport(report.id)}>
                            <VisibilityIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete">
                          <IconButton size="small" color="error" onClick={() => handleDeleteReport(report.id)}>
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Paper>
      )}

      {/* Tab 2: WHOIS Lookup */}
      {activeTab === 2 && (
        <Box>
          {/* WHOIS Input */}
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" sx={{ mb: 3, fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
              <ManageSearchIcon />
              WHOIS Lookup
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Look up domain registration information or IP address ownership details.
            </Typography>
            
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label={whoisType === "domain" ? "Domain Name" : "IP Address"}
                  placeholder={whoisType === "domain" ? "example.com" : "8.8.8.8"}
                  value={whoisTarget}
                  onChange={(e) => setWhoisTarget(e.target.value)}
                  disabled={whoisLoading}
                  onKeyDown={(e) => e.key === "Enter" && handleWhoisLookup()}
                  InputProps={{
                    startAdornment: whoisType === "domain" ? 
                      <LanguageIcon sx={{ mr: 1, color: "text.secondary" }} /> :
                      <RouterIcon sx={{ mr: 1, color: "text.secondary" }} />,
                  }}
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <FormControl fullWidth>
                  <InputLabel>Lookup Type</InputLabel>
                  <Select
                    value={whoisType}
                    label="Lookup Type"
                    onChange={(e) => {
                      setWhoisType(e.target.value as "domain" | "ip");
                      setWhoisTarget("");
                      setWhoisDomainResult(null);
                      setWhoisIPResult(null);
                      setWhoisError(null);
                    }}
                    disabled={whoisLoading}
                  >
                    <MenuItem value="domain">Domain WHOIS</MenuItem>
                    <MenuItem value="ip">IP WHOIS</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={3}>
                <Button
                  fullWidth
                  variant="contained"
                  size="large"
                  onClick={handleWhoisLookup}
                  disabled={whoisLoading || !whoisTarget.trim()}
                  sx={{
                    height: 56,
                    background: `linear-gradient(135deg, #f59e0b 0%, #d97706 100%)`,
                    "&:hover": {
                      background: `linear-gradient(135deg, #d97706 0%, #b45309 100%)`,
                    },
                  }}
                  startIcon={whoisLoading ? <CircularProgress size={20} color="inherit" /> : <SearchIcon />}
                >
                  {whoisLoading ? "Looking up..." : "Lookup"}
                </Button>
              </Grid>
            </Grid>

            {/* Quick lookup suggestions */}
            <Box sx={{ mt: 2 }}>
              <Typography variant="caption" color="text.secondary" sx={{ mr: 1 }}>
                Quick lookups:
              </Typography>
              {whoisType === "domain" ? (
                <>
                  {["google.com", "github.com", "cloudflare.com"].map((d) => (
                    <Chip
                      key={d}
                      label={d}
                      size="small"
                      variant="outlined"
                      sx={{ mr: 1, mb: 1, cursor: "pointer" }}
                      onClick={() => setWhoisTarget(d)}
                    />
                  ))}
                </>
              ) : (
                <>
                  {["8.8.8.8", "1.1.1.1", "208.67.222.222"].map((ip) => (
                    <Chip
                      key={ip}
                      label={ip}
                      size="small"
                      variant="outlined"
                      sx={{ mr: 1, mb: 1, cursor: "pointer" }}
                      onClick={() => setWhoisTarget(ip)}
                    />
                  ))}
                </>
              )}
            </Box>
          </Paper>

          {/* WHOIS Error */}
          {whoisError && (
            <Alert severity="error" sx={{ mb: 3 }}>
              {whoisError}
            </Alert>
          )}

          {/* Domain WHOIS Results */}
          {whoisDomainResult && !whoisDomainResult.error && (
            <Paper sx={{ p: 3, mb: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3 }}>
                <Typography variant="h6" fontWeight={600}>
                  WHOIS Results: {whoisDomainResult.domain}
                </Typography>
                <Box>
                  <Button
                    size="small"
                    startIcon={<ContentCopyIcon />}
                    onClick={handleCopyWhoisData}
                    sx={{ mr: 1 }}
                  >
                    Copy
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    onClick={() => setShowRawWhois(!showRawWhois)}
                  >
                    {showRawWhois ? "Hide Raw" : "Show Raw"}
                  </Button>
                </Box>
              </Box>

              <Grid container spacing={3}>
                {/* Registrar Info */}
                <Grid item xs={12} md={6}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                    <CardContent>
                      <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#3b82f6", display: "flex", alignItems: "center", gap: 1 }}>
                        <StorageIcon fontSize="small" />
                        Registrar Information
                      </Typography>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                        <Box>
                          <Typography variant="caption" color="text.secondary">Registrar</Typography>
                          <Typography variant="body2" fontWeight={500}>{whoisDomainResult.registrar || "N/A"}</Typography>
                        </Box>
                        {whoisDomainResult.registrar_url && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">Registrar URL</Typography>
                            <Typography variant="body2" sx={{ fontFamily: "monospace", wordBreak: "break-all" }}>
                              {whoisDomainResult.registrar_url}
                            </Typography>
                          </Box>
                        )}
                        {whoisDomainResult.dnssec && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">DNSSEC</Typography>
                            <Chip 
                              label={whoisDomainResult.dnssec} 
                              size="small" 
                              color={whoisDomainResult.dnssec.toLowerCase().includes("signed") ? "success" : "default"}
                            />
                          </Box>
                        )}
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Dates */}
                <Grid item xs={12} md={6}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                    <CardContent>
                      <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#10b981", display: "flex", alignItems: "center", gap: 1 }}>
                        <CalendarTodayIcon fontSize="small" />
                        Registration Dates
                      </Typography>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                        <Box>
                          <Typography variant="caption" color="text.secondary">Created</Typography>
                          <Typography variant="body2" fontWeight={500}>{whoisDomainResult.creation_date || "N/A"}</Typography>
                        </Box>
                        <Box>
                          <Typography variant="caption" color="text.secondary">Expires</Typography>
                          <Typography variant="body2" fontWeight={500} sx={{ color: whoisDomainResult.expiration_date ? "#f59e0b" : "inherit" }}>
                            {whoisDomainResult.expiration_date || "N/A"}
                          </Typography>
                        </Box>
                        <Box>
                          <Typography variant="caption" color="text.secondary">Updated</Typography>
                          <Typography variant="body2" fontWeight={500}>{whoisDomainResult.updated_date || "N/A"}</Typography>
                        </Box>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Registrant Info */}
                {(whoisDomainResult.registrant_organization || whoisDomainResult.registrant_name || whoisDomainResult.registrant_country) && (
                  <Grid item xs={12} md={6}>
                    <Card sx={{ height: "100%", bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                      <CardContent>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#8b5cf6", display: "flex", alignItems: "center", gap: 1 }}>
                          <BusinessIcon fontSize="small" />
                          Registrant Information
                        </Typography>
                        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                          {whoisDomainResult.registrant_organization && (
                            <Box>
                              <Typography variant="caption" color="text.secondary">Organization</Typography>
                              <Typography variant="body2" fontWeight={500}>{whoisDomainResult.registrant_organization}</Typography>
                            </Box>
                          )}
                          {whoisDomainResult.registrant_name && (
                            <Box>
                              <Typography variant="caption" color="text.secondary">Name</Typography>
                              <Typography variant="body2" fontWeight={500}>{whoisDomainResult.registrant_name}</Typography>
                            </Box>
                          )}
                          {whoisDomainResult.registrant_country && (
                            <Box>
                              <Typography variant="caption" color="text.secondary">Country</Typography>
                              <Typography variant="body2" fontWeight={500}>{whoisDomainResult.registrant_country}</Typography>
                            </Box>
                          )}
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                )}

                {/* Name Servers */}
                {whoisDomainResult.name_servers.length > 0 && (
                  <Grid item xs={12} md={6}>
                    <Card sx={{ height: "100%", bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                      <CardContent>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
                          <DnsIcon fontSize="small" />
                          Name Servers ({whoisDomainResult.name_servers.length})
                        </Typography>
                        <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                          {whoisDomainResult.name_servers.map((ns, i) => (
                            <Box key={i} sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                              <Typography variant="body2" sx={{ fontFamily: "monospace" }}>{ns}</Typography>
                              <CopyButton text={ns} />
                            </Box>
                          ))}
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                )}

                {/* Domain Status */}
                {whoisDomainResult.status.length > 0 && (
                  <Grid item xs={12}>
                    <Card sx={{ bgcolor: alpha("#6366f1", 0.05), border: `1px solid ${alpha("#6366f1", 0.2)}` }}>
                      <CardContent>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#6366f1" }}>
                          Domain Status ({whoisDomainResult.status.length})
                        </Typography>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                          {whoisDomainResult.status.map((status, i) => (
                            <Chip
                              key={i}
                              label={status}
                              size="small"
                              sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}
                            />
                          ))}
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                )}
              </Grid>

              {/* Raw WHOIS */}
              {showRawWhois && whoisDomainResult.raw_text && (
                <Accordion sx={{ mt: 3 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle2" fontWeight={600}>Raw WHOIS Data</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Paper sx={{ p: 2, bgcolor: "#1e1e1e", maxHeight: 400, overflow: "auto" }}>
                      <Typography
                        component="pre"
                        sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}
                      >
                        {whoisDomainResult.raw_text}
                      </Typography>
                    </Paper>
                  </AccordionDetails>
                </Accordion>
              )}
            </Paper>
          )}

          {/* IP WHOIS Results */}
          {whoisIPResult && !whoisIPResult.error && (
            <Paper sx={{ p: 3, mb: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3 }}>
                <Typography variant="h6" fontWeight={600}>
                  IP WHOIS Results: {whoisIPResult.ip_address}
                </Typography>
                <Box>
                  <Button
                    size="small"
                    startIcon={<ContentCopyIcon />}
                    onClick={handleCopyWhoisData}
                    sx={{ mr: 1 }}
                  >
                    Copy
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    onClick={() => setShowRawWhois(!showRawWhois)}
                  >
                    {showRawWhois ? "Hide Raw" : "Show Raw"}
                  </Button>
                </Box>
              </Box>

              <Grid container spacing={3}>
                {/* Network Info */}
                <Grid item xs={12} md={6}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                    <CardContent>
                      <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#3b82f6", display: "flex", alignItems: "center", gap: 1 }}>
                        <RouterIcon fontSize="small" />
                        Network Information
                      </Typography>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                        {whoisIPResult.network_name && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">Network Name</Typography>
                            <Typography variant="body2" fontWeight={500}>{whoisIPResult.network_name}</Typography>
                          </Box>
                        )}
                        {whoisIPResult.network_range && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">Network Range</Typography>
                            <Typography variant="body2" sx={{ fontFamily: "monospace" }}>{whoisIPResult.network_range}</Typography>
                          </Box>
                        )}
                        {whoisIPResult.cidr && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">CIDR</Typography>
                            <Typography variant="body2" sx={{ fontFamily: "monospace" }}>{whoisIPResult.cidr}</Typography>
                          </Box>
                        )}
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Organization Info */}
                <Grid item xs={12} md={6}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                    <CardContent>
                      <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#8b5cf6", display: "flex", alignItems: "center", gap: 1 }}>
                        <BusinessIcon fontSize="small" />
                        Organization
                      </Typography>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                        {whoisIPResult.organization && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">Organization</Typography>
                            <Typography variant="body2" fontWeight={500}>{whoisIPResult.organization}</Typography>
                          </Box>
                        )}
                        {whoisIPResult.country && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">Country</Typography>
                            <Typography variant="body2" fontWeight={500}>{whoisIPResult.country}</Typography>
                          </Box>
                        )}
                        {whoisIPResult.registrar && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">Registry (RIR)</Typography>
                            <Chip label={whoisIPResult.registrar} size="small" color="primary" variant="outlined" />
                          </Box>
                        )}
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>

                {/* ASN Info */}
                {(whoisIPResult.asn || whoisIPResult.asn_name) && (
                  <Grid item xs={12} md={6}>
                    <Card sx={{ height: "100%", bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                      <CardContent>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#10b981", display: "flex", alignItems: "center", gap: 1 }}>
                          <HubIcon fontSize="small" />
                          ASN Information
                        </Typography>
                        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                          {whoisIPResult.asn && (
                            <Box>
                              <Typography variant="caption" color="text.secondary">ASN</Typography>
                              <Typography variant="body2" fontWeight={500} sx={{ fontFamily: "monospace" }}>{whoisIPResult.asn}</Typography>
                            </Box>
                          )}
                          {whoisIPResult.asn_name && (
                            <Box>
                              <Typography variant="caption" color="text.secondary">ASN Name</Typography>
                              <Typography variant="body2" fontWeight={500}>{whoisIPResult.asn_name}</Typography>
                            </Box>
                          )}
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                )}

                {/* Contacts */}
                {(whoisIPResult.abuse_contact || whoisIPResult.tech_contact) && (
                  <Grid item xs={12} md={6}>
                    <Card sx={{ height: "100%", bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                      <CardContent>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
                          <EmailIcon fontSize="small" />
                          Contact Information
                        </Typography>
                        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                          {whoisIPResult.abuse_contact && (
                            <Box>
                              <Typography variant="caption" color="text.secondary">Abuse Contact</Typography>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                <Typography variant="body2" sx={{ fontFamily: "monospace" }}>{whoisIPResult.abuse_contact}</Typography>
                                <CopyButton text={whoisIPResult.abuse_contact} />
                              </Box>
                            </Box>
                          )}
                          {whoisIPResult.tech_contact && (
                            <Box>
                              <Typography variant="caption" color="text.secondary">Tech Contact</Typography>
                              <Typography variant="body2" sx={{ fontFamily: "monospace" }}>{whoisIPResult.tech_contact}</Typography>
                            </Box>
                          )}
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                )}

                {/* Description */}
                {whoisIPResult.description.length > 0 && (
                  <Grid item xs={12}>
                    <Card sx={{ bgcolor: alpha("#6366f1", 0.05), border: `1px solid ${alpha("#6366f1", 0.2)}` }}>
                      <CardContent>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: "#6366f1" }}>
                          Description
                        </Typography>
                        {whoisIPResult.description.map((desc, i) => (
                          <Typography key={i} variant="body2" color="text.secondary">
                            {desc}
                          </Typography>
                        ))}
                      </CardContent>
                    </Card>
                  </Grid>
                )}
              </Grid>

              {/* Raw WHOIS */}
              {showRawWhois && whoisIPResult.raw_text && (
                <Accordion sx={{ mt: 3 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle2" fontWeight={600}>Raw WHOIS Data</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Paper sx={{ p: 2, bgcolor: "#1e1e1e", maxHeight: 400, overflow: "auto" }}>
                      <Typography
                        component="pre"
                        sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}
                      >
                        {whoisIPResult.raw_text}
                      </Typography>
                    </Paper>
                  </AccordionDetails>
                </Accordion>
              )}
            </Paper>
          )}
        </Box>
      )}

      {/* Snackbar for copy feedback */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={2000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        message={snackbar.message}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      />

      {/* Floating Chat Window - Visible when results are available */}
      {result && (
        <Paper
          sx={{
            position: "fixed",
            bottom: 16,
            right: 16,
            left: chatMaximized ? { xs: 16, md: 256 } : "auto",
            width: chatMaximized ? "auto" : chatOpen ? { xs: "calc(100% - 32px)", sm: 400 } : 200,
            maxWidth: chatMaximized ? "none" : 400,
            zIndex: 1200,
            borderRadius: 3,
            boxShadow: "0 -4px 20px rgba(0,0,0,0.15)",
            overflow: "hidden",
            transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
          }}
        >
          {/* Chat Header */}
          <Box
            sx={{
              p: 2,
              bgcolor: theme.palette.primary.main,
              color: "white",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
            }}
          >
            <Box 
              sx={{ display: "flex", alignItems: "center", gap: 1, cursor: "pointer", flex: 1 }}
              onClick={() => setChatOpen(!chatOpen)}
            >
              <ChatIcon />
              <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                Ask About DNS Results
              </Typography>
            </Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
              <IconButton size="small" sx={{ color: "white" }} onClick={() => setChatMaximized(!chatMaximized)}>
                {chatMaximized ? <CloseFullscreenIcon /> : <OpenInFullIcon />}
              </IconButton>
              <IconButton size="small" sx={{ color: "white" }} onClick={() => setChatOpen(!chatOpen)}>
                {chatOpen ? <ExpandMoreIcon /> : <ExpandLessIcon />}
              </IconButton>
            </Box>
          </Box>

          {/* Chat Content */}
          <Collapse in={chatOpen}>
            {/* Messages Area */}
            <Box
              sx={{
                height: chatMaximized ? "calc(66vh - 120px)" : 280,
                overflowY: "auto",
                p: 2,
                bgcolor: alpha(theme.palette.background.default, 0.5),
                transition: "height 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
              }}
            >
              {/* Welcome message */}
              {chatMessages.length === 0 && (
                <Box sx={{ textAlign: "center", py: 4 }}>
                  <SmartToyIcon sx={{ fontSize: 48, color: "text.disabled", mb: 1 }} />
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Ask me anything about this DNS scan!
                  </Typography>
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                    {[
                      "What are the most critical vulnerabilities?",
                      "How would an attacker exploit this?",
                      "Explain the subdomain takeover risks",
                      "Generate a penetration testing plan",
                      "What's the remediation priority?",
                      "Predict additional subdomains to probe",
                    ].map((suggestion, i) => (
                      <Chip
                        key={i}
                        label={suggestion}
                        variant="outlined"
                        size="small"
                        onClick={() => setChatInput(suggestion)}
                        sx={{ cursor: "pointer", "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) } }}
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
                    display: "flex",
                    justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
                    mb: 2,
                  }}
                >
                  <Box
                    sx={{
                      maxWidth: "85%",
                      display: "flex",
                      gap: 1,
                      flexDirection: msg.role === "user" ? "row-reverse" : "row",
                    }}
                  >
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        borderRadius: "50%",
                        bgcolor: msg.role === "user" ? theme.palette.primary.main : theme.palette.secondary.main,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        flexShrink: 0,
                      }}
                    >
                      {msg.role === "user" ? (
                        <PersonIcon sx={{ fontSize: 18, color: "white" }} />
                      ) : (
                        <SmartToyIcon sx={{ fontSize: 18, color: "white" }} />
                      )}
                    </Box>
                    <Paper
                      sx={{
                        p: 1.5,
                        bgcolor: msg.role === "user" ? theme.palette.primary.main : theme.palette.background.paper,
                        color: msg.role === "user" ? "white" : "text.primary",
                        borderRadius: 2,
                        "& p": { m: 0 },
                        "& p:not(:last-child)": { mb: 1 },
                        "& ul, & ol": { pl: 2, m: 0 },
                        "& li": { mb: 0.5 },
                        "& strong": { fontWeight: 600 },
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
                <Box sx={{ display: "flex", justifyContent: "flex-start", mb: 2 }}>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        borderRadius: "50%",
                        bgcolor: theme.palette.secondary.main,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                    >
                      <SmartToyIcon sx={{ fontSize: 18, color: "white" }} />
                    </Box>
                    <Paper sx={{ p: 1.5, borderRadius: 2 }}>
                      <Box sx={{ display: "flex", gap: 0.5 }}>
                        <CircularProgress size={8} />
                        <CircularProgress size={8} sx={{ animationDelay: "0.2s" }} />
                        <CircularProgress size={8} sx={{ animationDelay: "0.4s" }} />
                      </Box>
                    </Paper>
                  </Box>
                </Box>
              )}

              {/* Error message */}
              {chatError && (
                <Alert severity="error" sx={{ mb: 2 }} onClose={() => setChatError(null)}>
                  {chatError}
                </Alert>
              )}

              <div ref={chatEndRef} />
            </Box>

            {/* Input Area */}
            <Box
              sx={{
                p: 2,
                borderTop: `1px solid ${theme.palette.divider}`,
                bgcolor: theme.palette.background.paper,
              }}
            >
              <Box sx={{ display: "flex", gap: 1 }}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Ask about the DNS findings..."
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyDown={handleChatKeyDown}
                  disabled={chatLoading}
                  sx={{
                    "& .MuiOutlinedInput-root": {
                      borderRadius: 3,
                    },
                  }}
                />
                <IconButton
                  color="primary"
                  onClick={handleSendChat}
                  disabled={!chatInput.trim() || chatLoading}
                  sx={{
                    bgcolor: theme.palette.primary.main,
                    color: "white",
                    "&:hover": { bgcolor: theme.palette.primary.dark },
                    "&.Mui-disabled": { bgcolor: "grey.300" },
                  }}
                >
                  <SendIcon />
                </IconButton>
              </Box>
            </Box>
          </Collapse>
        </Paper>
      )}
    </Container>
  );
}
