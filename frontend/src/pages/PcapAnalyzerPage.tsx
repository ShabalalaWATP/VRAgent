import { useState, useCallback, useRef, useEffect } from "react";
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
  Divider,
  Card,
  CardContent,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Breadcrumbs,
  Link as MuiLink,
  TextField,
  IconButton,
  Collapse,
  Tabs,
  Tab,
  Menu,
  MenuItem,
} from "@mui/material";
import { Link, useSearchParams } from "react-router-dom";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SecurityIcon from "@mui/icons-material/Security";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import DnsIcon from "@mui/icons-material/Dns";
import LanguageIcon from "@mui/icons-material/Language";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import DeleteIcon from "@mui/icons-material/Delete";
import InsightsIcon from "@mui/icons-material/Insights";
import RouterIcon from "@mui/icons-material/Router";
import ReportIcon from "@mui/icons-material/Assessment";
import ShieldIcon from "@mui/icons-material/Shield";
import BugReportIcon from "@mui/icons-material/BugReport";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import TimelineIcon from "@mui/icons-material/Timeline";
import RecommendIcon from "@mui/icons-material/Recommend";
import DevicesIcon from "@mui/icons-material/Devices";
import GppBadIcon from "@mui/icons-material/GppBad";
import GppGoodIcon from "@mui/icons-material/GppGood";
import GppMaybeIcon from "@mui/icons-material/GppMaybe";
import ErrorIcon from "@mui/icons-material/Error";
import InfoIcon from "@mui/icons-material/Info";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import NavigateNextIcon from "@mui/icons-material/NavigateNext";
import HubIcon from "@mui/icons-material/Hub";
import SendIcon from "@mui/icons-material/Send";
import ChatIcon from "@mui/icons-material/Chat";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import PersonIcon from "@mui/icons-material/Person";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import HistoryIcon from "@mui/icons-material/History";
import VisibilityIcon from "@mui/icons-material/Visibility";
import DownloadIcon from "@mui/icons-material/Download";
import DescriptionIcon from "@mui/icons-material/Description";
import PictureAsPdfIcon from "@mui/icons-material/PictureAsPdf";
import ArticleIcon from "@mui/icons-material/Article";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import { useDropzone } from "react-dropzone";
import ReactMarkdown from "react-markdown";
import NetworkTopologyGraph, { TopologyNode, TopologyLink } from "../components/NetworkTopologyGraph";
import { 
  analyzePcaps, 
  getPcapStatus, 
  MultiPcapAnalysisResponse, 
  AIAnalysisResult, 
  AISecurityReport,
  chatAboutPcap,
  ChatMessage,
  getPcapReports,
  getPcapReport,
  deletePcapReport,
  SavedReportSummary,
  SavedReportDetail,
  apiClient,
} from "../api/client";

// Severity colors
const severityColors: Record<string, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#3b82f6",
};

// Priority colors
const priorityColors: Record<string, string> = {
  immediate: "#dc2626",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

// Risk level colors and icons
const riskLevelConfig: Record<string, { color: string; icon: React.ReactNode; bgcolor: string }> = {
  critical: { color: "#dc2626", icon: <GppBadIcon />, bgcolor: "rgba(220, 38, 38, 0.1)" },
  high: { color: "#f97316", icon: <GppMaybeIcon />, bgcolor: "rgba(249, 115, 22, 0.1)" },
  medium: { color: "#eab308", icon: <GppMaybeIcon />, bgcolor: "rgba(234, 179, 8, 0.1)" },
  low: { color: "#22c55e", icon: <GppGoodIcon />, bgcolor: "rgba(34, 197, 94, 0.1)" },
};

function StructuredReportSection({ report, theme }: { report: AISecurityReport; theme: any }) {
  const riskConfig = riskLevelConfig[report.risk_level.toLowerCase()] || riskLevelConfig.medium;

  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
      {/* Risk Overview */}
      <Paper
        sx={{
          p: 3,
          bgcolor: riskConfig.bgcolor,
          border: `2px solid ${riskConfig.color}`,
          borderRadius: 2,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <Box sx={{ color: riskConfig.color, fontSize: 48 }}>{riskConfig.icon}</Box>
          <Box>
            <Typography variant="h4" sx={{ fontWeight: 800, color: riskConfig.color }}>
              {report.risk_level.toUpperCase()} RISK
            </Typography>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <Typography variant="h6" color="text.secondary">
                Risk Score: {report.risk_score}/100
              </Typography>
              <LinearProgress
                variant="determinate"
                value={report.risk_score}
                sx={{
                  width: 100,
                  height: 10,
                  borderRadius: 5,
                  bgcolor: alpha(riskConfig.color, 0.2),
                  "& .MuiLinearProgress-bar": {
                    bgcolor: riskConfig.color,
                    borderRadius: 5,
                  },
                }}
              />
            </Box>
          </Box>
        </Box>
      </Paper>

      {/* Executive Summary */}
      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
          <ReportIcon color="primary" /> Executive Summary
        </Typography>
        <Typography variant="body1" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.8 }}>
          {report.executive_summary}
        </Typography>
      </Paper>

      {/* What Happened - Narrative Section */}
      {report.what_happened && (
        <Paper sx={{ p: 3, bgcolor: alpha(theme.palette.info.main, 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TimelineIcon color="info" /> What Happened in This Capture
          </Typography>
          
          {/* Main Narrative */}
          <Typography variant="body1" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.9, mb: 3 }}>
            {report.what_happened.narrative}
          </Typography>
          
          {/* Communication Flow */}
          {report.what_happened.communication_flow && (
            <Box sx={{ mb: 3 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, color: "primary.main" }}>
                📡 Communication Flow
              </Typography>
              <Typography variant="body2" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.7, pl: 2, borderLeft: `3px solid ${theme.palette.primary.main}` }}>
                {report.what_happened.communication_flow}
              </Typography>
            </Box>
          )}
          
          {/* Timeline */}
          {report.what_happened.timeline && report.what_happened.timeline.length > 0 && (
            <Box>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "primary.main" }}>
                ⏱️ Event Timeline
              </Typography>
              <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
                {report.what_happened.timeline.map((event, i) => (
                  <Card key={i} variant="outlined" sx={{ borderLeft: `4px solid ${theme.palette.info.main}` }}>
                    <CardContent sx={{ py: 2 }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        <Chip label={event.timestamp_range} size="small" color="info" variant="outlined" />
                        <Typography variant="caption" color="text.secondary">
                          Hosts: {event.hosts_involved?.join(", ")}
                        </Typography>
                      </Box>
                      <Typography variant="body2" sx={{ fontWeight: 500, mb: 1 }}>
                        {event.description}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        <strong>Significance:</strong> {event.significance}
                      </Typography>
                    </CardContent>
                  </Card>
                ))}
              </Box>
            </Box>
          )}
        </Paper>
      )}

      {/* Key Findings - Enhanced */}
      {report.key_findings && report.key_findings.length > 0 && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <BugReportIcon color="error" /> Key Security Findings ({report.key_findings.length})
          </Typography>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {report.key_findings.map((finding, i) => (
              <Card key={i} variant="outlined" sx={{ borderLeft: `4px solid ${severityColors[finding.severity.toLowerCase()] || "#888"}` }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Chip
                      label={finding.severity.toUpperCase()}
                      size="small"
                      sx={{
                        bgcolor: alpha(severityColors[finding.severity.toLowerCase()] || "#888", 0.15),
                        color: severityColors[finding.severity.toLowerCase()] || "#888",
                        fontWeight: 700,
                      }}
                    />
                    <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                      {finding.title}
                    </Typography>
                  </Box>
                  
                  {/* New detailed what_we_found field */}
                  {finding.what_we_found && (
                    <Typography variant="body2" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.7, mb: 2 }}>
                      {finding.what_we_found}
                    </Typography>
                  )}
                  
                  {/* Legacy description field */}
                  {!finding.what_we_found && finding.description && (
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      {finding.description}
                    </Typography>
                  )}
                  
                  {/* Technical Evidence */}
                  {(finding.technical_evidence || finding.evidence) && (
                    <Box sx={{ bgcolor: alpha(theme.palette.divider, 0.3), p: 1.5, borderRadius: 1, mb: 2 }}>
                      <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary", display: "block", mb: 0.5 }}>
                        📋 Technical Evidence
                      </Typography>
                      <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
                        {finding.technical_evidence || finding.evidence}
                      </Typography>
                    </Box>
                  )}
                  
                  {/* Potential Impact */}
                  {finding.potential_impact && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="caption" sx={{ fontWeight: 700, color: "warning.main", display: "block", mb: 0.5 }}>
                        ⚠️ Potential Impact
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {finding.potential_impact}
                      </Typography>
                    </Box>
                  )}
                  
                  {/* Recommendation */}
                  {(finding.recommended_action || finding.recommendation) && (
                    <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1, mt: 1, p: 1.5, bgcolor: alpha(theme.palette.success.main, 0.1), borderRadius: 1 }}>
                      <RecommendIcon fontSize="small" color="success" sx={{ mt: 0.3 }} />
                      <Typography variant="body2" color="success.dark" sx={{ fontWeight: 500 }}>
                        {finding.recommended_action || finding.recommendation}
                      </Typography>
                    </Box>
                  )}
                </CardContent>
              </Card>
            ))}
          </Box>
        </Paper>
      )}

      {/* Credential Exposure */}
      {report.credential_exposure && report.credential_exposure.severity !== "None" && (
        <Paper sx={{ p: 3, bgcolor: alpha(severityColors[report.credential_exposure.severity.toLowerCase()] || "#888", 0.05) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <VpnKeyIcon sx={{ color: severityColors[report.credential_exposure.severity.toLowerCase()] }} />
            Credential Exposure Analysis
            <Chip
              label={report.credential_exposure.severity}
              size="small"
              sx={{ ml: 1, bgcolor: severityColors[report.credential_exposure.severity.toLowerCase()], color: "white" }}
            />
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            {report.credential_exposure.summary}
          </Typography>
          {report.credential_exposure.exposed_credentials && report.credential_exposure.exposed_credentials.length > 0 && (
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Type</TableCell>
                    <TableCell>Service</TableCell>
                    <TableCell>Source</TableCell>
                    <TableCell>Destination</TableCell>
                    <TableCell>Risk</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {report.credential_exposure.exposed_credentials.map((cred, i) => (
                    <TableRow key={i}>
                      <TableCell><Chip label={cred.type} size="small" variant="outlined" /></TableCell>
                      <TableCell>{cred.service}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace" }}>{cred.source_ip}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace" }}>{cred.dest_ip}</TableCell>
                      <TableCell>{cred.risk}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
          {report.credential_exposure.immediate_actions && report.credential_exposure.immediate_actions.length > 0 && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "error.main" }}>
                🚨 Immediate Actions Required:
              </Typography>
              <List dense>
                {report.credential_exposure.immediate_actions.map((action, i) => (
                  <ListItem key={i}>
                    <ListItemIcon><ErrorIcon color="error" fontSize="small" /></ListItemIcon>
                    <ListItemText primary={action} />
                  </ListItem>
                ))}
              </List>
            </Box>
          )}
        </Paper>
      )}

      {/* Attack Indicators - Enhanced with overall assessment */}
      {report.attack_indicators && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <ShieldIcon color="warning" /> Attack Pattern Analysis
          </Typography>
          
          {/* Overall Assessment */}
          {report.attack_indicators.overall_assessment && (
            <Typography variant="body1" sx={{ mb: 3, whiteSpace: "pre-wrap", lineHeight: 1.7 }}>
              {report.attack_indicators.overall_assessment}
            </Typography>
          )}
          
          <Grid container spacing={2}>
            {[
              { key: "reconnaissance", label: "Reconnaissance", icon: <TrendingUpIcon /> },
              { key: "lateral_movement", label: "Lateral Movement", icon: <RouterIcon /> },
              { key: "data_exfiltration", label: "Data Exfiltration", icon: <CloudUploadIcon /> },
              { key: "command_and_control", label: "Command & Control", icon: <LanguageIcon /> },
            ].map(({ key, label, icon }) => {
              const data = report.attack_indicators[key as keyof typeof report.attack_indicators];
              // Handle the case where data might be a string or undefined
              if (!data || typeof data === "string") return null;
              const attackData = data as { detected: boolean; evidence?: string; explanation?: string };
              
              return (
                <Grid item xs={12} sm={6} key={key}>
                  <Card variant="outlined" sx={{ bgcolor: attackData.detected ? alpha("#dc2626", 0.05) : alpha("#22c55e", 0.05) }}>
                    <CardContent>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        <Box sx={{ color: attackData.detected ? "error.main" : "success.main" }}>{icon}</Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                          {label}
                        </Typography>
                        <Chip
                          label={attackData.detected ? "DETECTED" : "NOT DETECTED"}
                          size="small"
                          color={attackData.detected ? "error" : "success"}
                          sx={{ ml: "auto" }}
                        />
                      </Box>
                      {/* Show detailed explanation (new field) or evidence (legacy field) */}
                      {(attackData.explanation || attackData.evidence) && (
                        <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: "pre-wrap" }}>
                          {attackData.explanation || attackData.evidence}
                        </Typography>
                      )}
                    </CardContent>
                  </Card>
                </Grid>
              );
            })}
          </Grid>
        </Paper>
      )}

      {/* Indicators of Compromise */}
      {report.indicators_of_compromise && report.indicators_of_compromise.length > 0 && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <GppBadIcon color="error" /> Indicators of Compromise ({report.indicators_of_compromise.length})
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>Value</TableCell>
                  <TableCell>Threat Level</TableCell>
                  <TableCell>Context</TableCell>
                  <TableCell>Action</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {report.indicators_of_compromise.map((ioc, i) => (
                  <TableRow key={i}>
                    <TableCell><Chip label={ioc.type} size="small" variant="outlined" /></TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontWeight: 500 }}>{ioc.value}</TableCell>
                    <TableCell>
                      <Chip
                        label={ioc.threat_level}
                        size="small"
                        sx={{
                          bgcolor: alpha(severityColors[ioc.threat_level.toLowerCase()] || "#888", 0.15),
                          color: severityColors[ioc.threat_level.toLowerCase()] || "#888",
                        }}
                      />
                    </TableCell>
                    <TableCell>{ioc.context}</TableCell>
                    <TableCell>{ioc.recommended_action}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}

      {/* Traffic Analysis - Enhanced */}
      {report.traffic_analysis && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <InsightsIcon color="info" /> Traffic Analysis
          </Typography>
          
          {/* Narrative Summary (new field) */}
          {report.traffic_analysis.narrative_summary && (
            <Typography variant="body1" sx={{ mb: 3, whiteSpace: "pre-wrap", lineHeight: 1.7 }}>
              {report.traffic_analysis.narrative_summary}
            </Typography>
          )}
          
          <Typography variant="body1" sx={{ mb: 2, fontWeight: 500 }}>
            {report.traffic_analysis.overall_assessment}
          </Typography>
          
          {/* Protocol Breakdown Explained (new field) */}
          {report.traffic_analysis.protocol_breakdown_explained && (
            <Box sx={{ mb: 2, p: 2, bgcolor: alpha("#3b82f6", 0.05), borderRadius: 1, borderLeft: "4px solid #3b82f6" }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>📊 Protocol Breakdown</Typography>
              <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
                {report.traffic_analysis.protocol_breakdown_explained}
              </Typography>
            </Box>
          )}
          
          {/* Data Flow Analysis (new field) */}
          {(report.traffic_analysis.data_flow_analysis || report.traffic_analysis.data_transfer_analysis) && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>📈 Data Flow Analysis</Typography>
              <Typography variant="body2" color="text.secondary">
                {report.traffic_analysis.data_flow_analysis || report.traffic_analysis.data_transfer_analysis}
              </Typography>
            </Box>
          )}
          
          {/* Encryption Assessment */}
          {(report.traffic_analysis.encryption_assessment || report.traffic_analysis.encrypted_vs_cleartext) && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>🔐 Encryption Assessment</Typography>
              <Typography variant="body2" color="text.secondary">
                {report.traffic_analysis.encryption_assessment || report.traffic_analysis.encrypted_vs_cleartext}
              </Typography>
            </Box>
          )}
          
          {/* Suspicious Patterns - Handle both string[] and object[] */}
          {report.traffic_analysis.suspicious_patterns && report.traffic_analysis.suspicious_patterns.length > 0 && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>⚠️ Suspicious Patterns:</Typography>
              {/* Check if patterns are strings or objects */}
              {typeof report.traffic_analysis.suspicious_patterns[0] === 'string' ? (
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                  {(report.traffic_analysis.suspicious_patterns as string[]).map((pattern, i) => (
                    <Chip key={i} label={pattern} color="warning" variant="outlined" />
                  ))}
                </Box>
              ) : (
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {(report.traffic_analysis.suspicious_patterns as Array<{ pattern_name: string; description: string; evidence: string; severity: string }>).map((pattern, i) => (
                    <Card key={i} variant="outlined" sx={{ borderLeft: `4px solid ${severityColors[pattern.severity?.toLowerCase()] || "#f97316"}` }}>
                      <CardContent sx={{ py: 1.5 }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <Chip label={pattern.severity || "Warning"} size="small" color="warning" />
                          <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>{pattern.pattern_name}</Typography>
                        </Box>
                        <Typography variant="body2" sx={{ mb: 1 }}>{pattern.description}</Typography>
                        {pattern.evidence && (
                          <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block" }}>
                            Evidence: {pattern.evidence}
                          </Typography>
                        )}
                      </CardContent>
                    </Card>
                  ))}
                </Box>
              )}
            </Box>
          )}
          
          {report.traffic_analysis.protocols_of_concern && report.traffic_analysis.protocols_of_concern.length > 0 && (
            <Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>🔴 Protocols of Concern:</Typography>
              {report.traffic_analysis.protocols_of_concern.map((proto, i) => (
                <Card key={i} variant="outlined" sx={{ mb: 1 }}>
                  <CardContent sx={{ py: 1 }}>
                    <Typography variant="subtitle2">{proto.protocol}</Typography>
                    <Typography variant="body2" color="text.secondary">{proto.concern}</Typography>
                    {proto.affected_hosts && proto.affected_hosts.length > 0 && (
                      <Typography variant="caption" sx={{ fontFamily: "monospace" }}>
                        Hosts: {proto.affected_hosts.join(", ")}
                      </Typography>
                    )}
                  </CardContent>
                </Card>
              ))}
            </Box>
          )}
        </Paper>
      )}

      {/* DNS Analysis - Enhanced */}
      {report.dns_analysis && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <DnsIcon color="secondary" /> DNS Analysis
          </Typography>
          
          {/* Narrative Summary (new field) */}
          {report.dns_analysis.narrative_summary && (
            <Typography variant="body1" sx={{ mb: 3, whiteSpace: "pre-wrap", lineHeight: 1.7 }}>
              {report.dns_analysis.narrative_summary}
            </Typography>
          )}
          
          <Typography variant="body1" sx={{ mb: 2, fontWeight: 500 }}>
            {report.dns_analysis.overall_assessment}
          </Typography>
          
          {/* Legitimate Activity (new field) */}
          {report.dns_analysis.legitimate_activity && (
            <Box sx={{ mb: 2, p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 1 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "success.main", mb: 1 }}>✅ Legitimate Activity</Typography>
              <Typography variant="body2">{report.dns_analysis.legitimate_activity}</Typography>
            </Box>
          )}
          
          {/* DGA Analysis */}
          {(report.dns_analysis.dga_analysis || report.dns_analysis.dga_indicators) && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>🎲 DGA (Domain Generation Algorithm) Analysis</Typography>
              <Typography variant="body2" color="text.secondary">
                {report.dns_analysis.dga_analysis || report.dns_analysis.dga_indicators}
              </Typography>
            </Box>
          )}
          
          {/* Tunneling Analysis */}
          {(report.dns_analysis.tunneling_analysis || report.dns_analysis.tunneling_indicators) && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>🚇 DNS Tunneling Analysis</Typography>
              <Typography variant="body2" color="text.secondary">
                {report.dns_analysis.tunneling_analysis || report.dns_analysis.tunneling_indicators}
              </Typography>
            </Box>
          )}
          
          {/* Suspicious Domains */}
          {report.dns_analysis.suspicious_domains && report.dns_analysis.suspicious_domains.length > 0 && (
            <Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: "warning.main" }}>⚠️ Suspicious Domains</Typography>
              <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                {report.dns_analysis.suspicious_domains.map((domain, i) => (
                  <Card key={i} variant="outlined" sx={{ borderLeft: "4px solid #f97316" }}>
                    <CardContent sx={{ py: 1.5 }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        <Typography variant="subtitle2" sx={{ fontFamily: "monospace", fontWeight: 600 }}>
                          {domain.domain}
                        </Typography>
                        <Chip label={domain.threat_category} size="small" color="warning" variant="outlined" />
                      </Box>
                      <Typography variant="body2" color="text.secondary">
                        {domain.why_suspicious || domain.reason}
                      </Typography>
                      {domain.recommended_action && (
                        <Box sx={{ mt: 1, display: "flex", alignItems: "center", gap: 1 }}>
                          <RecommendIcon fontSize="small" color="success" />
                          <Typography variant="caption" color="success.main">{domain.recommended_action}</Typography>
                        </Box>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </Box>
            </Box>
          )}
        </Paper>
      )}

      {/* Hosts Analysis - NEW SECTION */}
      {report.hosts_analysis && report.hosts_analysis.length > 0 && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <DevicesIcon color="primary" /> Host Behavior Analysis ({report.hosts_analysis.length} hosts)
          </Typography>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {report.hosts_analysis.map((host, i) => (
              <Card key={i} variant="outlined" sx={{ borderLeft: `4px solid ${severityColors[host.risk_assessment?.toLowerCase().includes('high') ? 'high' : host.risk_assessment?.toLowerCase().includes('critical') ? 'critical' : 'low'] || "#3b82f6"}` }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2, flexWrap: "wrap" }}>
                    <Typography variant="subtitle1" sx={{ fontFamily: "monospace", fontWeight: 600 }}>
                      {host.ip_address}
                    </Typography>
                    {host.hostname && (
                      <Typography variant="body2" color="text.secondary">
                        ({host.hostname})
                      </Typography>
                    )}
                    <Chip label={host.likely_role} size="small" variant="outlined" />
                    {host.connections_made && (
                      <Chip label={`${host.connections_made} connections`} size="small" color="info" variant="outlined" />
                    )}
                    {host.data_transferred && (
                      <Chip label={host.data_transferred} size="small" color="secondary" variant="outlined" />
                    )}
                  </Box>
                  
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    {host.behavior_summary}
                  </Typography>
                  
                  {host.services_identified && host.services_identified.length > 0 && (
                    <Box sx={{ mb: 1 }}>
                      <Typography variant="caption" sx={{ fontWeight: 600 }}>Services: </Typography>
                      {host.services_identified.map((svc, j) => (
                        <Chip key={j} label={svc} size="small" sx={{ mr: 0.5, mb: 0.5 }} variant="outlined" />
                      ))}
                    </Box>
                  )}
                  
                  <Box sx={{ p: 1.5, bgcolor: alpha(theme.palette.divider, 0.3), borderRadius: 1, mt: 1 }}>
                    <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>Risk Assessment</Typography>
                    <Typography variant="body2">{host.risk_assessment}</Typography>
                  </Box>
                  
                  {host.concerns && host.concerns.length > 0 && (
                    <Box sx={{ mt: 1 }}>
                      <Typography variant="caption" sx={{ fontWeight: 700, color: "warning.main" }}>Concerns:</Typography>
                      <List dense disablePadding>
                        {host.concerns.map((concern, j) => (
                          <ListItem key={j} sx={{ py: 0 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}><WarningIcon fontSize="small" color="warning" /></ListItemIcon>
                            <ListItemText primary={concern} primaryTypographyProps={{ variant: "body2" }} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}
                </CardContent>
              </Card>
            ))}
          </Box>
        </Paper>
      )}

      {/* Affected Assets (legacy) */}
      {report.affected_assets && report.affected_assets.length > 0 && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <DevicesIcon color="primary" /> Affected Assets ({report.affected_assets.length})
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>IP Address</TableCell>
                  <TableCell>Role</TableCell>
                  <TableCell>Risk Level</TableCell>
                  <TableCell>Services</TableCell>
                  <TableCell>Concerns</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {report.affected_assets.map((asset, i) => (
                  <TableRow key={i}>
                    <TableCell sx={{ fontFamily: "monospace", fontWeight: 500 }}>
                      {asset.ip}
                      {asset.hostname && <Typography variant="caption" display="block" color="text.secondary">{asset.hostname}</Typography>}
                    </TableCell>
                    <TableCell><Chip label={asset.role} size="small" variant="outlined" /></TableCell>
                    <TableCell>
                      <Chip
                        label={asset.risk_level}
                        size="small"
                        sx={{
                          bgcolor: alpha(severityColors[asset.risk_level.toLowerCase()] || "#888", 0.15),
                          color: severityColors[asset.risk_level.toLowerCase()] || "#888",
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      {asset.services_exposed?.map((svc, j) => (
                        <Chip key={j} label={svc} size="small" sx={{ mr: 0.5, mb: 0.5 }} variant="outlined" />
                      ))}
                    </TableCell>
                    <TableCell>{asset.concerns}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}

      {/* Timeline Analysis */}
      {report.timeline_analysis && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TimelineIcon color="info" /> Timeline Analysis
          </Typography>
          <Typography variant="body1" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.7 }}>{report.timeline_analysis}</Typography>
        </Paper>
      )}

      {/* Recommendations - Enhanced */}
      {report.recommendations && report.recommendations.length > 0 && (
        <Paper sx={{ p: 3, bgcolor: alpha(theme.palette.success.main, 0.05) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <RecommendIcon color="success" /> Recommendations ({report.recommendations.length})
          </Typography>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {report.recommendations.map((rec, i) => (
              <Card key={i} variant="outlined" sx={{ borderLeft: `4px solid ${priorityColors[rec.priority.toLowerCase()] || "#888"}` }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, flexWrap: "wrap" }}>
                    <Chip
                      label={rec.priority.toUpperCase()}
                      size="small"
                      sx={{
                        bgcolor: priorityColors[rec.priority.toLowerCase()] || "#888",
                        color: "white",
                        fontWeight: 700,
                      }}
                    />
                    {(rec.category || rec.responsible_team) && (
                      <Chip label={rec.category || rec.responsible_team} size="small" variant="outlined" />
                    )}
                    {(rec.effort || rec.effort_level) && (
                      <Chip label={`Effort: ${rec.effort || rec.effort_level}`} size="small" variant="outlined" />
                    )}
                  </Box>
                  
                  {/* Title (new) or Action (legacy) */}
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                    {rec.title || rec.action}
                  </Typography>
                  
                  {/* Detailed Action (new field) */}
                  {rec.detailed_action && (
                    <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                      {rec.detailed_action}
                    </Typography>
                  )}
                  
                  {/* Rationale */}
                  <Box sx={{ bgcolor: alpha(theme.palette.divider, 0.3), p: 1.5, borderRadius: 1, mb: 1 }}>
                    <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>Why This Matters</Typography>
                    <Typography variant="body2" color="text.secondary">
                      {rec.rationale}
                    </Typography>
                  </Box>
                  
                  {/* Expected Outcome (new field) */}
                  {rec.expected_outcome && (
                    <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1, mt: 1 }}>
                      <CheckCircleIcon fontSize="small" color="success" sx={{ mt: 0.2 }} />
                      <Typography variant="body2" color="success.main">
                        <strong>Expected Outcome:</strong> {rec.expected_outcome}
                      </Typography>
                    </Box>
                  )}
                </CardContent>
              </Card>
            ))}
          </Box>
        </Paper>
      )}

      {/* Conclusion - NEW SECTION */}
      {report.conclusion && (
        <Paper sx={{ p: 3, bgcolor: alpha(theme.palette.primary.main, 0.05), border: `2px solid ${theme.palette.primary.main}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "primary.main" }}>
            <ReportIcon color="primary" /> Conclusion
          </Typography>
          <Typography variant="body1" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.9 }}>
            {report.conclusion}
          </Typography>
        </Paper>
      )}
    </Box>
  );
}

export default function PcapAnalyzerPage() {
  const theme = useTheme();
  const [searchParams] = useSearchParams();
  
  // Get project context from URL params (when navigating from a project)
  const projectId = searchParams.get("projectId") ? parseInt(searchParams.get("projectId")!, 10) : undefined;
  const projectName = searchParams.get("projectName") || undefined;
  
  // File upload state
  const [files, setFiles] = useState<File[]>([]);
  const [analyzing, setAnalyzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<MultiPcapAnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusChecked, setStatusChecked] = useState(false);
  const [pcapAvailable, setPcapAvailable] = useState(true);

  // Chat state
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Tab and saved reports state
  const [activeTab, setActiveTab] = useState(0);
  const [savedReports, setSavedReports] = useState<SavedReportSummary[]>([]);
  const [savedReportsTotal, setSavedReportsTotal] = useState(0);
  const [loadingReports, setLoadingReports] = useState(false);
  const [viewingReport, setViewingReport] = useState<SavedReportDetail | null>(null);
  const [loadingReportDetail, setLoadingReportDetail] = useState(false);
  
  // Export state
  const [exportAnchorEl, setExportAnchorEl] = useState<null | HTMLElement>(null);
  const [exportReportId, setExportReportId] = useState<number | null>(null);

  // Auto-scroll chat to bottom when new messages arrive
  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [chatMessages]);

  // Handle sending chat message
  const handleSendMessage = async () => {
    // Support both fresh results AND saved reports
    const hasContext = results || viewingReport;
    if (!chatInput.trim() || !hasContext || chatLoading) return;

    const userMessage: ChatMessage = { role: "user", content: chatInput.trim() };
    setChatMessages((prev) => [...prev, userMessage]);
    setChatInput("");
    setChatLoading(true);
    setChatError(null);

    try {
      let pcapContext;
      
      if (results) {
        // Fresh analysis results
        const firstAnalysis = results.analyses[0];
        pcapContext = {
          summary: firstAnalysis?.summary,
          findings: firstAnalysis?.findings,
          ai_analysis: firstAnalysis?.ai_analysis,
        };
      } else if (viewingReport) {
        // Saved report - reconstruct context from saved data
        pcapContext = {
          summary: {
            total_packets: viewingReport.summary_data?.total_packets,
            total_findings: viewingReport.summary_data?.total_findings,
            ...viewingReport.summary_data?.summaries?.[0],
          },
          findings: viewingReport.findings_data,
          ai_analysis: viewingReport.ai_report,
        };
      }

      const response = await chatAboutPcap({
        message: userMessage.content,
        conversation_history: chatMessages,
        pcap_context: pcapContext!,
      });

      if (response.error) {
        setChatError(response.error);
      } else {
        const assistantMessage: ChatMessage = { role: "assistant", content: response.response };
        setChatMessages((prev) => [...prev, assistantMessage]);
      }
    } catch (err: any) {
      setChatError(err.message || "Failed to send message");
    } finally {
      setChatLoading(false);
    }
  };

  // Handle Enter key in chat input
  const handleChatKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  // Check if PCAP analysis is available on mount
  const checkStatus = useCallback(async () => {
    if (statusChecked) return;
    try {
      const status = await getPcapStatus();
      setPcapAvailable(status.available);
      setStatusChecked(true);
    } catch {
      setPcapAvailable(false);
      setStatusChecked(true);
    }
  }, [statusChecked]);

  // Check status on first render
  useState(() => {
    checkStatus();
  });

  // Load saved reports
  const loadSavedReports = useCallback(async () => {
    setLoadingReports(true);
    try {
      const result = await getPcapReports(0, 50);
      setSavedReports(result.reports);
      setSavedReportsTotal(result.total);
    } catch (err: any) {
      console.error("Failed to load saved reports:", err);
    } finally {
      setLoadingReports(false);
    }
  }, []);

  // Load reports when switching to saved reports tab
  useEffect(() => {
    if (activeTab === 1) {
      loadSavedReports();
    }
  }, [activeTab, loadSavedReports]);

  // View a saved report
  const handleViewReport = async (reportId: number) => {
    setLoadingReportDetail(true);
    // Clear chat when switching to a different report
    setChatMessages([]);
    setChatError(null);
    try {
      const detail = await getPcapReport(reportId);
      setViewingReport(detail);
    } catch (err: any) {
      setError(err.message || "Failed to load report");
    } finally {
      setLoadingReportDetail(false);
    }
  };

  // Delete a saved report
  const handleDeleteReport = async (reportId: number) => {
    if (!confirm("Are you sure you want to delete this report?")) return;
    try {
      await deletePcapReport(reportId);
      // Refresh the list
      loadSavedReports();
      // Clear viewing if we deleted the one being viewed
      if (viewingReport?.id === reportId) {
        setViewingReport(null);
        setChatMessages([]);
      }
    } catch (err: any) {
      setError(err.message || "Failed to delete report");
    }
  };

  // Go back from viewing a report
  const handleBackToReports = () => {
    setViewingReport(null);
    setChatMessages([]);
  };

  // Export handlers
  const handleExportClick = (event: React.MouseEvent<HTMLElement>, reportId: number) => {
    setExportAnchorEl(event.currentTarget);
    setExportReportId(reportId);
  };

  const handleExportClose = () => {
    setExportAnchorEl(null);
    setExportReportId(null);
  };

  const handleExport = async (format: "markdown" | "pdf" | "docx") => {
    if (!exportReportId) return;
    try {
      const blob = await apiClient.exportNetworkReport(exportReportId, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `pcap_report_${exportReportId}.${format === "markdown" ? "md" : format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setError(err.message || "Export failed");
    }
    handleExportClose();
  };

  const onDrop = useCallback((acceptedFiles: File[]) => {
    setFiles((prev) => [...prev, ...acceptedFiles]);
    setError(null);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      "application/vnd.tcpdump.pcap": [".pcap", ".pcapng", ".cap"],
      "application/octet-stream": [".pcap", ".pcapng", ".cap"],
    },
    maxSize: 100 * 1024 * 1024, // 100MB
  });

  const removeFile = (index: number) => {
    setFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const handleAnalyze = async () => {
    if (files.length === 0) return;

    setAnalyzing(true);
    setProgress(10);
    setError(null);
    setResults(null);

    try {
      setProgress(30);
      const result = await analyzePcaps(files, true, 100000, true, projectId);
      setProgress(100);
      setResults(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setAnalyzing(false);
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const formatDuration = (seconds: number): string => {
    if (seconds < 60) return `${seconds.toFixed(1)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.floor(seconds % 60)}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  };

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Breadcrumbs */}
      <Breadcrumbs 
        separator={<NavigateNextIcon fontSize="small" />} 
        sx={{ mb: 3 }}
      >
        {projectId && projectName ? (
          <>
            <MuiLink
              component={Link}
              to={`/projects/${projectId}`}
              sx={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: 0.5,
                textDecoration: 'none',
                color: 'text.secondary',
                '&:hover': { color: 'primary.main' }
              }}
            >
              📁 {projectName}
            </MuiLink>
            <MuiLink
              component={Link}
              to={`/projects/${projectId}?tab=network`}
              sx={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: 0.5,
                textDecoration: 'none',
                color: 'text.secondary',
                '&:hover': { color: 'primary.main' }
              }}
            >
              <HubIcon fontSize="small" />
              Network
            </MuiLink>
          </>
        ) : (
          <MuiLink
            component={Link}
            to="/network"
            sx={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: 0.5,
              textDecoration: 'none',
              color: 'text.secondary',
              '&:hover': { color: 'primary.main' }
            }}
          >
            <HubIcon fontSize="small" />
            Network Analysis
          </MuiLink>
        )}
        <Typography color="text.primary">PCAP Analyzer</Typography>
      </Breadcrumbs>

      {/* Header */}
      <Box sx={{ mb: 4, textAlign: "center" }}>
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 2, mb: 2 }}>
          <NetworkCheckIcon sx={{ fontSize: 48, color: theme.palette.primary.main }} />
          <Typography
            variant="h3"
            sx={{
              fontWeight: 800,
              background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
            }}
          >
            PCAP Analyzer
          </Typography>
        </Box>
        <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 700, mx: "auto", mb: 2 }}>
          Upload Wireshark packet captures (.pcap, .pcapng) for security analysis. Detects cleartext credentials,
          suspicious traffic patterns, protocol anomalies, and more.
        </Typography>
        {projectId && projectName && (
          <Alert 
            severity="info" 
            sx={{ 
              maxWidth: 500, 
              mx: "auto", 
              mb: 2,
              '& .MuiAlert-message': { width: '100%', textAlign: 'center' }
            }}
          >
            Reports will be saved to project: <strong>{projectName}</strong>
          </Alert>
        )}
        <Chip
          component={Link}
          to="/learn/wireshark"
          icon={<InfoIcon sx={{ fontSize: 16 }} />}
          label="Learn Wireshark Essentials →"
          clickable
          size="small"
          sx={{
            background: alpha("#06b6d4", 0.1),
            border: `1px solid ${alpha("#06b6d4", 0.3)}`,
            color: "#22d3ee",
            fontWeight: 500,
            "&:hover": {
              background: alpha("#06b6d4", 0.2),
            },
          }}
        />
      </Box>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={activeTab}
          onChange={(_, newValue) => setActiveTab(newValue)}
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab 
            icon={<CloudUploadIcon />} 
            iconPosition="start" 
            label="New Analysis" 
          />
          <Tab 
            icon={<HistoryIcon />} 
            iconPosition="start" 
            label={`Saved Reports${savedReportsTotal > 0 ? ` (${savedReportsTotal})` : ''}`}
          />
        </Tabs>
      </Paper>

      {/* Tab Content */}
      {activeTab === 0 && (
        <>
          {/* Status Warning */}
          {!pcapAvailable && statusChecked && (
            <Alert severity="warning" sx={{ mb: 3 }}>
              PCAP analysis is not available. The server needs scapy installed: <code>pip install scapy</code>
            </Alert>
          )}

      {/* Upload Section */}
      <Paper
        {...getRootProps()}
        sx={{
          p: 4,
          mb: 3,
          textAlign: "center",
          cursor: "pointer",
          border: `2px dashed ${isDragActive ? theme.palette.primary.main : alpha(theme.palette.divider, 0.3)}`,
          bgcolor: isDragActive ? alpha(theme.palette.primary.main, 0.05) : "transparent",
          transition: "all 0.2s ease",
          "&:hover": {
            borderColor: theme.palette.primary.main,
            bgcolor: alpha(theme.palette.primary.main, 0.02),
          },
        }}
      >
        <input {...getInputProps()} />
        <CloudUploadIcon sx={{ fontSize: 64, color: "text.secondary", mb: 2 }} />
        <Typography variant="h6" gutterBottom>
          {isDragActive ? "Drop PCAP files here..." : "Drag & drop PCAP files here"}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          or click to select files • Supports .pcap, .pcapng, .cap • Max 100MB per file
        </Typography>
      </Paper>

      {/* Selected Files */}
      {files.length > 0 && (
        <Paper sx={{ p: 2, mb: 3 }}>
          <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600 }}>
            Selected Files ({files.length})
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {files.map((file, index) => (
              <Chip
                key={index}
                label={`${file.name} (${formatBytes(file.size)})`}
                onDelete={() => removeFile(index)}
                deleteIcon={<DeleteIcon />}
                sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}
              />
            ))}
          </Box>
          <Box sx={{ mt: 2, display: "flex", gap: 2, alignItems: "center" }}>
            <Button
              variant="contained"
              onClick={handleAnalyze}
              disabled={analyzing || !pcapAvailable}
              startIcon={analyzing ? <CircularProgress size={20} /> : <SecurityIcon />}
              sx={{ px: 4 }}
            >
              {analyzing ? "Analyzing..." : "Analyze PCAPs"}
            </Button>
            <Button variant="outlined" onClick={() => setFiles([])} disabled={analyzing}>
              Clear All
            </Button>
          </Box>
          {analyzing && <LinearProgress sx={{ mt: 2 }} variant="determinate" value={progress} />}
        </Paper>
      )}

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Results */}
      {results && (
        <Box>
          {/* Results Header with Export */}
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
            <Typography variant="h5" fontWeight={700}>
              Analysis Results
            </Typography>
            <Box sx={{ display: "flex", gap: 1 }}>
              {results.report_id && (
                <>
                  <Button
                    startIcon={<DownloadIcon />}
                    onClick={(e) => handleExportClick(e, results.report_id!)}
                    variant="outlined"
                  >
                    Export
                  </Button>
                  <Menu
                    anchorEl={exportAnchorEl}
                    open={Boolean(exportAnchorEl) && exportReportId === results.report_id}
                    onClose={handleExportClose}
                  >
                    <MenuItem onClick={() => handleExport("markdown")}>
                      <ListItemIcon>
                        <DescriptionIcon fontSize="small" />
                      </ListItemIcon>
                      <ListItemText>Markdown (.md)</ListItemText>
                    </MenuItem>
                    <MenuItem onClick={() => handleExport("pdf")}>
                      <ListItemIcon>
                        <PictureAsPdfIcon fontSize="small" />
                      </ListItemIcon>
                      <ListItemText>PDF (.pdf)</ListItemText>
                    </MenuItem>
                    <MenuItem onClick={() => handleExport("docx")}>
                      <ListItemIcon>
                        <ArticleIcon fontSize="small" />
                      </ListItemIcon>
                      <ListItemText>Word (.docx)</ListItemText>
                    </MenuItem>
                  </Menu>
                </>
              )}
              <Button
                onClick={() => {
                  setResults(null);
                  setFiles([]);
                }}
              >
                New Analysis
              </Button>
            </Box>
          </Box>
          {/* Summary Cards */}
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} sm={6} md={3}>
              <Card sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                <CardContent sx={{ textAlign: "center" }}>
                  <RouterIcon sx={{ fontSize: 40, color: theme.palette.primary.main, mb: 1 }} />
                  <Typography variant="h4" fontWeight={700}>
                    {results.total_files}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Files Analyzed
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card sx={{ bgcolor: alpha(theme.palette.info.main, 0.1) }}>
                <CardContent sx={{ textAlign: "center" }}>
                  <InsightsIcon sx={{ fontSize: 40, color: theme.palette.info.main, mb: 1 }} />
                  <Typography variant="h4" fontWeight={700}>
                    {results.total_packets.toLocaleString()}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Total Packets
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card
                sx={{
                  bgcolor: alpha(
                    results.total_findings > 0 ? theme.palette.error.main : theme.palette.success.main,
                    0.1
                  ),
                }}
              >
                <CardContent sx={{ textAlign: "center" }}>
                  {results.total_findings > 0 ? (
                    <WarningIcon sx={{ fontSize: 40, color: theme.palette.error.main, mb: 1 }} />
                  ) : (
                    <CheckCircleIcon sx={{ fontSize: 40, color: theme.palette.success.main, mb: 1 }} />
                  )}
                  <Typography variant="h4" fontWeight={700}>
                    {results.total_findings}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Security Findings
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card sx={{ bgcolor: alpha(theme.palette.secondary.main, 0.1) }}>
                <CardContent sx={{ textAlign: "center" }}>
                  <DnsIcon sx={{ fontSize: 40, color: theme.palette.secondary.main, mb: 1 }} />
                  <Typography variant="h4" fontWeight={700}>
                    {results.analyses.reduce((sum, a) => sum + a.summary.dns_queries.length, 0)}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    DNS Queries
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Per-File Results */}
          {results.analyses.map((analysis, index) => (
            <Accordion key={index} defaultExpanded={results.analyses.length === 1}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 600 }}>
                    {analysis.filename}
                  </Typography>
                  <Chip
                    label={`${analysis.summary.total_packets.toLocaleString()} packets`}
                    size="small"
                    sx={{ bgcolor: alpha(theme.palette.info.main, 0.1) }}
                  />
                  <Chip
                    label={formatDuration(analysis.summary.duration_seconds)}
                    size="small"
                    sx={{ bgcolor: alpha(theme.palette.secondary.main, 0.1) }}
                  />
                  {analysis.findings.length > 0 && (
                    <Chip
                      label={`${analysis.findings.length} findings`}
                      size="small"
                      color="error"
                    />
                  )}
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={3}>
                  {/* Protocol Distribution */}
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2 }}>
                      <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600 }}>
                        Protocol Distribution
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                        {Object.entries(analysis.summary.protocols)
                          .sort(([, a], [, b]) => b - a)
                          .slice(0, 12)
                          .map(([proto, count]) => (
                            <Chip
                              key={proto}
                              label={`${proto}: ${count.toLocaleString()}`}
                              size="small"
                              sx={{
                                bgcolor: alpha(theme.palette.primary.main, 0.1),
                                fontFamily: "monospace",
                              }}
                            />
                          ))}
                      </Box>
                    </Paper>
                  </Grid>

                  {/* Top Talkers */}
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2 }}>
                      <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600 }}>
                        Top Communicating Hosts
                      </Typography>
                      <TableContainer>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>IP Address</TableCell>
                              <TableCell align="right">Packets</TableCell>
                              <TableCell align="right">Bytes</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {analysis.summary.top_talkers.slice(0, 5).map((host, i) => (
                              <TableRow key={i}>
                                <TableCell sx={{ fontFamily: "monospace" }}>{host.ip}</TableCell>
                                <TableCell align="right">{host.packets.toLocaleString()}</TableCell>
                                <TableCell align="right">{formatBytes(host.bytes)}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </Paper>
                  </Grid>

                  {/* DNS Queries */}
                  {analysis.summary.dns_queries.length > 0 && (
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2 }}>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                          <DnsIcon fontSize="small" />
                          DNS Queries ({analysis.summary.dns_queries.length})
                        </Typography>
                        <Box sx={{ maxHeight: 200, overflow: "auto" }}>
                          {analysis.summary.dns_queries.slice(0, 30).map((query, i) => (
                            <Typography
                              key={i}
                              variant="body2"
                              sx={{ fontFamily: "monospace", fontSize: "0.75rem", mb: 0.5 }}
                            >
                              {query}
                            </Typography>
                          ))}
                          {analysis.summary.dns_queries.length > 30 && (
                            <Typography variant="caption" color="text.secondary">
                              ... and {analysis.summary.dns_queries.length - 30} more
                            </Typography>
                          )}
                        </Box>
                      </Paper>
                    </Grid>
                  )}

                  {/* HTTP Hosts */}
                  {analysis.summary.http_hosts.length > 0 && (
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2 }}>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                          <LanguageIcon fontSize="small" />
                          HTTP Hosts ({analysis.summary.http_hosts.length})
                        </Typography>
                        <Box sx={{ maxHeight: 200, overflow: "auto" }}>
                          {analysis.summary.http_hosts.slice(0, 30).map((host, i) => (
                            <Typography
                              key={i}
                              variant="body2"
                              sx={{ fontFamily: "monospace", fontSize: "0.75rem", mb: 0.5 }}
                            >
                              {host}
                            </Typography>
                          ))}
                          {analysis.summary.http_hosts.length > 30 && (
                            <Typography variant="caption" color="text.secondary">
                              ... and {analysis.summary.http_hosts.length - 30} more
                            </Typography>
                          )}
                        </Box>
                      </Paper>
                    </Grid>
                  )}

                  {/* Network Topology Graph */}
                  {analysis.summary.topology_nodes && analysis.summary.topology_nodes.length > 0 && (
                    <Grid item xs={12}>
                      <NetworkTopologyGraph
                        nodes={analysis.summary.topology_nodes as TopologyNode[]}
                        links={(analysis.summary.topology_links || []) as TopologyLink[]}
                        title={`Network Topology - ${analysis.filename}`}
                        height={450}
                        onNodeClick={(node) => {
                          console.log("Clicked node:", node);
                        }}
                      />
                    </Grid>
                  )}

                  {/* Security Findings */}
                  {analysis.findings.length > 0 && (
                    <Grid item xs={12}>
                      <Paper sx={{ p: 2 }}>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600, color: theme.palette.error.main }}>
                          ⚠️ Security Findings ({analysis.findings.length})
                        </Typography>
                        <TableContainer>
                          <Table size="small">
                            <TableHead>
                              <TableRow>
                                <TableCell>Severity</TableCell>
                                <TableCell>Title</TableCell>
                                <TableCell>Source</TableCell>
                                <TableCell>Destination</TableCell>
                                <TableCell>Protocol</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {analysis.findings.map((finding, i) => (
                                <TableRow key={i}>
                                  <TableCell>
                                    <Chip
                                      label={finding.severity.toUpperCase()}
                                      size="small"
                                      sx={{
                                        bgcolor: alpha(severityColors[finding.severity] || "#888", 0.15),
                                        color: severityColors[finding.severity] || "#888",
                                        fontWeight: 700,
                                        fontSize: "0.7rem",
                                      }}
                                    />
                                  </TableCell>
                                  <TableCell>
                                    <Tooltip title={finding.description}>
                                      <Typography variant="body2" sx={{ fontWeight: 500 }}>
                                        {finding.title}
                                      </Typography>
                                    </Tooltip>
                                  </TableCell>
                                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                                    {finding.source_ip || "-"}
                                  </TableCell>
                                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                                    {finding.dest_ip || "-"}
                                    {finding.port && `:${finding.port}`}
                                  </TableCell>
                                  <TableCell>{finding.protocol || "-"}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </Paper>
                    </Grid>
                  )}

                  {/* Conversations */}
                  {analysis.conversations.length > 0 && (
                    <Grid item xs={12}>
                      <Paper sx={{ p: 2 }}>
                        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 600 }}>
                          Top Network Conversations
                        </Typography>
                        <TableContainer>
                          <Table size="small">
                            <TableHead>
                              <TableRow>
                                <TableCell>Source</TableCell>
                                <TableCell>Destination</TableCell>
                                <TableCell>Service</TableCell>
                                <TableCell align="right">Packets</TableCell>
                                <TableCell align="right">Bytes</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {analysis.conversations.slice(0, 10).map((conv, i) => (
                                <TableRow key={i}>
                                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                                    {conv.src}:{conv.sport}
                                  </TableCell>
                                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                                    {conv.dst}:{conv.dport}
                                  </TableCell>
                                  <TableCell>
                                    <Chip label={conv.service} size="small" variant="outlined" />
                                  </TableCell>
                                  <TableCell align="right">{conv.packets.toLocaleString()}</TableCell>
                                  <TableCell align="right">{formatBytes(conv.bytes)}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </Paper>
                    </Grid>
                  )}

                  {/* AI Analysis */}
                  {analysis.ai_analysis && (
                    <Grid item xs={12}>
                      <Paper
                        sx={{
                          p: 3,
                          bgcolor: alpha(theme.palette.secondary.main, 0.03),
                          border: `1px solid ${alpha(theme.palette.secondary.main, 0.2)}`,
                        }}
                      >
                        <Typography
                          variant="h5"
                          sx={{ mb: 3, fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}
                        >
                          <InsightsIcon sx={{ color: theme.palette.secondary.main, fontSize: 32 }} />
                          AI Security Assessment Report
                        </Typography>
                        <Divider sx={{ mb: 3 }} />
                        
                        {/* Check if it's a structured report or raw text */}
                        {(() => {
                          const aiData = analysis.ai_analysis as AIAnalysisResult | string;
                          if (typeof aiData === "object" && "structured_report" in aiData && aiData.structured_report) {
                            return <StructuredReportSection report={aiData.structured_report} theme={theme} />;
                          } else if (typeof aiData === "object" && "raw_analysis" in aiData && aiData.raw_analysis) {
                            return (
                              <Box>
                                <Alert severity="info" sx={{ mb: 2 }}>
                                  Displaying raw analysis (structured parsing unavailable)
                                </Alert>
                                <Box
                                  sx={{
                                    "& h1, & h2, & h3": { mt: 2, mb: 1 },
                                    "& p": { mb: 1.5 },
                                    "& ul, & ol": { pl: 2, mb: 1.5 },
                                    "& li": { mb: 0.5 },
                                    "& code": {
                                      bgcolor: alpha(theme.palette.primary.main, 0.1),
                                      px: 0.5,
                                      borderRadius: 0.5,
                                      fontFamily: "monospace",
                                    },
                                  }}
                                >
                                  <ReactMarkdown>{aiData.raw_analysis}</ReactMarkdown>
                                </Box>
                              </Box>
                            );
                          } else if (typeof aiData === "object" && "error" in aiData && aiData.error) {
                            return <Alert severity="error">{aiData.error}</Alert>;
                          } else if (typeof aiData === "string") {
                            return (
                              <Box
                                sx={{
                                  "& h1, & h2, & h3": { mt: 2, mb: 1 },
                                  "& p": { mb: 1.5 },
                                  "& ul, & ol": { pl: 2, mb: 1.5 },
                                  "& li": { mb: 0.5 },
                                  "& code": {
                                    bgcolor: alpha(theme.palette.primary.main, 0.1),
                                    px: 0.5,
                                    borderRadius: 0.5,
                                    fontFamily: "monospace",
                                  },
                                }}
                              >
                                <ReactMarkdown>{aiData}</ReactMarkdown>
                              </Box>
                            );
                          }
                          return null;
                        })()}
                      </Paper>
                    </Grid>
                  )}
                </Grid>
              </AccordionDetails>
            </Accordion>
          ))}
        </Box>
      )}

      {/* Empty State */}
      {!results && files.length === 0 && !error && (
        <Paper sx={{ p: 6, textAlign: "center" }}>
          <NetworkCheckIcon sx={{ fontSize: 80, color: "text.disabled", mb: 2 }} />
          <Typography variant="h6" color="text.secondary" gutterBottom>
            No PCAP files selected
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Upload Wireshark captures to analyze network traffic for security issues
          </Typography>
        </Paper>
      )}
        </>
      )}

      {/* Tab 1: Saved Reports */}
      {activeTab === 1 && (
        <Box>
          {loadingReports ? (
            <Box sx={{ display: "flex", justifyContent: "center", p: 4 }}>
              <CircularProgress />
            </Box>
          ) : viewingReport ? (
            // Viewing a single report
            <Box>
              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                <Button
                  startIcon={<ExpandLessIcon />}
                  onClick={handleBackToReports}
                >
                  Back to Reports
                </Button>
                <Box sx={{ display: "flex", gap: 1 }}>
                  <Button
                    startIcon={<DownloadIcon />}
                    onClick={(e) => handleExportClick(e, viewingReport.id)}
                    variant="outlined"
                  >
                    Export
                  </Button>
                  <Menu
                    anchorEl={exportAnchorEl}
                    open={Boolean(exportAnchorEl)}
                    onClose={handleExportClose}
                  >
                    <MenuItem onClick={() => handleExport("markdown")}>
                      <ListItemIcon>
                        <DescriptionIcon fontSize="small" />
                      </ListItemIcon>
                      <ListItemText>Markdown (.md)</ListItemText>
                    </MenuItem>
                    <MenuItem onClick={() => handleExport("pdf")}>
                      <ListItemIcon>
                        <PictureAsPdfIcon fontSize="small" />
                      </ListItemIcon>
                      <ListItemText>PDF (.pdf)</ListItemText>
                    </MenuItem>
                    <MenuItem onClick={() => handleExport("docx")}>
                      <ListItemIcon>
                        <ArticleIcon fontSize="small" />
                      </ListItemIcon>
                      <ListItemText>Word (.docx)</ListItemText>
                    </MenuItem>
                  </Menu>
                </Box>
              </Box>
              
              <Paper sx={{ p: 3, mb: 2 }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 2 }}>
                  <Box>
                    <Typography variant="h5" sx={{ fontWeight: 700 }}>
                      {viewingReport.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {new Date(viewingReport.created_at).toLocaleString()}
                    </Typography>
                  </Box>
                  <Chip
                    label={viewingReport.risk_level.toUpperCase()}
                    sx={{
                      bgcolor: severityColors[viewingReport.risk_level] || severityColors.medium,
                      color: "white",
                      fontWeight: 600,
                    }}
                  />
                </Box>
                
                <Grid container spacing={2} sx={{ mb: 3 }}>
                  <Grid item xs={4}>
                    <Box sx={{ textAlign: "center", p: 2, bgcolor: alpha(theme.palette.primary.main, 0.1), borderRadius: 2 }}>
                      <Typography variant="h4" color="primary" sx={{ fontWeight: 700 }}>
                        {viewingReport.summary_data?.total_packets?.toLocaleString() || 0}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">Packets</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={4}>
                    <Box sx={{ textAlign: "center", p: 2, bgcolor: alpha(theme.palette.warning.main, 0.1), borderRadius: 2 }}>
                      <Typography variant="h4" color="warning.main" sx={{ fontWeight: 700 }}>
                        {viewingReport.findings_data?.length || 0}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">Findings</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={4}>
                    <Box sx={{ textAlign: "center", p: 2, bgcolor: alpha(theme.palette.info.main, 0.1), borderRadius: 2 }}>
                      <Typography variant="h4" color="info.main" sx={{ fontWeight: 700 }}>
                        {viewingReport.risk_score?.toFixed(0) || 0}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">Risk Score</Typography>
                    </Box>
                  </Grid>
                </Grid>
              </Paper>

              {/* Findings */}
              {viewingReport.findings_data && viewingReport.findings_data.length > 0 && (
                <Accordion defaultExpanded>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography sx={{ fontWeight: 600 }}>
                      Security Findings ({viewingReport.findings_data.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>Severity</TableCell>
                            <TableCell>Title</TableCell>
                            <TableCell>Description</TableCell>
                            <TableCell>Protocol</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {viewingReport.findings_data.map((finding, i) => (
                            <TableRow key={i}>
                              <TableCell>
                                <Chip
                                  label={finding.severity}
                                  size="small"
                                  sx={{
                                    bgcolor: severityColors[finding.severity] || severityColors.medium,
                                    color: "white",
                                    textTransform: "capitalize",
                                  }}
                                />
                              </TableCell>
                              <TableCell>{finding.title}</TableCell>
                              <TableCell sx={{ maxWidth: 300 }}>{finding.description}</TableCell>
                              <TableCell>{finding.protocol || "N/A"}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* AI Report */}
              {viewingReport.ai_report?.analyses && viewingReport.ai_report.analyses.length > 0 && (
                <Accordion sx={{ mt: 2 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography sx={{ fontWeight: 600 }}>AI Analysis</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    {viewingReport.ai_report.analyses.map((analysis: any, i: number) => {
                      const structuredReport = analysis?.structured_report;
                      if (structuredReport) {
                        return (
                          <Box key={i}>
                            <StructuredReportSection report={structuredReport} theme={theme} />
                          </Box>
                        );
                      }
                      return null;
                    })}
                  </AccordionDetails>
                </Accordion>
              )}
            </Box>
          ) : savedReports.length === 0 ? (
            <Paper sx={{ p: 4, textAlign: "center" }}>
              <HistoryIcon sx={{ fontSize: 64, color: "text.secondary", mb: 2 }} />
              <Typography variant="h6" color="text.secondary">
                No saved reports yet
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Analyze a PCAP file to create your first report
              </Typography>
              <Button
                variant="contained"
                sx={{ mt: 2 }}
                onClick={() => setActiveTab(0)}
              >
                Upload PCAP
              </Button>
            </Paper>
          ) : (
            // Reports list
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Title</TableCell>
                    <TableCell>Risk</TableCell>
                    <TableCell>Findings</TableCell>
                    <TableCell>Date</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {savedReports.map((report) => (
                    <TableRow key={report.id} hover>
                      <TableCell>
                        <Typography sx={{ fontWeight: 500 }}>{report.title}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {report.filename}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={report.risk_level.toUpperCase()}
                          size="small"
                          sx={{
                            bgcolor: severityColors[report.risk_level] || severityColors.medium,
                            color: "white",
                            fontWeight: 600,
                          }}
                        />
                      </TableCell>
                      <TableCell>{report.total_findings}</TableCell>
                      <TableCell>
                        {new Date(report.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Report">
                          <IconButton
                            size="small"
                            color="primary"
                            onClick={() => handleViewReport(report.id)}
                          >
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Export">
                          <IconButton
                            size="small"
                            color="info"
                            onClick={(e) => handleExportClick(e, report.id)}
                          >
                            <DownloadIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete Report">
                          <IconButton
                            size="small"
                            color="error"
                            onClick={() => handleDeleteReport(report.id)}
                          >
                            <DeleteIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}

          {/* Shared Export Menu for Reports List */}
          <Menu
            anchorEl={exportAnchorEl}
            open={Boolean(exportAnchorEl)}
            onClose={handleExportClose}
          >
            <MenuItem onClick={() => handleExport("markdown")}>
              <DescriptionIcon sx={{ mr: 1 }} /> Markdown
            </MenuItem>
            <MenuItem onClick={() => handleExport("pdf")}>
              <PictureAsPdfIcon sx={{ mr: 1 }} /> PDF
            </MenuItem>
            <MenuItem onClick={() => handleExport("docx")}>
              <ArticleIcon sx={{ mr: 1 }} /> Word Document
            </MenuItem>
          </Menu>
        </Box>
      )}

      {/* Chat Window - Visible when results OR viewing a saved report */}
      {(results || viewingReport) && (
        <Paper
          sx={{
            position: "fixed",
            bottom: 0,
            right: 24,
            width: chatOpen ? 450 : 200,
            maxHeight: chatOpen ? "60vh" : "auto",
            zIndex: 1200,
            borderRadius: "12px 12px 0 0",
            boxShadow: "0 -4px 20px rgba(0,0,0,0.15)",
            overflow: "hidden",
            transition: "all 0.3s ease",
          }}
        >
          {/* Chat Header */}
          <Box
            onClick={() => setChatOpen(!chatOpen)}
            sx={{
              p: 2,
              bgcolor: theme.palette.primary.main,
              color: "white",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              "&:hover": { bgcolor: theme.palette.primary.dark },
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <ChatIcon />
              <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                Ask About This Report
              </Typography>
            </Box>
            <IconButton size="small" sx={{ color: "white" }}>
              {chatOpen ? <ExpandMoreIcon /> : <ExpandLessIcon />}
            </IconButton>
          </Box>

          {/* Chat Content */}
          <Collapse in={chatOpen}>
            {/* Messages Area */}
            <Box
              sx={{
                height: "calc(60vh - 140px)",
                maxHeight: 400,
                overflowY: "auto",
                p: 2,
                bgcolor: alpha(theme.palette.background.default, 0.5),
              }}
            >
              {/* Welcome message */}
              {chatMessages.length === 0 && (
                <Box sx={{ textAlign: "center", py: 4 }}>
                  <SmartToyIcon sx={{ fontSize: 48, color: "text.disabled", mb: 1 }} />
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Ask me anything about this PCAP analysis!
                  </Typography>
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                    {[
                      "What's the most suspicious activity?",
                      "Explain the DNS traffic",
                      "Are there any data exfiltration signs?",
                      "Summarize the key findings",
                    ].map((suggestion, i) => (
                      <Chip
                        key={i}
                        label={suggestion}
                        variant="outlined"
                        size="small"
                        onClick={() => {
                          setChatInput(suggestion);
                        }}
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
                        "& code": {
                          bgcolor: alpha(msg.role === "user" ? "#fff" : theme.palette.primary.main, 0.2),
                          px: 0.5,
                          borderRadius: 0.5,
                          fontFamily: "monospace",
                          fontSize: "0.85em",
                        },
                        "& ul, & ol": { pl: 2, m: 0 },
                        "& li": { mb: 0.5 },
                      }}
                    >
                      <ReactMarkdown>{msg.content}</ReactMarkdown>
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
                  placeholder="Ask a question about the analysis..."
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyDown={handleChatKeyDown}
                  disabled={chatLoading}
                  multiline
                  maxRows={3}
                  sx={{
                    "& .MuiOutlinedInput-root": {
                      borderRadius: 2,
                    },
                  }}
                />
                <IconButton
                  color="primary"
                  onClick={handleSendMessage}
                  disabled={!chatInput.trim() || chatLoading}
                  sx={{
                    bgcolor: theme.palette.primary.main,
                    color: "white",
                    "&:hover": { bgcolor: theme.palette.primary.dark },
                    "&:disabled": { bgcolor: theme.palette.action.disabledBackground },
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
