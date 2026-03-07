import { useEffect, useState } from "react";
import {
  Alert,
  alpha,
  Box,
  Card,
  CardContent,
  Chip,
  Grid,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  useTheme,
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import TimelineIcon from "@mui/icons-material/Timeline";
import ShieldIcon from "@mui/icons-material/Shield";
import LanguageIcon from "@mui/icons-material/Language";
import LanIcon from "@mui/icons-material/Lan";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import DnsIcon from "@mui/icons-material/Dns";
import DescriptionIcon from "@mui/icons-material/Description";
import WarningIcon from "@mui/icons-material/Warning";
import type { PcapAnalysisResponse, PcapAttackSurface, PcapEnhancedProtocols } from "../api/client";

const severityColors: Record<string, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  advisory: "#3b82f6",
  info: "#3b82f6",
};

const safeLower = (value?: string | null): string => (value || "").toLowerCase();

const formatBytes = (bytes: number): string => {
  if (!bytes) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const truncateText = (value: unknown, maxLength: number = 220): string => {
  if (value === undefined || value === null) return "";
  const normalized = String(value).replace(/\s+/g, " ").trim();
  if (normalized.length <= maxLength) return normalized;
  return `${normalized.slice(0, maxLength - 3)}...`;
};

const maskSensitiveValue = (value?: string | null): string => {
  if (!value) return "Masked";
  if (value.length <= 12) return `${value.slice(0, 3)}...${value.slice(-2)}`;
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
};

const formatCaptureTimestamp = (timestamp?: number | null): string => {
  if (typeof timestamp !== "number" || Number.isNaN(timestamp)) return "N/A";
  if (timestamp > 1_000_000_000_000) return new Date(timestamp).toLocaleString();
  if (timestamp > 1_000_000_000) return new Date(timestamp * 1000).toLocaleString();
  return `${timestamp.toFixed(3)}s`;
};

function TextPreviewBlock({ title, value }: { title: string; value?: string | null }) {
  const theme = useTheme();
  if (!value) return null;

  return (
    <Box>
      <Typography variant="caption" sx={{ fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5 }}>
        {title}
      </Typography>
      <Box
        component="pre"
        sx={{
          mt: 1,
          mb: 0,
          p: 1.5,
          borderRadius: 2,
          bgcolor: alpha(theme.palette.primary.main, 0.05),
          border: `1px solid ${alpha(theme.palette.primary.main, 0.12)}`,
          fontFamily: "monospace",
          fontSize: "0.75rem",
          lineHeight: 1.6,
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
          overflowX: "auto",
        }}
      >
        {truncateText(value, 1400)}
      </Box>
    </Box>
  );
}

export type PcapDeepInspectionCapture = {
  label: string;
  conversations?: PcapAnalysisResponse["conversations"];
  attack_surface?: PcapAttackSurface | null;
  enhanced_protocols?: PcapEnhancedProtocols | null;
};

export default function PcapDeepInspectionSection({ capture }: { capture: PcapDeepInspectionCapture }) {
  const theme = useTheme();
  const attackSurface = capture.attack_surface;
  const enhancedProtocols = capture.enhanced_protocols;
  const endpoints = attackSurface?.endpoints || [];
  const authTokens = attackSurface?.auth_tokens || [];
  const authMechanisms = attackSurface?.auth_mechanisms || [];
  const authWeaknesses = attackSurface?.auth_weaknesses || [];
  const sensitiveLeaks = attackSurface?.sensitive_data_leaks || [];
  const protocolWeaknesses = attackSurface?.protocol_weaknesses || [];
  const httpSessions = enhancedProtocols?.http_sessions || [];
  const websocketSessions = enhancedProtocols?.websocket_sessions || [];
  const tcpStreams = enhancedProtocols?.tcp_streams || [];
  const databaseQueries = enhancedProtocols?.database_queries || [];
  const extractedFiles = enhancedProtocols?.extracted_files || [];
  const timelineEvents = enhancedProtocols?.timeline_events || [];

  const sections: Array<{
    key: string;
    title: string;
    subtitle: string;
    stat: string;
    icon: React.ReactNode;
    content: React.ReactNode;
  }> = [];

  if (attackSurface && (endpoints.length || authTokens.length || sensitiveLeaks.length || protocolWeaknesses.length || authMechanisms.length || authWeaknesses.length)) {
    sections.push({
      key: "attack-surface",
      title: "Attack Surface",
      subtitle: "Endpoints, tokens, leaks",
      stat: `${endpoints.length + authTokens.length + sensitiveLeaks.length}`,
      icon: <ShieldIcon color="primary" />,
      content: (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {(authMechanisms.length > 0 || authWeaknesses.length > 0) && (
            <Paper sx={{ p: 2 }}>
              {authMechanisms.length > 0 && (
                <Box sx={{ mb: authWeaknesses.length > 0 ? 2 : 0 }}>
                  <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 700 }}>
                    Authentication Mechanisms
                  </Typography>
                  <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                    {authMechanisms.map((mechanism) => (
                      <Chip key={mechanism} label={mechanism} size="small" sx={{ fontFamily: "monospace" }} />
                    ))}
                  </Box>
                </Box>
              )}
              {authWeaknesses.length > 0 && (
                <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                  {authWeaknesses.map((issue, index) => (
                    <Chip key={`${issue}-${index}`} label={issue} size="small" color="warning" variant="outlined" />
                  ))}
                </Box>
              )}
            </Paper>
          )}

          {endpoints.length > 0 && (
            <TableContainer component={Paper} variant="outlined">
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Method</TableCell>
                    <TableCell>Endpoint</TableCell>
                    <TableCell>Auth</TableCell>
                    <TableCell align="right">Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {endpoints.slice(0, 10).map((endpoint, index) => (
                    <TableRow key={`${endpoint.method}-${endpoint.url}-${index}`}>
                      <TableCell>
                        <Chip label={endpoint.method || "REQ"} size="small" color="primary" variant="outlined" />
                      </TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                        {truncateText(endpoint.url || `${endpoint.host || ""}${endpoint.path || ""}`, 90)}
                      </TableCell>
                      <TableCell>{endpoint.auth_type || "None"}</TableCell>
                      <TableCell align="right">{endpoint.response_status || "-"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}

          {authTokens.length > 0 && (
            <Paper sx={{ p: 2 }}>
              <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 700 }}>
                Tokens and Session Material
              </Typography>
              <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                {authTokens.slice(0, 8).map((token, index) => (
                  <Paper key={`${token.token_hash || token.endpoint || index}`} variant="outlined" sx={{ p: 1.5 }}>
                    <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", alignItems: "center", mb: 1 }}>
                      <Chip label={token.token_type || "token"} size="small" color="secondary" />
                      <Chip label={token.dest_host || token.endpoint || "unknown target"} size="small" variant="outlined" />
                    </Box>
                    <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                      {token.token_value_masked || maskSensitiveValue(token.token_value)}
                    </Typography>
                  </Paper>
                ))}
              </Box>
            </Paper>
          )}

          {sensitiveLeaks.length > 0 && (
            <TableContainer component={Paper} variant="outlined">
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Type</TableCell>
                    <TableCell>Value</TableCell>
                    <TableCell>Context</TableCell>
                    <TableCell>Severity</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {sensitiveLeaks.slice(0, 10).map((leak, index) => (
                    <TableRow key={`${leak.data_type}-${leak.packet_number}-${index}`}>
                      <TableCell>{leak.data_type || "unknown"}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                        {maskSensitiveValue(leak.data_value)}
                      </TableCell>
                      <TableCell>{truncateText(leak.context, 60)}</TableCell>
                      <TableCell>
                        <Chip
                          label={(leak.severity || "high").toUpperCase()}
                          size="small"
                          sx={{
                            bgcolor: alpha(severityColors[safeLower(leak.severity)] || "#dc2626", 0.12),
                            color: severityColors[safeLower(leak.severity)] || "#dc2626",
                            fontWeight: 700,
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}

          {protocolWeaknesses.length > 0 && (
            <Paper sx={{ p: 2 }}>
              <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 700 }}>
                Protocol Weaknesses
              </Typography>
              {protocolWeaknesses.slice(0, 8).map((weakness, index) => (
                <Box key={`${weakness.weakness_type}-${index}`} sx={{ display: "flex", gap: 1, alignItems: "flex-start", mb: 1 }}>
                  <WarningIcon sx={{ color: severityColors[safeLower(weakness.severity)] || theme.palette.warning.main, mt: 0.25 }} />
                  <Typography variant="body2">{weakness.description || weakness.evidence || weakness.weakness_type}</Typography>
                </Box>
              ))}
            </Paper>
          )}
        </Box>
      ),
    });
  }

  if (httpSessions.length > 0) {
    sections.push({
      key: "http-sessions",
      title: "HTTP Sessions",
      subtitle: "Requests, responses, bodies",
      stat: `${httpSessions.length}`,
      icon: <LanguageIcon color="primary" />,
      content: (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
          {httpSessions.slice(0, 12).map((session, index) => (
            <Accordion key={`${session.session_id || session.url || index}`} disableGutters>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap", width: "100%" }}>
                  <Chip label={session.method || "HTTP"} size="small" color="primary" />
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontWeight: 600 }}>
                    {truncateText(session.url || `${session.host || ""}${session.path || ""}`, 100)}
                  </Typography>
                  {session.response_status !== undefined && <Chip label={`HTTP ${session.response_status}`} size="small" variant="outlined" />}
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <TextPreviewBlock title="Request Body" value={session.request_body} />
                <TextPreviewBlock title="Response Body" value={session.response_body} />
                {!session.request_body && !session.response_body && (
                  <Alert severity="info">No plaintext request or response body was reconstructed for this session.</Alert>
                )}
              </AccordionDetails>
            </Accordion>
          ))}
        </Box>
      ),
    });
  }

  if (websocketSessions.length > 0) {
    sections.push({
      key: "websocket",
      title: "WebSocket Payloads",
      subtitle: "Realtime message previews",
      stat: `${enhancedProtocols?.websocket_message_count || websocketSessions.reduce((total, session) => total + (session.message_count || 0), 0)}`,
      icon: <LanIcon color="secondary" />,
      content: (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
          {websocketSessions.slice(0, 8).map((session, index) => (
            <Accordion key={`${session.session_id || session.url || index}`} disableGutters>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap", width: "100%" }}>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontWeight: 600 }}>
                    {truncateText(session.url || `${session.server_ip}:${session.server_port}`, 100)}
                  </Typography>
                  <Chip label={`${session.message_count || (session.messages || []).length} messages`} size="small" color="secondary" />
                  <Chip label={formatBytes(session.total_bytes || 0)} size="small" variant="outlined" />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                {(session.messages || []).slice(0, 8).map((message, messageIndex) => (
                  <Paper key={`${message.packet_number || messageIndex}-${messageIndex}`} variant="outlined" sx={{ p: 1.5, mb: 1.5 }}>
                    <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", alignItems: "center", mb: 1 }}>
                      <Chip
                        label={message.direction === "client_to_server" ? "Client to Server" : "Server to Client"}
                        size="small"
                        color={message.direction === "client_to_server" ? "primary" : "secondary"}
                        variant="outlined"
                      />
                      <Chip label={message.opcode_name || `Opcode ${message.opcode}`} size="small" variant="outlined" />
                    </Box>
                    <TextPreviewBlock title={`Payload ${messageIndex + 1}`} value={message.payload} />
                  </Paper>
                ))}
              </AccordionDetails>
            </Accordion>
          ))}
        </Box>
      ),
    });
  }

  if (tcpStreams.length > 0) {
    sections.push({
      key: "tcp-streams",
      title: "TCP Streams",
      subtitle: "Follow stream style previews",
      stat: `${tcpStreams.length}`,
      icon: <NetworkCheckIcon color="primary" />,
      content: (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
          {tcpStreams.slice(0, 10).map((stream, index) => (
            <Accordion key={`${stream.stream_id || index}`} disableGutters>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap", width: "100%" }}>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontWeight: 600 }}>
                    {stream.client_ip}:{stream.client_port} {"<->"} {stream.server_ip}:{stream.server_port}
                  </Typography>
                  <Chip label={stream.protocol || "TCP"} size="small" color="primary" variant="outlined" />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <TextPreviewBlock title="Client to Server Preview" value={stream.client_data_preview} />
                <TextPreviewBlock title="Server to Client Preview" value={stream.server_data_preview} />
                {!stream.client_data_preview && !stream.server_data_preview && (
                  <Alert severity="info">The stream was reconstructed, but the preview was binary or empty.</Alert>
                )}
              </AccordionDetails>
            </Accordion>
          ))}
        </Box>
      ),
    });
  }

  if (databaseQueries.length > 0) {
    sections.push({
      key: "database",
      title: "Database Traffic",
      subtitle: "Queries and commands",
      stat: `${databaseQueries.length}`,
      icon: <DnsIcon color="secondary" />,
      content: (
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Protocol</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Database</TableCell>
                <TableCell>User</TableCell>
                <TableCell>Query</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {databaseQueries.slice(0, 15).map((query, index) => (
                <TableRow key={`${query.packet_number || index}-${index}`}>
                  <TableCell>{query.protocol}</TableCell>
                  <TableCell>{query.query_type}</TableCell>
                  <TableCell>{query.database || "-"}</TableCell>
                  <TableCell>{query.username || "-"}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", maxWidth: 420 }}>
                    {truncateText(query.query, 180)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      ),
    });
  }

  if (extractedFiles.length > 0) {
    sections.push({
      key: "files",
      title: "Extracted Files",
      subtitle: "Transferred artifacts",
      stat: `${extractedFiles.length}`,
      icon: <DescriptionIcon color="primary" />,
      content: (
        <Grid container spacing={2}>
          {extractedFiles.slice(0, 12).map((file, index) => (
            <Grid item xs={12} md={6} key={`${file.sha256_hash || file.filename}-${index}`}>
              <Paper sx={{ p: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                  {file.filename}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {file.mime_type} | {formatBytes(file.size || 0)} | {file.source_protocol}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
                  SHA256: {truncateText(file.sha256_hash, 24)}
                </Typography>
                <TextPreviewBlock title="Content Preview" value={file.content_preview} />
              </Paper>
            </Grid>
          ))}
        </Grid>
      ),
    });
  }

  if (timelineEvents.length > 0) {
    sections.push({
      key: "timeline",
      title: "Timeline",
      subtitle: "Sequence of notable events",
      stat: `${timelineEvents.length}`,
      icon: <TimelineIcon color="primary" />,
      content: (
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Time</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Event</TableCell>
                <TableCell>Description</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {timelineEvents.slice(0, 20).map((event, index) => (
                <TableRow key={`${event.packet_number || index}-${index}`}>
                  <TableCell sx={{ whiteSpace: "nowrap" }}>{formatCaptureTimestamp(event.timestamp)}</TableCell>
                  <TableCell>
                    <Chip
                      label={(event.severity || "info").toUpperCase()}
                      size="small"
                      sx={{
                        bgcolor: alpha(severityColors[safeLower(event.severity)] || "#3b82f6", 0.12),
                        color: severityColors[safeLower(event.severity)] || "#3b82f6",
                        fontWeight: 700,
                      }}
                    />
                  </TableCell>
                  <TableCell>{event.event_type}</TableCell>
                  <TableCell>{truncateText(event.description, 120)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      ),
    });
  }

  const firstSectionKey = sections[0]?.key || "";
  const [activeSection, setActiveSection] = useState<string>(firstSectionKey);

  useEffect(() => {
    if (!firstSectionKey) {
      if (activeSection) {
        setActiveSection("");
      }
      return;
    }

    if (!sections.some((section) => section.key === activeSection)) {
      setActiveSection(firstSectionKey);
    }
  }, [activeSection, firstSectionKey, sections]);

  if (!firstSectionKey) return null;

  const currentSection = sections.find((section) => section.key === activeSection) || sections[0];

  return (
    <Paper sx={{ p: 2.5, bgcolor: alpha(theme.palette.info.main, 0.02), border: `1px solid ${alpha(theme.palette.info.main, 0.16)}` }}>
      <Box sx={{ mb: 2.5 }}>
        <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
          <TimelineIcon color="info" />
          Deep Inspection
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          Click into protocol summaries to inspect plaintext bodies, stream previews, payload samples, and other evidence the AI can use.
        </Typography>
      </Box>

      <Grid container spacing={2} sx={{ mb: 2.5 }}>
        {sections.map((section) => {
          const active = section.key === currentSection.key;
          return (
            <Grid item xs={12} sm={6} md={4} lg={3} key={section.key}>
              <Card
                onClick={() => setActiveSection(section.key)}
                sx={{
                  height: "100%",
                  cursor: "pointer",
                  border: `1px solid ${alpha(active ? theme.palette.primary.main : theme.palette.divider, active ? 0.5 : 0.6)}`,
                  bgcolor: active ? alpha(theme.palette.primary.main, 0.08) : theme.palette.background.paper,
                }}
              >
                <CardContent>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                    {section.icon}
                    <Typography variant="h5" sx={{ fontWeight: 800 }}>
                      {section.stat}
                    </Typography>
                  </Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                    {section.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {section.subtitle}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          );
        })}
      </Grid>

      <Paper variant="outlined" sx={{ p: 2.5 }}>
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
          {currentSection.title}
        </Typography>
        {currentSection.content}
      </Paper>
    </Paper>
  );
}
