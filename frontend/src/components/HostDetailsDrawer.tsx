import React, { useState } from "react";
import {
  Drawer,
  Box,
  Typography,
  IconButton,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Paper,
  Tooltip,
  alpha,
  useTheme,
} from "@mui/material";
import {
  Close as CloseIcon,
  Computer as ComputerIcon,
  Security as SecurityIcon,
  Dns as DnsIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  CheckCircle as CheckIcon,
  LanOutlined as LanIcon,
  Storage as StorageIcon,
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
    scripts?: Array<{ id: string; output: string }>;
  }>;
  scripts?: Array<{ id: string; output: string }>;
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

interface HostDetailsDrawerProps {
  open: boolean;
  onClose: () => void;
  host: NmapHost | null;
  findings?: NmapFinding[];
}

const getSeverityColor = (severity: string) => {
  switch (severity?.toLowerCase()) {
    case "critical": return "error";
    case "high": return "error";
    case "medium": return "warning";
    case "low": return "info";
    default: return "default";
  }
};

const getSeverityIcon = (severity: string) => {
  switch (severity?.toLowerCase()) {
    case "critical": return <ErrorIcon color="error" />;
    case "high": return <WarningIcon color="error" />;
    case "medium": return <WarningIcon color="warning" />;
    case "low": return <InfoIcon color="info" />;
    default: return <CheckIcon color="success" />;
  }
};

const getOSIcon = (os?: string) => {
  if (!os) return "❓";
  const lower = os.toLowerCase();
  if (lower.includes("windows")) return "🪟";
  if (lower.includes("linux") || lower.includes("ubuntu") || lower.includes("debian")) return "🐧";
  if (lower.includes("mac") || lower.includes("darwin")) return "🍎";
  if (lower.includes("cisco") || lower.includes("router")) return "🌐";
  return "💻";
};

export const HostDetailsDrawer: React.FC<HostDetailsDrawerProps> = ({
  open,
  onClose,
  host,
  findings = [],
}) => {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);

  if (!host) return null;

  const hostFindings = findings.filter(f => f.host === host.ip);
  const openPorts = host.ports?.filter(p => p.state === "open") || [];
  const filteredPorts = host.ports?.filter(p => p.state === "filtered") || [];

  // Group findings by severity
  const criticalFindings = hostFindings.filter(f => f.severity === "critical");
  const highFindings = hostFindings.filter(f => f.severity === "high");
  const mediumFindings = hostFindings.filter(f => f.severity === "medium");
  const lowFindings = hostFindings.filter(f => f.severity === "low");

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      PaperProps={{
        sx: {
          width: { xs: "100%", sm: 500, md: 600 },
          p: 0,
        },
      }}
    >
      {/* Header */}
      <Box
        sx={{
          p: 2,
          borderBottom: `1px solid ${theme.palette.divider}`,
          background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.secondary.main, 0.1)} 100%)`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                fontSize: 32,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              {getOSIcon(host.os_guess)}
            </Box>
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 700 }}>
                {host.hostname || host.ip}
              </Typography>
              {host.hostname && (
                <Typography variant="body2" color="text.secondary">
                  {host.ip}
                </Typography>
              )}
            </Box>
          </Box>
          <IconButton onClick={onClose}>
            <CloseIcon />
          </IconButton>
        </Box>

        {/* Quick stats */}
        <Box sx={{ display: "flex", gap: 1, mt: 2, flexWrap: "wrap" }}>
          <Chip
            icon={<LanIcon />}
            label={`${openPorts.length} open ports`}
            size="small"
            color="primary"
            variant="outlined"
          />
          {filteredPorts.length > 0 && (
            <Chip
              label={`${filteredPorts.length} filtered`}
              size="small"
              variant="outlined"
            />
          )}
          {hostFindings.length > 0 && (
            <Chip
              icon={<SecurityIcon />}
              label={`${hostFindings.length} findings`}
              size="small"
              color={criticalFindings.length > 0 || highFindings.length > 0 ? "error" : "warning"}
              variant="outlined"
            />
          )}
          {host.os_guess && (
            <Chip
              icon={<ComputerIcon />}
              label={host.os_guess.length > 30 ? host.os_guess.substring(0, 30) + "..." : host.os_guess}
              size="small"
              variant="outlined"
            />
          )}
        </Box>
      </Box>

      {/* Tabs */}
      <Tabs
        value={activeTab}
        onChange={(_, v) => setActiveTab(v)}
        sx={{ borderBottom: `1px solid ${theme.palette.divider}`, px: 2 }}
      >
        <Tab label={`Ports (${openPorts.length})`} />
        <Tab label={`Findings (${hostFindings.length})`} />
        <Tab label="Details" />
      </Tabs>

      {/* Content */}
      <Box sx={{ p: 2, overflow: "auto", flex: 1 }}>
        {/* Ports Tab */}
        {activeTab === 0 && (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Port</TableCell>
                  <TableCell>Service</TableCell>
                  <TableCell>Product/Version</TableCell>
                  <TableCell>State</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {host.ports?.map((port, idx) => (
                  <TableRow key={idx} hover>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: "monospace", fontWeight: 600 }}>
                        {port.port}/{port.protocol}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={port.service || "unknown"}
                        size="small"
                        sx={{ fontFamily: "monospace" }}
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {[port.product, port.version].filter(Boolean).join(" ") || "-"}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={port.state}
                        size="small"
                        color={port.state === "open" ? "success" : port.state === "filtered" ? "warning" : "default"}
                      />
                    </TableCell>
                  </TableRow>
                ))}
                {(!host.ports || host.ports.length === 0) && (
                  <TableRow>
                    <TableCell colSpan={4} sx={{ textAlign: "center", py: 4 }}>
                      <Typography color="text.secondary">No ports scanned</Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {/* Findings Tab */}
        {activeTab === 1 && (
          <Box>
            {hostFindings.length === 0 ? (
              <Paper sx={{ p: 4, textAlign: "center" }}>
                <CheckIcon sx={{ fontSize: 48, color: "success.main", mb: 1 }} />
                <Typography color="text.secondary">No security findings for this host</Typography>
              </Paper>
            ) : (
              <List disablePadding>
                {hostFindings.map((finding, idx) => (
                  <React.Fragment key={idx}>
                    <ListItem
                      sx={{
                        flexDirection: "column",
                        alignItems: "flex-start",
                        bgcolor: alpha(
                          finding.severity === "critical" || finding.severity === "high"
                            ? theme.palette.error.main
                            : finding.severity === "medium"
                            ? theme.palette.warning.main
                            : theme.palette.info.main,
                          0.05
                        ),
                        borderRadius: 1,
                        mb: 1,
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
                        {getSeverityIcon(finding.severity)}
                        <Typography variant="subtitle2" sx={{ flex: 1 }}>
                          {finding.title}
                        </Typography>
                        <Chip
                          label={finding.severity.toUpperCase()}
                          size="small"
                          color={getSeverityColor(finding.severity) as any}
                        />
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                        {finding.description}
                      </Typography>
                      {finding.port && (
                        <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5 }}>
                          Port: {finding.port} | Service: {finding.service || "N/A"}
                        </Typography>
                      )}
                      {finding.cve_ids && finding.cve_ids.length > 0 && (
                        <Box sx={{ display: "flex", gap: 0.5, mt: 1, flexWrap: "wrap" }}>
                          {finding.cve_ids.map((cve) => (
                            <Chip
                              key={cve}
                              label={cve}
                              size="small"
                              color="error"
                              variant="outlined"
                              onClick={() => window.open(`https://nvd.nist.gov/vuln/detail/${cve}`, "_blank")}
                              sx={{ cursor: "pointer" }}
                            />
                          ))}
                        </Box>
                      )}
                    </ListItem>
                  </React.Fragment>
                ))}
              </List>
            )}
          </Box>
        )}

        {/* Details Tab */}
        {activeTab === 2 && (
          <Box>
            <List>
              <ListItem>
                <ListItemIcon><DnsIcon /></ListItemIcon>
                <ListItemText
                  primary="IP Address"
                  secondary={host.ip}
                />
              </ListItem>
              <Divider component="li" />
              <ListItem>
                <ListItemIcon><DnsIcon /></ListItemIcon>
                <ListItemText
                  primary="Hostname"
                  secondary={host.hostname || "Not resolved"}
                />
              </ListItem>
              <Divider component="li" />
              <ListItem>
                <ListItemIcon><ComputerIcon /></ListItemIcon>
                <ListItemText
                  primary="Operating System"
                  secondary={
                    host.os_guess
                      ? `${host.os_guess}${host.os_accuracy ? ` (${host.os_accuracy}% confidence)` : ""}`
                      : "Not detected"
                  }
                />
              </ListItem>
              <Divider component="li" />
              <ListItem>
                <ListItemIcon><StorageIcon /></ListItemIcon>
                <ListItemText
                  primary="Status"
                  secondary={host.status || "up"}
                />
              </ListItem>
            </List>

            {/* Services summary */}
            <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
              Services Detected
            </Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
              {[...new Set(openPorts.map(p => p.service).filter(Boolean))].map((service) => (
                <Chip key={service} label={service} size="small" />
              ))}
              {openPorts.every(p => !p.service) && (
                <Typography variant="body2" color="text.secondary">
                  No services identified
                </Typography>
              )}
            </Box>

            {/* Host scripts output */}
            {host.scripts && host.scripts.length > 0 && (
              <>
                <Typography variant="subtitle2" sx={{ mt: 3, mb: 1 }}>
                  NSE Script Results
                </Typography>
                {host.scripts.map((script, idx) => (
                  <Paper
                    key={idx}
                    sx={{
                      p: 1.5,
                      mb: 1,
                      bgcolor: alpha(theme.palette.background.default, 0.5),
                    }}
                  >
                    <Typography variant="caption" color="primary" sx={{ fontWeight: 600 }}>
                      {script.id}
                    </Typography>
                    <Typography
                      variant="body2"
                      sx={{
                        fontFamily: "monospace",
                        fontSize: "0.75rem",
                        whiteSpace: "pre-wrap",
                        mt: 0.5,
                      }}
                    >
                      {script.output}
                    </Typography>
                  </Paper>
                ))}
              </>
            )}
          </Box>
        )}
      </Box>
    </Drawer>
  );
};

export default HostDetailsDrawer;
