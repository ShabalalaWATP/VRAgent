import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  Grid,
  Card,
  CardContent,
  Chip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Button,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  keyframes,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import HubIcon from "@mui/icons-material/Hub";
import RadarIcon from "@mui/icons-material/Radar";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import SecurityIcon from "@mui/icons-material/Security";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import StorageIcon from "@mui/icons-material/Storage";
import ChatIcon from "@mui/icons-material/Chat";
import DownloadIcon from "@mui/icons-material/Download";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import AssessmentIcon from "@mui/icons-material/Assessment";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import ShieldIcon from "@mui/icons-material/Shield";
import BugReportIcon from "@mui/icons-material/BugReport";
import VisibilityIcon from "@mui/icons-material/Visibility";
import TimelineIcon from "@mui/icons-material/Timeline";
import SpeedIcon from "@mui/icons-material/Speed";
import WarningIcon from "@mui/icons-material/Warning";
import GppGoodIcon from "@mui/icons-material/GppGood";

// Animations
const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-8px); }
`;

const pulse = keyframes`
  0%, 100% { transform: scale(1); opacity: 1; }
  50% { transform: scale(1.05); opacity: 0.9; }
`;

const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

export default function NetworkAnalysisGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();

  const features = [
    {
      title: "Nmap Scanner & Analyzer",
      icon: <RadarIcon sx={{ fontSize: 32 }} />,
      color: "#8b5cf6",
      gradient: "linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)",
      description: "Industry-standard port scanning and service detection with AI-powered insights.",
      capabilities: [
        "Live scanning with 5+ scan profiles (Basic, Quick, Full, Service, OS Detection)",
        "Upload and analyze existing Nmap XML/text output files",
        "Target validation for IPs, CIDR ranges, and hostnames",
        "Real-time scan progress with live output streaming",
        "Vulnerability correlation and CVE lookups",
      ],
      link: "/network/nmap",
    },
    {
      title: "PCAP Analyzer",
      icon: <NetworkCheckIcon sx={{ fontSize: 32 }} />,
      color: "#06b6d4",
      gradient: "linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)",
      description: "Deep packet inspection and traffic analysis for security investigations.",
      capabilities: [
        "Upload PCAP/PCAPNG files from Wireshark or tcpdump",
        "Protocol distribution analysis (TCP, UDP, HTTP, DNS, etc.)",
        "Automatic detection of cleartext credentials",
        "Suspicious pattern identification (beaconing, data exfil)",
        "Connection mapping and traffic flow visualization",
      ],
      link: "/network/pcap",
    },
    {
      title: "AI Security Analysis",
      icon: <SmartToyIcon sx={{ fontSize: 32 }} />,
      color: "#10b981",
      gradient: "linear-gradient(135deg, #10b981 0%, #059669 100%)",
      description: "Google Gemini AI transforms raw network data into actionable intelligence.",
      capabilities: [
        "Executive summary with key findings",
        "Risk scoring (0-100) with severity classification",
        "Attack surface assessment and exposure analysis",
        "Vulnerable service identification with CVE references",
        "Prioritized remediation recommendations",
      ],
      link: null,
    },
    {
      title: "Interactive AI Chat",
      icon: <ChatIcon sx={{ fontSize: 32 }} />,
      color: "#f59e0b",
      gradient: "linear-gradient(135deg, #f59e0b 0%, #d97706 100%)",
      description: "Have a conversation with AI about your network security findings.",
      capabilities: [
        "Ask follow-up questions about specific findings",
        "Get tailored remediation guidance for your environment",
        "Explore attack scenarios and potential impact",
        "Request deeper analysis on hosts or services",
        "Full conversation history maintained per report",
      ],
      link: null,
    },
    {
      title: "Report Management",
      icon: <StorageIcon sx={{ fontSize: 32 }} />,
      color: "#6366f1",
      gradient: "linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)",
      description: "All your network analysis reports saved and organized in one place.",
      capabilities: [
        "Automatic save of all scan results to database",
        "Filter reports by type (Nmap, PCAP)",
        "View historical scans and track changes over time",
        "Quick access to view or delete reports",
        "Export reports in multiple formats",
      ],
      link: "/network",
    },
    {
      title: "Professional Exports",
      icon: <DownloadIcon sx={{ fontSize: 32 }} />,
      color: "#ef4444",
      gradient: "linear-gradient(135deg, #ef4444 0%, #dc2626 100%)",
      description: "Generate professional reports for stakeholders and documentation.",
      capabilities: [
        "Markdown (.md) for technical documentation",
        "PDF for formal reporting and presentations",
        "Word (.docx) for editing and customization",
        "All exports include full AI analysis",
      ],
      link: null,
    },
  ];

  const workflowSteps = [
    {
      label: "Choose Your Analysis Type",
      description: "Select Nmap Analyzer for port/service scanning or PCAP Analyzer for traffic analysis. Each tool is optimized for its specific use case.",
      icon: <HubIcon />,
    },
    {
      label: "Provide Input Data",
      description: "For Nmap: Enter a target IP/hostname or upload existing scan files. For PCAP: Upload your packet capture file from Wireshark or tcpdump.",
      icon: <CloudUploadIcon />,
    },
    {
      label: "Configure & Execute",
      description: "Choose scan options (for Nmap) or let automatic analysis begin (for PCAP). Watch real-time progress as your data is processed.",
      icon: <PlayArrowIcon />,
    },
    {
      label: "AI Analysis",
      description: "Google Gemini AI automatically analyzes results, generating a comprehensive security report with risk scores and findings.",
      icon: <SmartToyIcon />,
    },
    {
      label: "Review & Investigate",
      description: "Explore the structured report with executive summary, findings, and recommendations. Use AI chat to dig deeper into specific issues.",
      icon: <AssessmentIcon />,
    },
    {
      label: "Export & Share",
      description: "Download professional reports in Markdown, PDF, or DOCX format. All reports are automatically saved for future reference.",
      icon: <DownloadIcon />,
    },
  ];

  const useCases = [
    {
      title: "Penetration Testing",
      icon: <BugReportIcon />,
      color: "#ef4444",
      description: "Use Nmap to discover attack surface and PCAP to analyze test traffic",
    },
    {
      title: "Security Audits",
      icon: <ShieldIcon />,
      color: "#8b5cf6",
      description: "Document network exposure with AI-generated compliance-ready reports",
    },
    {
      title: "Incident Response",
      icon: <WarningIcon />,
      color: "#f59e0b",
      description: "Analyze captured traffic to understand breach scope and attacker behavior",
    },
    {
      title: "Network Monitoring",
      icon: <VisibilityIcon />,
      color: "#06b6d4",
      description: "Regular scans to track changes in your network's security posture",
    },
  ];

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Back Link */}
      <Box sx={{ mb: 3 }}>
        <Chip
          component={Link}
          to="/learn"
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          clickable
          variant="outlined"
          sx={{ borderRadius: 2 }}
        />
      </Box>

      {/* Hero Header */}
      <Paper
        sx={{
          p: 5,
          mb: 5,
          borderRadius: 4,
          background: `linear-gradient(135deg, ${alpha("#0ea5e9", 0.15)} 0%, ${alpha("#6366f1", 0.1)} 50%, ${alpha("#8b5cf6", 0.05)} 100%)`,
          border: `1px solid ${alpha("#0ea5e9", 0.3)}`,
          position: "relative",
          overflow: "hidden",
        }}
      >
        {/* Floating background elements */}
        <Box
          sx={{
            position: "absolute",
            top: -50,
            right: -50,
            width: 200,
            height: 200,
            borderRadius: "50%",
            background: `radial-gradient(circle, ${alpha("#0ea5e9", 0.2)} 0%, transparent 70%)`,
            animation: `${float} 6s ease-in-out infinite`,
          }}
        />
        <Box
          sx={{
            position: "absolute",
            bottom: -30,
            left: "30%",
            width: 150,
            height: 150,
            borderRadius: "50%",
            background: `radial-gradient(circle, ${alpha("#8b5cf6", 0.15)} 0%, transparent 70%)`,
            animation: `${float} 5s ease-in-out infinite`,
            animationDelay: "1s",
          }}
        />

        <Box sx={{ position: "relative", zIndex: 1 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
            <Box
              sx={{
                width: 80,
                height: 80,
                borderRadius: 3,
                background: `linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: `0 8px 32px ${alpha("#0ea5e9", 0.4)}`,
                animation: `${float} 4s ease-in-out infinite`,
              }}
            >
              <HubIcon sx={{ fontSize: 44, color: "white" }} />
            </Box>
            <Box>
              <Typography
                variant="h3"
                sx={{
                  fontWeight: 800,
                  background: `linear-gradient(135deg, #0ea5e9 0%, #6366f1 50%, #8b5cf6 100%)`,
                  backgroundSize: "200% auto",
                  backgroundClip: "text",
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                  animation: `${shimmer} 4s linear infinite`,
                }}
              >
                Network Analysis Hub
              </Typography>
              <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                AI-Powered Network Security Analysis
              </Typography>
            </Box>
          </Box>

          <Typography variant="body1" sx={{ maxWidth: 700, mb: 3, fontSize: "1.1rem", lineHeight: 1.7 }}>
            The Network Analysis Hub combines industry-standard tools like <strong>Nmap</strong> and{" "}
            <strong>Wireshark</strong> with Google <strong>Gemini AI</strong> to deliver comprehensive 
            security insights. Scan networks, analyze traffic, and get actionable intelligence—all in one place.
          </Typography>

          <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
            <Button
              variant="contained"
              startIcon={<RocketLaunchIcon />}
              onClick={() => navigate("/network")}
              sx={{
                background: `linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%)`,
                px: 3,
                py: 1.5,
                fontWeight: 600,
                boxShadow: `0 4px 20px ${alpha("#0ea5e9", 0.4)}`,
                "&:hover": {
                  boxShadow: `0 6px 30px ${alpha("#0ea5e9", 0.5)}`,
                },
              }}
            >
              Launch Network Hub
            </Button>
            <Button
              variant="outlined"
              startIcon={<RadarIcon />}
              component={Link}
              to="/learn/nmap"
              sx={{
                borderColor: alpha("#8b5cf6", 0.5),
                color: "#a78bfa",
                "&:hover": {
                  borderColor: "#8b5cf6",
                  bgcolor: alpha("#8b5cf6", 0.1),
                },
              }}
            >
              Learn Nmap
            </Button>
            <Button
              variant="outlined"
              startIcon={<NetworkCheckIcon />}
              component={Link}
              to="/learn/wireshark"
              sx={{
                borderColor: alpha("#06b6d4", 0.5),
                color: "#22d3ee",
                "&:hover": {
                  borderColor: "#06b6d4",
                  bgcolor: alpha("#06b6d4", 0.1),
                },
              }}
            >
              Learn Wireshark
            </Button>
          </Box>
        </Box>
      </Paper>

      {/* Key Stats */}
      <Grid container spacing={3} sx={{ mb: 5 }}>
        {[
          { value: "2", label: "Analysis Tools", icon: <HubIcon />, color: "#0ea5e9" },
          { value: "5+", label: "Scan Types", icon: <RadarIcon />, color: "#8b5cf6" },
          { value: "AI", label: "Powered Analysis", icon: <SmartToyIcon />, color: "#10b981" },
          { value: "3", label: "Export Formats", icon: <DownloadIcon />, color: "#f59e0b" },
        ].map((stat, idx) => (
          <Grid item xs={6} md={3} key={idx}>
            <Paper
              sx={{
                p: 3,
                textAlign: "center",
                borderRadius: 3,
                border: `1px solid ${alpha(stat.color, 0.2)}`,
                background: `linear-gradient(135deg, ${alpha(stat.color, 0.05)} 0%, transparent 100%)`,
                transition: "all 0.3s ease",
                "&:hover": {
                  transform: "translateY(-4px)",
                  boxShadow: `0 8px 30px ${alpha(stat.color, 0.2)}`,
                },
              }}
            >
              <Box sx={{ color: stat.color, mb: 1 }}>{stat.icon}</Box>
              <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                {stat.value}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {stat.label}
              </Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* Use Cases */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
          <TipsAndUpdatesIcon sx={{ color: "#f59e0b" }} />
          Use Cases
        </Typography>
        <Grid container spacing={2}>
          {useCases.map((useCase, idx) => (
            <Grid item xs={12} sm={6} md={3} key={idx}>
              <Paper
                sx={{
                  p: 2.5,
                  height: "100%",
                  borderRadius: 2,
                  border: `1px solid ${alpha(useCase.color, 0.2)}`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    borderColor: useCase.color,
                    bgcolor: alpha(useCase.color, 0.05),
                  },
                }}
              >
                <Box sx={{ color: useCase.color, mb: 1.5 }}>{useCase.icon}</Box>
                <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 0.5 }}>
                  {useCase.title}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {useCase.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Features Grid */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
        <SpeedIcon sx={{ color: "#6366f1" }} />
        Capabilities
      </Typography>
      <Grid container spacing={3} sx={{ mb: 5 }}>
        {features.map((feature) => (
          <Grid item xs={12} md={6} key={feature.title}>
            <Card
              sx={{
                height: "100%",
                borderRadius: 3,
                border: `1px solid ${alpha(feature.color, 0.2)}`,
                transition: "all 0.3s ease",
                "&:hover": {
                  transform: "translateY(-4px)",
                  borderColor: feature.color,
                  boxShadow: `0 8px 30px ${alpha(feature.color, 0.2)}`,
                },
              }}
            >
              <CardContent sx={{ p: 3 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <Box
                    sx={{
                      width: 56,
                      height: 56,
                      borderRadius: 2,
                      background: feature.gradient,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      color: "white",
                      boxShadow: `0 4px 15px ${alpha(feature.color, 0.4)}`,
                    }}
                  >
                    {feature.icon}
                  </Box>
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="h6" sx={{ fontWeight: 700 }}>
                      {feature.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {feature.description}
                    </Typography>
                  </Box>
                </Box>
                <Divider sx={{ my: 2 }} />
                <List dense disablePadding>
                  {feature.capabilities.map((cap, idx) => (
                    <ListItem key={idx} sx={{ py: 0.5, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 18, color: feature.color }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={cap}
                        primaryTypographyProps={{ variant: "body2" }}
                      />
                    </ListItem>
                  ))}
                </List>
                {feature.link && (
                  <Button
                    component={Link}
                    to={feature.link}
                    size="small"
                    sx={{
                      mt: 2,
                      color: feature.color,
                      "&:hover": {
                        bgcolor: alpha(feature.color, 0.1),
                      },
                    }}
                  >
                    Go to {feature.title} →
                  </Button>
                )}
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Workflow Stepper */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
          <TimelineIcon sx={{ color: "#10b981" }} />
          How It Works
        </Typography>
        <Stepper orientation="vertical">
          {workflowSteps.map((step, index) => (
            <Step key={step.label} active={true}>
              <StepLabel
                StepIconComponent={() => (
                  <Box
                    sx={{
                      width: 36,
                      height: 36,
                      borderRadius: "50%",
                      bgcolor: alpha("#10b981", 0.1),
                      color: "#10b981",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontWeight: 700,
                    }}
                  >
                    {index + 1}
                  </Box>
                )}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                  <Box sx={{ color: "#10b981" }}>{step.icon}</Box>
                  {step.label}
                </Typography>
              </StepLabel>
              <StepContent>
                <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
                  {step.description}
                </Typography>
              </StepContent>
            </Step>
          ))}
        </Stepper>
      </Paper>

      {/* CTA Footer */}
      <Paper
        sx={{
          p: 4,
          borderRadius: 3,
          textAlign: "center",
          background: `linear-gradient(135deg, ${alpha("#10b981", 0.1)} 0%, ${alpha("#0ea5e9", 0.05)} 100%)`,
          border: `1px solid ${alpha("#10b981", 0.2)}`,
        }}
      >
        <GppGoodIcon sx={{ fontSize: 48, color: "#10b981", mb: 2 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
          Ready to Analyze Your Network?
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 500, mx: "auto" }}>
          Start discovering vulnerabilities and security issues in your network infrastructure with AI-powered analysis.
        </Typography>
        <Button
          variant="contained"
          size="large"
          startIcon={<RocketLaunchIcon />}
          onClick={() => navigate("/network")}
          sx={{
            background: `linear-gradient(135deg, #10b981 0%, #0ea5e9 100%)`,
            px: 4,
            py: 1.5,
            fontWeight: 700,
            fontSize: "1rem",
            boxShadow: `0 4px 20px ${alpha("#10b981", 0.4)}`,
            "&:hover": {
              boxShadow: `0 6px 30px ${alpha("#10b981", 0.5)}`,
            },
          }}
        >
          Launch Network Analysis Hub
        </Button>
      </Paper>
    </Container>
  );
}
