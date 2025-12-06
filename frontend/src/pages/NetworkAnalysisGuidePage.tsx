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
} from "@mui/material";
import { Link } from "react-router-dom";
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

export default function NetworkAnalysisGuidePage() {
  const theme = useTheme();

  const features = [
    {
      title: "Nmap Scanner & Analyzer",
      icon: <RadarIcon />,
      color: "#8b5cf6",
      description: "Run live Nmap scans or upload existing scan files for AI-powered analysis.",
      capabilities: [
        "Live scanning with multiple scan types (Basic, Quick, Full, Service Detection, OS Detection)",
        "Upload and analyze existing Nmap XML/text output files",
        "Target validation for IPs, CIDR ranges, and hostnames",
        "Real-time scan progress tracking",
      ],
    },
    {
      title: "PCAP Analyzer",
      icon: <NetworkCheckIcon />,
      color: "#3b82f6",
      description: "Capture live network traffic or analyze PCAP files to identify security issues.",
      capabilities: [
        "Live packet capture with configurable profiles (Web, DNS, Auth, Database)",
        "Upload and analyze PCAP/PCAPNG files",
        "Protocol distribution and connection tracking",
        "HTTP/DNS/suspicious pattern detection",
      ],
    },
    {
      title: "AI-Powered Analysis",
      icon: <SmartToyIcon />,
      color: "#10b981",
      description: "Google Gemini AI generates comprehensive security reports from your network data.",
      capabilities: [
        "Network overview and attack surface assessment",
        "Risk scoring (0-100 scale) with severity ratings",
        "Vulnerable services identification",
        "Detailed remediation recommendations",
      ],
    },
    {
      title: "Interactive AI Chat",
      icon: <ChatIcon />,
      color: "#f59e0b",
      description: "Chat with Gemini AI about your scan results to get deeper insights.",
      capabilities: [
        "Ask questions about specific findings",
        "Get remediation guidance tailored to your environment",
        "Explore attack scenarios and their impact",
        "Conversation history maintained during session",
      ],
    },
    {
      title: "Report Management",
      icon: <StorageIcon />,
      color: "#6366f1",
      description: "Save, view, and manage your network analysis reports.",
      capabilities: [
        "All scan results automatically saved to database",
        "Browse saved reports with filtering by type",
        "View historical scans and compare results",
        "Delete old reports to manage storage",
      ],
    },
    {
      title: "Export Options",
      icon: <DownloadIcon />,
      color: "#ef4444",
      description: "Download professional reports in multiple formats.",
      capabilities: [
        "Markdown export for documentation",
        "PDF export for formal reports",
        "DOCX export for editing and sharing",
      ],
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

      {/* Header */}
      <Paper
        sx={{
          p: 4,
          mb: 4,
          borderRadius: 3,
          background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.1)}, ${alpha("#8b5cf6", 0.05)})`,
          border: `1px solid ${alpha("#3b82f6", 0.2)}`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <Box
            sx={{
              width: 64,
              height: 64,
              borderRadius: 2,
              bgcolor: alpha("#3b82f6", 0.1),
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <HubIcon sx={{ fontSize: 36, color: "#3b82f6" }} />
          </Box>
          <Box>
            <Typography variant="h4" sx={{ fontWeight: 700 }}>
              Network Analysis Hub
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Understanding VRAgent's network security analysis capabilities
            </Typography>
          </Box>
        </Box>
      </Paper>

      {/* Introduction */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          What is the Network Analysis Hub?
        </Typography>
        <Typography variant="body1" paragraph>
          The Network Analysis Hub is VRAgent's dedicated module for analyzing network infrastructure and traffic. 
          It combines industry-standard tools like <strong>Nmap</strong> and <strong>Wireshark/tshark</strong> with 
          AI-powered analysis from Google Gemini to provide comprehensive security insights.
        </Typography>
        <Typography variant="body1" paragraph>
          Whether you're performing a penetration test, conducting a security audit, or investigating suspicious 
          network activity, the Network Analysis Hub helps you:
        </Typography>
        <List>
          {[
            "Discover hosts and services on your network",
            "Identify vulnerable services and misconfigurations",
            "Analyze captured network traffic for security issues",
            "Get AI-generated security reports with remediation guidance",
            "Chat with AI to explore findings in depth",
          ].map((item, index) => (
            <ListItem key={index} sx={{ py: 0.5 }}>
              <ListItemIcon sx={{ minWidth: 36 }}>
                <CheckCircleIcon sx={{ color: "#10b981" }} />
              </ListItemIcon>
              <ListItemText primary={item} />
            </ListItem>
          ))}
        </List>
      </Paper>

      {/* Features Grid */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
        Key Features
      </Typography>
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {features.map((feature) => (
          <Grid item xs={12} md={6} key={feature.title}>
            <Card
              sx={{
                height: "100%",
                borderRadius: 3,
                border: `1px solid ${alpha(feature.color, 0.2)}`,
                "&:hover": {
                  borderColor: feature.color,
                  boxShadow: `0 4px 20px ${alpha(feature.color, 0.15)}`,
                },
              }}
            >
              <CardContent sx={{ p: 3 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <Box
                    sx={{
                      width: 48,
                      height: 48,
                      borderRadius: 2,
                      bgcolor: alpha(feature.color, 0.1),
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      color: feature.color,
                    }}
                  >
                    {feature.icon}
                  </Box>
                  <Typography variant="h6" sx={{ fontWeight: 700 }}>
                    {feature.title}
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  {feature.description}
                </Typography>
                <List dense>
                  {feature.capabilities.map((cap, idx) => (
                    <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}>
                        <Box
                          sx={{
                            width: 6,
                            height: 6,
                            borderRadius: "50%",
                            bgcolor: feature.color,
                          }}
                        />
                      </ListItemIcon>
                      <ListItemText
                        primary={cap}
                        primaryTypographyProps={{ variant: "body2" }}
                      />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Quick Start */}
      <Paper sx={{ p: 4, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          Getting Started
        </Typography>
        <Typography variant="body1" paragraph>
          Access the Network Analysis Hub from the sidebar navigation. From there you can:
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} md={4}>
            <Paper
              sx={{
                p: 2,
                borderRadius: 2,
                bgcolor: alpha("#8b5cf6", 0.05),
                border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
              }}
            >
              <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                1. Nmap Scanning
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Enter a target IP/hostname, select a scan type, and click "Start Scan". 
                Or upload existing Nmap output files.
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper
              sx={{
                p: 2,
                borderRadius: 2,
                bgcolor: alpha("#3b82f6", 0.05),
                border: `1px solid ${alpha("#3b82f6", 0.2)}`,
              }}
            >
              <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                2. PCAP Analysis
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Upload a PCAP file or start a live capture. The AI will analyze 
                traffic patterns and identify security concerns.
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper
              sx={{
                p: 2,
                borderRadius: 2,
                bgcolor: alpha("#10b981", 0.05),
                border: `1px solid ${alpha("#10b981", 0.2)}`,
              }}
            >
              <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                3. Review & Chat
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Review the AI-generated report, then use the chat feature to ask 
                follow-up questions about specific findings.
              </Typography>
            </Paper>
          </Grid>
        </Grid>
      </Paper>
    </Container>
  );
}
