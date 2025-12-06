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
  CardActionArea,
  Chip,
  Divider,
} from "@mui/material";
import { useNavigate } from "react-router-dom";
import SchoolIcon from "@mui/icons-material/School";
import SecurityIcon from "@mui/icons-material/Security";
import PsychologyIcon from "@mui/icons-material/Psychology";
import LinkIcon from "@mui/icons-material/Link";
import GpsFixedIcon from "@mui/icons-material/GpsFixed";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import WarningIcon from "@mui/icons-material/Warning";
import BugReportIcon from "@mui/icons-material/BugReport";
import TerminalIcon from "@mui/icons-material/Terminal";
import PhoneAndroidIcon from "@mui/icons-material/PhoneAndroid";
import LockIcon from "@mui/icons-material/Lock";
import FolderSpecialIcon from "@mui/icons-material/FolderSpecial";
import RadarIcon from "@mui/icons-material/Radar";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import ApiIcon from "@mui/icons-material/Api";
import MemoryIcon from "@mui/icons-material/Memory";
import HubIcon from "@mui/icons-material/Hub";
import WifiIcon from "@mui/icons-material/Wifi";

interface LearnCard {
  title: string;
  description: string;
  icon: React.ReactNode;
  path: string;
  color: string;
  tags: string[];
  badge?: string;
}

// VRAgent-specific pages (About the App)
const appCards: LearnCard[] = [
  {
    title: "How Scanning Works",
    description: "Discover the 9-step pipeline VRAgent uses to scan your code, from git cloning through AI analysis.",
    icon: <SecurityIcon sx={{ fontSize: 40 }} />,
    path: "/learn/scanning",
    color: "#3b82f6",
    tags: ["SAST", "SCA", "SBOM", "Secrets"],
    badge: "Start Here",
  },
  {
    title: "AI Analysis Explained",
    description: "See how Gemini AI transforms raw vulnerability data into actionable security intelligence.",
    icon: <PsychologyIcon sx={{ fontSize: 40 }} />,
    path: "/learn/ai-analysis",
    color: "#8b5cf6",
    tags: ["Gemini AI", "Prompts", "Red Team"],
  },
  {
    title: "VRAgent Architecture",
    description: "Deep dive into Docker services, backend architecture, data models, and the scan pipeline.",
    icon: <AccountTreeIcon sx={{ fontSize: 40 }} />,
    path: "/learn/architecture",
    color: "#6366f1",
    tags: ["Docker", "FastAPI", "PostgreSQL"],
  },
];

// Network Analysis learning pages
const networkCards: LearnCard[] = [
  {
    title: "Network Analysis Hub",
    description: "Learn what the Network Analysis Hub does: Nmap scanning, PCAP analysis, and AI-powered insights.",
    icon: <HubIcon sx={{ fontSize: 40 }} />,
    path: "/learn/network-hub",
    color: "#0ea5e9",
    tags: ["Nmap", "PCAP", "AI Chat"],
    badge: "New",
  },
  {
    title: "Wireshark Essentials",
    description: "Master packet analysis with essential display filters, capture filters, and security use cases.",
    icon: <WifiIcon sx={{ fontSize: 40 }} />,
    path: "/learn/wireshark",
    color: "#06b6d4",
    tags: ["Filters", "BPF", "Packets"],
  },
  {
    title: "Nmap & Zenmap Guide",
    description: "Network scanning fundamentals: scan types, common commands, and NSE scripting basics.",
    icon: <RadarIcon sx={{ fontSize: 40 }} />,
    path: "/learn/nmap",
    color: "#8b5cf6",
    tags: ["Port Scanning", "NSE", "Discovery"],
  },
];

// General security learning pages
const securityCards: LearnCard[] = [
  {
    title: "Cyber Kill Chain",
    description: "Master the 7 phases of the Lockheed Martin Cyber Kill Chain. Understand how attackers operate.",
    icon: <LinkIcon sx={{ fontSize: 40 }} />,
    path: "/learn/kill-chain",
    color: "#ef4444",
    tags: ["Attack Phases", "Defense", "Threat Intel"],
  },
  {
    title: "MITRE ATT&CK",
    description: "Explore the knowledge base of adversary tactics and techniques. 14 tactics, 200+ techniques.",
    icon: <GpsFixedIcon sx={{ fontSize: 40 }} />,
    path: "/learn/mitre-attack",
    color: "#f59e0b",
    tags: ["TTPs", "Threat Modeling", "Detection"],
  },
  {
    title: "OWASP Top 10",
    description: "The industry standard for web application security. Deep dive into the 10 most critical risks.",
    icon: <WarningIcon sx={{ fontSize: 40 }} />,
    path: "/learn/owasp",
    color: "#dc2626",
    tags: ["Web Security", "2021", "Prevention"],
  },
  {
    title: "OWASP Mobile Top 10",
    description: "Critical security risks for mobile applications (2024). Platform-specific guidance.",
    icon: <PhoneAndroidIcon sx={{ fontSize: 40 }} />,
    path: "/learn/owasp-mobile",
    color: "#8b5cf6",
    tags: ["Mobile", "Android", "iOS"],
  },
  {
    title: "CVE, CWE, CVSS & EPSS",
    description: "Understand vulnerability identification and scoring systems. Interactive CVSS calculator.",
    icon: <BugReportIcon sx={{ fontSize: 40 }} />,
    path: "/learn/cve-cwe-cvss",
    color: "#ea580c",
    tags: ["Scoring", "Severity", "Prioritization"],
  },
  {
    title: "Web Pentesting Guide",
    description: "Comprehensive methodology for web app security assessments. From recon to reporting.",
    icon: <SecurityIcon sx={{ fontSize: 40 }} />,
    path: "/learn/pentest-guide",
    color: "#dc2626",
    tags: ["Methodology", "Attacks", "Reporting"],
  },
  {
    title: "Auth & Crypto Foundations",
    description: "Authentication, cryptography, sessions, JWTs, OAuth, TLS, and access control.",
    icon: <LockIcon sx={{ fontSize: 40 }} />,
    path: "/learn/auth-crypto",
    color: "#059669",
    tags: ["Auth", "Crypto", "JWT", "OAuth"],
  },
  {
    title: "Data & Secrets Guide",
    description: "File uploads/downloads, data storage, logs, backups, secrets hunting, and exfiltration.",
    icon: <FolderSpecialIcon sx={{ fontSize: 40 }} />,
    path: "/learn/data-secrets",
    color: "#d97706",
    tags: ["File Upload", "Secrets", "Exfil"],
  },
  {
    title: "Fuzzing Deep Dive",
    description: "Automated bug hunting with coverage-guided fuzzing. AFL++, libFuzzer, crash triage.",
    icon: <RadarIcon sx={{ fontSize: 40 }} />,
    path: "/learn/fuzzing",
    color: "#ef4444",
    tags: ["AFL++", "Automation", "Crashes"],
  },
  {
    title: "API Security Testing",
    description: "REST & GraphQL security testing. BOLA, authentication bypass, injection, rate limits.",
    icon: <ApiIcon sx={{ fontSize: 40 }} />,
    path: "/learn/api-security",
    color: "#3b82f6",
    tags: ["REST", "GraphQL", "OWASP API"],
  },
  {
    title: "Reverse Engineering Intro",
    description: "Binary analysis fundamentals. Disassembly, debugging, x86 assembly, Ghidra basics.",
    icon: <MemoryIcon sx={{ fontSize: 40 }} />,
    path: "/learn/reverse-engineering",
    color: "#a855f7",
    tags: ["Binary", "Malware", "Ghidra"],
  },
  {
    title: "Mobile App Pentesting",
    description: "Android & iOS security testing. Frida, SSL pinning bypass, data storage analysis.",
    icon: <PhoneAndroidIcon sx={{ fontSize: 40 }} />,
    path: "/learn/mobile-pentest",
    color: "#10b981",
    tags: ["Android", "iOS", "Frida"],
    badge: "New",
  },
];

// Reference pages
const referenceCards: LearnCard[] = [
  {
    title: "Security Glossary",
    description: "Comprehensive dictionary of 120+ cybersecurity terms with definitions and category filtering.",
    icon: <MenuBookIcon sx={{ fontSize: 40 }} />,
    path: "/learn/glossary",
    color: "#10b981",
    tags: ["Definitions", "Reference", "Terms"],
  },
  {
    title: "Commands Reference",
    description: "Essential Linux, PowerShell, Nmap, and Wireshark commands. Copy-to-clipboard ready.",
    icon: <TerminalIcon sx={{ fontSize: 40 }} />,
    path: "/learn/commands",
    color: "#6366f1",
    tags: ["Linux", "PowerShell", "Nmap"],
  },
];

interface CardGridProps {
  cards: LearnCard[];
  columns?: { xs: number; sm: number; md: number; lg: number };
}

function CardGrid({ cards, columns = { xs: 12, sm: 6, md: 4, lg: 3 } }: CardGridProps) {
  const navigate = useNavigate();
  
  return (
    <Grid container spacing={3}>
      {cards.map((card) => (
        <Grid item xs={columns.xs} sm={columns.sm} md={columns.md} lg={columns.lg} key={card.path}>
          <Card
            sx={{
              height: "100%",
              borderRadius: 3,
              border: `1px solid ${alpha(card.color, 0.15)}`,
              transition: "all 0.3s ease",
              position: "relative",
              overflow: "visible",
              "&:hover": {
                transform: "translateY(-4px)",
                boxShadow: `0 12px 40px ${alpha(card.color, 0.15)}`,
                borderColor: card.color,
              },
            }}
          >
            {card.badge && (
              <Chip
                label={card.badge}
                size="small"
                sx={{
                  position: "absolute",
                  top: -10,
                  right: 16,
                  bgcolor: card.color,
                  color: "white",
                  fontWeight: 700,
                  fontSize: "0.7rem",
                }}
              />
            )}
            <CardActionArea
              onClick={() => navigate(card.path)}
              sx={{ height: "100%", display: "flex", flexDirection: "column", alignItems: "stretch" }}
            >
              <CardContent sx={{ flex: 1, display: "flex", flexDirection: "column", p: 3 }}>
                <Box
                  sx={{
                    width: 56,
                    height: 56,
                    borderRadius: 2,
                    bgcolor: alpha(card.color, 0.1),
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    mb: 2,
                    color: card.color,
                  }}
                >
                  {card.icon}
                </Box>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 1.5, lineHeight: 1.3 }}>
                  {card.title}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2, flex: 1, lineHeight: 1.6 }}>
                  {card.description}
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                  {card.tags.map((tag) => (
                    <Chip
                      key={tag}
                      label={tag}
                      size="small"
                      sx={{
                        fontSize: "0.65rem",
                        height: 22,
                        bgcolor: alpha(card.color, 0.08),
                        color: card.color,
                        fontWeight: 500,
                      }}
                    />
                  ))}
                </Box>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
      ))}
    </Grid>
  );
}

export default function LearnHubPage() {
  const theme = useTheme();
  const navigate = useNavigate();

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ textAlign: "center", mb: 6 }}>
        <Box
          sx={{
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            width: 100,
            height: 100,
            borderRadius: "50%",
            background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.2)}, ${alpha(theme.palette.secondary.main, 0.2)})`,
            mb: 3,
            boxShadow: `0 8px 32px ${alpha(theme.palette.primary.main, 0.3)}`,
            border: `3px solid ${alpha(theme.palette.primary.main, 0.3)}`,
          }}
        >
          <SchoolIcon sx={{ fontSize: 50, color: "primary.main" }} />
        </Box>
        <Typography
          variant="h2"
          sx={{
            fontWeight: 800,
            mb: 2,
            background: `linear-gradient(135deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          Security Learning Hub
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 700, mx: "auto", lineHeight: 1.7 }}>
          Master cybersecurity concepts, frameworks, and tools. From understanding how VRAgent scans your code to advanced threat modeling with MITRE ATT&CK.
        </Typography>
      </Box>

      {/* Stats Bar */}
      <Paper
        sx={{
          p: 3,
          mb: 5,
          borderRadius: 3,
          display: "flex",
          justifyContent: "center",
          flexWrap: "wrap",
          gap: 4,
          background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.03)}, ${alpha(theme.palette.secondary.main, 0.03)})`,
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
        }}
      >
        {[
          { value: "20", label: "Learning Topics" },
          { value: "120+", label: "Glossary Terms" },
          { value: "200+", label: "Commands" },
          { value: "30+", label: "Attack Types" },
        ].map((stat, i) => (
          <Box key={i} sx={{ textAlign: "center", minWidth: 100 }}>
            <Typography variant="h4" sx={{ fontWeight: 800, color: "primary.main" }}>
              {stat.value}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {stat.label}
            </Typography>
          </Box>
        ))}
      </Paper>

      {/* SECTION 1: About VRAgent */}
      <Box sx={{ mb: 6 }}>
        <Paper
          sx={{
            p: 3,
            mb: 3,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#6366f1", 0.1)}, ${alpha("#8b5cf6", 0.05)})`,
            border: `1px solid ${alpha("#6366f1", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
            <RocketLaunchIcon sx={{ color: "#6366f1", fontSize: 32 }} />
            <Typography variant="h5" sx={{ fontWeight: 700 }}>
              🛡️ About VRAgent
            </Typography>
          </Box>
          <Typography variant="body2" color="text.secondary">
            Learn how VRAgent works under the hood. Understand the scanning pipeline, AI analysis, and system architecture.
          </Typography>
        </Paper>
        
        <CardGrid cards={appCards} columns={{ xs: 12, sm: 6, md: 4, lg: 4 }} />
      </Box>

      <Divider sx={{ my: 5 }} />

      {/* SECTION 2: Network Analysis */}
      <Box sx={{ mb: 6 }}>
        <Paper
          sx={{
            p: 3,
            mb: 3,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#0ea5e9", 0.1)}, ${alpha("#06b6d4", 0.05)})`,
            border: `1px solid ${alpha("#0ea5e9", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
            <HubIcon sx={{ color: "#0ea5e9", fontSize: 32 }} />
            <Typography variant="h5" sx={{ fontWeight: 700 }}>
              🌐 Network Analysis
            </Typography>
          </Box>
          <Typography variant="body2" color="text.secondary">
            Master network security tools. Learn how to use VRAgent's Network Hub, Wireshark, and Nmap effectively.
          </Typography>
        </Paper>
        
        <CardGrid cards={networkCards} columns={{ xs: 12, sm: 6, md: 4, lg: 4 }} />
      </Box>

      <Divider sx={{ my: 5 }} />

      {/* SECTION 3: Security Fundamentals */}
      <Box sx={{ mb: 6 }}>
        <Paper
          sx={{
            p: 3,
            mb: 3,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#ef4444", 0.1)}, ${alpha("#f59e0b", 0.05)})`,
            border: `1px solid ${alpha("#ef4444", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
            <SecurityIcon sx={{ color: "#ef4444", fontSize: 32 }} />
            <Typography variant="h5" sx={{ fontWeight: 700 }}>
              🎯 Security Fundamentals
            </Typography>
          </Box>
          <Typography variant="body2" color="text.secondary">
            Core security concepts, frameworks, and methodologies every security professional should know.
          </Typography>
        </Paper>
        
        <CardGrid cards={securityCards} />
      </Box>

      <Divider sx={{ my: 5 }} />

      {/* SECTION 4: Quick Reference */}
      <Box sx={{ mb: 6 }}>
        <Paper
          sx={{
            p: 3,
            mb: 3,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#10b981", 0.1)}, ${alpha("#6366f1", 0.05)})`,
            border: `1px solid ${alpha("#10b981", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
            <MenuBookIcon sx={{ color: "#10b981", fontSize: 32 }} />
            <Typography variant="h5" sx={{ fontWeight: 700 }}>
              📚 Quick Reference
            </Typography>
          </Box>
          <Typography variant="body2" color="text.secondary">
            Handy glossaries and command references to keep at your fingertips during assessments.
          </Typography>
        </Paper>
        
        <CardGrid cards={referenceCards} columns={{ xs: 12, sm: 6, md: 6, lg: 6 }} />
      </Box>

      {/* Footer CTA */}
      <Paper
        sx={{
          mt: 6,
          p: 4,
          borderRadius: 3,
          textAlign: "center",
          background: `linear-gradient(135deg, ${alpha(theme.palette.info.main, 0.05)}, ${alpha(theme.palette.success.main, 0.05)})`,
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
        }}
      >
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
          🚀 Ready to Scan Your Code?
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Now that you understand how VRAgent works, start scanning your projects for vulnerabilities.
        </Typography>
        <Chip
          label="Go to Projects →"
          clickable
          onClick={() => navigate("/")}
          sx={{
            bgcolor: "primary.main",
            color: "white",
            fontWeight: 600,
            px: 2,
            "&:hover": { bgcolor: "primary.dark" },
          }}
        />
      </Paper>
    </Container>
  );
}
