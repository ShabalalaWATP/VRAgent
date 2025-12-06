import {
  Container,
  CssBaseline,
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  Box,
  Tooltip,
  useTheme,
  alpha,
  keyframes,
  Chip,
  Button,
} from "@mui/material";
import { Routes, Route, Link } from "react-router-dom";
import { useThemeMode } from "./theme/ThemeProvider";
import ProjectListPage from "./pages/ProjectListPage";
import ProjectDetailPage from "./pages/ProjectDetailPage";
import ReportDetailPage from "./pages/ReportDetailPage";
import LearnHubPage from "./pages/LearnHubPage";
import ScanningPage from "./pages/ScanningPage";
import AIAnalysisPage from "./pages/AIAnalysisPage";
import KillChainPage from "./pages/KillChainPage";
import MitreAttackPage from "./pages/MitreAttackPage";
import GlossaryPage from "./pages/GlossaryPage";
import OwaspTop10Page from "./pages/OwaspTop10Page";
import CveCweCvssPage from "./pages/CveCweCvssPage";
import CommandsPage from "./pages/CommandsPage";
import PentestGuidePage from "./pages/PentestGuidePage";
import OwaspMobilePage from "./pages/OwaspMobilePage";
import AuthCryptoGuidePage from "./pages/AuthCryptoGuidePage";
import DataSecretsPage from "./pages/DataSecretsPage";
import FuzzingGuidePage from "./pages/FuzzingGuidePage";
import ArchitecturePage from "./pages/ArchitecturePage";
import ApiSecurityPage from "./pages/ApiSecurityPage";
import ReverseEngineeringPage from "./pages/ReverseEngineeringPage";
import MobilePentestPage from "./pages/MobilePentestPage";
import PcapAnalyzerPage from "./pages/PcapAnalyzerPage";
import NetworkAnalysisHub from "./pages/NetworkAnalysisHub";
import NmapAnalyzerPage from "./pages/NmapAnalyzerPage";
import NetworkAnalysisGuidePage from "./pages/NetworkAnalysisGuidePage";
import WiresharkGuidePage from "./pages/WiresharkGuidePage";
import NmapGuidePage from "./pages/NmapGuidePage";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import HubIcon from "@mui/icons-material/Hub";

// Animations
const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
`;

const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-3px); }
`;

// Icons as inline SVG for simplicity
const DarkModeIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 3a9 9 0 1 0 9 9c0-.46-.04-.92-.1-1.36a5.389 5.389 0 0 1-4.4 2.26 5.403 5.403 0 0 1-3.14-9.8c-.44-.06-.9-.1-1.36-.1z" />
  </svg>
);

const LightModeIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58a.996.996 0 0 0-1.41 0 .996.996 0 0 0 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41L5.99 4.58zm12.37 12.37a.996.996 0 0 0-1.41 0 .996.996 0 0 0 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0a.996.996 0 0 0 0-1.41l-1.06-1.06zm1.06-10.96a.996.996 0 0 0 0-1.41.996.996 0 0 0-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06zM7.05 18.36a.996.996 0 0 0 0-1.41.996.996 0 0 0-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06z" />
  </svg>
);

const ShieldIcon = () => (
  <svg width="32" height="32" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z" />
  </svg>
);

const GitHubIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
  </svg>
);

function App() {
  const { mode, toggleTheme } = useThemeMode();
  const theme = useTheme();

  return (
    <>
      <CssBaseline />
      <AppBar 
        position="sticky" 
        elevation={0}
        sx={{
          background: mode === "dark" 
            ? `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.95)} 0%, ${alpha(theme.palette.background.default, 0.98)} 100%)`
            : `linear-gradient(135deg, ${alpha("#ffffff", 0.95)} 0%, ${alpha("#f8fafc", 0.98)} 100%)`,
          backdropFilter: "blur(20px)",
          borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
        }}
      >
        <Toolbar sx={{ px: { xs: 2, sm: 4 }, py: 2, minHeight: { xs: 90, sm: 110 } }}>
          <Link
            to="/"
            style={{
              display: "flex",
              alignItems: "center",
              color: "inherit",
              textDecoration: "none",
            }}
          >
            {/* Logo Image */}
            <Box
              component="img"
              src="/images/logo.jpg"
              alt="VRAgent Logo"
              sx={{
                width: { xs: 64, sm: 80 },
                height: { xs: 64, sm: 80 },
                borderRadius: 3,
                objectFit: "cover",
                boxShadow: `0 4px 20px ${alpha(theme.palette.primary.main, 0.4)}`,
                mr: 2.5,
                animation: `${float} 3s ease-in-out infinite`,
              }}
            />

            {/* Title and Subtitle */}
            <Box>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                <Typography
                  variant="h4"
                  component="span"
                  sx={{
                    fontWeight: 800,
                    fontSize: { xs: "1.5rem", sm: "1.85rem" },
                    background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 50%, ${theme.palette.primary.light} 100%)`,
                    backgroundSize: "200% auto",
                    backgroundClip: "text",
                    WebkitBackgroundClip: "text",
                    WebkitTextFillColor: "transparent",
                    letterSpacing: "-0.03em",
                    animation: `${shimmer} 4s linear infinite`,
                  }}
                >
                  VRAgent
                </Typography>
                <Chip
                  label="BETA"
                  size="small"
                  sx={{
                    height: 20,
                    fontSize: "0.6rem",
                    fontWeight: 700,
                    letterSpacing: "0.05em",
                    bgcolor: alpha(theme.palette.warning.main, 0.15),
                    color: theme.palette.warning.main,
                    border: `1px solid ${alpha(theme.palette.warning.main, 0.3)}`,
                    animation: `${pulse} 2s ease-in-out infinite`,
                  }}
                />
              </Box>
              <Typography
                variant="caption"
                component="div"
                sx={{
                  color: "text.secondary",
                  fontSize: { xs: "0.65rem", sm: "0.75rem" },
                  fontWeight: 500,
                  letterSpacing: "0.15em",
                  textTransform: "uppercase",
                  mt: 0.25,
                }}
              >
                Security Vulnerability Scanner
              </Typography>
            </Box>
          </Link>

          <Box sx={{ flexGrow: 1 }} />

          {/* Action Buttons */}
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
            <Tooltip title="Projects - Manage your codebases">
              <Button
                component={Link}
                to="/"
                startIcon={<Box component="span" sx={{ display: "flex" }}><svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z" /></svg></Box>}
                variant="outlined"
                size="medium"
                sx={{
                  color: theme.palette.text.secondary,
                  fontWeight: 600,
                  px: 2,
                  py: 1,
                  borderRadius: 2,
                  textTransform: "none",
                  fontSize: "0.95rem",
                  borderColor: alpha(theme.palette.divider, 0.3),
                  "&:hover": {
                    borderColor: theme.palette.primary.main,
                    bgcolor: alpha(theme.palette.primary.main, 0.1),
                    color: theme.palette.primary.main,
                  },
                  transition: "all 0.3s ease",
                }}
              >
                Projects
              </Button>
            </Tooltip>
            
            <Tooltip title="Network Analysis - PCAP & Nmap Security Analysis">
              <Button
                component={Link}
                to="/network"
                startIcon={<HubIcon sx={{ fontSize: "1.3rem !important" }} />}
                variant="contained"
                size="medium"
                sx={{
                  background: `linear-gradient(135deg, #06b6d4 0%, #0891b2 50%, #0e7490 100%)`,
                  color: "white",
                  fontWeight: 700,
                  px: 2.5,
                  py: 1,
                  borderRadius: 2,
                  textTransform: "none",
                  fontSize: "0.95rem",
                  boxShadow: `0 4px 15px ${alpha("#0891b2", 0.4)}, 0 0 20px ${alpha("#0891b2", 0.2)}`,
                  border: `1px solid ${alpha("#06b6d4", 0.5)}`,
                  "&:hover": {
                    background: `linear-gradient(135deg, #0891b2 0%, #0e7490 50%, #155e75 100%)`,
                    boxShadow: `0 6px 25px ${alpha("#0891b2", 0.5)}, 0 0 30px ${alpha("#0891b2", 0.3)}`,
                    transform: "translateY(-2px)",
                  },
                  "&:active": {
                    transform: "translateY(0)",
                  },
                  transition: "all 0.3s ease",
                }}
              >
                Network Analysis
              </Button>
            </Tooltip>
            
            <Tooltip title="Security Learning Hub - Tutorials, Guides & Reference">
              <Button
                component={Link}
                to="/learn"
                startIcon={<MenuBookIcon sx={{ fontSize: "1.3rem !important" }} />}
                variant="contained"
                size="medium"
                sx={{
                  background: `linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #a855f7 100%)`,
                  color: "white",
                  fontWeight: 700,
                  px: 2.5,
                  py: 1,
                  borderRadius: 2,
                  textTransform: "none",
                  fontSize: "0.95rem",
                  boxShadow: `0 4px 15px ${alpha("#8b5cf6", 0.4)}, 0 0 20px ${alpha("#8b5cf6", 0.2)}`,
                  animation: `${pulse} 3s ease-in-out infinite`,
                  border: `1px solid ${alpha("#a855f7", 0.5)}`,
                  "&:hover": {
                    background: `linear-gradient(135deg, #4f46e5 0%, #7c3aed 50%, #9333ea 100%)`,
                    boxShadow: `0 6px 25px ${alpha("#8b5cf6", 0.5)}, 0 0 30px ${alpha("#8b5cf6", 0.3)}`,
                    transform: "translateY(-2px)",
                  },
                  "&:active": {
                    transform: "translateY(0)",
                  },
                  transition: "all 0.3s ease",
                }}
              >
                Learn
              </Button>
            </Tooltip>
            
            <Tooltip title="View on GitHub">
              <IconButton
                component="a"
                href="https://github.com/ShabalalaWATP/VRAgent"
                target="_blank"
                rel="noopener noreferrer"
                sx={{
                  color: "text.secondary",
                  bgcolor: alpha(theme.palette.divider, 0.1),
                  "&:hover": {
                    bgcolor: alpha(theme.palette.primary.main, 0.1),
                    color: "text.primary",
                  },
                }}
              >
                <GitHubIcon />
              </IconButton>
            </Tooltip>
            
            <Tooltip title={mode === "dark" ? "Switch to light mode" : "Switch to dark mode"}>
              <IconButton
                onClick={toggleTheme}
                sx={{
                  color: "text.secondary",
                  bgcolor: alpha(theme.palette.divider, 0.1),
                  transition: "all 0.3s ease",
                  "&:hover": {
                    bgcolor: alpha(theme.palette.primary.main, 0.1),
                    color: theme.palette.primary.main,
                    transform: "rotate(180deg)",
                  },
                }}
              >
                {mode === "dark" ? <LightModeIcon /> : <DarkModeIcon />}
              </IconButton>
            </Tooltip>
          </Box>
        </Toolbar>
      </AppBar>

      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Routes>
          <Route path="/" element={<ProjectListPage />} />
          <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
          <Route path="/reports/:reportId" element={<ReportDetailPage />} />
          <Route path="/network" element={<NetworkAnalysisHub />} />
          <Route path="/network/pcap" element={<PcapAnalyzerPage />} />
          <Route path="/network/nmap" element={<NmapAnalyzerPage />} />
          <Route path="/pcap" element={<PcapAnalyzerPage />} />
          <Route path="/learn" element={<LearnHubPage />} />
          <Route path="/learn/scanning" element={<ScanningPage />} />
          <Route path="/learn/ai-analysis" element={<AIAnalysisPage />} />
          <Route path="/learn/kill-chain" element={<KillChainPage />} />
          <Route path="/learn/mitre-attack" element={<MitreAttackPage />} />
          <Route path="/learn/glossary" element={<GlossaryPage />} />
          <Route path="/learn/owasp" element={<OwaspTop10Page />} />
          <Route path="/learn/cve-cwe-cvss" element={<CveCweCvssPage />} />
          <Route path="/learn/commands" element={<CommandsPage />} />
          <Route path="/learn/pentest-guide" element={<PentestGuidePage />} />
          <Route path="/learn/owasp-mobile" element={<OwaspMobilePage />} />
          <Route path="/learn/auth-crypto" element={<AuthCryptoGuidePage />} />
          <Route path="/learn/data-secrets" element={<DataSecretsPage />} />
          <Route path="/learn/fuzzing" element={<FuzzingGuidePage />} />
          <Route path="/learn/architecture" element={<ArchitecturePage />} />
          <Route path="/learn/api-security" element={<ApiSecurityPage />} />
          <Route path="/learn/reverse-engineering" element={<ReverseEngineeringPage />} />
          <Route path="/learn/mobile-pentest" element={<MobilePentestPage />} />
          <Route path="/learn/network-hub" element={<NetworkAnalysisGuidePage />} />
          <Route path="/learn/wireshark" element={<WiresharkGuidePage />} />
          <Route path="/learn/nmap" element={<NmapGuidePage />} />
        </Routes>
      </Container>
    </>
  );
}

export default App;
