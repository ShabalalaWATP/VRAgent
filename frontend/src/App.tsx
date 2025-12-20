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
  CircularProgress,
} from "@mui/material";
import { Routes, Route, Link } from "react-router-dom";
import { lazy, Suspense } from "react";
import { useThemeMode } from "./theme/ThemeProvider";
import { useAuth } from "./contexts/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import UserMenu from "./components/UserMenu";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import HubIcon from "@mui/icons-material/Hub";
import MemoryIcon from "@mui/icons-material/Memory";

// Lazy load all pages
const ProjectListPage = lazy(() => import("./pages/ProjectListPage"));
const ProjectDetailPage = lazy(() => import("./pages/ProjectDetailPage"));
const ReportDetailPage = lazy(() => import("./pages/ReportDetailPage"));
const LearnHubPage = lazy(() => import("./pages/LearnHubPage"));
const ScanningPage = lazy(() => import("./pages/ScanningPage"));
const AIAnalysisPage = lazy(() => import("./pages/AIAnalysisPage"));
const KillChainPage = lazy(() => import("./pages/KillChainPage"));
const MitreAttackPage = lazy(() => import("./pages/MitreAttackPage"));
const GlossaryPage = lazy(() => import("./pages/GlossaryPage"));
const OwaspTop10Page = lazy(() => import("./pages/OwaspTop10Page"));
const CveCweCvssPage = lazy(() => import("./pages/CveCweCvssPage"));
const CommandsPage = lazy(() => import("./pages/CommandsPage"));
const PentestGuidePage = lazy(() => import("./pages/PentestGuidePage"));
const OwaspMobilePage = lazy(() => import("./pages/OwaspMobilePage"));
const AuthCryptoGuidePage = lazy(() => import("./pages/AuthCryptoGuidePage"));
const DataSecretsPage = lazy(() => import("./pages/DataSecretsPage"));
const FuzzingGuidePage = lazy(() => import("./pages/FuzzingGuidePage"));
const ArchitecturePage = lazy(() => import("./pages/ArchitecturePage"));
const ApiSecurityPage = lazy(() => import("./pages/ApiSecurityPage"));
const ReverseEngineeringPage = lazy(() => import("./pages/ReverseEngineeringPage"));
const MobilePentestPage = lazy(() => import("./pages/MobilePentestPage"));
const PcapAnalyzerPage = lazy(() => import("./pages/PcapAnalyzerPage"));
const NetworkAnalysisHub = lazy(() => import("./pages/NetworkAnalysisHub"));
const NmapAnalyzerPage = lazy(() => import("./pages/NmapAnalyzerPage"));
const NetworkAnalysisGuidePage = lazy(() => import("./pages/NetworkAnalysisGuidePage"));
const WiresharkGuidePage = lazy(() => import("./pages/WiresharkGuidePage"));
const NmapGuidePage = lazy(() => import("./pages/NmapGuidePage"));
const SSLTLSGuidePage = lazy(() => import("./pages/SSLTLSGuidePage"));
const SSLScannerPage = lazy(() => import("./pages/SSLScannerPage"));
const DNSAnalyzerPage = lazy(() => import("./pages/DNSAnalyzerPage"));
const DNSGuidePage = lazy(() => import("./pages/DNSGuidePage"));
const TracerouteAnalyzerPage = lazy(() => import("./pages/TracerouteAnalyzerPage"));
const TracerouteGuidePage = lazy(() => import("./pages/TracerouteGuidePage"));
const APITesterPage = lazy(() => import("./pages/APITesterPage"));
const APITestingGuidePage = lazy(() => import("./pages/APITestingGuidePage"));
const CyberThreatIntelPage = lazy(() => import("./pages/CyberThreatIntelPage"));
const FuzzingPage = lazy(() => import("./pages/FuzzingPage"));
const FuzzingToolGuidePage = lazy(() => import("./pages/FuzzingToolGuidePage"));
const MITMWorkbenchPage = lazy(() => import("./pages/MITMWorkbenchPage"));
const MITMGuidePage = lazy(() => import("./pages/MITMGuidePage"));
const DigitalForensicsPage = lazy(() => import("./pages/DigitalForensicsPage"));
const OSINTReconPage = lazy(() => import("./pages/OSINTReconPage"));
const LateralMovementPage = lazy(() => import("./pages/LateralMovementPage"));
const ReverseEngineeringHubPage = lazy(() => import("./pages/ReverseEngineeringHubPage"));
const ApkAnalysisGuidePage = lazy(() => import("./pages/ApkAnalysisGuidePage"));
const BinaryAnalysisGuidePage = lazy(() => import("./pages/BinaryAnalysisGuidePage"));
const AndroidReverseEngineeringGuidePage = lazy(() => import("./pages/AndroidReverseEngineeringGuidePage"));
const PrivilegeEscalationGuidePage = lazy(() => import("./pages/PrivilegeEscalationGuidePage"));
const CyberSecurityCertificationsPage = lazy(() => import("./pages/CyberSecurityCertificationsPage"));
const IncidentResponseGuidePage = lazy(() => import("./pages/IncidentResponseGuidePage"));
const ContainerKubernetesExploitationPage = lazy(() => import("./pages/ContainerKubernetesExploitationPage"));
const LivingOffTheLandPage = lazy(() => import("./pages/LivingOffTheLandPage"));
const AntiVirusDetectionPage = lazy(() => import("./pages/AntiVirusDetectionPage"));
const WindowsPersistenceMechanismsPage = lazy(() => import("./pages/WindowsPersistenceMechanismsPage"));
const CredentialHarvestingPage = lazy(() => import("./pages/CredentialHarvestingPage"));
const DataExfiltrationPage = lazy(() => import("./pages/DataExfiltrationPage"));
const ArpDnsPoisoningPage = lazy(() => import("./pages/ArpDnsPoisoningPage"));
const PivotingTunnelingPage = lazy(() => import("./pages/PivotingTunnelingPage"));
const C2FrameworksGuidePage = lazy(() => import("./pages/C2FrameworksGuidePage"));
const DDoSAttackTechniquesPage = lazy(() => import("./pages/DDoSAttackTechniquesPage"));
const WirelessPentestingPage = lazy(() => import("./pages/WirelessPentestingPage"));
const NetworkProtocolExploitationPage = lazy(() => import("./pages/NetworkProtocolExploitationPage"));
const SQLInjectionPage = lazy(() => import("./pages/SQLInjectionPage"));
const DeserializationAttacksPage = lazy(() => import("./pages/DeserializationAttacksPage"));
const ReturnOrientedProgrammingPage = lazy(() => import("./pages/ReturnOrientedProgrammingPage"));
const Debugging101Page = lazy(() => import("./pages/Debugging101Page"));
const GhidraGuidePage = lazy(() => import("./pages/GhidraGuidePage"));
const SSRFGuidePage = lazy(() => import("./pages/SSRFGuidePage"));
const BufferOverflowGuidePage = lazy(() => import("./pages/BufferOverflowGuidePage"));
const DockerForensicsGuidePage = lazy(() => import("./pages/DockerForensicsGuidePage"));
const CareerPathsPage = lazy(() => import("./pages/CareerPathsPage"));
const SecurityPortfolioPage = lazy(() => import("./pages/SecurityPortfolioPage"));
const IOSPentestingPage = lazy(() => import("./pages/iOSPentestingPage"));
const HeapExploitationPage = lazy(() => import("./pages/HeapExploitationPage"));
const IntegerOverflowPage = lazy(() => import("./pages/IntegerOverflowPage"));
const OutOfBoundsPage = lazy(() => import("./pages/OutOfBoundsPage"));
const SIEMFundamentalsPage = lazy(() => import("./pages/SIEMFundamentalsPage"));
const SOCWorkflowPage = lazy(() => import("./pages/SOCWorkflowPage"));
const ThreatHuntingPage = lazy(() => import("./pages/ThreatHuntingPage"));
const CommandInjectionPage = lazy(() => import("./pages/CommandInjectionPage"));
const XSSGuidePage = lazy(() => import("./pages/XSSGuidePage"));
const WindowsInternalsREPage = lazy(() => import("./pages/WindowsInternalsREPage"));

// Auth pages
const LoginPage = lazy(() => import("./pages/LoginPage"));
const RegisterPage = lazy(() => import("./pages/RegisterPage"));
const AdminPage = lazy(() => import("./pages/AdminPage"));
const ProfilePage = lazy(() => import("./pages/ProfilePage"));

// Shared animations imported from theme
import { pulse, shimmer, float } from './theme/animations';

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
  const { isAuthenticated, isLoading: authLoading } = useAuth();
  const theme = useTheme();

  // Show loading while checking auth
  if (authLoading) {
    return (
      <>
        <CssBaseline />
        <Box
          sx={{
            minHeight: "100vh",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: theme.palette.background.default,
          }}
        >
          <CircularProgress />
        </Box>
      </>
    );
  }

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

          {/* Action Buttons - Only show when authenticated */}
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
            {isAuthenticated && (
              <>
                <Tooltip title="Projects - Manage your codebases">
                  <Button
                    component={Link}
                    to="/"
                    startIcon={<Box component="span" sx={{ display: "flex" }}><svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z" /></svg></Box>}
                    variant="contained"
                    size="medium"
                    sx={{
                      background: `linear-gradient(135deg, #10b981 0%, #059669 50%, #047857 100%)`,
                      color: "white",
                      fontWeight: 700,
                      px: 2.5,
                      py: 1,
                      borderRadius: 2,
                      textTransform: "none",
                      fontSize: "0.95rem",
                      boxShadow: `0 4px 15px ${alpha("#059669", 0.4)}, 0 0 20px ${alpha("#059669", 0.2)}`,
                      border: `1px solid ${alpha("#10b981", 0.5)}`,
                      "&:hover": {
                        background: `linear-gradient(135deg, #059669 0%, #047857 50%, #065f46 100%)`,
                        boxShadow: `0 6px 25px ${alpha("#059669", 0.5)}, 0 0 30px ${alpha("#059669", 0.3)}`,
                        transform: "translateY(-2px)",
                      },
                      "&:active": {
                        transform: "translateY(0)",
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
                
                <Tooltip title="Reverse Engineering - Binary, APK & Docker Analysis">
                  <Button
                    component={Link}
                    to="/reverse"
                    startIcon={<MemoryIcon sx={{ fontSize: "1.3rem !important" }} />}
                    variant="contained"
                    size="medium"
                    sx={{
                      background: `linear-gradient(135deg, #f97316 0%, #ea580c 50%, #dc2626 100%)`,
                      color: "white",
                      fontWeight: 700,
                      px: 2.5,
                      py: 1,
                      borderRadius: 2,
                      textTransform: "none",
                      fontSize: "0.95rem",
                      boxShadow: `0 4px 15px ${alpha("#ea580c", 0.4)}, 0 0 20px ${alpha("#ea580c", 0.2)}`,
                      border: `1px solid ${alpha("#f97316", 0.5)}`,
                      "&:hover": {
                        background: `linear-gradient(135deg, #ea580c 0%, #dc2626 50%, #b91c1c 100%)`,
                        boxShadow: `0 6px 25px ${alpha("#ea580c", 0.5)}, 0 0 30px ${alpha("#ea580c", 0.3)}`,
                        transform: "translateY(-2px)",
                      },
                      "&:active": {
                        transform: "translateY(0)",
                      },
                      transition: "all 0.3s ease",
                    }}
                  >
                    Reverse Engineering
                  </Button>
                </Tooltip>
              </>
            )}
            
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

            {/* User Menu */}
            <UserMenu />
          </Box>
        </Toolbar>
      </AppBar>

      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Suspense fallback={
          <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
            <CircularProgress />
          </Box>
        }>
          <Routes>
            {/* Public Auth Routes */}
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            
            {/* Admin Route */}
            <Route path="/admin" element={
              <ProtectedRoute requireAdmin>
                <AdminPage />
              </ProtectedRoute>
            } />
            
            {/* Profile Route */}
            <Route path="/profile" element={
              <ProtectedRoute>
                <ProfilePage />
              </ProtectedRoute>
            } />
            
            {/* Protected Routes */}
            <Route path="/" element={
              <ProtectedRoute>
                <ProjectListPage />
              </ProtectedRoute>
            } />
            <Route path="/projects/:projectId" element={
              <ProtectedRoute>
                <ProjectDetailPage />
              </ProtectedRoute>
            } />
            <Route path="/reports/:reportId" element={
              <ProtectedRoute>
                <ReportDetailPage />
              </ProtectedRoute>
            } />
            <Route path="/network" element={
              <ProtectedRoute>
                <NetworkAnalysisHub />
              </ProtectedRoute>
            } />
            <Route path="/network/pcap" element={
              <ProtectedRoute>
                <PcapAnalyzerPage />
              </ProtectedRoute>
            } />
            <Route path="/network/nmap" element={
              <ProtectedRoute>
                <NmapAnalyzerPage />
              </ProtectedRoute>
            } />
            <Route path="/network/ssl" element={
              <ProtectedRoute>
                <SSLScannerPage />
              </ProtectedRoute>
            } />
            <Route path="/network/dns" element={
              <ProtectedRoute>
                <DNSAnalyzerPage />
              </ProtectedRoute>
            } />
            <Route path="/network/traceroute" element={
              <ProtectedRoute>
                <TracerouteAnalyzerPage />
              </ProtectedRoute>
            } />
            <Route path="/network/api-tester" element={
              <ProtectedRoute>
                <APITesterPage />
              </ProtectedRoute>
            } />
            <Route path="/network/fuzzer" element={
              <ProtectedRoute>
                <FuzzingPage />
              </ProtectedRoute>
            } />
            <Route path="/network/mitm" element={
              <ProtectedRoute>
                <MITMWorkbenchPage />
              </ProtectedRoute>
            } />
            <Route path="/reverse" element={
              <ProtectedRoute>
                <ReverseEngineeringHubPage />
              </ProtectedRoute>
            } />
            
            {/* Public Learn Routes - No authentication required */}
            <Route path="/learn" element={<LearnHubPage />} />
            <Route path="/learn/mitm" element={<MITMGuidePage />} />
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
            <Route path="/learn/ssl-tls" element={<SSLTLSGuidePage />} />
            <Route path="/learn/dns" element={<DNSGuidePage />} />
            <Route path="/learn/traceroute" element={<TracerouteGuidePage />} />
            <Route path="/learn/api-testing" element={<APITestingGuidePage />} />
            <Route path="/learn/cti" element={<CyberThreatIntelPage />} />
            <Route path="/learn/fuzzing-tool" element={<FuzzingToolGuidePage />} />
            <Route path="/learn/digital-forensics" element={<DigitalForensicsPage />} />
            <Route path="/learn/osint" element={<OSINTReconPage />} />
            <Route path="/learn/lateral-movement" element={<LateralMovementPage />} />
            <Route path="/learn/apk-analysis" element={<ApkAnalysisGuidePage />} />
            <Route path="/learn/binary-analysis" element={<BinaryAnalysisGuidePage />} />
            <Route path="/learn/android-reverse-engineering" element={<AndroidReverseEngineeringGuidePage />} />
            <Route path="/learn/privilege-escalation" element={<PrivilegeEscalationGuidePage />} />
            <Route path="/learn/certifications" element={<CyberSecurityCertificationsPage />} />
            <Route path="/learn/career-paths" element={<CareerPathsPage />} />
            <Route path="/learn/portfolio" element={<SecurityPortfolioPage />} />
            <Route path="/learn/ios-pentesting" element={<IOSPentestingPage />} />
            <Route path="/learn/heap-exploitation" element={<HeapExploitationPage />} />
            <Route path="/learn/integer-overflow" element={<IntegerOverflowPage />} />
            <Route path="/learn/oob-read-write" element={<OutOfBoundsPage />} />
            <Route path="/learn/siem" element={<SIEMFundamentalsPage />} />
            <Route path="/learn/soc-workflow" element={<SOCWorkflowPage />} />
            <Route path="/learn/threat-hunting" element={<ThreatHuntingPage />} />
            <Route path="/learn/command-injection" element={<CommandInjectionPage />} />
            <Route path="/learn/xss" element={<XSSGuidePage />} />
            <Route path="/learn/incident-response" element={<IncidentResponseGuidePage />} />
            <Route path="/learn/container-k8s" element={<ContainerKubernetesExploitationPage />} />
            <Route path="/learn/living-off-the-land" element={<LivingOffTheLandPage />} />
            <Route path="/learn/anti-virus-detection" element={<AntiVirusDetectionPage />} />
            <Route path="/learn/windows-persistence" element={<WindowsPersistenceMechanismsPage />} />
            <Route path="/learn/credential-harvesting" element={<CredentialHarvestingPage />} />
            <Route path="/learn/data-exfiltration" element={<DataExfiltrationPage />} />
            <Route path="/learn/arp-dns-poisoning" element={<ArpDnsPoisoningPage />} />
            <Route path="/learn/pivoting-tunneling" element={<PivotingTunnelingPage />} />
            <Route path="/learn/c2-frameworks" element={<C2FrameworksGuidePage />} />
            <Route path="/learn/ddos-techniques" element={<DDoSAttackTechniquesPage />} />
            <Route path="/learn/wireless-pentesting" element={<WirelessPentestingPage />} />
            <Route path="/learn/network-protocol-exploitation" element={<NetworkProtocolExploitationPage />} />
            <Route path="/learn/sql-injection" element={<SQLInjectionPage />} />
            <Route path="/learn/deserialization-attacks" element={<DeserializationAttacksPage />} />
            <Route path="/learn/rop" element={<ReturnOrientedProgrammingPage />} />
            <Route path="/learn/debugging-101" element={<Debugging101Page />} />
            <Route path="/learn/ghidra" element={<GhidraGuidePage />} />
            <Route path="/learn/windows-internals" element={<WindowsInternalsREPage />} />
            <Route path="/learn/ssrf" element={<SSRFGuidePage />} />
            <Route path="/learn/buffer-overflow" element={<BufferOverflowGuidePage />} />
            <Route path="/learn/docker-forensics" element={<DockerForensicsGuidePage />} />
          </Routes>
        </Suspense>
      </Container>
    </>
  );
}

export default App;
