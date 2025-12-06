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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from "@mui/material";
import { Link } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import RadarIcon from "@mui/icons-material/Radar";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SpeedIcon from "@mui/icons-material/Speed";
import SearchIcon from "@mui/icons-material/Search";
import SecurityIcon from "@mui/icons-material/Security";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";

export default function NmapGuidePage() {
  const theme = useTheme();

  const scanTypes = [
    { flag: "-sS", name: "SYN Scan", description: "Stealthy half-open scan (default, requires root)", speed: "Fast" },
    { flag: "-sT", name: "TCP Connect", description: "Full TCP connection, no root required", speed: "Medium" },
    { flag: "-sU", name: "UDP Scan", description: "Scan UDP ports (slow but important)", speed: "Slow" },
    { flag: "-sV", name: "Version Detection", description: "Detect service versions on open ports", speed: "Medium" },
    { flag: "-O", name: "OS Detection", description: "Identify target operating system", speed: "Medium" },
    { flag: "-A", name: "Aggressive", description: "Enable OS detection, version, scripts, traceroute", speed: "Slow" },
    { flag: "-sn", name: "Ping Scan", description: "Host discovery only, no port scan", speed: "Fast" },
    { flag: "-sC", name: "Script Scan", description: "Run default NSE scripts", speed: "Medium" },
  ];

  const commonCommands = [
    { command: "nmap 192.168.1.1", description: "Basic scan of top 1000 ports" },
    { command: "nmap -p- 192.168.1.1", description: "Scan all 65535 ports" },
    { command: "nmap -p 22,80,443 192.168.1.1", description: "Scan specific ports" },
    { command: "nmap -sV -sC 192.168.1.1", description: "Version + default scripts" },
    { command: "nmap -A 192.168.1.1", description: "Aggressive scan (comprehensive)" },
    { command: "nmap -sn 192.168.1.0/24", description: "Discover hosts on subnet" },
    { command: "nmap --script vuln 192.168.1.1", description: "Run vulnerability scripts" },
    { command: "nmap -oX scan.xml 192.168.1.1", description: "Save output as XML" },
  ];

  const nsScripts = [
    { category: "vuln", description: "Vulnerability detection scripts" },
    { category: "exploit", description: "Attempt to exploit vulnerabilities" },
    { category: "auth", description: "Authentication-related scripts" },
    { category: "brute", description: "Brute force password auditing" },
    { category: "discovery", description: "Network discovery scripts" },
    { category: "safe", description: "Scripts that won't crash services" },
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
          background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.1)}, ${alpha("#6366f1", 0.05)})`,
          border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <Box
            sx={{
              width: 64,
              height: 64,
              borderRadius: 2,
              bgcolor: alpha("#8b5cf6", 0.1),
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <RadarIcon sx={{ fontSize: 36, color: "#8b5cf6" }} />
          </Box>
          <Box>
            <Typography variant="h4" sx={{ fontWeight: 700 }}>
              Nmap Essentials
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Network exploration and security auditing
            </Typography>
          </Box>
        </Box>
      </Paper>

      {/* What is Nmap */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          What is Nmap?
        </Typography>
        <Typography variant="body1" paragraph>
          Nmap ("Network Mapper") is a free, open-source tool for network discovery and security auditing. 
          It's used by security professionals worldwide to:
        </Typography>
        <Grid container spacing={2} sx={{ mb: 2 }}>
          {[
            "Discover hosts on a network",
            "Identify open ports & services",
            "Detect operating systems",
            "Find vulnerabilities",
          ].map((item) => (
            <Grid item xs={6} md={3} key={item}>
              <Chip
                label={item}
                sx={{
                  width: "100%",
                  bgcolor: alpha("#8b5cf6", 0.1),
                  color: "#8b5cf6",
                  fontWeight: 500,
                }}
              />
            </Grid>
          ))}
        </Grid>
        <Typography variant="body2" color="text.secondary">
          <strong>Zenmap</strong> is the official GUI frontend for Nmap, making it easier to visualize 
          results and save scan profiles.
        </Typography>
      </Paper>

      {/* Scan Types */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <SpeedIcon sx={{ color: "#3b82f6" }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Scan Types
          </Typography>
        </Box>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700 }}>Flag</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Name</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Speed</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {scanTypes.map((row) => (
                <TableRow key={row.flag} hover>
                  <TableCell>
                    <code style={{ 
                      backgroundColor: alpha("#3b82f6", 0.1), 
                      padding: "2px 8px", 
                      borderRadius: 4,
                      fontSize: "0.85rem"
                    }}>
                      {row.flag}
                    </code>
                  </TableCell>
                  <TableCell sx={{ fontWeight: 500 }}>{row.name}</TableCell>
                  <TableCell>{row.description}</TableCell>
                  <TableCell>
                    <Chip 
                      label={row.speed} 
                      size="small"
                      sx={{
                        bgcolor: row.speed === "Fast" ? alpha("#10b981", 0.1) : 
                                 row.speed === "Medium" ? alpha("#f59e0b", 0.1) : alpha("#ef4444", 0.1),
                        color: row.speed === "Fast" ? "#10b981" : 
                               row.speed === "Medium" ? "#f59e0b" : "#ef4444",
                      }}
                    />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* Common Commands */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <SearchIcon sx={{ color: "#10b981" }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Common Commands
          </Typography>
        </Box>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700 }}>Command</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {commonCommands.map((row) => (
                <TableRow key={row.command} hover>
                  <TableCell>
                    <code style={{ 
                      backgroundColor: alpha("#10b981", 0.1), 
                      padding: "4px 10px", 
                      borderRadius: 4,
                      fontSize: "0.85rem",
                      display: "inline-block"
                    }}>
                      {row.command}
                    </code>
                  </TableCell>
                  <TableCell>{row.description}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* NSE Scripts */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <SecurityIcon sx={{ color: "#ef4444" }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Nmap Scripting Engine (NSE)
          </Typography>
        </Box>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          NSE extends Nmap with scripts for vulnerability detection, exploitation, and more. 
          Use <code>--script=category</code> to run script categories.
        </Typography>
        <Grid container spacing={2}>
          {nsScripts.map((script) => (
            <Grid item xs={12} sm={6} md={4} key={script.category}>
              <Card sx={{ borderRadius: 2, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                <CardContent sx={{ py: 2 }}>
                  <code style={{ 
                    backgroundColor: alpha("#ef4444", 0.1), 
                    padding: "2px 8px", 
                    borderRadius: 4,
                    fontSize: "0.85rem"
                  }}>
                    --script={script.category}
                  </code>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                    {script.description}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Tips */}
      <Paper
        sx={{
          p: 4,
          borderRadius: 3,
          background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.1)}, ${alpha("#f59e0b", 0.05)})`,
          border: `1px solid ${alpha("#f59e0b", 0.2)}`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <TipsAndUpdatesIcon sx={{ color: "#f59e0b" }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Quick Tips
          </Typography>
        </Box>
        <Grid container spacing={2}>
          {[
            "Always save XML output (-oX) for parsing and importing into VRAgent",
            "Use -T4 for faster scans on local networks (-T0 to -T5 scale)",
            "Combine -sV and -sC for comprehensive service detection",
            "Use --top-ports 100 to scan only the most common ports",
            "Add -Pn to skip host discovery if ICMP is blocked",
            "Use -v or -vv for verbose output during long scans",
          ].map((tip, idx) => (
            <Grid item xs={12} md={6} key={idx}>
              <Typography variant="body2">
                <strong>{idx + 1}.</strong> {tip}
              </Typography>
            </Grid>
          ))}
        </Grid>
      </Paper>
    </Container>
  );
}
