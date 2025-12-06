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
  Divider,
} from "@mui/material";
import { Link } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import FilterListIcon from "@mui/icons-material/FilterList";
import VisibilityIcon from "@mui/icons-material/Visibility";
import SecurityIcon from "@mui/icons-material/Security";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";

export default function WiresharkGuidePage() {
  const theme = useTheme();

  const displayFilters = [
    { filter: "ip.addr == 192.168.1.1", description: "Traffic to/from specific IP" },
    { filter: "tcp.port == 80", description: "HTTP traffic (port 80)" },
    { filter: "tcp.port == 443", description: "HTTPS traffic (port 443)" },
    { filter: "dns", description: "All DNS traffic" },
    { filter: "http", description: "All HTTP traffic" },
    { filter: "tcp.flags.syn == 1", description: "TCP SYN packets (connections)" },
    { filter: "tcp.flags.rst == 1", description: "TCP RST packets (resets)" },
    { filter: "frame contains \"password\"", description: "Packets containing 'password'" },
    { filter: "http.request.method == \"POST\"", description: "HTTP POST requests" },
    { filter: "ssl.handshake", description: "TLS/SSL handshakes" },
  ];

  const captureFilters = [
    { filter: "host 192.168.1.1", description: "Traffic to/from specific host" },
    { filter: "port 80", description: "Traffic on port 80" },
    { filter: "net 192.168.1.0/24", description: "Traffic from subnet" },
    { filter: "tcp", description: "Only TCP traffic" },
    { filter: "udp", description: "Only UDP traffic" },
    { filter: "not broadcast", description: "Exclude broadcast traffic" },
  ];

  const securityUses = [
    {
      title: "Credential Hunting",
      description: "Look for plaintext credentials in HTTP, FTP, Telnet traffic",
      filter: "http.authbasic or ftp or telnet",
    },
    {
      title: "Suspicious DNS",
      description: "Find DNS queries to unusual domains or high query volumes",
      filter: "dns.qry.name contains \"suspicious\"",
    },
    {
      title: "Data Exfiltration",
      description: "Large outbound transfers or unusual protocols",
      filter: "tcp.len > 1000 and ip.dst != 10.0.0.0/8",
    },
    {
      title: "Port Scanning",
      description: "Many SYN packets without established connections",
      filter: "tcp.flags.syn == 1 and tcp.flags.ack == 0",
    },
    {
      title: "Malware Beaconing",
      description: "Regular, periodic connections to external hosts",
      filter: "ip.dst != 10.0.0.0/8 and tcp.flags.syn == 1",
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
          background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.1)}, ${alpha("#06b6d4", 0.05)})`,
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
            <NetworkCheckIcon sx={{ fontSize: 36, color: "#3b82f6" }} />
          </Box>
          <Box>
            <Typography variant="h4" sx={{ fontWeight: 700 }}>
              Wireshark Essentials
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Network packet analysis for security professionals
            </Typography>
          </Box>
        </Box>
      </Paper>

      {/* What is Wireshark */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          What is Wireshark?
        </Typography>
        <Typography variant="body1" paragraph>
          Wireshark is the world's most popular network protocol analyzer. It lets you capture and 
          interactively browse network traffic, making it invaluable for:
        </Typography>
        <Grid container spacing={2} sx={{ mb: 2 }}>
          {[
            "Network troubleshooting",
            "Security analysis",
            "Protocol development",
            "Education & learning",
          ].map((item) => (
            <Grid item xs={6} md={3} key={item}>
              <Chip
                label={item}
                sx={{
                  width: "100%",
                  bgcolor: alpha("#3b82f6", 0.1),
                  color: "#3b82f6",
                  fontWeight: 500,
                }}
              />
            </Grid>
          ))}
        </Grid>
        <Typography variant="body2" color="text.secondary">
          <strong>tshark</strong> is the command-line version of Wireshark, used by VRAgent's PCAP 
          analyzer for automated packet capture and analysis.
        </Typography>
      </Paper>

      {/* Display Filters */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <FilterListIcon sx={{ color: "#8b5cf6" }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Display Filters
          </Typography>
        </Box>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Display filters let you focus on specific traffic after capture. Apply these in the filter bar.
        </Typography>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700 }}>Filter</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {displayFilters.map((row) => (
                <TableRow key={row.filter} hover>
                  <TableCell>
                    <code style={{ 
                      backgroundColor: alpha("#8b5cf6", 0.1), 
                      padding: "2px 8px", 
                      borderRadius: 4,
                      fontSize: "0.85rem"
                    }}>
                      {row.filter}
                    </code>
                  </TableCell>
                  <TableCell>{row.description}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* Capture Filters */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <VisibilityIcon sx={{ color: "#10b981" }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Capture Filters (BPF)
          </Typography>
        </Box>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Capture filters use BPF syntax and are set <em>before</em> capture starts. They reduce file 
          size by only capturing matching traffic.
        </Typography>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700 }}>Filter</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {captureFilters.map((row) => (
                <TableRow key={row.filter} hover>
                  <TableCell>
                    <code style={{ 
                      backgroundColor: alpha("#10b981", 0.1), 
                      padding: "2px 8px", 
                      borderRadius: 4,
                      fontSize: "0.85rem"
                    }}>
                      {row.filter}
                    </code>
                  </TableCell>
                  <TableCell>{row.description}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* Security Analysis */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <SecurityIcon sx={{ color: "#ef4444" }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Security Analysis Use Cases
          </Typography>
        </Box>
        <Grid container spacing={2}>
          {securityUses.map((use) => (
            <Grid item xs={12} md={6} key={use.title}>
              <Card
                sx={{
                  height: "100%",
                  borderRadius: 2,
                  border: `1px solid ${alpha("#ef4444", 0.2)}`,
                }}
              >
                <CardContent>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                    {use.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    {use.description}
                  </Typography>
                  <code style={{ 
                    backgroundColor: alpha("#ef4444", 0.1), 
                    padding: "2px 8px", 
                    borderRadius: 4,
                    fontSize: "0.8rem",
                    display: "inline-block"
                  }}>
                    {use.filter}
                  </code>
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
            "Use Statistics → Conversations to see traffic between hosts",
            "Right-click a packet → Follow → TCP Stream to see full conversation",
            "Statistics → Protocol Hierarchy shows traffic breakdown",
            "Export objects (File → Export Objects → HTTP) to extract files",
            "Use coloring rules to highlight suspicious traffic",
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
