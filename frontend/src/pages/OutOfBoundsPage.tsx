import React from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
  Button,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  alpha,
  useTheme,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import DataArrayIcon from "@mui/icons-material/DataArray";
import VisibilityIcon from "@mui/icons-material/Visibility";
import EditIcon from "@mui/icons-material/Edit";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import { useNavigate } from "react-router-dom";

interface OOBType {
  title: string;
  icon: React.ReactNode;
  description: string;
  impact: string[];
  color: string;
}

const oobTypes: OOBType[] = [
  {
    title: "Out-of-Bounds Read (OOB-R)",
    icon: <VisibilityIcon />,
    description: "Reading memory beyond allocated buffer boundaries",
    impact: [
      "Information disclosure (memory leak)",
      "Bypass ASLR via pointer leak",
      "Read sensitive data (keys, passwords)",
      "Crash (if unmapped memory)",
    ],
    color: "#3b82f6",
  },
  {
    title: "Out-of-Bounds Write (OOB-W)",
    icon: <EditIcon />,
    description: "Writing memory beyond allocated buffer boundaries",
    impact: [
      "Corrupt adjacent data structures",
      "Overwrite function pointers",
      "Modify heap/stack metadata",
      "Achieve code execution",
    ],
    color: "#ef4444",
  },
];

const commonCauses = [
  { cause: "Missing bounds check", example: "array[user_index]" },
  { cause: "Off-by-one error", example: "for (i <= len)" },
  { cause: "Integer overflow in index", example: "array[base + offset]" },
  { cause: "Negative index", example: "array[(signed)input]" },
  { cause: "Incorrect length calculation", example: "memcpy(dst, src, wrong_len)" },
  { cause: "Type confusion", example: "Wrong struct size assumption" },
];

const exploitPrimitives = [
  "Relative read/write (adjacent objects)",
  "Arbitrary read (via controlled index)",
  "Arbitrary write (via controlled index + value)",
  "Info leak → defeat ASLR",
  "Vtable/function pointer overwrite",
];

export default function OutOfBoundsPage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `Out-of-Bounds Read/Write Guide - Covers OOB-R (information disclosure, ASLR bypass, sensitive data leaks) and OOB-W (data corruption, function pointer overwrites, code execution). Explains common causes including missing bounds checks, off-by-one errors, integer overflow in index, negative index, and type confusion. Lists exploit primitives.`;

  return (
    <LearnPageLayout pageTitle="Out-of-Bounds Read/Write" pageContext={pageContext}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 2 }}>
            Back to Learning Hub
          </Button>
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
              <DataArrayIcon sx={{ fontSize: 36, color: "#8b5cf6" }} />
            </Box>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Out-of-Bounds Read/Write
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Array and buffer boundary violations
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Memory Corruption" color="secondary" size="small" />
            <Chip label="Info Leak" size="small" sx={{ bgcolor: alpha("#3b82f6", 0.1), color: "#3b82f6" }} />
            <Chip label="Arbitrary R/W" size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
          </Box>
        </Box>

        {/* Overview */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <DataArrayIcon color="primary" /> Overview
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8 }}>
            Out-of-bounds (OOB) vulnerabilities occur when code accesses memory outside the intended buffer boundaries. 
            OOB reads leak sensitive information; OOB writes corrupt memory. Both are common in C/C++ and can be 
            stepping stones to full exploitation, especially when combined with other primitives.
          </Typography>
        </Paper>

        {/* OOB Types */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🎯 Vulnerability Types</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          {oobTypes.map((oob) => (
            <Grid item xs={12} md={6} key={oob.title}>
              <Paper
                sx={{
                  p: 3,
                  height: "100%",
                  borderRadius: 3,
                  border: `1px solid ${alpha(oob.color, 0.2)}`,
                  "&:hover": { borderColor: oob.color },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <Box
                    sx={{
                      width: 48,
                      height: 48,
                      borderRadius: 2,
                      bgcolor: alpha(oob.color, 0.1),
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      color: oob.color,
                    }}
                  >
                    {oob.icon}
                  </Box>
                  <Typography variant="h6" sx={{ fontWeight: 700 }}>
                    {oob.title}
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  {oob.description}
                </Typography>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: oob.color }}>
                  Impact:
                </Typography>
                <List dense>
                  {oob.impact.map((item, i) => (
                    <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}>
                        <CheckCircleIcon sx={{ fontSize: 14, color: oob.color }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Common Causes */}
        <Paper
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.05)}, ${alpha("#ef4444", 0.05)})`,
            border: `1px solid ${alpha("#f59e0b", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>⚠️ Common Causes</Typography>
          <Grid container spacing={2}>
            {commonCauses.map((c) => (
              <Grid item xs={12} sm={6} key={c.cause}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                  <Box>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>{c.cause}</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace" }}>
                      {c.example}
                    </Typography>
                  </Box>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Exploit Primitives */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🔧 Exploit Primitives</Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {exploitPrimitives.map((p) => (
              <Chip key={p} label={p} variant="outlined" size="small" />
            ))}
          </Box>
        </Paper>

        {/* Warning */}
        <Paper
          sx={{
            p: 2,
            mb: 4,
            borderRadius: 2,
            bgcolor: alpha("#10b981", 0.05),
            border: `1px solid ${alpha("#10b981", 0.2)}`,
            display: "flex",
            alignItems: "center",
            gap: 2,
          }}
        >
          <WarningIcon sx={{ color: "#10b981" }} />
          <Typography variant="body2">
            <strong>Mitigations:</strong> Bounds checking, AddressSanitizer (ASan), safe libraries, memory-safe languages.
          </Typography>
        </Paper>

        {/* Related */}
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📚 Related Learning</Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Buffer Overflow →" clickable onClick={() => navigate("/learn/buffer-overflow")} sx={{ fontWeight: 600 }} />
            <Chip label="Integer Overflow →" clickable onClick={() => navigate("/learn/integer-overflow")} sx={{ fontWeight: 600 }} />
            <Chip label="Heap Exploitation →" clickable onClick={() => navigate("/learn/heap-exploitation")} sx={{ fontWeight: 600 }} />
          </Box>
        </Paper>
      </Container>
    </LearnPageLayout>
  );
}
