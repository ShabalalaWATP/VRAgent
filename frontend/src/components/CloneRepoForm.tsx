import { useState } from "react";
import {
  Box,
  Button,
  TextField,
  Typography,
  InputAdornment,
  Collapse,
  alpha,
  useTheme,
  LinearProgress,
  Stack,
  Chip,
  keyframes,
} from "@mui/material";
import { cloneRepository } from "../api/client";

// Animations
const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.6; }
`;

const slideIn = keyframes`
  from { opacity: 0; transform: translateY(-10px); }
  to { opacity: 1; transform: translateY(0); }
`;

// Icons
const GitHubIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
  </svg>
);

const CloneIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-2 10h-4v4h-2v-4H7v-2h4V7h2v4h4v2z" />
  </svg>
);

const CheckIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z" />
  </svg>
);

const BranchIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M6 5a2 2 0 0 0-2 2v10a2 2 0 0 0 4 0v-1.4a5 5 0 0 0 4 2 5 5 0 0 0 4-2V17a2 2 0 1 0 4 0V7a2 2 0 0 0-4 0v6.4a5 5 0 0 0-4-2 5 5 0 0 0-4 2V7a2 2 0 0 0-2-2z"/>
  </svg>
);

interface CloneRepoFormProps {
  projectId: number;
  onCloneSuccess: () => void;
}

export default function CloneRepoForm({ projectId, onCloneSuccess }: CloneRepoFormProps) {
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const theme = useTheme();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoUrl.trim()) {
      setError("Please enter a repository URL");
      return;
    }

    // Basic URL validation
    const urlPattern = /^(https?:\/\/|git@)(github\.com|gitlab\.com|bitbucket\.org|dev\.azure\.com)/;
    if (!urlPattern.test(repoUrl.trim())) {
      setError("Please enter a valid GitHub, GitLab, Bitbucket, or Azure DevOps URL");
      return;
    }

    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const result = await cloneRepository(
        projectId,
        repoUrl.trim(),
        branch.trim() || undefined
      );
      setSuccess(`Successfully cloned ${result.repo_name} (branch: ${result.branch})`);
      setRepoUrl("");
      setBranch("");
      onCloneSuccess();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to clone repository";
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  // Platform detection for styling
  const getPlatformInfo = () => {
    if (repoUrl.includes("github.com")) return { name: "GitHub", color: "#333" };
    if (repoUrl.includes("gitlab.com")) return { name: "GitLab", color: "#FC6D26" };
    if (repoUrl.includes("bitbucket.org")) return { name: "Bitbucket", color: "#0052CC" };
    if (repoUrl.includes("dev.azure.com")) return { name: "Azure DevOps", color: "#0078D7" };
    return null;
  };

  const platform = getPlatformInfo();

  return (
    <Box
      component="form"
      onSubmit={handleSubmit}
      sx={{ display: "flex", flexDirection: "column", gap: 2.5 }}
    >
      {/* Header */}
      <Box>
        <Stack direction="row" spacing={1} flexWrap="wrap" sx={{ mb: 1.5 }}>
          {["GitHub", "GitLab", "Bitbucket", "Azure"].map((p) => (
            <Chip
              key={p}
              label={p}
              size="small"
              sx={{
                background: alpha(theme.palette.primary.main, 0.1),
                border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
                fontWeight: 500,
                fontSize: "0.75rem",
              }}
            />
          ))}
        </Stack>
        <Typography variant="body2" color="text.secondary">
          Clone a public repository for security analysis
        </Typography>
      </Box>

      {/* URL Input */}
      <Box
        sx={{
          position: "relative",
          borderRadius: 2,
          overflow: "hidden",
          background: `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.8)} 0%, ${alpha(theme.palette.background.paper, 0.6)} 100%)`,
          backdropFilter: "blur(10px)",
          border: `1px solid ${alpha(theme.palette.divider, 0.2)}`,
          transition: "all 0.3s ease",
          "&:focus-within": {
            border: `1px solid ${theme.palette.primary.main}`,
            boxShadow: `0 0 20px ${alpha(theme.palette.primary.main, 0.2)}`,
          },
        }}
      >
        <TextField
          placeholder="https://github.com/owner/repository"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          fullWidth
          disabled={loading}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <Box 
                  sx={{ 
                    color: platform ? platform.color : "text.secondary",
                    transition: "color 0.3s ease",
                  }}
                >
                  <GitHubIcon />
                </Box>
              </InputAdornment>
            ),
            endAdornment: platform && (
              <InputAdornment position="end">
                <Chip
                  label={platform.name}
                  size="small"
                  sx={{
                    height: 24,
                    fontSize: "0.7rem",
                    fontWeight: 600,
                    background: alpha(theme.palette.primary.main, 0.15),
                    animation: `${slideIn} 0.3s ease`,
                  }}
                />
              </InputAdornment>
            ),
          }}
          sx={{
            "& .MuiOutlinedInput-root": {
              borderRadius: 2,
              "& fieldset": { border: "none" },
            },
            "& .MuiInputBase-input": {
              py: 1.75,
            },
          }}
        />
      </Box>

      {/* Advanced Options */}
      <Box>
        <Button
          size="small"
          onClick={() => setShowAdvanced(!showAdvanced)}
          startIcon={<BranchIcon />}
          sx={{ 
            textTransform: "none",
            color: "text.secondary",
            fontWeight: 500,
            "&:hover": {
              color: "primary.main",
              background: alpha(theme.palette.primary.main, 0.05),
            },
          }}
        >
          {showAdvanced ? "Hide" : "Show"} branch options
        </Button>
        
        <Collapse in={showAdvanced}>
          <Box
            sx={{
              mt: 2,
              p: 2,
              borderRadius: 2,
              background: alpha(theme.palette.background.paper, 0.5),
              backdropFilter: "blur(10px)",
              border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            }}
          >
            <TextField
              label="Branch"
              placeholder="main"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              fullWidth
              disabled={loading}
              size="small"
              helperText="Leave empty to use the default branch"
              sx={{
                "& .MuiOutlinedInput-root": {
                  background: alpha(theme.palette.background.paper, 0.5),
                },
              }}
            />
          </Box>
        </Collapse>
      </Box>

      {/* Loading Progress */}
      {loading && (
        <Box sx={{ animation: `${slideIn} 0.3s ease` }}>
          <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
            <Typography 
              variant="caption" 
              fontWeight={500}
              sx={{ animation: `${pulse} 1.5s ease-in-out infinite` }}
            >
              🔄 Cloning repository...
            </Typography>
          </Stack>
          <LinearProgress 
            sx={{
              height: 6,
              borderRadius: 3,
              background: alpha(theme.palette.primary.main, 0.1),
              "& .MuiLinearProgress-bar": {
                borderRadius: 3,
                background: `linear-gradient(90deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
              },
            }}
          />
        </Box>
      )}

      {/* Error Message */}
      {error && (
        <Box
          sx={{
            p: 2,
            borderRadius: 2,
            background: alpha(theme.palette.error.main, 0.1),
            border: `1px solid ${alpha(theme.palette.error.main, 0.3)}`,
            animation: `${slideIn} 0.3s ease`,
          }}
        >
          <Typography variant="body2" color="error" fontWeight={500}>
            ❌ {error}
          </Typography>
        </Box>
      )}

      {/* Success Message */}
      {success && (
        <Box
          sx={{
            p: 2,
            borderRadius: 2,
            background: `linear-gradient(135deg, ${alpha(theme.palette.success.main, 0.1)} 0%, ${alpha(theme.palette.primary.main, 0.05)} 100%)`,
            border: `1px solid ${alpha(theme.palette.success.main, 0.3)}`,
            animation: `${slideIn} 0.3s ease`,
          }}
        >
          <Stack direction="row" spacing={1} alignItems="center">
            <Box sx={{ color: "success.main" }}>
              <CheckIcon />
            </Box>
            <Typography variant="body2" fontWeight={500} color="success.main">
              {success}
            </Typography>
          </Stack>
        </Box>
      )}

      {/* Submit Button */}
      <Button
        type="submit"
        variant="contained"
        disabled={loading || !repoUrl.trim()}
        startIcon={<CloneIcon />}
        sx={{
          py: 1.5,
          fontWeight: 600,
          fontSize: "0.95rem",
          background: repoUrl.trim()
            ? `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`
            : undefined,
          boxShadow: repoUrl.trim()
            ? `0 4px 20px ${alpha(theme.palette.primary.main, 0.4)}`
            : "none",
          transition: "all 0.3s ease",
          "&:hover": {
            background: `linear-gradient(135deg, ${theme.palette.primary.light} 0%, ${theme.palette.secondary.light} 100%)`,
            boxShadow: `0 6px 30px ${alpha(theme.palette.primary.main, 0.5)}`,
            transform: "translateY(-2px)",
          },
          "&:active": {
            transform: "translateY(0)",
          },
          "&:disabled": {
            background: alpha(theme.palette.action.disabled, 0.1),
          },
        }}
      >
        {loading ? "Cloning..." : "🚀 Clone Repository"}
      </Button>

      {/* Footer Note */}
      <Typography 
        variant="caption" 
        color="text.secondary" 
        sx={{ 
          textAlign: "center",
          opacity: 0.8,
        }}
      >
        🔓 Only public repositories are currently supported
      </Typography>
    </Box>
  );
}
