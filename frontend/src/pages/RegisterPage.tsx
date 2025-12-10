import { useState } from "react";
import { Link as RouterLink } from "react-router-dom";
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Alert,
  InputAdornment,
  IconButton,
  Divider,
  alpha,
  useTheme,
  keyframes,
  CircularProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Grid,
} from "@mui/material";
import { useAuth } from "../contexts/AuthContext";
import VisibilityIcon from "@mui/icons-material/Visibility";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import EmailIcon from "@mui/icons-material/Email";
import LockIcon from "@mui/icons-material/Lock";
import PersonIcon from "@mui/icons-material/Person";
import BadgeIcon from "@mui/icons-material/Badge";
import SecurityIcon from "@mui/icons-material/Security";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import HourglassEmptyIcon from "@mui/icons-material/HourglassEmpty";
import VerifiedUserIcon from "@mui/icons-material/VerifiedUser";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";

const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-10px); }
`;

const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

export default function RegisterPage() {
  const theme = useTheme();
  const { register } = useAuth();

  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);
  const [successMessage, setSuccessMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  // Password validation
  const passwordRequirements = [
    { met: password.length >= 8, text: "At least 8 characters" },
    { met: /[A-Z]/.test(password), text: "One uppercase letter" },
    { met: /[a-z]/.test(password), text: "One lowercase letter" },
    { met: /[0-9]/.test(password), text: "One number" },
  ];

  const isPasswordValid = passwordRequirements.every((req) => req.met);
  const doPasswordsMatch = password === confirmPassword && confirmPassword.length > 0;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!isPasswordValid) {
      setError("Password does not meet requirements");
      return;
    }

    if (!doPasswordsMatch) {
      setError("Passwords do not match");
      return;
    }

    setIsLoading(true);

    const result = await register(email, username, firstName, lastName, password);
    
    if (result.success) {
      setSuccess(true);
      setSuccessMessage(result.message || "Account request submitted!");
    } else {
      setError(result.error || "Registration failed");
    }
    
    setIsLoading(false);
  };

  // Success state
  if (success) {
    return (
      <Box
        sx={{
          minHeight: "80vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          py: 4,
        }}
      >
        <Paper
          elevation={0}
          sx={{
            p: 4,
            width: "100%",
            maxWidth: 500,
            borderRadius: 4,
            background: alpha(theme.palette.background.paper, 0.8),
            backdropFilter: "blur(20px)",
            border: `1px solid ${alpha(theme.palette.success.main, 0.3)}`,
            boxShadow: `0 20px 60px ${alpha(theme.palette.success.main, 0.15)}`,
            textAlign: "center",
          }}
        >
          <Box
            sx={{
              display: "inline-flex",
              p: 2,
              borderRadius: "50%",
              background: alpha(theme.palette.success.main, 0.15),
              mb: 3,
            }}
          >
            <CheckCircleIcon sx={{ fontSize: 64, color: "success.main" }} />
          </Box>
          
          <Typography variant="h4" fontWeight={700} gutterBottom>
            Request Submitted!
          </Typography>
          
          <Typography color="text.secondary" sx={{ mb: 4 }}>
            {successMessage}
          </Typography>

          <Paper
            sx={{
              p: 3,
              mb: 4,
              background: alpha(theme.palette.background.default, 0.5),
              borderRadius: 2,
            }}
          >
            <Typography variant="subtitle2" color="text.secondary" gutterBottom>
              What happens next?
            </Typography>
            <List dense>
              <ListItem>
                <ListItemIcon sx={{ minWidth: 36 }}>
                  <HourglassEmptyIcon color="warning" fontSize="small" />
                </ListItemIcon>
                <ListItemText primary="Administrator reviews your request" />
              </ListItem>
              <ListItem>
                <ListItemIcon sx={{ minWidth: 36 }}>
                  <VerifiedUserIcon color="info" fontSize="small" />
                </ListItemIcon>
                <ListItemText primary="Your account gets approved" />
              </ListItem>
              <ListItem>
                <ListItemIcon sx={{ minWidth: 36 }}>
                  <RocketLaunchIcon color="success" fontSize="small" />
                </ListItemIcon>
                <ListItemText primary="You can sign in and start using VRAgent" />
              </ListItem>
            </List>
          </Paper>

          <Button
            component={RouterLink}
            to="/login"
            variant="contained"
            size="large"
            fullWidth
            sx={{
              py: 1.5,
              fontWeight: 600,
              background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
            }}
          >
            Back to Login
          </Button>
        </Paper>
      </Box>
    );
  }

  return (
    <Box
      sx={{
        minHeight: "80vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        py: 4,
      }}
    >
      <Paper
        elevation={0}
        sx={{
          p: 4,
          width: "100%",
          maxWidth: 480,
          borderRadius: 4,
          background: alpha(theme.palette.background.paper, 0.8),
          backdropFilter: "blur(20px)",
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          boxShadow: `0 20px 60px ${alpha(theme.palette.common.black, 0.2)}`,
        }}
      >
        {/* Logo & Title */}
        <Box sx={{ textAlign: "center", mb: 4 }}>
          <Box
            sx={{
              display: "inline-flex",
              p: 2,
              borderRadius: 3,
              background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.2)} 0%, ${alpha(theme.palette.secondary.main, 0.2)} 100%)`,
              mb: 2,
              animation: `${float} 3s ease-in-out infinite`,
            }}
          >
            <SecurityIcon sx={{ fontSize: 48, color: "primary.main" }} />
          </Box>
          <Typography
            variant="h4"
            sx={{
              fontWeight: 800,
              background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
              backgroundSize: "200% auto",
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              animation: `${shimmer} 4s linear infinite`,
            }}
          >
            Request Account
          </Typography>
          <Typography color="text.secondary" sx={{ mt: 1 }}>
            Create an account request to get started
          </Typography>
        </Box>

        {/* Error Alert */}
        {error && (
          <Alert severity="error" sx={{ mb: 3, borderRadius: 2 }}>
            {error}
          </Alert>
        )}

        {/* Register Form */}
        <form onSubmit={handleSubmit}>
          <Grid container spacing={2} sx={{ mb: 2 }}>
            <Grid item xs={6}>
              <TextField
                fullWidth
                label="Forename"
                value={firstName}
                onChange={(e) => setFirstName(e.target.value)}
                required
                autoComplete="given-name"
                autoFocus
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <BadgeIcon color="action" />
                    </InputAdornment>
                  ),
                }}
              />
            </Grid>
            <Grid item xs={6}>
              <TextField
                fullWidth
                label="Surname"
                value={lastName}
                onChange={(e) => setLastName(e.target.value)}
                required
                autoComplete="family-name"
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <BadgeIcon color="action" />
                    </InputAdornment>
                  ),
                }}
              />
            </Grid>
          </Grid>

          <TextField
            fullWidth
            label="Email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoComplete="email"
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <EmailIcon color="action" />
                </InputAdornment>
              ),
            }}
            sx={{ mb: 2 }}
          />

          <TextField
            fullWidth
            label="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoComplete="username"
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <PersonIcon color="action" />
                </InputAdornment>
              ),
            }}
            helperText="This will be your login username"
            sx={{ mb: 2 }}
          />

          <TextField
            fullWidth
            label="Password"
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="new-password"
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <LockIcon color="action" />
                </InputAdornment>
              ),
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton
                    onClick={() => setShowPassword(!showPassword)}
                    edge="end"
                    size="small"
                  >
                    {showPassword ? <VisibilityOffIcon /> : <VisibilityIcon />}
                  </IconButton>
                </InputAdornment>
              ),
            }}
            sx={{ mb: 1 }}
          />

          {/* Password Requirements */}
          <Box sx={{ mb: 2, pl: 1 }}>
            {passwordRequirements.map((req, index) => (
              <Typography
                key={index}
                variant="caption"
                sx={{
                  display: "flex",
                  alignItems: "center",
                  gap: 0.5,
                  color: req.met ? "success.main" : "text.secondary",
                }}
              >
                <CheckCircleIcon sx={{ fontSize: 14 }} />
                {req.text}
              </Typography>
            ))}
          </Box>

          <TextField
            fullWidth
            label="Confirm Password"
            type={showPassword ? "text" : "password"}
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
            autoComplete="new-password"
            error={confirmPassword.length > 0 && !doPasswordsMatch}
            helperText={
              confirmPassword.length > 0 && !doPasswordsMatch
                ? "Passwords do not match"
                : ""
            }
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <LockIcon color="action" />
                </InputAdornment>
              ),
            }}
            sx={{ mb: 3 }}
          />

          <Button
            fullWidth
            type="submit"
            variant="contained"
            size="large"
            disabled={isLoading || !firstName || !lastName || !email || !username || !isPasswordValid || !doPasswordsMatch}
            sx={{
              py: 1.5,
              fontWeight: 600,
              fontSize: "1rem",
              background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
              boxShadow: `0 4px 20px ${alpha(theme.palette.primary.main, 0.4)}`,
              "&:hover": {
                boxShadow: `0 6px 30px ${alpha(theme.palette.primary.main, 0.5)}`,
              },
            }}
          >
            {isLoading ? (
              <CircularProgress size={24} color="inherit" />
            ) : (
              "Submit Request"
            )}
          </Button>
        </form>

        {/* Login Link */}
        <Divider sx={{ my: 3 }}>
          <Typography variant="body2" color="text.secondary">
            Already have an account?
          </Typography>
        </Divider>

        <Button
          fullWidth
          component={RouterLink}
          to="/login"
          variant="outlined"
          size="large"
          sx={{
            py: 1.5,
            fontWeight: 600,
            borderWidth: 2,
            "&:hover": {
              borderWidth: 2,
            },
          }}
        >
          Sign In
        </Button>
      </Paper>
    </Box>
  );
}
