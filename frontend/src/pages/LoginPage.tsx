import { useState } from "react";
import { useNavigate, useLocation, Link as RouterLink } from "react-router-dom";
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
} from "@mui/material";
import { useAuth } from "../contexts/AuthContext";
import VisibilityIcon from "@mui/icons-material/Visibility";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import PersonIcon from "@mui/icons-material/Person";
import LockIcon from "@mui/icons-material/Lock";
import SecurityIcon from "@mui/icons-material/Security";
import ShieldIcon from "@mui/icons-material/Shield";
import VpnKeyIcon from "@mui/icons-material/VpnKey";

// Animations
const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-10px); }
`;

const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

const pulse = keyframes`
  0%, 100% { opacity: 0.4; transform: scale(1); }
  50% { opacity: 0.8; transform: scale(1.05); }
`;

const rotate = keyframes`
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
`;

const floatSlow = keyframes`
  0%, 100% { transform: translateY(0px) translateX(0px); }
  25% { transform: translateY(-20px) translateX(10px); }
  50% { transform: translateY(-10px) translateX(-10px); }
  75% { transform: translateY(-30px) translateX(5px); }
`;

const glow = keyframes`
  0%, 100% { box-shadow: 0 0 20px rgba(99, 102, 241, 0.3), 0 0 40px rgba(99, 102, 241, 0.2); }
  50% { box-shadow: 0 0 40px rgba(99, 102, 241, 0.5), 0 0 80px rgba(99, 102, 241, 0.3); }
`;

export default function LoginPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const { login, isAuthenticated } = useAuth();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  // Get the page user was trying to access
  const from = location.state?.from?.pathname || "/";

  // Redirect if already authenticated
  if (isAuthenticated) {
    navigate(from, { replace: true });
    return null;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    const result = await login(username, password);
    
    if (result.success) {
      navigate(from, { replace: true });
    } else {
      setError(result.error || "Login failed");
    }
    
    setIsLoading(false);
  };

  return (
    <Box
      sx={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        zIndex: 1200,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        overflow: "hidden",
      }}
    >
      {/* Animated Background */}
      <Box
        sx={{
          position: "absolute",
          inset: 0,
          background: theme.palette.mode === "dark"
            ? `radial-gradient(ellipse at 20% 20%, ${alpha("#1e1b4b", 0.8)} 0%, transparent 50%),
               radial-gradient(ellipse at 80% 80%, ${alpha("#064e3b", 0.6)} 0%, transparent 50%),
               radial-gradient(ellipse at 50% 50%, ${alpha("#0c0a09", 1)} 0%, ${alpha("#0c0a09", 1)} 100%)`
            : `radial-gradient(ellipse at 20% 20%, ${alpha("#c7d2fe", 0.8)} 0%, transparent 50%),
               radial-gradient(ellipse at 80% 80%, ${alpha("#a7f3d0", 0.6)} 0%, transparent 50%),
               radial-gradient(ellipse at 50% 50%, ${alpha("#f8fafc", 1)} 0%, ${alpha("#f1f5f9", 1)} 100%)`,
        }}
      />

      {/* Blurred Overlay Pattern */}
      <Box
        sx={{
          position: "absolute",
          inset: 0,
          backdropFilter: "blur(100px)",
          background: alpha(theme.palette.background.default, 0.3),
        }}
      />

      {/* Floating Security Icons */}
      {[...Array(6)].map((_, i) => (
        <Box
          key={i}
          sx={{
            position: "absolute",
            color: alpha(theme.palette.primary.main, 0.15),
            animation: `${floatSlow} ${8 + i * 2}s ease-in-out infinite`,
            animationDelay: `${i * 0.5}s`,
            left: `${10 + i * 15}%`,
            top: `${15 + (i % 3) * 25}%`,
          }}
        >
          {i % 3 === 0 ? (
            <SecurityIcon sx={{ fontSize: 40 + i * 10 }} />
          ) : i % 3 === 1 ? (
            <ShieldIcon sx={{ fontSize: 35 + i * 8 }} />
          ) : (
            <VpnKeyIcon sx={{ fontSize: 30 + i * 6 }} />
          )}
        </Box>
      ))}

      {/* Animated Gradient Orbs */}
      <Box
        sx={{
          position: "absolute",
          width: 400,
          height: 400,
          borderRadius: "50%",
          background: `radial-gradient(circle, ${alpha(theme.palette.primary.main, 0.3)} 0%, transparent 70%)`,
          top: "-10%",
          left: "-10%",
          animation: `${pulse} 8s ease-in-out infinite`,
          filter: "blur(60px)",
        }}
      />
      <Box
        sx={{
          position: "absolute",
          width: 300,
          height: 300,
          borderRadius: "50%",
          background: `radial-gradient(circle, ${alpha(theme.palette.secondary.main, 0.3)} 0%, transparent 70%)`,
          bottom: "-5%",
          right: "-5%",
          animation: `${pulse} 6s ease-in-out infinite`,
          animationDelay: "2s",
          filter: "blur(60px)",
        }}
      />
      <Box
        sx={{
          position: "absolute",
          width: 200,
          height: 200,
          borderRadius: "50%",
          background: `radial-gradient(circle, ${alpha("#10b981", 0.25)} 0%, transparent 70%)`,
          top: "60%",
          left: "10%",
          animation: `${pulse} 10s ease-in-out infinite`,
          animationDelay: "4s",
          filter: "blur(40px)",
        }}
      />

      {/* Rotating Ring */}
      <Box
        sx={{
          position: "absolute",
          width: 600,
          height: 600,
          borderRadius: "50%",
          border: `2px dashed ${alpha(theme.palette.primary.main, 0.1)}`,
          animation: `${rotate} 60s linear infinite`,
        }}
      />
      <Box
        sx={{
          position: "absolute",
          width: 500,
          height: 500,
          borderRadius: "50%",
          border: `1px dashed ${alpha(theme.palette.secondary.main, 0.08)}`,
          animation: `${rotate} 45s linear infinite reverse`,
        }}
      />

      {/* Login Card */}
      <Paper
        elevation={0}
        sx={{
          position: "relative",
          p: 5,
          width: "100%",
          maxWidth: 460,
          borderRadius: 4,
          background: alpha(theme.palette.background.paper, theme.palette.mode === "dark" ? 0.8 : 0.9),
          backdropFilter: "blur(20px)",
          border: `1px solid ${alpha(theme.palette.divider, 0.15)}`,
          boxShadow: `0 25px 80px ${alpha(theme.palette.common.black, 0.3)}, 
                      0 10px 30px ${alpha(theme.palette.common.black, 0.2)}`,
          animation: `${glow} 4s ease-in-out infinite`,
        }}
      >
        {/* Logo & Title */}
        <Box sx={{ textAlign: "center", mb: 4 }}>
          <Box
            sx={{
              position: "relative",
              display: "inline-block",
              mb: 3,
            }}
          >
            {/* Glowing ring behind logo */}
            <Box
              sx={{
                position: "absolute",
                inset: -15,
                borderRadius: "50%",
                background: `conic-gradient(from 0deg, 
                  ${alpha(theme.palette.primary.main, 0.4)}, 
                  ${alpha(theme.palette.secondary.main, 0.4)}, 
                  ${alpha("#10b981", 0.4)},
                  ${alpha(theme.palette.primary.main, 0.4)})`,
                animation: `${rotate} 8s linear infinite`,
                filter: "blur(15px)",
              }}
            />
            <Box
              component="img"
              src="/images/logo.jpg"
              alt="VRAgent Logo"
              sx={{
                position: "relative",
                width: 130,
                height: 130,
                borderRadius: "50%",
                border: `4px solid ${alpha(theme.palette.background.paper, 0.9)}`,
                boxShadow: `0 10px 40px ${alpha(theme.palette.primary.main, 0.4)}`,
                animation: `${float} 3s ease-in-out infinite`,
              }}
            />
          </Box>
          
          <Typography
            variant="h3"
            sx={{
              fontWeight: 800,
              background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 50%, #10b981 100%)`,
              backgroundSize: "200% auto",
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              animation: `${shimmer} 4s linear infinite`,
              letterSpacing: "-0.02em",
            }}
          >
            VRAgent
          </Typography>
          <Typography 
            color="text.secondary" 
            sx={{ 
              mt: 1,
              fontSize: "0.95rem",
              fontWeight: 500,
            }}
          >
            Security Vulnerability Scanner
          </Typography>
          <Typography 
            sx={{ 
              mt: 0.5,
              fontSize: "0.8rem",
              color: alpha(theme.palette.text.secondary, 0.7),
              letterSpacing: "0.1em",
              textTransform: "uppercase",
            }}
          >
            Sign in to continue
          </Typography>
        </Box>

        {/* Error Alert */}
        {error && (
          <Alert 
            severity="error" 
            sx={{ 
              mb: 3, 
              borderRadius: 2,
              animation: "shake 0.5s ease-in-out",
              "@keyframes shake": {
                "0%, 100%": { transform: "translateX(0)" },
                "25%": { transform: "translateX(-5px)" },
                "75%": { transform: "translateX(5px)" },
              },
            }}
          >
            {error}
          </Alert>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit}>
          <TextField
            fullWidth
            label="Username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoComplete="username"
            autoFocus
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <PersonIcon sx={{ color: theme.palette.primary.main }} />
                </InputAdornment>
              ),
            }}
            sx={{ 
              mb: 2.5,
              "& .MuiOutlinedInput-root": {
                borderRadius: 2,
                transition: "all 0.3s ease",
                "&:hover": {
                  boxShadow: `0 0 0 2px ${alpha(theme.palette.primary.main, 0.1)}`,
                },
                "&.Mui-focused": {
                  boxShadow: `0 0 0 3px ${alpha(theme.palette.primary.main, 0.2)}`,
                },
              },
            }}
          />

          <TextField
            fullWidth
            label="Password"
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <LockIcon sx={{ color: theme.palette.primary.main }} />
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
            sx={{ 
              mb: 3.5,
              "& .MuiOutlinedInput-root": {
                borderRadius: 2,
                transition: "all 0.3s ease",
                "&:hover": {
                  boxShadow: `0 0 0 2px ${alpha(theme.palette.primary.main, 0.1)}`,
                },
                "&.Mui-focused": {
                  boxShadow: `0 0 0 3px ${alpha(theme.palette.primary.main, 0.2)}`,
                },
              },
            }}
          />

          <Button
            fullWidth
            type="submit"
            variant="contained"
            size="large"
            disabled={isLoading || !username || !password}
            sx={{
              py: 1.75,
              fontWeight: 700,
              fontSize: "1.05rem",
              borderRadius: 2,
              background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
              boxShadow: `0 8px 30px ${alpha(theme.palette.primary.main, 0.5)}`,
              transition: "all 0.3s ease",
              "&:hover": {
                boxShadow: `0 12px 40px ${alpha(theme.palette.primary.main, 0.6)}`,
                transform: "translateY(-2px)",
              },
              "&:active": {
                transform: "translateY(0)",
              },
              "&:disabled": {
                background: alpha(theme.palette.action.disabled, 0.3),
              },
            }}
          >
            {isLoading ? (
              <CircularProgress size={26} color="inherit" />
            ) : (
              "Sign In"
            )}
          </Button>
        </form>

        {/* Register Link */}
        <Divider sx={{ my: 3.5 }}>
          <Typography 
            variant="body2" 
            sx={{ 
              color: alpha(theme.palette.text.secondary, 0.8),
              px: 2,
            }}
          >
            Don't have an account?
          </Typography>
        </Divider>

        <Button
          fullWidth
          component={RouterLink}
          to="/register"
          variant="outlined"
          size="large"
          sx={{
            py: 1.5,
            fontWeight: 600,
            borderRadius: 2,
            borderWidth: 2,
            borderColor: alpha(theme.palette.primary.main, 0.5),
            color: theme.palette.primary.main,
            transition: "all 0.3s ease",
            "&:hover": {
              borderWidth: 2,
              borderColor: theme.palette.primary.main,
              background: alpha(theme.palette.primary.main, 0.08),
              transform: "translateY(-2px)",
            },
          }}
        >
          Request Account
        </Button>

        {/* Footer */}
        <Typography 
          variant="caption" 
          sx={{ 
            display: "block",
            textAlign: "center",
            mt: 3,
            color: alpha(theme.palette.text.secondary, 0.5),
          }}
        >
          Protected by enterprise-grade security
        </Typography>
      </Paper>
    </Box>
  );
}
