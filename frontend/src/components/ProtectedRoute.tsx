import { Navigate, useLocation } from "react-router-dom";
import { Box, CircularProgress, Typography, Paper, alpha, useTheme } from "@mui/material";
import { useAuth } from "../contexts/AuthContext";
import LockIcon from "@mui/icons-material/Lock";

type ProtectedRouteProps = {
  children: React.ReactNode;
  requireAdmin?: boolean;
};

export default function ProtectedRoute({ children, requireAdmin = false }: ProtectedRouteProps) {
  const { isAuthenticated, isAdmin, isLoading, user } = useAuth();
  const location = useLocation();
  const theme = useTheme();

  // Debug logging
  console.log("[ProtectedRoute]", { 
    path: location.pathname,
    isLoading, 
    isAuthenticated, 
    isAdmin,
    user: user?.email 
  });

  // Show loading spinner while checking auth
  if (isLoading) {
    return (
      <Box
        sx={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          minHeight: "60vh",
          gap: 2,
        }}
      >
        <CircularProgress size={48} />
        <Typography color="text.secondary">Checking authentication...</Typography>
      </Box>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    // Check if user exists but status is pending
    if (user && user.status === "pending") {
      return (
        <Box
          sx={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            minHeight: "60vh",
            gap: 3,
          }}
        >
          <Paper
            elevation={0}
            sx={{
              p: 4,
              textAlign: "center",
              maxWidth: 500,
              background: alpha(theme.palette.warning.main, 0.1),
              border: `1px solid ${alpha(theme.palette.warning.main, 0.3)}`,
              borderRadius: 3,
            }}
          >
            <LockIcon sx={{ fontSize: 64, color: "warning.main", mb: 2 }} />
            <Typography variant="h5" gutterBottom fontWeight={600}>
              Account Pending Approval
            </Typography>
            <Typography color="text.secondary">
              Your account is awaiting administrator approval. You'll receive access once your
              account has been approved.
            </Typography>
          </Paper>
        </Box>
      );
    }

    // Redirect to login, saving the attempted location
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Check admin requirement
  if (requireAdmin && !isAdmin) {
    return (
      <Box
        sx={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          minHeight: "60vh",
          gap: 3,
        }}
      >
        <Paper
          elevation={0}
          sx={{
            p: 4,
            textAlign: "center",
            maxWidth: 500,
            background: alpha(theme.palette.error.main, 0.1),
            border: `1px solid ${alpha(theme.palette.error.main, 0.3)}`,
            borderRadius: 3,
          }}
        >
          <LockIcon sx={{ fontSize: 64, color: "error.main", mb: 2 }} />
          <Typography variant="h5" gutterBottom fontWeight={600}>
            Access Denied
          </Typography>
          <Typography color="text.secondary">
            You don't have permission to access this page. Administrator privileges are required.
          </Typography>
        </Paper>
      </Box>
    );
  }

  return <>{children}</>;
}
