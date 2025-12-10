import { useState } from "react";
import { useNavigate, Link as RouterLink } from "react-router-dom";
import {
  Box,
  IconButton,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Typography,
  Avatar,
  alpha,
  useTheme,
  Chip,
} from "@mui/material";
import { useAuth } from "../contexts/AuthContext";
import PersonIcon from "@mui/icons-material/Person";
import LogoutIcon from "@mui/icons-material/Logout";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import LoginIcon from "@mui/icons-material/Login";

export default function UserMenu() {
  const theme = useTheme();
  const navigate = useNavigate();
  const { user, isAuthenticated, isAdmin, logout } = useAuth();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = () => {
    logout();
    handleClose();
    navigate("/login");
  };

  // Not authenticated - show login button
  if (!isAuthenticated) {
    return (
      <IconButton
        component={RouterLink}
        to="/login"
        sx={{
          color: "text.secondary",
          bgcolor: alpha(theme.palette.divider, 0.1),
          "&:hover": {
            bgcolor: alpha(theme.palette.primary.main, 0.1),
            color: "text.primary",
          },
        }}
      >
        <LoginIcon />
      </IconButton>
    );
  }

  // Get initials for avatar
  const initials = user?.username
    ? user.username.substring(0, 2).toUpperCase()
    : user?.email?.substring(0, 2).toUpperCase() || "U";

  return (
    <>
      <IconButton
        onClick={handleOpen}
        sx={{
          p: 0.5,
          border: `2px solid ${alpha(theme.palette.primary.main, 0.5)}`,
          "&:hover": {
            borderColor: theme.palette.primary.main,
          },
        }}
      >
        <Avatar
          sx={{
            width: 32,
            height: 32,
            bgcolor: isAdmin ? theme.palette.primary.main : theme.palette.secondary.main,
            fontSize: "0.875rem",
            fontWeight: 600,
          }}
        >
          {initials}
        </Avatar>
      </IconButton>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
        onClick={handleClose}
        transformOrigin={{ horizontal: "right", vertical: "top" }}
        anchorOrigin={{ horizontal: "right", vertical: "bottom" }}
        PaperProps={{
          elevation: 0,
          sx: {
            mt: 1.5,
            minWidth: 220,
            overflow: "visible",
            filter: "drop-shadow(0px 2px 8px rgba(0,0,0,0.32))",
            border: `1px solid ${theme.palette.divider}`,
            borderRadius: 2,
            "&:before": {
              content: '""',
              display: "block",
              position: "absolute",
              top: 0,
              right: 14,
              width: 10,
              height: 10,
              bgcolor: "background.paper",
              transform: "translateY(-50%) rotate(45deg)",
              zIndex: 0,
              borderLeft: `1px solid ${theme.palette.divider}`,
              borderTop: `1px solid ${theme.palette.divider}`,
            },
          },
        }}
      >
        {/* User Info */}
        <Box sx={{ px: 2, py: 1.5 }}>
          <Typography variant="subtitle1" fontWeight={600}>
            {user?.username}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            {user?.email}
          </Typography>
          {isAdmin && (
            <Chip
              size="small"
              label="Administrator"
              color="primary"
              icon={<AdminPanelSettingsIcon />}
              sx={{ height: 24 }}
            />
          )}
        </Box>

        <Divider />

        {/* Admin Link */}
        {isAdmin && (
          <MenuItem component={RouterLink} to="/admin">
            <ListItemIcon>
              <AdminPanelSettingsIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>User Management</ListItemText>
          </MenuItem>
        )}

        {/* Profile */}
        <MenuItem component={RouterLink} to="/profile">
          <ListItemIcon>
            <PersonIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>My Profile</ListItemText>
        </MenuItem>

        <Divider />

        {/* Logout */}
        <MenuItem onClick={handleLogout}>
          <ListItemIcon>
            <LogoutIcon fontSize="small" color="error" />
          </ListItemIcon>
          <ListItemText>
            <Typography color="error.main">Sign Out</Typography>
          </ListItemText>
        </MenuItem>
      </Menu>
    </>
  );
}
