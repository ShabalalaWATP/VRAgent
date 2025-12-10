import { useState, useEffect, useCallback } from "react";
import {
  Box,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Chip,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
  Alert,
  Tooltip,
  alpha,
  useTheme,
  CircularProgress,
  InputAdornment,
  Tabs,
  Tab,
  Badge,
  Card,
  CardContent,
  Grid,
} from "@mui/material";
import { useAuth } from "../contexts/AuthContext";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import BlockIcon from "@mui/icons-material/Block";
import DeleteIcon from "@mui/icons-material/Delete";
import EditIcon from "@mui/icons-material/Edit";
import PersonAddIcon from "@mui/icons-material/PersonAdd";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import SearchIcon from "@mui/icons-material/Search";
import RefreshIcon from "@mui/icons-material/Refresh";
import PeopleIcon from "@mui/icons-material/People";
import HourglassEmptyIcon from "@mui/icons-material/HourglassEmpty";
import VerifiedUserIcon from "@mui/icons-material/VerifiedUser";
import LockResetIcon from "@mui/icons-material/LockReset";

const API_URL = import.meta.env.VITE_API_URL || "/api";

type User = {
  id: number;
  email: string;
  username: string;
  first_name?: string;
  last_name?: string;
  role: "user" | "admin";
  status: "pending" | "approved" | "suspended";
  created_at: string;
  last_login?: string;
};

type TabValue = "all" | "pending" | "approved" | "suspended";

export default function AdminPage() {
  const theme = useTheme();
  const { getAccessToken } = useAuth();
  
  const [users, setUsers] = useState<User[]>([]);
  const [filteredUsers, setFilteredUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [activeTab, setActiveTab] = useState<TabValue>("all");

  // Dialog states
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [passwordDialogOpen, setPasswordDialogOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);

  // Form states
  const [newUser, setNewUser] = useState({ email: "", username: "", firstName: "", lastName: "", password: "", role: "user" as "user" | "admin" });
  const [newPassword, setNewPassword] = useState("");

  const fetchUsers = useCallback(async () => {
    setIsLoading(true);
    setError("");
    try {
      const token = getAccessToken();
      const response = await fetch(`${API_URL}/admin/users`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        setUsers(data);
      } else {
        setError("Failed to fetch users");
      }
    } catch (err: any) {
      setError(err.message || "Network error");
    }
    setIsLoading(false);
  }, [getAccessToken]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  // Filter users based on search and tab
  useEffect(() => {
    let filtered = users;

    // Filter by tab
    if (activeTab !== "all") {
      filtered = filtered.filter((user) => user.status === activeTab);
    }

    // Filter by search
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (user) =>
          user.email.toLowerCase().includes(query) ||
          user.username.toLowerCase().includes(query) ||
          (user.first_name?.toLowerCase() || "").includes(query) ||
          (user.last_name?.toLowerCase() || "").includes(query)
      );
    }

    setFilteredUsers(filtered);
  }, [users, activeTab, searchQuery]);

  const handleApprove = async (userId: number) => {
    try {
      const token = getAccessToken();
      const response = await fetch(`${API_URL}/admin/users/${userId}/approve`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (response.ok) {
        setSuccess("User approved successfully");
        fetchUsers();
      } else {
        setError("Failed to approve user");
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleSuspend = async (userId: number) => {
    try {
      const token = getAccessToken();
      const response = await fetch(`${API_URL}/admin/users/${userId}/suspend`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (response.ok) {
        setSuccess("User suspended successfully");
        fetchUsers();
      } else {
        setError("Failed to suspend user");
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleDelete = async () => {
    if (!selectedUser) return;
    try {
      const token = getAccessToken();
      const response = await fetch(`${API_URL}/admin/users/${selectedUser.id}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (response.ok) {
        setSuccess("User deleted successfully");
        setDeleteDialogOpen(false);
        setSelectedUser(null);
        fetchUsers();
      } else {
        setError("Failed to delete user");
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleCreateUser = async () => {
    try {
      const token = getAccessToken();
      const response = await fetch(`${API_URL}/admin/users`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: newUser.email,
          username: newUser.username,
          first_name: newUser.firstName || null,
          last_name: newUser.lastName || null,
          password: newUser.password,
          role: newUser.role,
        }),
      });
      if (response.ok) {
        setSuccess("User created successfully");
        setCreateDialogOpen(false);
        setNewUser({ email: "", username: "", firstName: "", lastName: "", password: "", role: "user" });
        fetchUsers();
      } else {
        const data = await response.json();
        setError(data.detail || "Failed to create user");
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleUpdateRole = async () => {
    if (!selectedUser) return;
    try {
      const token = getAccessToken();
      const response = await fetch(`${API_URL}/admin/users/${selectedUser.id}/role`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role: selectedUser.role }),
      });
      if (response.ok) {
        setSuccess("User role updated successfully");
        setEditDialogOpen(false);
        setSelectedUser(null);
        fetchUsers();
      } else {
        setError("Failed to update role");
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleChangePassword = async () => {
    if (!selectedUser || !newPassword) return;
    try {
      const token = getAccessToken();
      const response = await fetch(`${API_URL}/admin/users/${selectedUser.id}/password`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ new_password: newPassword }),
      });
      if (response.ok) {
        setSuccess("Password changed successfully");
        setPasswordDialogOpen(false);
        setSelectedUser(null);
        setNewPassword("");
      } else {
        setError("Failed to change password");
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const getStatusChip = (status: string) => {
    switch (status) {
      case "approved":
        return <Chip size="small" label="Approved" color="success" icon={<CheckCircleIcon />} />;
      case "pending":
        return <Chip size="small" label="Pending" color="warning" icon={<HourglassEmptyIcon />} />;
      case "suspended":
        return <Chip size="small" label="Suspended" color="error" icon={<BlockIcon />} />;
      default:
        return <Chip size="small" label={status} />;
    }
  };

  const getRoleChip = (role: string) => {
    if (role === "admin") {
      return <Chip size="small" label="Admin" color="primary" icon={<AdminPanelSettingsIcon />} />;
    }
    return <Chip size="small" label="User" variant="outlined" />;
  };

  // Stats
  const pendingCount = users.filter((u) => u.status === "pending").length;
  const approvedCount = users.filter((u) => u.status === "approved").length;
  const suspendedCount = users.filter((u) => u.status === "suspended").length;

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" fontWeight={700} gutterBottom>
          <AdminPanelSettingsIcon sx={{ mr: 1, verticalAlign: "bottom" }} />
          User Management
        </Typography>
        <Typography color="text.secondary">
          Manage user accounts, approve requests, and control access
        </Typography>
      </Box>

      {/* Alerts */}
      {error && (
        <Alert severity="error" onClose={() => setError("")} sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}
      {success && (
        <Alert severity="success" onClose={() => setSuccess("")} sx={{ mb: 3 }}>
          {success}
        </Alert>
      )}

      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={4}>
          <Card
            sx={{
              background: `linear-gradient(135deg, ${alpha(theme.palette.warning.main, 0.1)} 0%, ${alpha(theme.palette.warning.main, 0.05)} 100%)`,
              border: `1px solid ${alpha(theme.palette.warning.main, 0.2)}`,
            }}
          >
            <CardContent>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    Pending Requests
                  </Typography>
                  <Typography variant="h3" fontWeight={700} color="warning.main">
                    {pendingCount}
                  </Typography>
                </Box>
                <HourglassEmptyIcon sx={{ fontSize: 48, color: "warning.main", opacity: 0.5 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Card
            sx={{
              background: `linear-gradient(135deg, ${alpha(theme.palette.success.main, 0.1)} 0%, ${alpha(theme.palette.success.main, 0.05)} 100%)`,
              border: `1px solid ${alpha(theme.palette.success.main, 0.2)}`,
            }}
          >
            <CardContent>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    Active Users
                  </Typography>
                  <Typography variant="h3" fontWeight={700} color="success.main">
                    {approvedCount}
                  </Typography>
                </Box>
                <VerifiedUserIcon sx={{ fontSize: 48, color: "success.main", opacity: 0.5 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Card
            sx={{
              background: `linear-gradient(135deg, ${alpha(theme.palette.info.main, 0.1)} 0%, ${alpha(theme.palette.info.main, 0.05)} 100%)`,
              border: `1px solid ${alpha(theme.palette.info.main, 0.2)}`,
            }}
          >
            <CardContent>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    Total Users
                  </Typography>
                  <Typography variant="h3" fontWeight={700} color="info.main">
                    {users.length}
                  </Typography>
                </Box>
                <PeopleIcon sx={{ fontSize: 48, color: "info.main", opacity: 0.5 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Main Content */}
      <Paper
        elevation={0}
        sx={{
          borderRadius: 3,
          border: `1px solid ${theme.palette.divider}`,
          overflow: "hidden",
        }}
      >
        {/* Toolbar */}
        <Box
          sx={{
            p: 2,
            display: "flex",
            alignItems: "center",
            gap: 2,
            borderBottom: `1px solid ${theme.palette.divider}`,
            flexWrap: "wrap",
          }}
        >
          <TextField
            size="small"
            placeholder="Search users..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon color="action" />
                </InputAdornment>
              ),
            }}
            sx={{ minWidth: 250 }}
          />
          
          <Box sx={{ flexGrow: 1 }} />
          
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={fetchUsers}
            disabled={isLoading}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<PersonAddIcon />}
            onClick={() => setCreateDialogOpen(true)}
          >
            Create User
          </Button>
        </Box>

        {/* Tabs */}
        <Tabs
          value={activeTab}
          onChange={(_, value) => setActiveTab(value)}
          sx={{ borderBottom: `1px solid ${theme.palette.divider}`, px: 2 }}
        >
          <Tab label="All Users" value="all" />
          <Tab
            label={
              <Badge badgeContent={pendingCount} color="warning">
                Pending
              </Badge>
            }
            value="pending"
          />
          <Tab label="Approved" value="approved" />
          <Tab label="Suspended" value="suspended" />
        </Tabs>

        {/* Table */}
        {isLoading ? (
          <Box sx={{ display: "flex", justifyContent: "center", py: 8 }}>
            <CircularProgress />
          </Box>
        ) : (
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>User</TableCell>
                  <TableCell>Name</TableCell>
                  <TableCell>Email</TableCell>
                  <TableCell>Role</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell>Last Login</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredUsers.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} align="center" sx={{ py: 8 }}>
                      <Typography color="text.secondary">No users found</Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredUsers.map((user) => (
                    <TableRow key={user.id} hover>
                      <TableCell>
                        <Typography fontWeight={600}>{user.username}</Typography>
                      </TableCell>
                      <TableCell>
                        {user.first_name || user.last_name 
                          ? `${user.first_name || ''} ${user.last_name || ''}`.trim()
                          : <Typography color="text.secondary" variant="body2">-</Typography>
                        }
                      </TableCell>
                      <TableCell>{user.email}</TableCell>
                      <TableCell>{getRoleChip(user.role)}</TableCell>
                      <TableCell>{getStatusChip(user.status)}</TableCell>
                      <TableCell>
                        {new Date(user.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell>
                        {user.last_login
                          ? new Date(user.last_login).toLocaleDateString()
                          : "Never"}
                      </TableCell>
                      <TableCell align="right">
                        {user.status === "pending" && (
                          <Tooltip title="Approve">
                            <IconButton
                              color="success"
                              onClick={() => handleApprove(user.id)}
                            >
                              <CheckCircleIcon />
                            </IconButton>
                          </Tooltip>
                        )}
                        {user.status === "approved" && (
                          <Tooltip title="Suspend">
                            <IconButton
                              color="warning"
                              onClick={() => handleSuspend(user.id)}
                            >
                              <BlockIcon />
                            </IconButton>
                          </Tooltip>
                        )}
                        {user.status === "suspended" && (
                          <Tooltip title="Reactivate">
                            <IconButton
                              color="success"
                              onClick={() => handleApprove(user.id)}
                            >
                              <CheckCircleIcon />
                            </IconButton>
                          </Tooltip>
                        )}
                        <Tooltip title="Change Password">
                          <IconButton
                            onClick={() => {
                              setSelectedUser(user);
                              setPasswordDialogOpen(true);
                            }}
                          >
                            <LockResetIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Edit Role">
                          <IconButton
                            onClick={() => {
                              setSelectedUser({ ...user });
                              setEditDialogOpen(true);
                            }}
                          >
                            <EditIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete">
                          <IconButton
                            color="error"
                            onClick={() => {
                              setSelectedUser(user);
                              setDeleteDialogOpen(true);
                            }}
                          >
                            <DeleteIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Paper>

      {/* Create User Dialog */}
      <Dialog open={createDialogOpen} onClose={() => setCreateDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create New User</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 1, display: "flex", flexDirection: "column", gap: 2 }}>
            <Box sx={{ display: "flex", gap: 2 }}>
              <TextField
                fullWidth
                label="Forename"
                value={newUser.firstName}
                onChange={(e) => setNewUser({ ...newUser, firstName: e.target.value })}
              />
              <TextField
                fullWidth
                label="Surname"
                value={newUser.lastName}
                onChange={(e) => setNewUser({ ...newUser, lastName: e.target.value })}
              />
            </Box>
            <TextField
              fullWidth
              label="Email"
              type="email"
              value={newUser.email}
              onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
              required
            />
            <TextField
              fullWidth
              label="Username"
              value={newUser.username}
              onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
              required
            />
            <TextField
              fullWidth
              label="Password"
              type="password"
              value={newUser.password}
              onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
              required
            />
            <TextField
              fullWidth
              select
              label="Role"
              value={newUser.role}
              onChange={(e) => setNewUser({ ...newUser, role: e.target.value as "user" | "admin" })}
            >
              <MenuItem value="user">User</MenuItem>
              <MenuItem value="admin">Admin</MenuItem>
            </TextField>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleCreateUser}>
            Create
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit Role Dialog */}
      <Dialog open={editDialogOpen} onClose={() => setEditDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Edit User Role</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 1 }}>
            <Typography gutterBottom>
              Editing role for: <strong>{selectedUser?.username}</strong>
            </Typography>
            <TextField
              fullWidth
              select
              label="Role"
              value={selectedUser?.role || "user"}
              onChange={(e) =>
                setSelectedUser(selectedUser ? { ...selectedUser, role: e.target.value as "user" | "admin" } : null)
              }
            >
              <MenuItem value="user">User</MenuItem>
              <MenuItem value="admin">Admin</MenuItem>
            </TextField>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleUpdateRole}>
            Update
          </Button>
        </DialogActions>
      </Dialog>

      {/* Change Password Dialog */}
      <Dialog open={passwordDialogOpen} onClose={() => setPasswordDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Change Password</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 1 }}>
            <Typography gutterBottom>
              Changing password for: <strong>{selectedUser?.username}</strong>
            </Typography>
            <TextField
              fullWidth
              label="New Password"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPasswordDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleChangePassword}>
            Change Password
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>Delete User</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete <strong>{selectedUser?.username}</strong>? This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" color="error" onClick={handleDelete}>
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
