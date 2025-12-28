import { useState, useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Avatar,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Divider,
  FormControl,
  IconButton,
  InputAdornment,
  InputLabel,
  List,
  ListItem,
  ListItemAvatar,
  ListItemButton,
  ListItemText,
  MenuItem,
  Paper,
  Select,
  Skeleton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
  alpha,
  useTheme,
  Theme,
} from "@mui/material";
import SearchIcon from "@mui/icons-material/Search";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import { api, ProjectCollaborator, socialApi, UserPublicProfile } from "../api/client";

// Icons
const PersonAddIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
    <path d="M15 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm-9-2V7H4v3H1v2h3v3h2v-3h3v-2H6zm9 4c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z" />
  </svg>
);

const DeleteIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z" />
  </svg>
);

const EditIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z" />
  </svg>
);

const PeopleIcon = () => (
  <svg width="32" height="32" viewBox="0 0 24 24" fill="currentColor">
    <path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z" />
  </svg>
);

const getRoleColor = (role: string, theme: Theme) => {
  switch (role) {
    case "admin":
      return { bg: alpha("#8b5cf6", 0.15), text: "#8b5cf6" };
    case "editor":
      return { bg: alpha(theme.palette.primary.main, 0.15), text: theme.palette.primary.main };
    case "viewer":
      return { bg: alpha(theme.palette.info.main, 0.15), text: theme.palette.info.main };
    default:
      return { bg: alpha(theme.palette.grey[500], 0.15), text: theme.palette.grey[500] };
  }
};

// User Discovery Selector Component
interface UserDiscoverySelectorProps {
  selectedUsername: string;
  onSelectUser: (username: string) => void;
  existingCollaborators: string[];
}

function UserDiscoverySelector({ selectedUsername, onSelectUser, existingCollaborators }: UserDiscoverySelectorProps) {
  const theme = useTheme();
  const [searchQuery, setSearchQuery] = useState("");
  const [users, setUsers] = useState<UserPublicProfile[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Load suggested users on mount
  useEffect(() => {
    const loadSuggestedUsers = async () => {
      setLoading(true);
      try {
        const data = await socialApi.getSuggestedUsers(0, 50);
        setUsers(data.users);
        setError("");
      } catch (err) {
        console.error("Failed to load users:", err);
        setError("Failed to load platform users");
      } finally {
        setLoading(false);
      }
    };
    loadSuggestedUsers();
  }, []);

  // Search when query changes
  useEffect(() => {
    if (!searchQuery.trim()) {
      // Reset to suggested users
      const loadSuggestedUsers = async () => {
        setLoading(true);
        try {
          const data = await socialApi.getSuggestedUsers(0, 50);
          setUsers(data.users);
          setError("");
        } catch (err) {
          setError("Failed to load users");
        } finally {
          setLoading(false);
        }
      };
      loadSuggestedUsers();
      return;
    }

    const timeoutId = setTimeout(async () => {
      setLoading(true);
      try {
        const data = await socialApi.searchUsers(searchQuery, 0, 50);
        setUsers(data.users);
        setError("");
      } catch (err) {
        console.error("Search failed:", err);
        setError("Search failed");
      } finally {
        setLoading(false);
      }
    }, 300);

    return () => clearTimeout(timeoutId);
  }, [searchQuery]);

  // Filter out existing collaborators
  const availableUsers = users.filter(
    (user) => !existingCollaborators.includes(user.username)
  );

  return (
    <Box>
      <TextField
        fullWidth
        size="small"
        placeholder="Search users by name or username..."
        value={searchQuery}
        onChange={(e) => setSearchQuery(e.target.value)}
        InputProps={{
          startAdornment: (
            <InputAdornment position="start">
              <SearchIcon color="action" />
            </InputAdornment>
          ),
        }}
        sx={{ mb: 2 }}
      />

      {selectedUsername && (
        <Alert 
          severity="success" 
          sx={{ mb: 2 }}
          icon={<CheckCircleIcon />}
        >
          Selected: <strong>{selectedUsername}</strong>
        </Alert>
      )}

      <Paper 
        variant="outlined" 
        sx={{ 
          maxHeight: 280, 
          overflow: "auto",
          bgcolor: alpha(theme.palette.background.default, 0.5),
        }}
      >
        {loading ? (
          <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
            <CircularProgress size={28} />
          </Box>
        ) : error ? (
          <Alert severity="error" sx={{ m: 2 }}>{error}</Alert>
        ) : availableUsers.length === 0 ? (
          <Box sx={{ p: 3, textAlign: "center" }}>
            <Typography color="text.secondary">
              {searchQuery ? "No users found matching your search" : "No available users to add"}
            </Typography>
          </Box>
        ) : (
          <List dense disablePadding>
            {availableUsers.map((user, index) => {
              const isSelected = selectedUsername === user.username;
              return (
                <Box key={user.id}>
                  {index > 0 && <Divider />}
                  <ListItemButton
                    selected={isSelected}
                    onClick={() => onSelectUser(user.username)}
                    sx={{
                      py: 1.5,
                      "&.Mui-selected": {
                        bgcolor: alpha(theme.palette.primary.main, 0.12),
                        "&:hover": {
                          bgcolor: alpha(theme.palette.primary.main, 0.18),
                        },
                      },
                    }}
                  >
                    <ListItemAvatar>
                      <Avatar
                        sx={{
                          width: 36,
                          height: 36,
                          bgcolor: isSelected 
                            ? theme.palette.primary.main 
                            : alpha(theme.palette.primary.main, 0.2),
                          color: isSelected 
                            ? theme.palette.primary.contrastText 
                            : theme.palette.primary.main,
                          fontSize: "0.9rem",
                          fontWeight: 600,
                        }}
                      >
                        {user.username[0].toUpperCase()}
                      </Avatar>
                    </ListItemAvatar>
                    <ListItemText
                      primary={
                        <Stack direction="row" alignItems="center" spacing={1}>
                          <Typography variant="body2" fontWeight={600}>
                            {user.username}
                          </Typography>
                          {isSelected && (
                            <CheckCircleIcon 
                              fontSize="small" 
                              color="primary" 
                            />
                          )}
                        </Stack>
                      }
                      secondary={
                        user.first_name || user.last_name
                          ? `${user.first_name || ""} ${user.last_name || ""}`.trim()
                          : user.bio || "Platform user"
                      }
                    />
                    {user.is_friend && (
                      <Chip 
                        label="Friend" 
                        size="small" 
                        color="success" 
                        variant="outlined"
                        sx={{ fontSize: "0.7rem" }}
                      />
                    )}
                  </ListItemButton>
                </Box>
              );
            })}
          </List>
        )}
      </Paper>

      <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
        {availableUsers.length} user{availableUsers.length !== 1 ? "s" : ""} available
        {existingCollaborators.length > 0 && ` (${existingCollaborators.length} already added)`}
      </Typography>
    </Box>
  );
}

interface ProjectCollaboratorsTabProps {
  projectId: number;
  isOwner: boolean;
  userRole?: "owner" | "editor" | "viewer" | "admin";
}

export default function ProjectCollaboratorsTab({ projectId, isOwner, userRole }: ProjectCollaboratorsTabProps) {
  const theme = useTheme();
  const queryClient = useQueryClient();
  
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newRole, setNewRole] = useState<"viewer" | "editor" | "admin">("editor");
  
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [editingCollaborator, setEditingCollaborator] = useState<ProjectCollaborator | null>(null);
  const [editRole, setEditRole] = useState<"viewer" | "editor" | "admin">("editor");
  
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deletingCollaborator, setDeletingCollaborator] = useState<ProjectCollaborator | null>(null);

  const canManageCollaborators = isOwner || userRole === "admin";

  const collaboratorsQuery = useQuery({
    queryKey: ["project-collaborators", projectId],
    queryFn: () => api.getProjectCollaborators(projectId),
    enabled: !!projectId,
  });

  const addMutation = useMutation({
    mutationFn: () => api.addProjectCollaborator(projectId, newUsername, newRole),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project-collaborators", projectId] });
      queryClient.invalidateQueries({ queryKey: ["project", projectId] });
      setAddDialogOpen(false);
      setNewUsername("");
      setNewRole("editor");
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ userId, role }: { userId: number; role: string }) => 
      api.updateProjectCollaborator(projectId, userId, role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project-collaborators", projectId] });
      setEditDialogOpen(false);
      setEditingCollaborator(null);
    },
  });

  const removeMutation = useMutation({
    mutationFn: (userId: number) => api.removeProjectCollaborator(projectId, userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project-collaborators", projectId] });
      queryClient.invalidateQueries({ queryKey: ["project", projectId] });
      setDeleteDialogOpen(false);
      setDeletingCollaborator(null);
    },
  });

  const handleEditClick = (collaborator: ProjectCollaborator) => {
    setEditingCollaborator(collaborator);
    setEditRole(collaborator.role);
    setEditDialogOpen(true);
  };

  const handleDeleteClick = (collaborator: ProjectCollaborator) => {
    setDeletingCollaborator(collaborator);
    setDeleteDialogOpen(true);
  };

  return (
    <Box>
      {/* Header */}
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 3 }}>
        <Stack direction="row" alignItems="center" spacing={2}>
          <Box
            sx={{
              width: 48,
              height: 48,
              borderRadius: 2,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.2)} 0%, ${alpha(theme.palette.secondary.main, 0.2)} 100%)`,
              color: theme.palette.primary.main,
            }}
          >
            <PeopleIcon />
          </Box>
          <Box>
            <Typography variant="h5" fontWeight={700}>
              Project Collaborators
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {collaboratorsQuery.data?.length || 0} collaborator{(collaboratorsQuery.data?.length || 0) !== 1 ? "s" : ""} on this project
            </Typography>
          </Box>
        </Stack>

        {canManageCollaborators && (
          <Button
            variant="contained"
            startIcon={<PersonAddIcon />}
            onClick={() => setAddDialogOpen(true)}
            sx={{
              background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
              color: "#fff",
              fontWeight: 600,
              "&:hover": {
                background: `linear-gradient(135deg, ${theme.palette.primary.light} 0%, ${theme.palette.secondary.light} 100%)`,
              },
            }}
          >
            Add Collaborator
          </Button>
        )}
      </Stack>

      {/* Loading */}
      {collaboratorsQuery.isLoading && (
        <Paper sx={{ p: 3 }}>
          <Skeleton variant="rectangular" height={200} />
        </Paper>
      )}

      {/* Error */}
      {collaboratorsQuery.isError && (
        <Alert severity="error">{(collaboratorsQuery.error as Error).message}</Alert>
      )}

      {/* Empty State */}
      {collaboratorsQuery.data && collaboratorsQuery.data.length === 0 && (
        <Paper
          sx={{
            p: 6,
            textAlign: "center",
            background: `linear-gradient(135deg, ${alpha(theme.palette.info.main, 0.05)} 0%, ${alpha(theme.palette.primary.main, 0.03)} 100%)`,
            border: `2px dashed ${alpha(theme.palette.info.main, 0.3)}`,
            borderRadius: 3,
          }}
        >
          <Box
            sx={{
              width: 80,
              height: 80,
              borderRadius: "50%",
              bgcolor: alpha(theme.palette.info.main, 0.1),
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              mx: "auto",
              mb: 3,
              color: theme.palette.info.main,
            }}
          >
            <PeopleIcon />
          </Box>
          <Typography variant="h6" gutterBottom fontWeight={600}>
            No collaborators yet
          </Typography>
          <Typography color="text.secondary" sx={{ maxWidth: 400, mx: "auto", mb: 3 }}>
            Add team members to collaborate on this shared project. They'll be able to view and edit based on their role.
          </Typography>
          {canManageCollaborators && (
            <Button
              variant="contained"
              startIcon={<PersonAddIcon />}
              onClick={() => setAddDialogOpen(true)}
              sx={{
                background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                color: "#fff",
                fontWeight: 600,
              }}
            >
              Add First Collaborator
            </Button>
          )}
        </Paper>
      )}

      {/* Collaborators Table */}
      {collaboratorsQuery.data && collaboratorsQuery.data.length > 0 && (
        <TableContainer
          component={Paper}
          sx={{
            background: `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.9)} 0%, ${alpha(theme.palette.background.paper, 0.7)} 100%)`,
            backdropFilter: "blur(20px)",
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            borderRadius: 3,
            overflow: "hidden",
          }}
        >
          <Table>
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700, fontSize: "0.85rem" }}>User</TableCell>
                <TableCell sx={{ fontWeight: 700, fontSize: "0.85rem" }}>Role</TableCell>
                <TableCell sx={{ fontWeight: 700, fontSize: "0.85rem" }}>Added</TableCell>
                {canManageCollaborators && (
                  <TableCell align="right" sx={{ fontWeight: 700, fontSize: "0.85rem" }}>Actions</TableCell>
                )}
              </TableRow>
            </TableHead>
            <TableBody>
              {collaboratorsQuery.data.map((collaborator, index) => (
                <TableRow
                  key={collaborator.id}
                  sx={{
                    transition: "all 0.2s ease",
                    "&:hover": {
                      bgcolor: alpha(theme.palette.primary.main, 0.05),
                    },
                    animation: `fadeIn 0.3s ease ${index * 0.05}s both`,
                    "@keyframes fadeIn": {
                      from: { opacity: 0, transform: "translateY(10px)" },
                      to: { opacity: 1, transform: "translateY(0)" },
                    },
                  }}
                >
                  <TableCell>
                    <Stack direction="row" alignItems="center" spacing={2}>
                      <Box
                        sx={{
                          width: 36,
                          height: 36,
                          borderRadius: "50%",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.2)} 0%, ${alpha(theme.palette.secondary.main, 0.2)} 100%)`,
                          color: theme.palette.primary.main,
                          fontWeight: 700,
                          fontSize: "0.9rem",
                        }}
                      >
                        {(collaborator.username || collaborator.email || "U")[0].toUpperCase()}
                      </Box>
                      <Box>
                        <Typography variant="body2" fontWeight={600}>
                          {collaborator.username || "Unknown User"}
                        </Typography>
                        {collaborator.email && (
                          <Typography variant="caption" color="text.secondary">
                            {collaborator.email}
                          </Typography>
                        )}
                      </Box>
                    </Stack>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={collaborator.role.charAt(0).toUpperCase() + collaborator.role.slice(1)}
                      size="small"
                      sx={{
                        bgcolor: getRoleColor(collaborator.role, theme).bg,
                        color: getRoleColor(collaborator.role, theme).text,
                        fontWeight: 600,
                        fontSize: "0.75rem",
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">
                      {new Date(collaborator.added_at).toLocaleDateString()}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {new Date(collaborator.added_at).toLocaleTimeString()}
                    </Typography>
                  </TableCell>
                  {canManageCollaborators && (
                    <TableCell align="right">
                      <Stack direction="row" spacing={0.5} justifyContent="flex-end">
                        <Tooltip title="Edit role">
                          <IconButton
                            size="small"
                            onClick={() => handleEditClick(collaborator)}
                            sx={{
                              color: "text.secondary",
                              "&:hover": {
                                color: theme.palette.primary.main,
                                bgcolor: alpha(theme.palette.primary.main, 0.1),
                              },
                            }}
                          >
                            <EditIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Remove collaborator">
                          <IconButton
                            size="small"
                            onClick={() => handleDeleteClick(collaborator)}
                            sx={{
                              color: "text.secondary",
                              "&:hover": {
                                color: theme.palette.error.main,
                                bgcolor: alpha(theme.palette.error.main, 0.1),
                              },
                            }}
                          >
                            <DeleteIcon />
                          </IconButton>
                        </Tooltip>
                      </Stack>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Role explanation card */}
      <Card
        sx={{
          mt: 3,
          background: alpha(theme.palette.background.paper, 0.5),
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
        }}
      >
        <CardContent>
          <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 2 }}>
            Role Permissions
          </Typography>
          <Stack spacing={1}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <Chip
                label="Viewer"
                size="small"
                sx={{
                  bgcolor: getRoleColor("viewer", theme).bg,
                  color: getRoleColor("viewer", theme).text,
                  fontWeight: 600,
                  minWidth: 70,
                }}
              />
              <Typography variant="body2" color="text.secondary">
                Can view the project, reports, and findings
              </Typography>
            </Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <Chip
                label="Editor"
                size="small"
                sx={{
                  bgcolor: getRoleColor("editor", theme).bg,
                  color: getRoleColor("editor", theme).text,
                  fontWeight: 600,
                  minWidth: 70,
                }}
              />
              <Typography variant="body2" color="text.secondary">
                Can edit, upload code, run scans, and modify project settings
              </Typography>
            </Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <Chip
                label="Admin"
                size="small"
                sx={{
                  bgcolor: getRoleColor("admin", theme).bg,
                  color: getRoleColor("admin", theme).text,
                  fontWeight: 600,
                  minWidth: 70,
                }}
              />
              <Typography variant="body2" color="text.secondary">
                Full access including managing collaborators
              </Typography>
            </Box>
          </Stack>
        </CardContent>
      </Card>

      {/* Add Collaborator Dialog with User Discovery */}
      <Dialog open={addDialogOpen} onClose={() => setAddDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Add Collaborator</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ mb: 2 }}>
            Search for a user or select from platform users to add as a collaborator.
          </DialogContentText>
          <UserDiscoverySelector
            selectedUsername={newUsername}
            onSelectUser={(username) => setNewUsername(username)}
            existingCollaborators={collaboratorsQuery.data?.map(c => c.username).filter((u): u is string => !!u) || []}
          />
          <FormControl fullWidth sx={{ mt: 3 }}>
            <InputLabel>Role</InputLabel>
            <Select
              value={newRole}
              label="Role"
              onChange={(e) => setNewRole(e.target.value as "viewer" | "editor" | "admin")}
            >
              <MenuItem value="viewer">Viewer - Can view only</MenuItem>
              <MenuItem value="editor">Editor - Can edit and run scans</MenuItem>
              <MenuItem value="admin">Admin - Full access including managing collaborators</MenuItem>
            </Select>
          </FormControl>
          {addMutation.isError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {(addMutation.error as Error).message}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAddDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={() => addMutation.mutate()}
            disabled={!newUsername.trim() || addMutation.isPending}
          >
            {addMutation.isPending ? "Adding..." : "Add Collaborator"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit Role Dialog */}
      <Dialog open={editDialogOpen} onClose={() => setEditDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Change Collaborator Role</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ mb: 3 }}>
            Update the role for <strong>{editingCollaborator?.username}</strong>
          </DialogContentText>
          <FormControl fullWidth sx={{ mt: 1 }}>
            <InputLabel>Role</InputLabel>
            <Select
              value={editRole}
              label="Role"
              onChange={(e) => setEditRole(e.target.value as "viewer" | "editor" | "admin")}
            >
              <MenuItem value="viewer">Viewer - Can view only</MenuItem>
              <MenuItem value="editor">Editor - Can edit and run scans</MenuItem>
              <MenuItem value="admin">Admin - Full access including managing collaborators</MenuItem>
            </Select>
          </FormControl>
          {updateMutation.isError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {(updateMutation.error as Error).message}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={() => {
              if (editingCollaborator) {
                updateMutation.mutate({ userId: editingCollaborator.user_id, role: editRole });
              }
            }}
            disabled={updateMutation.isPending}
          >
            {updateMutation.isPending ? "Updating..." : "Update Role"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>Remove Collaborator</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to remove <strong>{deletingCollaborator?.username}</strong> from this project?
            They will no longer have access to view or edit this project.
          </DialogContentText>
          {removeMutation.isError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {(removeMutation.error as Error).message}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            color="error"
            onClick={() => {
              if (deletingCollaborator) {
                removeMutation.mutate(deletingCollaborator.user_id);
              }
            }}
            disabled={removeMutation.isPending}
          >
            {removeMutation.isPending ? "Removing..." : "Remove"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
