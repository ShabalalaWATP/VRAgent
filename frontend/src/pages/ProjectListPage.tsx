import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Grid,
  IconButton,
  Paper,
  Skeleton,
  Stack,
  Tooltip,
  Typography,
  alpha,
  useTheme,
  keyframes,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import NewProjectForm from "../components/NewProjectForm";
import { api } from "../api/client";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import HubIcon from "@mui/icons-material/Hub";

// Animations
const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-8px); }
`;

const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

const pulse = keyframes`
  0%, 100% { transform: scale(1); opacity: 1; }
  50% { transform: scale(1.05); opacity: 0.9; }
`;

// Icons
const AddIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z" />
  </svg>
);

const FolderIcon = () => (
  <svg width="32" height="32" viewBox="0 0 24 24" fill="currentColor">
    <path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z" />
  </svg>
);

const ArrowRightIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z" />
  </svg>
);

const ShieldIcon = () => (
  <svg width="48" height="48" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z" />
  </svg>
);

const RocketIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 2.5c2 0 6.5 1 6.5 5 0 3.5-2.5 7-4.5 9.5V21h-4v-4c-2-2.5-4.5-6-4.5-9.5 0-4 4.5-5 6.5-5zm0 5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3z"/>
    <path d="M5 16c-1.5 0-3 1.5-3 3.5 0 2 1.5 3 3 2.5 1-.3 1.5-1 2-2.5-.5-2-2.5-3.5-2-3.5zM19 16c1.5 0 3 1.5 3 3.5 0 2-1.5 3-3 2.5-1-.3-1.5-1-2-2.5.5-2 2.5-3.5 2-3.5z"/>
  </svg>
);

const DeleteIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z" />
  </svg>
);

const WarningIcon = () => (
  <svg width="48" height="48" viewBox="0 0 24 24" fill="currentColor">
    <path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z" />
  </svg>
);

export default function ProjectListPage() {
  const [open, setOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [projectToDelete, setProjectToDelete] = useState<{ id: number; name: string } | null>(null);
  const theme = useTheme();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["projects"],
    queryFn: api.getProjects,
  });

  const deleteMutation = useMutation({
    mutationFn: (projectId: number) => api.deleteProject(projectId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["projects"] });
      setDeleteDialogOpen(false);
      setProjectToDelete(null);
    },
  });

  const handleDeleteClick = (project: { id: number; name: string }, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setProjectToDelete(project);
    setDeleteDialogOpen(true);
  };

  const handleConfirmDelete = () => {
    if (projectToDelete) {
      deleteMutation.mutate(projectToDelete.id);
    }
  };

  return (
    <Box>
      {/* Hero Header Section */}
      <Box
        sx={{
          position: "relative",
          mb: 5,
          p: 4,
          borderRadius: 4,
          overflow: "hidden",
          background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.secondary.main, 0.1)} 100%)`,
          backdropFilter: "blur(20px)",
          border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
        }}
      >
        {/* Floating background elements */}
        <Box
          sx={{
            position: "absolute",
            top: 0,
            right: 0,
            bottom: 0,
            width: "50%",
            overflow: "hidden",
            opacity: 0.4,
            pointerEvents: "none",
          }}
        >
          {[...Array(6)].map((_, i) => (
            <Box
              key={i}
              sx={{
                position: "absolute",
                width: 40 + i * 20,
                height: 40 + i * 20,
                borderRadius: "50%",
                background: `radial-gradient(circle, ${alpha(theme.palette.primary.main, 0.2)} 0%, transparent 70%)`,
                right: `${5 + i * 12}%`,
                top: `${10 + (i % 4) * 20}%`,
                animation: `${float} ${3 + i * 0.5}s ease-in-out infinite`,
                animationDelay: `${i * 0.3}s`,
              }}
            />
          ))}
        </Box>

        <Stack 
          direction={{ xs: "column", md: "row" }} 
          justifyContent="space-between" 
          alignItems={{ xs: "flex-start", md: "center" }}
          spacing={3}
          sx={{ position: "relative", zIndex: 1 }}
        >
          <Box>
            <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 1 }}>
              <Box
                sx={{
                  width: 56,
                  height: 56,
                  borderRadius: 3,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                  color: "#fff",
                  animation: `${float} 4s ease-in-out infinite`,
                }}
              >
                <ShieldIcon />
              </Box>
              <Box>
                <Typography 
                  variant="h3" 
                  fontWeight={800}
                  sx={{
                    background: `linear-gradient(135deg, ${theme.palette.text.primary} 0%, ${alpha(theme.palette.text.primary, 0.7)} 100%)`,
                    backgroundClip: "text",
                    WebkitBackgroundClip: "text",
                    letterSpacing: "-0.02em",
                  }}
                >
                  Projects
                </Typography>
              </Box>
            </Stack>
            <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 500, mb: 2 }}>
              Manage your codebases and run AI-powered vulnerability scans to detect security issues before they become problems.
            </Typography>
            
            {/* Quick Learn Access */}
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              <Chip
                icon={<HubIcon sx={{ fontSize: 18 }} />}
                label="Network Analysis - Analyze PCAP & Nmap scans →"
                clickable
                onClick={() => navigate("/network")}
                sx={{
                  background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.15)}, ${alpha("#0891b2", 0.1)})`,
                  border: `1px solid ${alpha("#06b6d4", 0.3)}`,
                  color: "#22d3ee",
                  fontWeight: 500,
                  fontSize: "0.8rem",
                  py: 2.5,
                  px: 1,
                  "&:hover": {
                    background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.25)}, ${alpha("#0891b2", 0.2)})`,
                    boxShadow: `0 4px 20px ${alpha("#06b6d4", 0.3)}`,
                  },
                }}
              />
              <Chip
                icon={<MenuBookIcon sx={{ fontSize: 18 }} />}
                label="New to security scanning? Visit the Learning Hub →"
                clickable
                onClick={() => navigate("/learn")}
                sx={{
                  background: `linear-gradient(135deg, ${alpha("#6366f1", 0.15)}, ${alpha("#8b5cf6", 0.1)})`,
                  border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
                  color: "#a78bfa",
                  fontWeight: 500,
                  fontSize: "0.8rem",
                  py: 2.5,
                  px: 1,
                  "&:hover": {
                    background: `linear-gradient(135deg, ${alpha("#6366f1", 0.25)}, ${alpha("#8b5cf6", 0.2)})`,
                    boxShadow: `0 4px 20px ${alpha("#8b5cf6", 0.3)}`,
                  },
                }}
              />
            </Box>
          </Box>
          
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setOpen(true)}
            sx={{
              px: 4,
              py: 1.75,
              fontSize: "1rem",
              fontWeight: 600,
              borderRadius: 3,
              background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
              boxShadow: `0 4px 20px ${alpha(theme.palette.primary.main, 0.4)}`,
              transition: "all 0.3s ease",
              "&:hover": {
                background: `linear-gradient(135deg, ${theme.palette.primary.light} 0%, ${theme.palette.secondary.light} 100%)`,
                boxShadow: `0 6px 30px ${alpha(theme.palette.primary.main, 0.5)}`,
                transform: "translateY(-3px)",
              },
              "&:active": {
                transform: "translateY(0)",
              },
            }}
          >
            New Project
          </Button>
        </Stack>
      </Box>

      {/* Loading State */}
      {isLoading && (
        <Grid container spacing={3}>
          {[1, 2, 3].map((i) => (
            <Grid item xs={12} sm={6} md={4} key={i}>
              <Card
                sx={{
                  background: `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.9)} 0%, ${alpha(theme.palette.background.paper, 0.7)} 100%)`,
                  backdropFilter: "blur(20px)",
                }}
              >
                <CardContent>
                  <Skeleton variant="circular" width={48} height={48} sx={{ mb: 2 }} />
                  <Skeleton variant="text" width="60%" height={28} />
                  <Skeleton variant="text" width="80%" />
                  <Skeleton variant="text" width="40%" sx={{ mt: 2 }} />
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Error State */}
      {isError && (
        <Paper
          sx={{
            p: 4,
            textAlign: "center",
            background: alpha(theme.palette.error.main, 0.1),
            border: `1px solid ${alpha(theme.palette.error.main, 0.3)}`,
            borderRadius: 3,
          }}
        >
          <Typography color="error" fontWeight={500}>
            {(error as Error).message}
          </Typography>
        </Paper>
      )}

      {/* Empty State */}
      {data && data.length === 0 && (
        <Paper
          sx={{
            p: 8,
            textAlign: "center",
            background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.05)} 0%, ${alpha(theme.palette.secondary.main, 0.03)} 100%)`,
            border: `2px dashed ${alpha(theme.palette.primary.main, 0.3)}`,
            borderRadius: 4,
          }}
        >
          <Box
            sx={{
              width: 100,
              height: 100,
              borderRadius: "50%",
              bgcolor: alpha(theme.palette.primary.main, 0.1),
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              mx: "auto",
              mb: 4,
              color: "primary.main",
              animation: `${pulse} 3s ease-in-out infinite`,
            }}
          >
            <RocketIcon />
          </Box>
          <Typography variant="h5" fontWeight={700} gutterBottom>
            Ready to launch? 🚀
          </Typography>
          <Typography color="text.secondary" sx={{ mb: 3, maxWidth: 400, mx: "auto" }}>
            Create your first project to start scanning for vulnerabilities and secure your codebase.
          </Typography>
          <Stack direction="row" spacing={2} justifyContent="center" flexWrap="wrap">
          <Button 
            variant="contained" 
            startIcon={<AddIcon />} 
            onClick={() => setOpen(true)}
            sx={{
              px: 4,
              py: 1.5,
              background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
              boxShadow: `0 4px 20px ${alpha(theme.palette.primary.main, 0.4)}`,
              "&:hover": {
                boxShadow: `0 6px 30px ${alpha(theme.palette.primary.main, 0.5)}`,
              },
            }}
          >
            Create First Project
          </Button>
          <Button
            variant="outlined"
            startIcon={<MenuBookIcon />}
            onClick={() => navigate("/learn")}
            sx={{
              px: 3,
              py: 1.5,
              borderColor: alpha("#8b5cf6", 0.5),
              color: "#a78bfa",
              "&:hover": {
                borderColor: "#8b5cf6",
                bgcolor: alpha("#8b5cf6", 0.1),
              },
            }}
          >
            Learn First
          </Button>
          </Stack>
        </Paper>
      )}

      {/* Projects Grid */}
      {data && data.length > 0 && (
        <Grid container spacing={3}>
          {data.map((project, index) => (
            <Grid item xs={12} sm={6} md={4} key={project.id}>
              <Card
                sx={{
                  height: "100%",
                  display: "flex",
                  flexDirection: "column",
                  position: "relative",
                  overflow: "hidden",
                  background: `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.9)} 0%, ${alpha(theme.palette.background.paper, 0.7)} 100%)`,
                  backdropFilter: "blur(20px)",
                  border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                  transition: "all 0.4s cubic-bezier(0.4, 0, 0.2, 1)",
                  animation: `fadeIn 0.4s ease ${index * 0.1}s both`,
                  "@keyframes fadeIn": {
                    from: { opacity: 0, transform: "translateY(20px)" },
                    to: { opacity: 1, transform: "translateY(0)" },
                  },
                  "&:hover": {
                    transform: "translateY(-8px)",
                    border: `1px solid ${alpha(theme.palette.primary.main, 0.3)}`,
                    boxShadow: `0 20px 40px ${alpha(theme.palette.primary.main, 0.2)}`,
                    "& .project-icon": {
                      animation: `${float} 2s ease-in-out infinite`,
                      background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                      color: "#fff",
                    },
                    "& .view-btn": {
                      background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                      color: "#fff",
                      borderColor: "transparent",
                    },
                  },
                  "&::before": {
                    content: '""',
                    position: "absolute",
                    top: 0,
                    left: 0,
                    right: 0,
                    height: 3,
                    background: `linear-gradient(90deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
                    opacity: 0,
                    transition: "opacity 0.3s ease",
                  },
                  "&:hover::before": {
                    opacity: 1,
                  },
                }}
              >
                <CardContent sx={{ flexGrow: 1, p: 3 }}>
                  <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
                    <Box
                      className="project-icon"
                      sx={{
                        width: 56,
                        height: 56,
                        borderRadius: 3,
                        background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.15)} 0%, ${alpha(theme.palette.secondary.main, 0.15)} 100%)`,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        mb: 2.5,
                        color: "primary.main",
                        transition: "all 0.4s ease",
                      }}
                    >
                      <FolderIcon />
                    </Box>
                    <Tooltip title="Delete project">
                      <IconButton
                        size="small"
                        onClick={(e) => handleDeleteClick({ id: project.id, name: project.name }, e)}
                        sx={{
                          color: alpha(theme.palette.error.main, 0.6),
                          transition: "all 0.2s ease",
                          "&:hover": {
                            color: theme.palette.error.main,
                            background: alpha(theme.palette.error.main, 0.1),
                            transform: "scale(1.1)",
                          },
                        }}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                  </Stack>

                  <Typography variant="h6" fontWeight={700} gutterBottom>
                    {project.name}
                  </Typography>

                  <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{
                      mb: 2.5,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      display: "-webkit-box",
                      WebkitLineClamp: 2,
                      WebkitBoxOrient: "vertical",
                      minHeight: 40,
                    }}
                  >
                    {project.description || "No description"}
                  </Typography>

                  <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" gap={1}>
                    <Chip
                      label={new Date(project.created_at).toLocaleDateString()}
                      size="small"
                      variant="outlined"
                      sx={{ 
                        fontSize: "0.75rem",
                        background: alpha(theme.palette.background.paper, 0.5),
                      }}
                    />
                    {project.git_url && (
                      <Chip
                        label="🔗 Git"
                        size="small"
                        sx={{ 
                          fontSize: "0.75rem",
                          background: alpha(theme.palette.secondary.main, 0.15),
                          color: theme.palette.secondary.main,
                          fontWeight: 600,
                        }}
                      />
                    )}
                  </Stack>
                </CardContent>

                <Box sx={{ p: 3, pt: 0 }}>
                  <Button
                    className="view-btn"
                    component={Link}
                    to={`/projects/${project.id}`}
                    fullWidth
                    variant="outlined"
                    endIcon={<ArrowRightIcon />}
                    sx={{
                      py: 1.25,
                      fontWeight: 600,
                      justifyContent: "space-between",
                      px: 2.5,
                      transition: "all 0.3s ease",
                    }}
                  >
                    Open Project
                  </Button>
                </Box>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Network Analysis Link */}
      <Card
        component={Link}
        to="/network"
        sx={{
          mt: 6,
          textDecoration: "none",
          display: "flex",
          alignItems: "center",
          p: 3,
          background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.08)} 0%, ${alpha("#0891b2", 0.05)} 100%)`,
          border: `1px solid ${alpha("#06b6d4", 0.2)}`,
          borderRadius: 3,
          transition: "all 0.3s ease",
          "&:hover": {
            transform: "translateY(-4px)",
            boxShadow: `0 10px 30px ${alpha("#06b6d4", 0.2)}`,
            border: `1px solid ${alpha("#06b6d4", 0.4)}`,
          },
        }}
      >
        <Box
          sx={{
            width: 56,
            height: 56,
            borderRadius: 2,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: `linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)`,
            color: "#fff",
            mr: 3,
          }}
        >
          <HubIcon sx={{ fontSize: 32 }} />
        </Box>
        <Box sx={{ flex: 1 }}>
          <Typography
            variant="h6"
            fontWeight={700}
            sx={{
              background: `linear-gradient(135deg, #22d3ee 0%, #0891b2 100%)`,
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              mb: 0.5,
            }}
          >
            Network Analysis
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Analyze Wireshark PCAP captures and Nmap scan results with AI-powered security insights
          </Typography>
        </Box>
        <Box sx={{ color: "#22d3ee" }}>
          <ArrowRightIcon />
        </Box>
      </Card>

      {/* Create Project Dialog */}
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        maxWidth="sm"
        fullWidth
        PaperProps={{
          sx: { 
            p: 2,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.95)} 0%, ${alpha(theme.palette.background.paper, 0.9)} 100%)`,
            backdropFilter: "blur(20px)",
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          },
        }}
      >
        <DialogTitle sx={{ pb: 1, px: 3 }}>
          <Stack direction="row" alignItems="center" spacing={2}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                color: "#fff",
              }}
            >
              <AddIcon />
            </Box>
            <Box>
              <Typography variant="h5" fontWeight={700}>
                New Project
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Add a codebase for security analysis
              </Typography>
            </Box>
          </Stack>
        </DialogTitle>
        <DialogContent sx={{ px: 3 }}>
          <NewProjectForm onCreated={() => setOpen(false)} />
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteDialogOpen}
        onClose={() => setDeleteDialogOpen(false)}
        maxWidth="xs"
        fullWidth
        PaperProps={{
          sx: {
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.95)} 0%, ${alpha(theme.palette.background.paper, 0.9)} 100%)`,
            backdropFilter: "blur(20px)",
            border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`,
            overflow: "hidden",
          },
        }}
      >
        <Box
          sx={{
            height: 4,
            background: `linear-gradient(90deg, ${theme.palette.error.main}, ${theme.palette.error.dark})`,
          }}
        />
        <DialogTitle sx={{ textAlign: "center", pt: 4, pb: 2 }}>
          <Box
            sx={{
              width: 80,
              height: 80,
              borderRadius: "50%",
              background: alpha(theme.palette.error.main, 0.1),
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              mx: "auto",
              mb: 2,
              color: theme.palette.error.main,
            }}
          >
            <WarningIcon />
          </Box>
          <Typography variant="h5" fontWeight={700}>
            Delete Project?
          </Typography>
        </DialogTitle>
        <DialogContent sx={{ textAlign: "center", pb: 2 }}>
          <Typography color="text.secondary">
            Are you sure you want to delete{" "}
            <Box component="span" sx={{ fontWeight: 700, color: "text.primary" }}>
              {projectToDelete?.name}
            </Box>
            ? This will permanently remove the project and all associated scans, reports, and findings.
          </Typography>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 3, gap: 2, justifyContent: "center" }}>
          <Button
            variant="outlined"
            onClick={() => setDeleteDialogOpen(false)}
            sx={{
              px: 4,
              py: 1.25,
              fontWeight: 600,
              borderRadius: 2,
            }}
          >
            Cancel
          </Button>
          <Button
            variant="contained"
            color="error"
            onClick={handleConfirmDelete}
            disabled={deleteMutation.isPending}
            sx={{
              px: 4,
              py: 1.25,
              fontWeight: 600,
              borderRadius: 2,
              boxShadow: `0 4px 20px ${alpha(theme.palette.error.main, 0.4)}`,
              "&:hover": {
                boxShadow: `0 6px 30px ${alpha(theme.palette.error.main, 0.5)}`,
              },
            }}
          >
            {deleteMutation.isPending ? "Deleting..." : "Delete Project"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
