import React, { useState } from "react";
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  Grid,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Tab,
  Tabs,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
  alpha,
  useTheme,
  Alert,
  Tooltip,
  Collapse,
} from "@mui/material";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import {
  apiClient,
  FindingWithNotes,
  NoteType,
  ProjectNotesSummary,
  ProjectNote,
  ProjectNoteType,
  ProjectNoteCreate,
} from "../api/client";
import { FindingNotesPanel } from "./FindingNotesPanel";
import RefreshIcon from "@mui/icons-material/Refresh";
import CommentIcon from "@mui/icons-material/Comment";
import BuildIcon from "@mui/icons-material/Build";
import WarningIcon from "@mui/icons-material/Warning";
import BlockIcon from "@mui/icons-material/Block";
import HourglassBottomIcon from "@mui/icons-material/HourglassBottom";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import AddIcon from "@mui/icons-material/Add";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";
import NoteIcon from "@mui/icons-material/Note";
import ChecklistIcon from "@mui/icons-material/Checklist";
import PriorityHighIcon from "@mui/icons-material/PriorityHigh";
import BookmarkIcon from "@mui/icons-material/Bookmark";

const FINDING_NOTE_TYPE_CONFIG: Record<NoteType, { label: string; color: string; icon: React.ReactNode }> = {
  comment: { label: "Comments", color: "#6366f1", icon: <CommentIcon /> },
  remediation: { label: "Remediation", color: "#10b981", icon: <BuildIcon /> },
  false_positive: { label: "False Positives", color: "#f59e0b", icon: <WarningIcon /> },
  accepted_risk: { label: "Accepted Risks", color: "#ef4444", icon: <BlockIcon /> },
  in_progress: { label: "In Progress", color: "#3b82f6", icon: <HourglassBottomIcon /> },
};

const PROJECT_NOTE_TYPE_CONFIG: Record<ProjectNoteType, { label: string; color: string; icon: React.ReactNode }> = {
  general: { label: "General", color: "#6366f1", icon: <NoteIcon /> },
  todo: { label: "To-Do", color: "#3b82f6", icon: <ChecklistIcon /> },
  important: { label: "Important", color: "#ef4444", icon: <PriorityHighIcon /> },
  reference: { label: "Reference", color: "#10b981", icon: <BookmarkIcon /> },
};

interface ProjectNotesTabProps {
  projectId: number;
}

const ProjectNotesTab: React.FC<ProjectNotesTabProps> = ({ projectId }) => {
  const theme = useTheme();
  const queryClient = useQueryClient();
  
  // Tab state
  const [activeTab, setActiveTab] = useState<"general" | "findings">("general");
  
  // Finding notes filters
  const [noteTypeFilter, setNoteTypeFilter] = useState<NoteType | "all">("all");
  const [hasNotesFilter, setHasNotesFilter] = useState<boolean | undefined>(true);
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);
  
  // Project notes state
  const [projectNoteTypeFilter, setProjectNoteTypeFilter] = useState<ProjectNoteType | "all">("all");
  const [addNoteDialog, setAddNoteDialog] = useState(false);
  const [editingNote, setEditingNote] = useState<ProjectNote | null>(null);
  const [newNote, setNewNote] = useState<ProjectNoteCreate>({
    title: "",
    content: "",
    note_type: "general",
  });

  // Fetch finding notes summary
  const summaryQuery = useQuery({
    queryKey: ["project-notes-summary", projectId],
    queryFn: () => apiClient.getProjectNotesSummary(projectId),
  });

  // Fetch findings with notes
  const findingsQuery = useQuery({
    queryKey: ["project-findings-with-notes", projectId, noteTypeFilter, hasNotesFilter],
    queryFn: () =>
      apiClient.getProjectFindingsWithNotes(
        projectId,
        hasNotesFilter,
        noteTypeFilter === "all" ? undefined : noteTypeFilter
      ),
    enabled: activeTab === "findings",
  });

  // Fetch general project notes
  const projectNotesQuery = useQuery({
    queryKey: ["project-general-notes", projectId, projectNoteTypeFilter],
    queryFn: () =>
      apiClient.getProjectGeneralNotes(
        projectId,
        projectNoteTypeFilter === "all" ? undefined : projectNoteTypeFilter
      ),
    enabled: activeTab === "general",
  });

  // Create project note mutation
  const createNoteMutation = useMutation({
    mutationFn: (note: ProjectNoteCreate) => apiClient.createProjectNote(projectId, note),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project-general-notes", projectId] });
      setAddNoteDialog(false);
      setNewNote({ title: "", content: "", note_type: "general" });
    },
  });

  // Update project note mutation
  const updateNoteMutation = useMutation({
    mutationFn: ({ noteId, note }: { noteId: number; note: ProjectNoteCreate }) =>
      apiClient.updateProjectNote(noteId, note),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project-general-notes", projectId] });
      setEditingNote(null);
    },
  });

  // Delete project note mutation
  const deleteNoteMutation = useMutation({
    mutationFn: (noteId: number) => apiClient.deleteProjectNote(noteId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project-general-notes", projectId] });
    },
  });

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case "critical": return "#dc2626";
      case "high": return "#ea580c";
      case "medium": return "#ca8a04";
      case "low": return "#16a34a";
      default: return "#6b7280";
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const handleSaveNote = () => {
    if (editingNote) {
      updateNoteMutation.mutate({
        noteId: editingNote.id,
        note: newNote,
      });
    } else {
      createNoteMutation.mutate(newNote);
    }
  };

  const handleEditNote = (note: ProjectNote) => {
    setEditingNote(note);
    setNewNote({
      title: note.title || "",
      content: note.content,
      note_type: note.note_type,
    });
    setAddNoteDialog(true);
  };

  const handleCloseDialog = () => {
    setAddNoteDialog(false);
    setEditingNote(null);
    setNewNote({ title: "", content: "", note_type: "general" });
  };

  return (
    <Box>
      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={activeTab}
          onChange={(_, v) => setActiveTab(v)}
          sx={{ borderBottom: 1, borderColor: "divider" }}
        >
          <Tab
            value="general"
            label="Project Notes"
            icon={<NoteIcon />}
            iconPosition="start"
          />
          <Tab
            value="findings"
            label="Finding Notes"
            icon={<CommentIcon />}
            iconPosition="start"
          />
        </Tabs>
      </Paper>

      {activeTab === "general" && (
        <Box>
          {/* Header with Add Button */}
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
            <Typography variant="h6" fontWeight={600}>
              Project Notes
            </Typography>
            <Box sx={{ display: "flex", gap: 2 }}>
              <FormControl size="small" sx={{ minWidth: 150 }}>
                <InputLabel>Type</InputLabel>
                <Select
                  value={projectNoteTypeFilter}
                  label="Type"
                  onChange={(e) => setProjectNoteTypeFilter(e.target.value as ProjectNoteType | "all")}
                >
                  <MenuItem value="all">All Types</MenuItem>
                  {Object.entries(PROJECT_NOTE_TYPE_CONFIG).map(([type, config]) => (
                    <MenuItem key={type} value={type}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Box sx={{ color: config.color }}>{config.icon}</Box>
                        {config.label}
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={() => setAddNoteDialog(true)}
              >
                Add Note
              </Button>
            </Box>
          </Box>

          {/* Project Notes List */}
          {projectNotesQuery.isLoading ? (
            <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
              <CircularProgress />
            </Box>
          ) : projectNotesQuery.error ? (
            <Alert severity="error">Failed to load notes: {String(projectNotesQuery.error)}</Alert>
          ) : projectNotesQuery.data?.length === 0 ? (
            <Paper sx={{ p: 4, textAlign: "center" }}>
              <NoteIcon sx={{ fontSize: 48, color: "text.secondary", mb: 2 }} />
              <Typography variant="h6" color="text.secondary" gutterBottom>
                No notes yet
              </Typography>
              <Typography color="text.secondary" sx={{ mb: 2 }}>
                Add general notes about your project, to-do items, or important references.
              </Typography>
              <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setAddNoteDialog(true)}>
                Create your first note
              </Button>
            </Paper>
          ) : (
            <Grid container spacing={2}>
              {projectNotesQuery.data?.map((note) => {
                const config = PROJECT_NOTE_TYPE_CONFIG[note.note_type as ProjectNoteType] || PROJECT_NOTE_TYPE_CONFIG.general;
                return (
                  <Grid item xs={12} md={6} key={note.id}>
                    <Card
                      sx={{
                        height: "100%",
                        border: `1px solid ${alpha(config.color, 0.3)}`,
                        "&:hover": {
                          boxShadow: `0 4px 12px ${alpha(config.color, 0.15)}`,
                        },
                      }}
                    >
                      <CardContent>
                        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <Chip
                              icon={config.icon as React.ReactElement}
                              label={config.label}
                              size="small"
                              sx={{
                                bgcolor: alpha(config.color, 0.1),
                                color: config.color,
                                "& .MuiChip-icon": { color: config.color },
                              }}
                            />
                          </Box>
                          <Box>
                            <Tooltip title="Edit">
                              <IconButton size="small" onClick={() => handleEditNote(note)}>
                                <EditIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Delete">
                              <IconButton
                                size="small"
                                color="error"
                                onClick={() => {
                                  if (confirm("Delete this note?")) {
                                    deleteNoteMutation.mutate(note.id);
                                  }
                                }}
                              >
                                <DeleteIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </Box>
                        {note.title && (
                          <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 1 }}>
                            {note.title}
                          </Typography>
                        )}
                        <Typography
                          variant="body2"
                          sx={{
                            whiteSpace: "pre-wrap",
                            color: "text.secondary",
                            maxHeight: 200,
                            overflow: "auto",
                          }}
                        >
                          {note.content}
                        </Typography>
                        <Typography variant="caption" color="text.disabled" sx={{ display: "block", mt: 2 }}>
                          {formatDate(note.created_at)}
                          {note.updated_at !== note.created_at && ` (edited ${formatDate(note.updated_at)})`}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                );
              })}
            </Grid>
          )}
        </Box>
      )}

      {activeTab === "findings" && (
        <Box>
          {/* Summary Cards */}
          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} md={4}>
              <Card
                sx={{
                  background: `linear-gradient(135deg, ${alpha("#6366f1", 0.1)} 0%, ${alpha("#8b5cf6", 0.05)} 100%)`,
                  border: `1px solid ${alpha("#6366f1", 0.2)}`,
                }}
              >
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <Box
                      sx={{
                        width: 48,
                        height: 48,
                        borderRadius: 2,
                        background: `linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)`,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                    >
                      <CommentIcon sx={{ fontSize: 28, color: "white" }} />
                    </Box>
                    <Box>
                      <Typography variant="h4" fontWeight={700}>
                        {summaryQuery.data?.total_notes ?? "-"}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Finding Notes
                      </Typography>
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={8}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2 }}>
                    Notes by Type
                  </Typography>
                  <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
                    {Object.entries(FINDING_NOTE_TYPE_CONFIG).map(([type, config]) => {
                      const count = summaryQuery.data?.by_type[type] ?? 0;
                      return (
                        <Chip
                          key={type}
                          icon={config.icon as React.ReactElement}
                          label={`${config.label}: ${count}`}
                          sx={{
                            bgcolor: alpha(config.color, 0.1),
                            color: config.color,
                            fontWeight: 600,
                            "& .MuiChip-icon": { color: config.color },
                          }}
                          onClick={() =>
                            setNoteTypeFilter(noteTypeFilter === type ? "all" : (type as NoteType))
                          }
                          variant={noteTypeFilter === type ? "filled" : "outlined"}
                        />
                      );
                    })}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Filters */}
          <Paper sx={{ p: 2, mb: 3 }}>
            <Box sx={{ display: "flex", gap: 2, alignItems: "center", flexWrap: "wrap" }}>
              <FormControl size="small" sx={{ minWidth: 150 }}>
                <InputLabel>Note Type</InputLabel>
                <Select
                  value={noteTypeFilter}
                  label="Note Type"
                  onChange={(e) => setNoteTypeFilter(e.target.value as NoteType | "all")}
                >
                  <MenuItem value="all">All Types</MenuItem>
                  {Object.entries(FINDING_NOTE_TYPE_CONFIG).map(([type, config]) => (
                    <MenuItem key={type} value={type}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Box sx={{ color: config.color }}>{config.icon}</Box>
                        {config.label}
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <FormControl size="small" sx={{ minWidth: 150 }}>
                <InputLabel>Filter</InputLabel>
                <Select
                  value={hasNotesFilter === undefined ? "all" : hasNotesFilter ? "with" : "without"}
                  label="Filter"
                  onChange={(e) => {
                    const val = e.target.value;
                    setHasNotesFilter(val === "all" ? undefined : val === "with");
                  }}
                >
                  <MenuItem value="with">With Notes</MenuItem>
                  <MenuItem value="without">Without Notes</MenuItem>
                  <MenuItem value="all">All Findings</MenuItem>
                </Select>
              </FormControl>

              <Box sx={{ flex: 1 }} />

              <Button
                startIcon={<RefreshIcon />}
                onClick={() => {
                  summaryQuery.refetch();
                  findingsQuery.refetch();
                }}
                disabled={summaryQuery.isLoading || findingsQuery.isLoading}
              >
                Refresh
              </Button>
            </Box>
          </Paper>

          {/* Findings Table */}
          {findingsQuery.isLoading ? (
            <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
              <CircularProgress />
            </Box>
          ) : findingsQuery.error ? (
            <Alert severity="error">Failed to load findings: {String(findingsQuery.error)}</Alert>
          ) : findingsQuery.data?.length === 0 ? (
            <Paper sx={{ p: 4, textAlign: "center" }}>
              <Typography color="text.secondary">
                {hasNotesFilter
                  ? "No findings with notes yet. Add notes to findings in the report view."
                  : "No findings match the current filter."}
              </Typography>
            </Paper>
          ) : (
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700, width: 50 }} />
                    <TableCell sx={{ fontWeight: 700 }}>Severity</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>File</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Summary</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: 100 }}>Notes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {findingsQuery.data?.map((finding) => (
                    <React.Fragment key={finding.id}>
                      <TableRow
                        hover
                        sx={{
                          cursor: "pointer",
                          "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.03) },
                        }}
                        onClick={() =>
                          setExpandedFinding(expandedFinding === finding.id ? null : finding.id)
                        }
                      >
                        <TableCell>
                          <IconButton size="small">
                            {expandedFinding === finding.id ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                          </IconButton>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={finding.severity}
                            size="small"
                            sx={{
                              bgcolor: alpha(getSeverityColor(finding.severity), 0.15),
                              color: getSeverityColor(finding.severity),
                              fontWeight: 600,
                            }}
                          />
                        </TableCell>
                        <TableCell>
                          <Chip label={finding.type} size="small" variant="outlined" />
                        </TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            sx={{
                              fontFamily: "monospace",
                              fontSize: "0.75rem",
                              maxWidth: 200,
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                            }}
                          >
                            {finding.file_path?.split("/").pop() || "—"}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            sx={{
                              maxWidth: 400,
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                            }}
                          >
                            {finding.summary}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            icon={<CommentIcon sx={{ fontSize: 14 }} />}
                            label={finding.notes_count}
                            size="small"
                            sx={{
                              bgcolor: finding.notes_count > 0 ? alpha("#6366f1", 0.1) : "transparent",
                              color: finding.notes_count > 0 ? "#6366f1" : "text.secondary",
                              fontWeight: 600,
                            }}
                          />
                        </TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell colSpan={6} sx={{ py: 0, border: 0 }}>
                          <Collapse in={expandedFinding === finding.id} timeout="auto" unmountOnExit>
                            <Box sx={{ py: 2, px: 3, bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
                              <Grid container spacing={2}>
                                <Grid item xs={12} md={6}>
                                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                                    Finding Details
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                    <strong>File:</strong> {finding.file_path || "—"}
                                  </Typography>
                                  {finding.start_line && (
                                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                      <strong>Line:</strong> {finding.start_line}
                                      {finding.end_line && ` - ${finding.end_line}`}
                                    </Typography>
                                  )}
                                  <Typography variant="body2" sx={{ mt: 1 }}>
                                    {finding.summary}
                                  </Typography>
                                </Grid>
                                <Grid item xs={12} md={6}>
                                  <FindingNotesPanel findingId={finding.id} />
                                </Grid>
                              </Grid>
                            </Box>
                          </Collapse>
                        </TableCell>
                      </TableRow>
                    </React.Fragment>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Box>
      )}

      {/* Add/Edit Note Dialog */}
      <Dialog open={addNoteDialog} onClose={handleCloseDialog} maxWidth="sm" fullWidth>
        <DialogTitle>{editingNote ? "Edit Note" : "Add Project Note"}</DialogTitle>
        <DialogContent>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
            <FormControl fullWidth size="small">
              <InputLabel>Note Type</InputLabel>
              <Select
                value={newNote.note_type}
                label="Note Type"
                onChange={(e) => setNewNote({ ...newNote, note_type: e.target.value as ProjectNoteType })}
              >
                {Object.entries(PROJECT_NOTE_TYPE_CONFIG).map(([type, config]) => (
                  <MenuItem key={type} value={type}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Box sx={{ color: config.color }}>{config.icon}</Box>
                      {config.label}
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <TextField
              label="Title (optional)"
              value={newNote.title}
              onChange={(e) => setNewNote({ ...newNote, title: e.target.value })}
              fullWidth
              size="small"
            />
            <TextField
              label="Content"
              value={newNote.content}
              onChange={(e) => setNewNote({ ...newNote, content: e.target.value })}
              fullWidth
              multiline
              rows={6}
              required
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleSaveNote}
            disabled={!newNote.content.trim() || createNoteMutation.isPending || updateNoteMutation.isPending}
          >
            {editingNote ? "Save Changes" : "Add Note"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ProjectNotesTab;
