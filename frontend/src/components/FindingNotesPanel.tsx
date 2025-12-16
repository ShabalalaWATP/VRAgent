import React, { useState } from "react";
import {
  Box,
  Button,
  Chip,
  Collapse,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  IconButton,
  InputLabel,
  Menu,
  MenuItem,
  Paper,
  Select,
  Stack,
  TextField,
  Tooltip,
  Typography,
  alpha,
  useTheme,
  CircularProgress,
  Alert,
} from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiClient, FindingNote, FindingNoteCreate, NoteType } from "../api/client";

// Icons
import AddCommentIcon from "@mui/icons-material/AddComment";
import CommentIcon from "@mui/icons-material/Comment";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import BuildIcon from "@mui/icons-material/Build";
import BlockIcon from "@mui/icons-material/Block";
import HourglassBottomIcon from "@mui/icons-material/HourglassBottom";

// Note type configuration
const NOTE_TYPE_CONFIG: Record<NoteType, { label: string; color: string; icon: React.ReactNode }> = {
  comment: {
    label: "Comment",
    color: "#6366f1",
    icon: <CommentIcon sx={{ fontSize: 16 }} />,
  },
  remediation: {
    label: "Remediation",
    color: "#10b981",
    icon: <BuildIcon sx={{ fontSize: 16 }} />,
  },
  false_positive: {
    label: "False Positive",
    color: "#f59e0b",
    icon: <WarningIcon sx={{ fontSize: 16 }} />,
  },
  accepted_risk: {
    label: "Accepted Risk",
    color: "#ef4444",
    icon: <BlockIcon sx={{ fontSize: 16 }} />,
  },
  in_progress: {
    label: "In Progress",
    color: "#3b82f6",
    icon: <HourglassBottomIcon sx={{ fontSize: 16 }} />,
  },
};

interface FindingNotesPanelProps {
  findingId: number;
  compact?: boolean;
}

export const FindingNotesPanel: React.FC<FindingNotesPanelProps> = ({ findingId, compact = false }) => {
  const theme = useTheme();
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState(false);
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [editNote, setEditNote] = useState<FindingNote | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null);

  // Form state
  const [noteContent, setNoteContent] = useState("");
  const [noteType, setNoteType] = useState<NoteType>("comment");

  // Fetch notes for this finding
  const { data: notes = [], isLoading } = useQuery({
    queryKey: ["finding-notes", findingId],
    queryFn: () => apiClient.getFindingNotes(findingId),
  });

  // Create note mutation
  const createMutation = useMutation({
    mutationFn: (note: FindingNoteCreate) => apiClient.createFindingNote(findingId, note),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["finding-notes", findingId] });
      setAddDialogOpen(false);
      setNoteContent("");
      setNoteType("comment");
    },
  });

  // Update note mutation
  const updateMutation = useMutation({
    mutationFn: ({ id, note }: { id: number; note: FindingNoteCreate }) =>
      apiClient.updateFindingNote(id, note),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["finding-notes", findingId] });
      setEditNote(null);
      setNoteContent("");
      setNoteType("comment");
    },
  });

  // Delete note mutation
  const deleteMutation = useMutation({
    mutationFn: (noteId: number) => apiClient.deleteFindingNote(noteId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["finding-notes", findingId] });
      setDeleteConfirm(null);
    },
  });

  const handleAddNote = () => {
    if (!noteContent.trim()) return;
    createMutation.mutate({ content: noteContent, note_type: noteType });
  };

  const handleUpdateNote = () => {
    if (!editNote || !noteContent.trim()) return;
    updateMutation.mutate({
      id: editNote.id,
      note: { content: noteContent, note_type: noteType },
    });
  };

  const handleEditClick = (note: FindingNote) => {
    setEditNote(note);
    setNoteContent(note.content);
    setNoteType(note.note_type);
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const notesCount = notes.length;

  // Compact mode - just show a badge/button
  if (compact) {
    return (
      <>
        <Tooltip title={notesCount > 0 ? `${notesCount} note(s)` : "Add note"}>
          <IconButton
            size="small"
            onClick={() => (notesCount > 0 ? setExpanded(true) : setAddDialogOpen(true))}
            sx={{
              color: notesCount > 0 ? "#6366f1" : "text.secondary",
              bgcolor: notesCount > 0 ? alpha("#6366f1", 0.1) : "transparent",
              "&:hover": { bgcolor: alpha("#6366f1", 0.2) },
            }}
          >
            {notesCount > 0 ? (
              <Box sx={{ position: "relative" }}>
                <CommentIcon sx={{ fontSize: 18 }} />
                <Box
                  sx={{
                    position: "absolute",
                    top: -4,
                    right: -6,
                    bgcolor: "#6366f1",
                    color: "white",
                    borderRadius: "50%",
                    width: 14,
                    height: 14,
                    fontSize: 10,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontWeight: 700,
                  }}
                >
                  {notesCount}
                </Box>
              </Box>
            ) : (
              <AddCommentIcon sx={{ fontSize: 18 }} />
            )}
          </IconButton>
        </Tooltip>

        {/* Notes Dialog for compact mode */}
        <Dialog open={expanded} onClose={() => setExpanded(false)} maxWidth="sm" fullWidth>
          <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <CommentIcon /> Notes ({notesCount})
          </DialogTitle>
          <DialogContent>
            <NotesList
              notes={notes}
              onEdit={handleEditClick}
              onDelete={(id) => setDeleteConfirm(id)}
              formatDate={formatDate}
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setAddDialogOpen(true)} startIcon={<AddCommentIcon />}>
              Add Note
            </Button>
            <Button onClick={() => setExpanded(false)}>Close</Button>
          </DialogActions>
        </Dialog>

        {/* Add/Edit Note Dialog */}
        <NoteFormDialog
          open={addDialogOpen || editNote !== null}
          onClose={() => {
            setAddDialogOpen(false);
            setEditNote(null);
            setNoteContent("");
            setNoteType("comment");
          }}
          noteContent={noteContent}
          setNoteContent={setNoteContent}
          noteType={noteType}
          setNoteType={setNoteType}
          onSave={editNote ? handleUpdateNote : handleAddNote}
          isEdit={editNote !== null}
          isLoading={createMutation.isPending || updateMutation.isPending}
        />

        {/* Delete Confirmation */}
        <Dialog open={deleteConfirm !== null} onClose={() => setDeleteConfirm(null)}>
          <DialogTitle>Delete Note?</DialogTitle>
          <DialogContent>
            <Typography>Are you sure you want to delete this note? This cannot be undone.</Typography>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDeleteConfirm(null)}>Cancel</Button>
            <Button
              color="error"
              variant="contained"
              onClick={() => deleteConfirm && deleteMutation.mutate(deleteConfirm)}
              disabled={deleteMutation.isPending}
            >
              Delete
            </Button>
          </DialogActions>
        </Dialog>
      </>
    );
  }

  // Full panel mode
  return (
    <Box sx={{ mt: 1 }}>
      {/* Header with expand toggle */}
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          gap: 1,
          cursor: "pointer",
          p: 1,
          borderRadius: 1,
          "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) },
        }}
        onClick={() => setExpanded(!expanded)}
      >
        <CommentIcon sx={{ fontSize: 18, color: "text.secondary" }} />
        <Typography variant="body2" fontWeight={500}>
          Notes ({notesCount})
        </Typography>
        {expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        <Box sx={{ flex: 1 }} />
        <Button
          size="small"
          startIcon={<AddCommentIcon />}
          onClick={(e) => {
            e.stopPropagation();
            setAddDialogOpen(true);
          }}
        >
          Add
        </Button>
      </Box>

      <Collapse in={expanded}>
        <Box sx={{ pl: 2, pr: 1, pb: 1 }}>
          {isLoading ? (
            <CircularProgress size={20} />
          ) : notes.length === 0 ? (
            <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
              No notes yet. Add one to track remediation or mark as false positive.
            </Typography>
          ) : (
            <NotesList
              notes={notes}
              onEdit={handleEditClick}
              onDelete={(id) => setDeleteConfirm(id)}
              formatDate={formatDate}
            />
          )}
        </Box>
      </Collapse>

      {/* Add/Edit Note Dialog */}
      <NoteFormDialog
        open={addDialogOpen || editNote !== null}
        onClose={() => {
          setAddDialogOpen(false);
          setEditNote(null);
          setNoteContent("");
          setNoteType("comment");
        }}
        noteContent={noteContent}
        setNoteContent={setNoteContent}
        noteType={noteType}
        setNoteType={setNoteType}
        onSave={editNote ? handleUpdateNote : handleAddNote}
        isEdit={editNote !== null}
        isLoading={createMutation.isPending || updateMutation.isPending}
      />

      {/* Delete Confirmation */}
      <Dialog open={deleteConfirm !== null} onClose={() => setDeleteConfirm(null)}>
        <DialogTitle>Delete Note?</DialogTitle>
        <DialogContent>
          <Typography>Are you sure you want to delete this note? This cannot be undone.</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirm(null)}>Cancel</Button>
          <Button
            color="error"
            variant="contained"
            onClick={() => deleteConfirm && deleteMutation.mutate(deleteConfirm)}
            disabled={deleteMutation.isPending}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

// Sub-component: Notes list
interface NotesListProps {
  notes: FindingNote[];
  onEdit: (note: FindingNote) => void;
  onDelete: (id: number) => void;
  formatDate: (date: string) => string;
}

const NotesList: React.FC<NotesListProps> = ({ notes, onEdit, onDelete, formatDate }) => {
  const theme = useTheme();

  return (
    <Stack spacing={1.5}>
      {notes.map((note) => {
        const config = NOTE_TYPE_CONFIG[note.note_type] || NOTE_TYPE_CONFIG.comment;
        return (
          <Paper
            key={note.id}
            sx={{
              p: 1.5,
              bgcolor: alpha(config.color, 0.05),
              border: `1px solid ${alpha(config.color, 0.2)}`,
            }}
          >
            <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
              <Chip
                icon={config.icon as React.ReactElement}
                label={config.label}
                size="small"
                sx={{
                  bgcolor: alpha(config.color, 0.1),
                  color: config.color,
                  fontWeight: 600,
                  fontSize: "0.7rem",
                  height: 22,
                  "& .MuiChip-icon": { color: config.color },
                }}
              />
              <Typography variant="caption" color="text.secondary" sx={{ ml: "auto" }}>
                {formatDate(note.created_at)}
              </Typography>
            </Box>
            <Typography variant="body2" sx={{ mt: 1, whiteSpace: "pre-wrap" }}>
              {note.content}
            </Typography>
            <Box sx={{ display: "flex", gap: 0.5, mt: 1 }}>
              <IconButton size="small" onClick={() => onEdit(note)}>
                <EditIcon sx={{ fontSize: 16 }} />
              </IconButton>
              <IconButton size="small" color="error" onClick={() => onDelete(note.id)}>
                <DeleteIcon sx={{ fontSize: 16 }} />
              </IconButton>
            </Box>
          </Paper>
        );
      })}
    </Stack>
  );
};

// Sub-component: Note form dialog
interface NoteFormDialogProps {
  open: boolean;
  onClose: () => void;
  noteContent: string;
  setNoteContent: (content: string) => void;
  noteType: NoteType;
  setNoteType: (type: NoteType) => void;
  onSave: () => void;
  isEdit: boolean;
  isLoading: boolean;
}

const NoteFormDialog: React.FC<NoteFormDialogProps> = ({
  open,
  onClose,
  noteContent,
  setNoteContent,
  noteType,
  setNoteType,
  onSave,
  isEdit,
  isLoading,
}) => {
  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{isEdit ? "Edit Note" : "Add Note"}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <FormControl fullWidth size="small">
            <InputLabel>Note Type</InputLabel>
            <Select
              value={noteType}
              label="Note Type"
              onChange={(e) => setNoteType(e.target.value as NoteType)}
            >
              {Object.entries(NOTE_TYPE_CONFIG).map(([type, config]) => (
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
            label="Note"
            multiline
            rows={4}
            fullWidth
            value={noteContent}
            onChange={(e) => setNoteContent(e.target.value)}
            placeholder="Add your notes here..."
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained"
          onClick={onSave}
          disabled={!noteContent.trim() || isLoading}
          startIcon={isLoading ? <CircularProgress size={16} /> : undefined}
        >
          {isEdit ? "Update" : "Add Note"}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

// Export a badge component for use in tables
export const FindingNotesBadge: React.FC<{ findingId: number }> = ({ findingId }) => {
  return <FindingNotesPanel findingId={findingId} compact />;
};

export default FindingNotesPanel;
