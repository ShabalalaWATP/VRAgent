import React, { useState, useMemo, useEffect, useRef, useCallback } from "react";
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
  InputAdornment,
  Menu,
  ListItemIcon,
  ListItemText,
  Divider,
  Badge,
  ToggleButton,
  ToggleButtonGroup,
  Autocomplete,
  Stack,
  Avatar,
  AvatarGroup,
  Fade,
  Snackbar,
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
  NotesCollaborationClient,
  NotesCollaborationUser,
  NotesCollaborationMessage,
} from "../api/client";
import { FindingNotesPanel } from "./FindingNotesPanel";
import ReactMarkdown from "react-markdown";
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
import SearchIcon from "@mui/icons-material/Search";
import PushPinIcon from "@mui/icons-material/PushPin";
import PushPinOutlinedIcon from "@mui/icons-material/PushPinOutlined";
import SortIcon from "@mui/icons-material/Sort";
import ViewListIcon from "@mui/icons-material/ViewList";
import ViewModuleIcon from "@mui/icons-material/ViewModule";
import DownloadIcon from "@mui/icons-material/Download";
import FullscreenIcon from "@mui/icons-material/Fullscreen";
import VisibilityIcon from "@mui/icons-material/Visibility";
import CodeIcon from "@mui/icons-material/Code";
import FormatBoldIcon from "@mui/icons-material/FormatBold";
import FormatItalicIcon from "@mui/icons-material/FormatItalic";
import FormatListBulletedIcon from "@mui/icons-material/FormatListBulleted";
import FormatListNumberedIcon from "@mui/icons-material/FormatListNumbered";
import LinkIcon from "@mui/icons-material/Link";
import CheckBoxIcon from "@mui/icons-material/CheckBox";
import LocalOfferIcon from "@mui/icons-material/LocalOffer";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import ArchiveIcon from "@mui/icons-material/Archive";
import WifiIcon from "@mui/icons-material/Wifi";
import WifiOffIcon from "@mui/icons-material/WifiOff";
import GroupIcon from "@mui/icons-material/Group";
import PersonIcon from "@mui/icons-material/Person";

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

// Note templates for quick creation
const NOTE_TEMPLATES = [
  {
    name: "Bug Report",
    note_type: "important" as ProjectNoteType,
    title: "Bug: ",
    content: `## Bug Description
**Summary:** 

**Steps to Reproduce:**
1. 
2. 
3. 

**Expected Behavior:**

**Actual Behavior:**

**Environment:**
- OS: 
- Browser/Version: 

**Additional Notes:**
`,
  },
  {
    name: "Meeting Notes",
    note_type: "general" as ProjectNoteType,
    title: "Meeting: ",
    content: `## Meeting Notes - ${new Date().toLocaleDateString()}

**Attendees:**
- 

**Agenda:**
1. 

**Discussion:**


**Action Items:**
- [ ] 
- [ ] 

**Next Steps:**
`,
  },
  {
    name: "To-Do List",
    note_type: "todo" as ProjectNoteType,
    title: "Tasks: ",
    content: `## Tasks

### High Priority
- [ ] 

### Medium Priority
- [ ] 

### Low Priority
- [ ] 

### Completed
- [x] 
`,
  },
  {
    name: "Research Notes",
    note_type: "reference" as ProjectNoteType,
    title: "Research: ",
    content: `## Research Notes

### Topic


### Key Findings
- 

### Resources
- [Link Title](url)

### Questions
1. 

### Conclusions

`,
  },
  {
    name: "Security Finding",
    note_type: "important" as ProjectNoteType,
    title: "Security: ",
    content: `## Security Finding

**Severity:** Critical / High / Medium / Low

**Affected Component:**

**Description:**

**Impact:**

**Recommendation:**

**References:**
- 

**Status:** Open / In Progress / Resolved
`,
  },
];

interface ProjectNotesTabProps {
  projectId: number;
  userId?: number;
  username?: string;
}

const ProjectNotesTab: React.FC<ProjectNotesTabProps> = ({ projectId, userId, username }) => {
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

  // Real-time collaboration state
  const [wsConnected, setWsConnected] = useState(false);
  const [activeUsers, setActiveUsers] = useState<NotesCollaborationUser[]>([]);
  const [typingUsers, setTypingUsers] = useState<Map<number, { userId: number; username: string; color: string }>>(new Map());
  const [activeEditors, setActiveEditors] = useState<Map<number, number[]>>(new Map());
  const [collabSnackbar, setCollabSnackbar] = useState<{ open: boolean; message: string }>({ open: false, message: '' });
  const wsClientRef = useRef<NotesCollaborationClient | null>(null);
  const typingTimeoutRef = useRef<Map<number, NodeJS.Timeout>>(new Map());

  // Enhanced features state
  const [searchQuery, setSearchQuery] = useState("");
  const [viewMode, setViewMode] = useState<"grid" | "list">("grid");
  const [sortBy, setSortBy] = useState<"date" | "title" | "type">("date");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [pinnedNotes, setPinnedNotes] = useState<Set<number>>(new Set());
  const [showArchived, setShowArchived] = useState(false);
  const [archivedNotes, setArchivedNotes] = useState<Set<number>>(new Set());
  const [fullscreenEditor, setFullscreenEditor] = useState(false);
  const [previewMode, setPreviewMode] = useState(false);
  const [noteTags, setNoteTags] = useState<Record<number, string[]>>({});
  const [currentTags, setCurrentTags] = useState<string[]>([]);
  const [tagFilter, setTagFilter] = useState<string | null>(null);
  
  // Menu state
  const [templateMenuAnchor, setTemplateMenuAnchor] = useState<null | HTMLElement>(null);
  const [sortMenuAnchor, setSortMenuAnchor] = useState<null | HTMLElement>(null);
  const [noteMenuAnchor, setNoteMenuAnchor] = useState<null | HTMLElement>(null);
  const [selectedNoteForMenu, setSelectedNoteForMenu] = useState<ProjectNote | null>(null);

  // WebSocket message handler
  const handleWsMessage = useCallback((message: NotesCollaborationMessage) => {
    switch (message.type) {
      case 'presence_sync':
        if (message.users) {
          setActiveUsers(message.users.filter(u => u.user_id !== userId));
        }
        if (message.active_editors) {
          const editors = new Map<number, number[]>();
          Object.entries(message.active_editors).forEach(([noteId, userIds]) => {
            editors.set(Number(noteId), userIds as number[]);
          });
          setActiveEditors(editors);
        }
        break;
      
      case 'user_joined':
        if (message.user && message.user.user_id !== userId) {
          setActiveUsers(prev => [...prev.filter(u => u.user_id !== message.user!.user_id), message.user!]);
          setCollabSnackbar({ open: true, message: `${message.user.username} joined` });
        }
        break;
      
      case 'user_left':
        if (message.user_id !== userId) {
          setActiveUsers(prev => prev.filter(u => u.user_id !== message.user_id));
          // Clear typing state for this user
          setTypingUsers(prev => {
            const next = new Map(prev);
            prev.forEach((value, key) => {
              if (value.userId === message.user_id) {
                next.delete(key);
              }
            });
            return next;
          });
          setCollabSnackbar({ open: true, message: `${message.username} left` });
        }
        break;
      
      case 'typing_start':
        if (message.user_id !== userId && message.note_id) {
          setTypingUsers(prev => {
            const next = new Map(prev);
            next.set(message.note_id!, {
              userId: message.user_id!,
              username: message.username!,
              color: message.color || '#6366f1',
            });
            return next;
          });
        }
        break;
      
      case 'typing_stop':
        if (message.note_id) {
          setTypingUsers(prev => {
            const next = new Map(prev);
            next.delete(message.note_id!);
            return next;
          });
        }
        break;
      
      case 'note_focus':
        if (message.note_id && message.editors) {
          setActiveEditors(prev => {
            const next = new Map(prev);
            next.set(message.note_id!, message.editors!.filter(id => id !== userId));
            return next;
          });
        }
        break;
      
      case 'note_blur':
        if (message.note_id && message.editors !== undefined) {
          setActiveEditors(prev => {
            const next = new Map(prev);
            if (message.editors!.length === 0 || message.editors!.every(id => id === userId)) {
              next.delete(message.note_id!);
            } else {
              next.set(message.note_id!, message.editors!.filter(id => id !== userId));
            }
            return next;
          });
        }
        break;
      
      case 'note_edit':
        // Remote edit - refresh the notes list
        if (message.user_id !== userId) {
          queryClient.invalidateQueries({ queryKey: ["project-general-notes", projectId] });
        }
        break;
      
      case 'note_created':
        // Remote note created - refresh the notes list
        if (message.user_id !== userId) {
          queryClient.invalidateQueries({ queryKey: ["project-general-notes", projectId] });
          setCollabSnackbar({ open: true, message: `${message.username} created a note` });
        }
        break;
      
      case 'note_deleted':
        // Remote note deleted - refresh the notes list
        if (message.user_id !== userId) {
          queryClient.invalidateQueries({ queryKey: ["project-general-notes", projectId] });
          setCollabSnackbar({ open: true, message: `${message.username} deleted a note` });
        }
        break;
    }
  }, [userId, projectId, queryClient]);

  // WebSocket connection
  useEffect(() => {
    if (!userId || !username) return;

    const client = new NotesCollaborationClient(
      projectId,
      userId,
      username,
      handleWsMessage,
      setWsConnected
    );

    wsClientRef.current = client;
    client.connect();

    return () => {
      client.disconnect();
      wsClientRef.current = null;
    };
  }, [projectId, userId, username, handleWsMessage]);

  // Helper to send typing indicator with debounce
  const sendTypingIndicator = useCallback((noteId: number) => {
    if (!wsClientRef.current) return;
    
    // Clear existing timeout for this note
    const existingTimeout = typingTimeoutRef.current.get(noteId);
    if (existingTimeout) {
      clearTimeout(existingTimeout);
    }
    
    // Send typing start
    wsClientRef.current.sendTypingStart(noteId);
    
    // Set timeout to send typing stop after 2 seconds of inactivity
    const timeout = setTimeout(() => {
      wsClientRef.current?.sendTypingStop(noteId);
      typingTimeoutRef.current.delete(noteId);
    }, 2000);
    
    typingTimeoutRef.current.set(noteId, timeout);
  }, []);

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
    onSuccess: (newNoteResult) => {
      queryClient.invalidateQueries({ queryKey: ["project-general-notes", projectId] });
      setAddNoteDialog(false);
      setFullscreenEditor(false);
      // Store tags for the new note
      if (currentTags.length > 0 && newNoteResult?.id) {
        setNoteTags(prev => ({ ...prev, [newNoteResult.id]: currentTags }));
      }
      setNewNote({ title: "", content: "", note_type: "general" });
      setCurrentTags([]);
      // Broadcast to collaborators
      if (wsClientRef.current && newNoteResult) {
        wsClientRef.current.sendNoteCreated(newNoteResult);
      }
    },
  });

  // Update project note mutation
  const updateNoteMutation = useMutation({
    mutationFn: ({ noteId, note }: { noteId: number; note: ProjectNoteCreate }) =>
      apiClient.updateProjectNote(noteId, note),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ["project-general-notes", projectId] });
      setEditingNote(null);
      setFullscreenEditor(false);
      if (editingNote && currentTags.length > 0) {
        setNoteTags(prev => ({ ...prev, [editingNote.id]: currentTags }));
      }
      setCurrentTags([]);
      // Broadcast edit to collaborators
      if (wsClientRef.current) {
        wsClientRef.current.sendNoteEdit(variables.noteId, {
          content: variables.note.content,
          title: variables.note.title || undefined,
        });
        wsClientRef.current.sendNoteBlur(variables.noteId);
      }
    },
  });

  // Delete project note mutation
  const deleteNoteMutation = useMutation({
    mutationFn: (noteId: number) => apiClient.deleteProjectNote(noteId),
    onSuccess: (_, noteId) => {
      queryClient.invalidateQueries({ queryKey: ["project-general-notes", projectId] });
      // Broadcast deletion to collaborators
      if (wsClientRef.current) {
        wsClientRef.current.sendNoteDeleted(noteId);
      }
    },
  });

  // Get all unique tags across notes
  const allTags = useMemo(() => {
    const tags = new Set<string>();
    Object.values(noteTags).forEach(noteTags => {
      noteTags.forEach(tag => tags.add(tag));
    });
    return Array.from(tags);
  }, [noteTags]);

  // Filter and sort notes
  const filteredAndSortedNotes = useMemo(() => {
    let notes = projectNotesQuery.data || [];
    
    // Filter by search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      notes = notes.filter(
        note =>
          note.title?.toLowerCase().includes(query) ||
          note.content.toLowerCase().includes(query)
      );
    }

    // Filter by tag
    if (tagFilter) {
      notes = notes.filter(note => noteTags[note.id]?.includes(tagFilter));
    }

    // Filter archived
    if (!showArchived) {
      notes = notes.filter(note => !archivedNotes.has(note.id));
    }

    // Sort notes
    notes = [...notes].sort((a, b) => {
      // Pinned notes always first
      const aPinned = pinnedNotes.has(a.id);
      const bPinned = pinnedNotes.has(b.id);
      if (aPinned && !bPinned) return -1;
      if (!aPinned && bPinned) return 1;

      let comparison = 0;
      switch (sortBy) {
        case "date":
          comparison = new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
          break;
        case "title":
          comparison = (a.title || "").localeCompare(b.title || "");
          break;
        case "type":
          comparison = a.note_type.localeCompare(b.note_type);
          break;
      }
      return sortOrder === "asc" ? -comparison : comparison;
    });

    return notes;
  }, [projectNotesQuery.data, searchQuery, sortBy, sortOrder, pinnedNotes, archivedNotes, showArchived, tagFilter, noteTags]);

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
    setCurrentTags(noteTags[note.id] || []);
    setAddNoteDialog(true);
  };

  const handleCloseDialog = () => {
    setAddNoteDialog(false);
    setFullscreenEditor(false);
    setEditingNote(null);
    setNewNote({ title: "", content: "", note_type: "general" });
    setCurrentTags([]);
    setPreviewMode(false);
  };

  const handleApplyTemplate = (template: typeof NOTE_TEMPLATES[0]) => {
    setNewNote({
      title: template.title,
      content: template.content,
      note_type: template.note_type,
    });
    setTemplateMenuAnchor(null);
    setAddNoteDialog(true);
  };

  const togglePin = (noteId: number) => {
    setPinnedNotes(prev => {
      const newSet = new Set(prev);
      if (newSet.has(noteId)) {
        newSet.delete(noteId);
      } else {
        newSet.add(noteId);
      }
      return newSet;
    });
  };

  const toggleArchive = (noteId: number) => {
    setArchivedNotes(prev => {
      const newSet = new Set(prev);
      if (newSet.has(noteId)) {
        newSet.delete(noteId);
      } else {
        newSet.add(noteId);
      }
      return newSet;
    });
  };

  const copyNoteToClipboard = (note: ProjectNote) => {
    const text = `# ${note.title || "Note"}\n\n${note.content}`;
    navigator.clipboard.writeText(text);
  };

  const exportAllNotes = () => {
    const notes = projectNotesQuery.data || [];
    let markdown = `# Project Notes\n\nExported: ${new Date().toLocaleString()}\n\n---\n\n`;
    
    notes.forEach(note => {
      const config = PROJECT_NOTE_TYPE_CONFIG[note.note_type as ProjectNoteType];
      markdown += `## ${note.title || "Untitled Note"}\n`;
      markdown += `**Type:** ${config?.label || note.note_type}\n`;
      markdown += `**Created:** ${formatDate(note.created_at)}\n`;
      if (noteTags[note.id]?.length) {
        markdown += `**Tags:** ${noteTags[note.id].join(", ")}\n`;
      }
      markdown += `\n${note.content}\n\n---\n\n`;
    });

    const blob = new Blob([markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `project-notes-${projectId}-${new Date().toISOString().split("T")[0]}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Insert markdown formatting
  const insertMarkdown = (format: string) => {
    const textarea = document.querySelector('textarea[name="note-content"]') as HTMLTextAreaElement;
    if (!textarea) return;

    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const selectedText = newNote.content.substring(start, end);
    let newText = "";
    let cursorOffset = 0;

    switch (format) {
      case "bold":
        newText = `**${selectedText || "bold text"}**`;
        cursorOffset = selectedText ? newText.length : 2;
        break;
      case "italic":
        newText = `*${selectedText || "italic text"}*`;
        cursorOffset = selectedText ? newText.length : 1;
        break;
      case "bullet":
        newText = `\n- ${selectedText || "list item"}`;
        cursorOffset = newText.length;
        break;
      case "number":
        newText = `\n1. ${selectedText || "list item"}`;
        cursorOffset = newText.length;
        break;
      case "link":
        newText = `[${selectedText || "link text"}](url)`;
        cursorOffset = selectedText ? newText.length - 1 : 1;
        break;
      case "checkbox":
        newText = `\n- [ ] ${selectedText || "task"}`;
        cursorOffset = newText.length;
        break;
      case "code":
        newText = selectedText.includes("\n") 
          ? `\`\`\`\n${selectedText || "code"}\n\`\`\``
          : `\`${selectedText || "code"}\``;
        cursorOffset = selectedText ? newText.length : 1;
        break;
    }

    const newContent = newNote.content.substring(0, start) + newText + newNote.content.substring(end);
    setNewNote({ ...newNote, content: newContent });
  };

  // Note card component for grid view
  const NoteCard = ({ note }: { note: ProjectNote }) => {
    const config = PROJECT_NOTE_TYPE_CONFIG[note.note_type as ProjectNoteType] || PROJECT_NOTE_TYPE_CONFIG.general;
    const isPinned = pinnedNotes.has(note.id);
    const isArchived = archivedNotes.has(note.id);
    const tags = noteTags[note.id] || [];
    const typingUser = typingUsers.get(note.id);
    const editors = activeEditors.get(note.id) || [];
    const otherEditors = editors.filter(id => id !== userId);

    return (
      <Card
        sx={{
          height: "100%",
          border: `1px solid ${alpha(config.color, 0.3)}`,
          opacity: isArchived ? 0.6 : 1,
          position: "relative",
          "&:hover": {
            boxShadow: `0 4px 12px ${alpha(config.color, 0.15)}`,
          },
          // Highlight if someone is editing
          ...(otherEditors.length > 0 && {
            boxShadow: `0 0 0 2px ${activeUsers.find(u => otherEditors.includes(u.user_id))?.color || '#6366f1'}`,
          }),
        }}
      >
        {isPinned && (
          <Box
            sx={{
              position: "absolute",
              top: -8,
              right: 12,
              color: "#f59e0b",
              transform: "rotate(45deg)",
            }}
          >
            <PushPinIcon fontSize="small" />
          </Box>
        )}
        
        {/* Active editors indicator */}
        {otherEditors.length > 0 && (
          <Box
            sx={{
              position: "absolute",
              top: 8,
              left: 8,
              display: "flex",
              alignItems: "center",
              gap: 0.5,
              bgcolor: alpha("#000", 0.7),
              borderRadius: 1,
              px: 1,
              py: 0.25,
            }}
          >
            <AvatarGroup max={3} sx={{ '& .MuiAvatar-root': { width: 18, height: 18, fontSize: 10 } }}>
              {otherEditors.map(editorId => {
                const user = activeUsers.find(u => u.user_id === editorId);
                return user ? (
                  <Tooltip key={editorId} title={`${user.username} is viewing`}>
                    <Avatar sx={{ bgcolor: user.color, width: 18, height: 18 }}>
                      {user.username[0].toUpperCase()}
                    </Avatar>
                  </Tooltip>
                ) : null;
              })}
            </AvatarGroup>
          </Box>
        )}

        <CardContent>
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
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
              {tags.map(tag => (
                <Chip
                  key={tag}
                  label={tag}
                  size="small"
                  variant="outlined"
                  icon={<LocalOfferIcon sx={{ fontSize: 14 }} />}
                  onClick={() => setTagFilter(tag === tagFilter ? null : tag)}
                  sx={{ 
                    height: 20, 
                    fontSize: "0.7rem",
                    bgcolor: tag === tagFilter ? alpha("#6366f1", 0.1) : "transparent",
                  }}
                />
              ))}
            </Box>
            <Box>
              <Tooltip title={isPinned ? "Unpin" : "Pin"}>
                <IconButton size="small" onClick={() => togglePin(note.id)}>
                  {isPinned ? (
                    <PushPinIcon fontSize="small" sx={{ color: "#f59e0b" }} />
                  ) : (
                    <PushPinOutlinedIcon fontSize="small" />
                  )}
                </IconButton>
              </Tooltip>
              <IconButton
                size="small"
                onClick={(e) => {
                  setSelectedNoteForMenu(note);
                  setNoteMenuAnchor(e.currentTarget);
                }}
              >
                <MoreVertIcon fontSize="small" />
              </IconButton>
            </Box>
          </Box>
          {note.title && (
            <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 1 }}>
              {note.title}
            </Typography>
          )}
          <Box
            className="markdown-content"
            sx={{
              maxHeight: viewMode === "grid" ? 150 : "none",
              overflow: "auto",
              fontSize: "0.9rem",
              lineHeight: 1.6,
              "& p": { margin: "0.5em 0" },
              // Bold text - ensure visibility
              "& strong, & b": { 
                fontWeight: 700,
                color: "text.primary",
              },
              // Italic text
              "& em, & i": { 
                fontStyle: "italic",
              },
              // Underline (using HTML <u> or custom marker)
              "& u": {
                textDecoration: "underline",
                textDecorationColor: "#6366f1",
                textUnderlineOffset: "2px",
              },
              // Strikethrough
              "& del, & s": {
                textDecoration: "line-through",
                opacity: 0.7,
              },
              // Blockquotes
              "& blockquote": {
                borderLeft: "4px solid #6366f1",
                pl: 2,
                ml: 0,
                my: 1,
                color: "text.secondary",
                fontStyle: "italic",
                bgcolor: alpha("#6366f1", 0.05),
                py: 0.5,
                borderRadius: "0 4px 4px 0",
              },
              // Unordered lists
              "& ul": { 
                pl: 3, 
                my: 1,
                listStyleType: "disc",
                "& li": {
                  mb: 0.5,
                  "&::marker": {
                    color: "#6366f1",
                  },
                },
                "& ul": {
                  listStyleType: "circle",
                  "& ul": {
                    listStyleType: "square",
                  },
                },
              },
              // Ordered lists
              "& ol": { 
                pl: 3, 
                my: 1,
                "& li": {
                  mb: 0.5,
                  "&::marker": {
                    color: "#6366f1",
                    fontWeight: 600,
                  },
                },
              },
              // Task list checkboxes
              "& li": {
                "& input[type='checkbox']": {
                  mr: 1,
                  accentColor: "#6366f1",
                  width: 16,
                  height: 16,
                  cursor: "pointer",
                },
              },
              // Inline code
              "& code": { 
                bgcolor: alpha("#6366f1", 0.1), 
                color: "#e91e63",
                px: 0.75, 
                py: 0.25,
                borderRadius: 0.5,
                fontFamily: "'Fira Code', 'Consolas', monospace",
                fontSize: "0.85em",
                fontWeight: 500,
              },
              // Code blocks
              "& pre": {
                bgcolor: alpha("#000", 0.08),
                p: 1.5,
                borderRadius: 1,
                overflow: "auto",
                border: `1px solid ${alpha("#000", 0.1)}`,
                "& code": { 
                  bgcolor: "transparent", 
                  px: 0,
                  py: 0,
                  color: "inherit",
                },
              },
              // Links
              "& a": { 
                color: "#6366f1",
                textDecoration: "none",
                fontWeight: 500,
                "&:hover": {
                  textDecoration: "underline",
                },
              },
              // Headings
              "& h1": { 
                fontSize: "1.5em", 
                fontWeight: 700, 
                mt: 1.5, 
                mb: 1,
                borderBottom: `2px solid ${alpha("#6366f1", 0.3)}`,
                pb: 0.5,
              },
              "& h2": { 
                fontSize: "1.3em", 
                fontWeight: 600, 
                mt: 1.5, 
                mb: 0.75,
                color: "text.primary",
              },
              "& h3": { 
                fontSize: "1.1em", 
                fontWeight: 600, 
                mt: 1, 
                mb: 0.5,
                color: "text.secondary",
              },
              "& h4, & h5, & h6": { 
                fontSize: "1em", 
                fontWeight: 600, 
                mt: 1, 
                mb: 0.5,
              },
              // Horizontal rule
              "& hr": {
                border: "none",
                borderTop: `1px solid ${alpha("#000", 0.15)}`,
                my: 2,
              },
              // Tables
              "& table": {
                borderCollapse: "collapse",
                width: "100%",
                my: 1,
                "& th, & td": {
                  border: `1px solid ${alpha("#000", 0.15)}`,
                  px: 1.5,
                  py: 0.75,
                  textAlign: "left",
                },
                "& th": {
                  bgcolor: alpha("#6366f1", 0.1),
                  fontWeight: 600,
                },
                "& tr:nth-of-type(even)": {
                  bgcolor: alpha("#000", 0.02),
                },
              },
              // Images
              "& img": {
                maxWidth: "100%",
                borderRadius: 1,
              },
            }}
          >
            <ReactMarkdown>{note.content}</ReactMarkdown>
          </Box>
          
          {/* Typing indicator */}
          <Fade in={!!typingUser}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, mt: 1 }}>
              <Box
                sx={{
                  display: "flex",
                  gap: 0.3,
                  "& span": {
                    width: 6,
                    height: 6,
                    borderRadius: "50%",
                    bgcolor: typingUser?.color || "#6366f1",
                    animation: "typing-bounce 1.4s infinite ease-in-out both",
                    "&:nth-of-type(1)": { animationDelay: "-0.32s" },
                    "&:nth-of-type(2)": { animationDelay: "-0.16s" },
                  },
                  "@keyframes typing-bounce": {
                    "0%, 80%, 100%": { transform: "scale(0)" },
                    "40%": { transform: "scale(1)" },
                  },
                }}
              >
                <span /><span /><span />
              </Box>
              <Typography variant="caption" sx={{ color: typingUser?.color, fontStyle: "italic" }}>
                {typingUser?.username} is typing...
              </Typography>
            </Box>
          </Fade>

          <Typography variant="caption" color="text.disabled" sx={{ display: "block", mt: 2 }}>
            {formatDate(note.created_at)}
            {note.updated_at !== note.created_at && ` (edited ${formatDate(note.updated_at)})`}
          </Typography>
        </CardContent>
      </Card>
    );
  };

  // Note list item component for list view
  const NoteListItem = ({ note }: { note: ProjectNote }) => {
    const config = PROJECT_NOTE_TYPE_CONFIG[note.note_type as ProjectNoteType] || PROJECT_NOTE_TYPE_CONFIG.general;
    const isPinned = pinnedNotes.has(note.id);
    const tags = noteTags[note.id] || [];
    const typingUser = typingUsers.get(note.id);
    const editors = activeEditors.get(note.id) || [];
    const otherEditors = editors.filter(id => id !== userId);

    return (
      <Paper
        sx={{
          p: 2,
          display: "flex",
          alignItems: "flex-start",
          gap: 2,
          border: `1px solid ${alpha(config.color, 0.2)}`,
          "&:hover": {
            bgcolor: alpha(config.color, 0.03),
          },
          // Highlight if someone is editing
          ...(otherEditors.length > 0 && {
            boxShadow: `0 0 0 2px ${activeUsers.find(u => otherEditors.includes(u.user_id))?.color || '#6366f1'}`,
          }),
        }}
      >
        {isPinned && (
          <PushPinIcon sx={{ color: "#f59e0b", fontSize: 18, mt: 0.5 }} />
        )}
        <Box sx={{ flex: 1 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
            <Chip
              icon={config.icon as React.ReactElement}
              label={config.label}
              size="small"
              sx={{
                bgcolor: alpha(config.color, 0.1),
                color: config.color,
                height: 22,
                "& .MuiChip-icon": { color: config.color },
              }}
            />
            {tags.map(tag => (
              <Chip
                key={tag}
                label={tag}
                size="small"
                variant="outlined"
                sx={{ height: 20, fontSize: "0.7rem" }}
              />
            ))}
            
            {/* Active editors in list view */}
            {otherEditors.length > 0 && (
              <AvatarGroup max={3} sx={{ '& .MuiAvatar-root': { width: 20, height: 20, fontSize: 10 } }}>
                {otherEditors.map(editorId => {
                  const user = activeUsers.find(u => u.user_id === editorId);
                  return user ? (
                    <Tooltip key={editorId} title={`${user.username} is viewing`}>
                      <Avatar sx={{ bgcolor: user.color }}>
                        {user.username[0].toUpperCase()}
                      </Avatar>
                    </Tooltip>
                  ) : null;
                })}
              </AvatarGroup>
            )}
            
            {/* Typing indicator for list view */}
            {typingUser && (
              <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                <Box
                  sx={{
                    display: "flex",
                    gap: 0.2,
                    "& span": {
                      width: 4,
                      height: 4,
                      borderRadius: "50%",
                      bgcolor: typingUser.color,
                      animation: "typing-bounce 1.4s infinite ease-in-out both",
                      "&:nth-of-type(1)": { animationDelay: "-0.32s" },
                      "&:nth-of-type(2)": { animationDelay: "-0.16s" },
                    },
                    "@keyframes typing-bounce": {
                      "0%, 80%, 100%": { transform: "scale(0)" },
                      "40%": { transform: "scale(1)" },
                    },
                  }}
                >
                  <span /><span /><span />
                </Box>
                <Typography variant="caption" sx={{ color: typingUser.color, fontStyle: "italic" }}>
                  {typingUser.username}...
                </Typography>
              </Box>
            )}
            
            <Typography variant="caption" color="text.secondary" sx={{ ml: "auto" }}>
              {formatDate(note.created_at)}
            </Typography>
          </Box>
          <Typography variant="subtitle2" fontWeight={600}>
            {note.title || "Untitled Note"}
          </Typography>
          <Typography
            variant="body2"
            color="text.secondary"
            sx={{
              overflow: "hidden",
              textOverflow: "ellipsis",
              display: "-webkit-box",
              WebkitLineClamp: 2,
              WebkitBoxOrient: "vertical",
            }}
          >
            {note.content.replace(/[#*`\[\]]/g, "").substring(0, 200)}
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 0.5 }}>
          <Tooltip title={isPinned ? "Unpin" : "Pin"}>
            <IconButton size="small" onClick={() => togglePin(note.id)}>
              {isPinned ? <PushPinIcon fontSize="small" /> : <PushPinOutlinedIcon fontSize="small" />}
            </IconButton>
          </Tooltip>
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
      </Paper>
    );
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
            label={
              <Badge badgeContent={projectNotesQuery.data?.length || 0} color="primary" max={99}>
                <Box sx={{ pr: 2 }}>Project Notes</Box>
              </Badge>
            }
            icon={<NoteIcon />}
            iconPosition="start"
          />
          <Tab
            value="findings"
            label={
              <Badge badgeContent={summaryQuery.data?.total_notes || 0} color="secondary" max={99}>
                <Box sx={{ pr: 2 }}>Finding Notes</Box>
              </Badge>
            }
            icon={<CommentIcon />}
            iconPosition="start"
          />
        </Tabs>
      </Paper>

      {activeTab === "general" && (
        <Box>
          {/* Collaboration Status Bar */}
          {userId && username && (
            <Paper
              sx={{
                p: 1.5,
                mb: 2,
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                bgcolor: alpha(theme.palette.background.paper, 0.8),
                backdropFilter: "blur(10px)",
              }}
            >
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                {/* Connection Status */}
                <Tooltip title={wsConnected ? "Real-time sync active" : "Connecting..."}>
                  <Chip
                    icon={wsConnected ? <WifiIcon /> : <WifiOffIcon />}
                    label={wsConnected ? "Live" : "Offline"}
                    size="small"
                    color={wsConnected ? "success" : "default"}
                    variant="outlined"
                  />
                </Tooltip>

                {/* Active Users */}
                {activeUsers.length > 0 && (
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <GroupIcon sx={{ fontSize: 18, color: "text.secondary" }} />
                    <AvatarGroup max={5} sx={{ '& .MuiAvatar-root': { width: 28, height: 28, fontSize: 12 } }}>
                      {activeUsers.map(user => (
                        <Tooltip key={user.user_id} title={user.username}>
                          <Avatar sx={{ bgcolor: user.color }}>
                            {user.username[0].toUpperCase()}
                          </Avatar>
                        </Tooltip>
                      ))}
                    </AvatarGroup>
                    <Typography variant="caption" color="text.secondary">
                      {activeUsers.length} collaborator{activeUsers.length !== 1 ? 's' : ''} online
                    </Typography>
                  </Box>
                )}
              </Box>

              {/* Current User */}
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <PersonIcon sx={{ fontSize: 16, color: "text.secondary" }} />
                <Typography variant="caption" color="text.secondary">
                  {username}
                </Typography>
              </Box>
            </Paper>
          )}

          {/* Enhanced Header with Search and Actions */}
          <Paper sx={{ p: 2, mb: 3 }}>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2, alignItems: "center" }}>
              {/* Search */}
              <TextField
                placeholder="Search notes..."
                size="small"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                sx={{ minWidth: 200, flex: 1 }}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon sx={{ color: "text.secondary" }} />
                    </InputAdornment>
                  ),
                }}
              />

              {/* Type Filter */}
              <FormControl size="small" sx={{ minWidth: 130 }}>
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

              {/* Tag Filter */}
              {allTags.length > 0 && (
                <FormControl size="small" sx={{ minWidth: 120 }}>
                  <InputLabel>Tag</InputLabel>
                  <Select
                    value={tagFilter || ""}
                    label="Tag"
                    onChange={(e) => setTagFilter(e.target.value || null)}
                  >
                    <MenuItem value="">All Tags</MenuItem>
                    {allTags.map(tag => (
                      <MenuItem key={tag} value={tag}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <LocalOfferIcon sx={{ fontSize: 16 }} />
                          {tag}
                        </Box>
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              )}

              {/* Sort */}
              <Button
                size="small"
                startIcon={<SortIcon />}
                onClick={(e) => setSortMenuAnchor(e.currentTarget)}
              >
                Sort
              </Button>

              {/* View Toggle */}
              <ToggleButtonGroup
                value={viewMode}
                exclusive
                onChange={(_, v) => v && setViewMode(v)}
                size="small"
              >
                <ToggleButton value="grid">
                  <ViewModuleIcon fontSize="small" />
                </ToggleButton>
                <ToggleButton value="list">
                  <ViewListIcon fontSize="small" />
                </ToggleButton>
              </ToggleButtonGroup>

              {/* Actions */}
              <Button
                variant="outlined"
                size="small"
                startIcon={<DownloadIcon />}
                onClick={exportAllNotes}
                disabled={!projectNotesQuery.data?.length}
              >
                Export
              </Button>

              {/* Template Menu */}
              <Button
                variant="outlined"
                size="small"
                onClick={(e) => setTemplateMenuAnchor(e.currentTarget)}
              >
                Templates
              </Button>

              {/* Add Note */}
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={() => setAddNoteDialog(true)}
              >
                Add Note
              </Button>
            </Box>

            {/* Active Filters */}
            {(searchQuery || tagFilter || projectNoteTypeFilter !== "all") && (
              <Box sx={{ display: "flex", gap: 1, mt: 2, flexWrap: "wrap" }}>
                {searchQuery && (
                  <Chip
                    label={`Search: "${searchQuery}"`}
                    size="small"
                    onDelete={() => setSearchQuery("")}
                  />
                )}
                {tagFilter && (
                  <Chip
                    label={`Tag: ${tagFilter}`}
                    size="small"
                    onDelete={() => setTagFilter(null)}
                  />
                )}
                {projectNoteTypeFilter !== "all" && (
                  <Chip
                    label={`Type: ${PROJECT_NOTE_TYPE_CONFIG[projectNoteTypeFilter]?.label}`}
                    size="small"
                    onDelete={() => setProjectNoteTypeFilter("all")}
                  />
                )}
              </Box>
            )}
          </Paper>

          {/* Project Notes List */}
          {projectNotesQuery.isLoading ? (
            <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
              <CircularProgress />
            </Box>
          ) : projectNotesQuery.error ? (
            <Alert severity="error">Failed to load notes: {String(projectNotesQuery.error)}</Alert>
          ) : filteredAndSortedNotes.length === 0 ? (
            <Paper sx={{ p: 4, textAlign: "center" }}>
              <NoteIcon sx={{ fontSize: 48, color: "text.secondary", mb: 2 }} />
              <Typography variant="h6" color="text.secondary" gutterBottom>
                {searchQuery || tagFilter ? "No notes match your filters" : "No notes yet"}
              </Typography>
              <Typography color="text.secondary" sx={{ mb: 2 }}>
                {searchQuery || tagFilter
                  ? "Try adjusting your search or filters."
                  : "Add general notes about your project, to-do items, or important references."}
              </Typography>
              {!searchQuery && !tagFilter && (
                <Box sx={{ display: "flex", gap: 2, justifyContent: "center" }}>
                  <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setAddNoteDialog(true)}>
                    Create your first note
                  </Button>
                  <Button variant="text" onClick={(e) => setTemplateMenuAnchor(e.currentTarget)}>
                    Use a template
                  </Button>
                </Box>
              )}
            </Paper>
          ) : viewMode === "grid" ? (
            <Grid container spacing={2}>
              {filteredAndSortedNotes.map((note) => (
                <Grid item xs={12} md={6} lg={4} key={note.id}>
                  <NoteCard note={note} />
                </Grid>
              ))}
            </Grid>
          ) : (
            <Stack spacing={1}>
              {filteredAndSortedNotes.map((note) => (
                <NoteListItem key={note.id} note={note} />
              ))}
            </Stack>
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
      <Dialog
        open={addNoteDialog || fullscreenEditor}
        onClose={handleCloseDialog}
        maxWidth={fullscreenEditor ? "lg" : "md"}
        fullWidth
        fullScreen={fullscreenEditor}
        TransitionProps={{
          onEntered: () => {
            // Send focus event when editing an existing note
            if (editingNote && wsClientRef.current) {
              wsClientRef.current.sendNoteFocus(editingNote.id);
            }
          },
          onExited: () => {
            // Send blur event when closing
            if (editingNote && wsClientRef.current) {
              wsClientRef.current.sendNoteBlur(editingNote.id);
            }
          },
        }}
      >
        <DialogTitle sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span>{editingNote ? "Edit Note" : "Add Project Note"}</span>
          <Box>
            <Tooltip title={previewMode ? "Edit" : "Preview"}>
              <IconButton onClick={() => setPreviewMode(!previewMode)}>
                {previewMode ? <CodeIcon /> : <VisibilityIcon />}
              </IconButton>
            </Tooltip>
            <Tooltip title={fullscreenEditor ? "Exit Fullscreen" : "Fullscreen"}>
              <IconButton onClick={() => setFullscreenEditor(!fullscreenEditor)}>
                <FullscreenIcon />
              </IconButton>
            </Tooltip>
          </Box>
        </DialogTitle>
        <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <Box sx={{ display: "flex", gap: 2, mt: 1 }}>
            <FormControl size="small" sx={{ minWidth: 150 }}>
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
              sx={{ flex: 1 }}
              size="small"
            />
          </Box>

          {/* Tags */}
          <Autocomplete
            multiple
            freeSolo
            options={allTags}
            value={currentTags}
            onChange={(_, newValue) => setCurrentTags(newValue)}
            renderTags={(value, getTagProps) =>
              value.map((option, index) => (
                <Chip
                  {...getTagProps({ index })}
                  key={option}
                  label={option}
                  size="small"
                  icon={<LocalOfferIcon sx={{ fontSize: 14 }} />}
                />
              ))
            }
            renderInput={(params) => (
              <TextField {...params} label="Tags" placeholder="Add tags..." size="small" />
            )}
          />

          {/* Markdown Toolbar */}
          {!previewMode && (
            <Box sx={{ display: "flex", gap: 0.5, borderBottom: 1, borderColor: "divider", pb: 1 }}>
              <Tooltip title="Bold">
                <IconButton size="small" onClick={() => insertMarkdown("bold")}>
                  <FormatBoldIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <Tooltip title="Italic">
                <IconButton size="small" onClick={() => insertMarkdown("italic")}>
                  <FormatItalicIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <Divider orientation="vertical" flexItem />
              <Tooltip title="Bullet List">
                <IconButton size="small" onClick={() => insertMarkdown("bullet")}>
                  <FormatListBulletedIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <Tooltip title="Numbered List">
                <IconButton size="small" onClick={() => insertMarkdown("number")}>
                  <FormatListNumberedIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <Tooltip title="Checkbox">
                <IconButton size="small" onClick={() => insertMarkdown("checkbox")}>
                  <CheckBoxIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <Divider orientation="vertical" flexItem />
              <Tooltip title="Link">
                <IconButton size="small" onClick={() => insertMarkdown("link")}>
                  <LinkIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <Tooltip title="Code">
                <IconButton size="small" onClick={() => insertMarkdown("code")}>
                  <CodeIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            </Box>
          )}

          {previewMode ? (
            <Paper
              variant="outlined"
              className="markdown-content"
              sx={{
                p: 2,
                flex: 1,
                minHeight: fullscreenEditor ? 400 : 250,
                overflow: "auto",
                fontSize: "0.9rem",
                lineHeight: 1.6,
                "& p": { margin: "0.5em 0" },
                // Bold text
                "& strong, & b": { 
                  fontWeight: 700,
                  color: "text.primary",
                },
                // Italic text
                "& em, & i": { fontStyle: "italic" },
                // Underline
                "& u": {
                  textDecoration: "underline",
                  textDecorationColor: "#6366f1",
                  textUnderlineOffset: "2px",
                },
                // Strikethrough
                "& del, & s": {
                  textDecoration: "line-through",
                  opacity: 0.7,
                },
                // Blockquotes
                "& blockquote": {
                  borderLeft: "4px solid #6366f1",
                  pl: 2,
                  ml: 0,
                  my: 1,
                  color: "text.secondary",
                  fontStyle: "italic",
                  bgcolor: alpha("#6366f1", 0.05),
                  py: 0.5,
                  borderRadius: "0 4px 4px 0",
                },
                // Lists
                "& ul": { 
                  pl: 3, 
                  my: 1,
                  listStyleType: "disc",
                  "& li": { mb: 0.5, "&::marker": { color: "#6366f1" } },
                },
                "& ol": { 
                  pl: 3, 
                  my: 1,
                  "& li": { mb: 0.5, "&::marker": { color: "#6366f1", fontWeight: 600 } },
                },
                // Task checkboxes
                "& li input[type='checkbox']": {
                  mr: 1,
                  accentColor: "#6366f1",
                },
                // Inline code
                "& code": { 
                  bgcolor: alpha("#6366f1", 0.1), 
                  color: "#e91e63",
                  px: 0.75, 
                  py: 0.25,
                  borderRadius: 0.5,
                  fontFamily: "'Fira Code', monospace",
                  fontSize: "0.85em",
                },
                // Code blocks
                "& pre": {
                  bgcolor: alpha("#000", 0.08),
                  p: 1.5,
                  borderRadius: 1,
                  overflow: "auto",
                  "& code": { bgcolor: "transparent", px: 0, color: "inherit" },
                },
                // Links
                "& a": { 
                  color: "#6366f1",
                  textDecoration: "none",
                  fontWeight: 500,
                  "&:hover": { textDecoration: "underline" },
                },
                // Headings
                "& h1": { fontSize: "1.5em", fontWeight: 700, mt: 1.5, mb: 1 },
                "& h2": { fontSize: "1.3em", fontWeight: 600, mt: 1.5, mb: 0.75 },
                "& h3": { fontSize: "1.1em", fontWeight: 600, mt: 1, mb: 0.5 },
                // Horizontal rule
                "& hr": { border: "none", borderTop: `1px solid ${alpha("#000", 0.15)}`, my: 2 },
                // Tables
                "& table": {
                  borderCollapse: "collapse",
                  width: "100%",
                  my: 1,
                  "& th, & td": { border: `1px solid ${alpha("#000", 0.15)}`, px: 1.5, py: 0.75 },
                  "& th": { bgcolor: alpha("#6366f1", 0.1), fontWeight: 600 },
                },
              }}
            >
              {newNote.content ? (
                <ReactMarkdown>{newNote.content}</ReactMarkdown>
              ) : (
                <Typography color="text.secondary" fontStyle="italic">
                  Nothing to preview yet...
                </Typography>
              )}
            </Paper>
          ) : (
            <TextField
              name="note-content"
              label="Content (Markdown supported)"
              value={newNote.content}
              onChange={(e) => {
                setNewNote({ ...newNote, content: e.target.value });
                // Send typing indicator when editing existing note
                if (editingNote) {
                  sendTypingIndicator(editingNote.id);
                }
              }}
              fullWidth
              multiline
              rows={fullscreenEditor ? 20 : 10}
              required
              placeholder="Write your note here... Supports **bold**, *italic*, - lists, [links](url), and more!"
              sx={{
                flex: 1,
                "& .MuiInputBase-root": {
                  fontFamily: "monospace",
                  fontSize: "0.9rem",
                },
              }}
            />
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleSaveNote}
            disabled={!newNote.content.trim() || createNoteMutation.isPending || updateNoteMutation.isPending}
          >
            {createNoteMutation.isPending || updateNoteMutation.isPending ? (
              <CircularProgress size={20} />
            ) : editingNote ? (
              "Save Changes"
            ) : (
              "Add Note"
            )}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Template Menu */}
      <Menu
        anchorEl={templateMenuAnchor}
        open={Boolean(templateMenuAnchor)}
        onClose={() => setTemplateMenuAnchor(null)}
      >
        <Typography variant="caption" sx={{ px: 2, py: 1, display: "block", color: "text.secondary" }}>
          Quick Templates
        </Typography>
        <Divider />
        {NOTE_TEMPLATES.map((template, index) => (
          <MenuItem key={index} onClick={() => handleApplyTemplate(template)}>
            <ListItemIcon>
              {PROJECT_NOTE_TYPE_CONFIG[template.note_type]?.icon}
            </ListItemIcon>
            <ListItemText>{template.name}</ListItemText>
          </MenuItem>
        ))}
      </Menu>

      {/* Sort Menu */}
      <Menu
        anchorEl={sortMenuAnchor}
        open={Boolean(sortMenuAnchor)}
        onClose={() => setSortMenuAnchor(null)}
      >
        <Typography variant="caption" sx={{ px: 2, py: 1, display: "block", color: "text.secondary" }}>
          Sort By
        </Typography>
        <Divider />
        {[
          { value: "date", label: "Date" },
          { value: "title", label: "Title" },
          { value: "type", label: "Type" },
        ].map((option) => (
          <MenuItem
            key={option.value}
            selected={sortBy === option.value}
            onClick={() => {
              if (sortBy === option.value) {
                setSortOrder(sortOrder === "asc" ? "desc" : "asc");
              } else {
                setSortBy(option.value as typeof sortBy);
              }
              setSortMenuAnchor(null);
            }}
          >
            {option.label}
            {sortBy === option.value && (
              <Typography variant="caption" sx={{ ml: 1 }}>
                ({sortOrder === "asc" ? "↑" : "↓"})
              </Typography>
            )}
          </MenuItem>
        ))}
      </Menu>

      {/* Note Context Menu */}
      <Menu
        anchorEl={noteMenuAnchor}
        open={Boolean(noteMenuAnchor)}
        onClose={() => {
          setNoteMenuAnchor(null);
          setSelectedNoteForMenu(null);
        }}
      >
        <MenuItem
          onClick={() => {
            if (selectedNoteForMenu) handleEditNote(selectedNoteForMenu);
            setNoteMenuAnchor(null);
          }}
        >
          <ListItemIcon>
            <EditIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Edit</ListItemText>
        </MenuItem>
        <MenuItem
          onClick={() => {
            if (selectedNoteForMenu) copyNoteToClipboard(selectedNoteForMenu);
            setNoteMenuAnchor(null);
          }}
        >
          <ListItemIcon>
            <ContentCopyIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Copy to Clipboard</ListItemText>
        </MenuItem>
        <MenuItem
          onClick={() => {
            if (selectedNoteForMenu) togglePin(selectedNoteForMenu.id);
            setNoteMenuAnchor(null);
          }}
        >
          <ListItemIcon>
            {selectedNoteForMenu && pinnedNotes.has(selectedNoteForMenu.id) ? (
              <PushPinIcon fontSize="small" />
            ) : (
              <PushPinOutlinedIcon fontSize="small" />
            )}
          </ListItemIcon>
          <ListItemText>
            {selectedNoteForMenu && pinnedNotes.has(selectedNoteForMenu.id) ? "Unpin" : "Pin"}
          </ListItemText>
        </MenuItem>
        <MenuItem
          onClick={() => {
            if (selectedNoteForMenu) toggleArchive(selectedNoteForMenu.id);
            setNoteMenuAnchor(null);
          }}
        >
          <ListItemIcon>
            <ArchiveIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>
            {selectedNoteForMenu && archivedNotes.has(selectedNoteForMenu.id) ? "Unarchive" : "Archive"}
          </ListItemText>
        </MenuItem>
        <Divider />
        <MenuItem
          onClick={() => {
            if (selectedNoteForMenu && confirm("Delete this note?")) {
              deleteNoteMutation.mutate(selectedNoteForMenu.id);
            }
            setNoteMenuAnchor(null);
          }}
          sx={{ color: "error.main" }}
        >
          <ListItemIcon>
            <DeleteIcon fontSize="small" color="error" />
          </ListItemIcon>
          <ListItemText>Delete</ListItemText>
        </MenuItem>
      </Menu>

      {/* Collaboration notification snackbar */}
      <Snackbar
        open={collabSnackbar.open}
        autoHideDuration={3000}
        onClose={() => setCollabSnackbar(prev => ({ ...prev, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
      >
        <Alert
          severity="info"
          variant="filled"
          icon={<GroupIcon />}
          onClose={() => setCollabSnackbar(prev => ({ ...prev, open: false }))}
        >
          {collabSnackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default ProjectNotesTab;
