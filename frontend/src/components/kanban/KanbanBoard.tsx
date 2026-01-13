/**
 * KanbanBoard - Main Kanban board component with drag-and-drop
 * Features: Real-time WebSocket sync, Filtering & Search
 */
import React, { useState, useCallback, useEffect, useMemo } from 'react';
import {
  Box,
  Paper,
  Typography,
  IconButton,
  Button,
  TextField,
  CircularProgress,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Tooltip,
  Badge,
  Collapse,
  Chip,
  Avatar,
  AvatarGroup,
  Select,
  FormControl,
  InputLabel,
  InputAdornment,
  Grid,
  alpha,
} from '@mui/material';
import {
  Add as AddIcon,
  MoreVert as MoreVertIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  DragIndicator as DragIcon,
  Refresh as RefreshIcon,
  ViewKanban as KanbanIcon,
  FilterList as FilterIcon,
  Search as SearchIcon,
  Clear as ClearIcon,
  Wifi as WifiIcon,
  WifiOff as WifiOffIcon,
  People as PeopleIcon,
} from '@mui/icons-material';
import {
  DragDropContext,
  Droppable,
  Draggable,
  DropResult,
  DraggableProvided,
  DroppableProvided,
} from '@hello-pangea/dnd';
import KanbanCard, { CardData } from './KanbanCard';
import CardDetailDialog from './CardDetailDialog';
import AddCardDialog, { NewCardData } from './AddCardDialog';
import { kanbanApi, KanbanBoard as KanbanBoardType, KanbanColumn, KanbanCard as KanbanCardType } from '../../api/client';
import { useKanbanWebSocket, KanbanUser } from '../../hooks/useKanbanWebSocket';

export interface ColumnData extends KanbanColumn {}

export interface BoardData extends KanbanBoardType {}

interface KanbanBoardProps {
  projectId: number;
  onFindingClick?: (findingId: number) => void;
}

const defaultColumnColors: Record<string, string> = {
  'Backlog': '#78909c',
  'To Do': '#5c6bc0',
  'In Progress': '#ffa726',
  'Review': '#ab47bc',
  'Done': '#66bb6a',
};

export const KanbanBoard: React.FC<KanbanBoardProps> = ({ projectId, onFindingClick }) => {
  const [board, setBoard] = useState<BoardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Dialogs
  const [addColumnOpen, setAddColumnOpen] = useState(false);
  const [newColumnName, setNewColumnName] = useState('');
  const [editColumnId, setEditColumnId] = useState<number | null>(null);
  const [editColumnName, setEditColumnName] = useState('');

  // Card dialogs
  const [addCardColumnId, setAddCardColumnId] = useState<number | null>(null);
  const [addCardDialogOpen, setAddCardDialogOpen] = useState(false);
  const [newCardTitle, setNewCardTitle] = useState('');
  const [selectedCard, setSelectedCard] = useState<CardData | null>(null);

  // Menu
  const [columnMenuAnchor, setColumnMenuAnchor] = useState<null | HTMLElement>(null);
  const [menuColumnId, setMenuColumnId] = useState<number | null>(null);

  // Filter state
  const [filtersExpanded, setFiltersExpanded] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [priorityFilter, setPriorityFilter] = useState<string>('all');
  const [assigneeFilter, setAssigneeFilter] = useState<string>('all');
  const [labelFilter, setLabelFilter] = useState<string>('all');
  const [dueDateFilter, setDueDateFilter] = useState<string>('all');
  const [showCompleted, setShowCompleted] = useState(true);

  // WebSocket handlers
  const handleCardCreated = useCallback((card: KanbanCardType, userId: number) => {
    setBoard(prev => {
      if (!prev) return prev;
      return {
        ...prev,
        columns: prev.columns.map(col =>
          col.id === card.column_id
            ? { ...col, cards: [...col.cards, card] }
            : col
        ),
      };
    });
  }, []);

  const handleCardUpdated = useCallback((cardId: number, updates: Partial<KanbanCardType>, userId: number) => {
    setBoard(prev => {
      if (!prev) return prev;
      return {
        ...prev,
        columns: prev.columns.map(col => ({
          ...col,
          cards: col.cards.map(card =>
            card.id === cardId ? { ...card, ...updates } : card
          ),
        })),
      };
    });
  }, []);

  const handleCardMoved = useCallback((cardId: number, sourceColumnId: number, targetColumnId: number, position: number, userId: number) => {
    setBoard(prev => {
      if (!prev) return prev;

      // Find the card
      let movedCard: KanbanCardType | undefined;
      const newColumns = prev.columns.map(col => {
        if (col.id === sourceColumnId) {
          const cardIndex = col.cards.findIndex(c => c.id === cardId);
          if (cardIndex >= 0) {
            movedCard = { ...col.cards[cardIndex], column_id: targetColumnId };
            return { ...col, cards: col.cards.filter(c => c.id !== cardId) };
          }
        }
        return col;
      });

      if (!movedCard) return prev;

      // Insert into target column
      return {
        ...prev,
        columns: newColumns.map(col => {
          if (col.id === targetColumnId) {
            const newCards = [...col.cards];
            newCards.splice(position, 0, movedCard!);
            return { ...col, cards: newCards };
          }
          return col;
        }),
      };
    });
  }, []);

  const handleCardDeleted = useCallback((cardId: number, userId: number) => {
    setBoard(prev => {
      if (!prev) return prev;
      return {
        ...prev,
        columns: prev.columns.map(col => ({
          ...col,
          cards: col.cards.filter(card => card.id !== cardId),
        })),
      };
    });
  }, []);

  const handleColumnCreated = useCallback((column: KanbanColumn, userId: number) => {
    setBoard(prev => {
      if (!prev) return prev;
      return {
        ...prev,
        columns: [...prev.columns, { ...column, cards: column.cards || [] }],
      };
    });
  }, []);

  const handleColumnUpdated = useCallback((columnId: number, updates: Partial<KanbanColumn>, userId: number) => {
    setBoard(prev => {
      if (!prev) return prev;
      return {
        ...prev,
        columns: prev.columns.map(col =>
          col.id === columnId ? { ...col, ...updates } : col
        ),
      };
    });
  }, []);

  const handleColumnDeleted = useCallback((columnId: number, userId: number) => {
    setBoard(prev => {
      if (!prev) return prev;
      return {
        ...prev,
        columns: prev.columns.filter(col => col.id !== columnId),
      };
    });
  }, []);

  const handleColumnsReordered = useCallback((columnIds: number[], userId: number) => {
    setBoard(prev => {
      if (!prev) return prev;
      const columnMap = new Map(prev.columns.map(col => [col.id, col]));
      const reorderedColumns = columnIds
        .map(id => columnMap.get(id))
        .filter((col): col is KanbanColumn => col !== undefined)
        .map((col, idx) => ({ ...col, position: idx }));
      return { ...prev, columns: reorderedColumns };
    });
  }, []);

  // WebSocket hook
  const { status: wsStatus, activeUsers } = useKanbanWebSocket({
    boardId: board?.id || 0,
    enabled: !!board?.id,
    onCardCreated: handleCardCreated,
    onCardUpdated: handleCardUpdated,
    onCardMoved: handleCardMoved,
    onCardDeleted: handleCardDeleted,
    onColumnCreated: handleColumnCreated,
    onColumnUpdated: handleColumnUpdated,
    onColumnDeleted: handleColumnDeleted,
    onColumnsReordered: handleColumnsReordered,
  });
  
  // Fetch board data
  const fetchBoard = useCallback(async () => {
    try {
      setLoading(true);
      const response = await kanbanApi.getProjectBoard(projectId);
      setBoard(response as BoardData);
      setError(null);
    } catch (err: unknown) {
      const error = err as Error;
      setError(error.message || 'Failed to load Kanban board');
    } finally {
      setLoading(false);
    }
  }, [projectId]);
  
  useEffect(() => {
    fetchBoard();
  }, [fetchBoard]);

  // Compute filter options from cards
  const filterOptions = useMemo(() => {
    if (!board) return { priorities: [], labels: [], assignees: [] };

    const allCards = board.columns.flatMap(c => c.cards);
    const priorities = [...new Set(allCards.map(c => c.priority).filter(Boolean))] as string[];
    const labels = [...new Set(allCards.flatMap(c => c.labels?.map(l => l.name) || []))];
    const assigneeMap = new Map<number, { user_id: number; username: string }>();
    allCards.forEach(card => {
      card.assignees?.forEach(a => {
        if (!assigneeMap.has(a.user_id)) {
          assigneeMap.set(a.user_id, { user_id: a.user_id, username: a.username });
        }
      });
    });

    return {
      priorities,
      labels,
      assignees: Array.from(assigneeMap.values()),
    };
  }, [board]);

  // Apply filters to columns
  const filteredColumns = useMemo(() => {
    if (!board) return [];

    return board.columns.map(column => ({
      ...column,
      cards: column.cards.filter(card => {
        // Text search (title, description, labels)
        if (searchQuery) {
          const query = searchQuery.toLowerCase();
          const matchesTitle = card.title.toLowerCase().includes(query);
          const matchesDesc = card.description?.toLowerCase().includes(query);
          const matchesLabels = card.labels?.some(l => l.name.toLowerCase().includes(query));
          if (!matchesTitle && !matchesDesc && !matchesLabels) {
            return false;
          }
        }

        // Priority filter
        if (priorityFilter !== 'all' && card.priority !== priorityFilter) {
          return false;
        }

        // Assignee filter
        if (assigneeFilter !== 'all') {
          const assigneeId = parseInt(assigneeFilter);
          if (!card.assignee_ids?.includes(assigneeId)) {
            return false;
          }
        }

        // Label filter
        if (labelFilter !== 'all') {
          if (!card.labels?.some(l => l.name === labelFilter)) {
            return false;
          }
        }

        // Due date filter
        if (dueDateFilter !== 'all') {
          const now = new Date();
          const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
          const weekFromNow = new Date(today.getTime() + 7 * 24 * 60 * 60 * 1000);

          if (dueDateFilter === 'overdue') {
            if (!card.due_date || new Date(card.due_date) >= today) return false;
          } else if (dueDateFilter === 'today') {
            if (!card.due_date) return false;
            const dueDate = new Date(card.due_date);
            if (dueDate < today || dueDate >= new Date(today.getTime() + 24 * 60 * 60 * 1000)) return false;
          } else if (dueDateFilter === 'week') {
            if (!card.due_date) return false;
            const dueDate = new Date(card.due_date);
            if (dueDate < today || dueDate > weekFromNow) return false;
          } else if (dueDateFilter === 'none') {
            if (card.due_date) return false;
          }
        }

        // Completed filter
        if (!showCompleted && card.completed_at) {
          return false;
        }

        return true;
      }),
    }));
  }, [board, searchQuery, priorityFilter, assigneeFilter, labelFilter, dueDateFilter, showCompleted]);

  // Count active filters
  const activeFilterCount = useMemo(() => {
    let count = 0;
    if (searchQuery) count++;
    if (priorityFilter !== 'all') count++;
    if (assigneeFilter !== 'all') count++;
    if (labelFilter !== 'all') count++;
    if (dueDateFilter !== 'all') count++;
    if (!showCompleted) count++;
    return count;
  }, [searchQuery, priorityFilter, assigneeFilter, labelFilter, dueDateFilter, showCompleted]);

  // Clear all filters
  const clearFilters = useCallback(() => {
    setSearchQuery('');
    setPriorityFilter('all');
    setAssigneeFilter('all');
    setLabelFilter('all');
    setDueDateFilter('all');
    setShowCompleted(true);
  }, []);

  // Drag and drop handler
  const handleDragEnd = async (result: DropResult) => {
    if (!result.destination || !board) return;
    
    const { source, destination, draggableId, type } = result;
    
    // Column reordering
    if (type === 'COLUMN') {
      const newColumns = Array.from(board.columns);
      const [movedColumn] = newColumns.splice(source.index, 1);
      newColumns.splice(destination.index, 0, movedColumn);
      
      // Update positions
      const reorderedColumns = newColumns.map((col, idx) => ({ ...col, position: idx }));
      setBoard({ ...board, columns: reorderedColumns });
      
      try {
        await kanbanApi.reorderColumns(board.id, reorderedColumns.map(c => c.id));
      } catch (err) {
        fetchBoard(); // Revert on error
      }
      return;
    }
    
    // Card movement
    const sourceColumn = board.columns.find(c => c.id === parseInt(source.droppableId));
    const destColumn = board.columns.find(c => c.id === parseInt(destination.droppableId));
    if (!sourceColumn || !destColumn) return;
    
    const cardId = parseInt(draggableId);
    const card = sourceColumn.cards.find(c => c.id === cardId);
    if (!card) return;
    
    // Same column reorder
    if (source.droppableId === destination.droppableId) {
      const newCards = Array.from(sourceColumn.cards);
      const [movedCard] = newCards.splice(source.index, 1);
      newCards.splice(destination.index, 0, movedCard);
      
      const updatedColumns = board.columns.map(col => {
        if (col.id === sourceColumn.id) {
          return { ...col, cards: newCards };
        }
        return col;
      });
      
      setBoard({ ...board, columns: updatedColumns });
    } else {
      // Move to different column
      const sourceCards = Array.from(sourceColumn.cards);
      const destCards = Array.from(destColumn.cards);
      const [movedCard] = sourceCards.splice(source.index, 1);
      destCards.splice(destination.index, 0, { ...movedCard, column_id: destColumn.id });
      
      const updatedColumns = board.columns.map(col => {
        if (col.id === sourceColumn.id) return { ...col, cards: sourceCards };
        if (col.id === destColumn.id) return { ...col, cards: destCards };
        return col;
      });
      
      setBoard({ ...board, columns: updatedColumns });
    }
    
    // API call to move card
    try {
      await kanbanApi.moveCard(cardId, parseInt(destination.droppableId), destination.index);
    } catch (err) {
      fetchBoard(); // Revert on error
    }
  };
  
  // Column operations
  const handleAddColumn = async () => {
    if (!newColumnName.trim() || !board) return;
    
    try {
      await kanbanApi.createColumn(board.id, {
        name: newColumnName.trim(),
      });
      setNewColumnName('');
      setAddColumnOpen(false);
      fetchBoard();
    } catch (err) {
      console.error('Failed to add column:', err);
    }
  };
  
  const handleEditColumn = async () => {
    if (!editColumnName.trim() || !editColumnId || !board) return;
    
    try {
      await kanbanApi.updateColumn(board.id, editColumnId, {
        name: editColumnName.trim(),
      });
      setEditColumnId(null);
      setEditColumnName('');
      fetchBoard();
    } catch (err) {
      console.error('Failed to edit column:', err);
    }
  };
  
  const handleDeleteColumn = async (columnId: number) => {
    if (!window.confirm('Delete this column and all its cards?') || !board) return;
    
    try {
      await kanbanApi.deleteColumn(board.id, columnId);
      fetchBoard();
    } catch (err) {
      console.error('Failed to delete column:', err);
    }
  };
  
  // Card operations
  const handleAddCard = async () => {
    if (!newCardTitle.trim() || !addCardColumnId) return;
    
    try {
      await kanbanApi.createCard(addCardColumnId, {
        title: newCardTitle.trim(),
      });
      setNewCardTitle('');
      setAddCardColumnId(null);
      fetchBoard();
    } catch (err) {
      console.error('Failed to add card:', err);
    }
  };
  
  const handleAddCardWithDetails = async (cardData: NewCardData) => {
    if (!addCardColumnId) return;
    
    try {
      await kanbanApi.createCard(addCardColumnId, {
        title: cardData.title,
        description: cardData.description,
        priority: cardData.priority as 'low' | 'medium' | 'high' | 'critical' | undefined,
        labels: cardData.labels,
        due_date: cardData.due_date,
        assignee_ids: cardData.assignee_ids,
        color: cardData.color,
      });
      setAddCardDialogOpen(false);
      setAddCardColumnId(null);
      fetchBoard();
    } catch (err) {
      console.error('Failed to add card:', err);
    }
  };
  
  const handleCardClick = (card: CardData) => {
    setSelectedCard(card);
  };
  
  const handleCardUpdate = () => {
    fetchBoard();
    setSelectedCard(null);
  };
  
  const handleCardDelete = async (cardId: number) => {
    try {
      await kanbanApi.deleteCard(cardId);
      fetchBoard();
      setSelectedCard(null);
    } catch (err) {
      console.error('Failed to delete card:', err);
    }
  };
  
  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 400 }}>
        <CircularProgress />
      </Box>
    );
  }
  
  if (error) {
    return (
      <Box sx={{ p: 2 }}>
        <Alert severity="error" action={
          <Button color="inherit" onClick={fetchBoard}>Retry</Button>
        }>
          {error}
        </Alert>
      </Box>
    );
  }
  
  if (!board) return null;
  
  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Board Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2, flexWrap: 'wrap' }}>
        <KanbanIcon color="primary" />
        <Typography variant="h6" sx={{ flexGrow: 1 }}>
          {board.name}
        </Typography>

        {/* Connection Status */}
        <Tooltip title={wsStatus === 'connected' ? 'Real-time sync active' : 'Connecting...'}>
          <Chip
            icon={wsStatus === 'connected' ? <WifiIcon /> : <WifiOffIcon />}
            label={wsStatus === 'connected' ? 'Live' : 'Offline'}
            size="small"
            color={wsStatus === 'connected' ? 'success' : 'default'}
            variant="outlined"
          />
        </Tooltip>

        {/* Active Users */}
        {activeUsers.length > 0 && (
          <Tooltip title={`${activeUsers.length} user${activeUsers.length > 1 ? 's' : ''} viewing: ${activeUsers.map(u => u.username).join(', ')}`}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <PeopleIcon fontSize="small" color="action" />
              <AvatarGroup max={3} sx={{ '& .MuiAvatar-root': { width: 24, height: 24, fontSize: '0.75rem' } }}>
                {activeUsers.map(user => (
                  <Avatar
                    key={user.user_id}
                    sx={{ bgcolor: user.color, width: 24, height: 24 }}
                  >
                    {user.username.charAt(0).toUpperCase()}
                  </Avatar>
                ))}
              </AvatarGroup>
            </Box>
          </Tooltip>
        )}

        {/* Filter Toggle */}
        <Tooltip title="Filter cards">
          <Badge badgeContent={activeFilterCount} color="primary">
            <IconButton
              onClick={() => setFiltersExpanded(!filtersExpanded)}
              size="small"
              color={filtersExpanded ? 'primary' : 'default'}
            >
              <FilterIcon />
            </IconButton>
          </Badge>
        </Tooltip>

        <Tooltip title="Refresh board">
          <IconButton onClick={fetchBoard} size="small">
            <RefreshIcon />
          </IconButton>
        </Tooltip>
        <Button
          variant="outlined"
          size="small"
          startIcon={<AddIcon />}
          onClick={() => setAddColumnOpen(true)}
        >
          Add Column
        </Button>
      </Box>

      {/* Filter Panel */}
      <Collapse in={filtersExpanded}>
        <Paper sx={{ p: 2, mb: 2, bgcolor: 'background.default' }}>
          <Grid container spacing={2} alignItems="center">
            {/* Search */}
            <Grid item xs={12} sm={6} md={3}>
              <TextField
                fullWidth
                size="small"
                placeholder="Search cards..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon fontSize="small" />
                    </InputAdornment>
                  ),
                  endAdornment: searchQuery && (
                    <InputAdornment position="end">
                      <IconButton size="small" onClick={() => setSearchQuery('')}>
                        <ClearIcon fontSize="small" />
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
              />
            </Grid>

            {/* Priority Filter */}
            <Grid item xs={6} sm={3} md={2}>
              <FormControl fullWidth size="small">
                <InputLabel>Priority</InputLabel>
                <Select
                  value={priorityFilter}
                  label="Priority"
                  onChange={(e) => setPriorityFilter(e.target.value)}
                >
                  <MenuItem value="all">All</MenuItem>
                  {filterOptions.priorities.map(p => (
                    <MenuItem key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            {/* Assignee Filter */}
            <Grid item xs={6} sm={3} md={2}>
              <FormControl fullWidth size="small">
                <InputLabel>Assignee</InputLabel>
                <Select
                  value={assigneeFilter}
                  label="Assignee"
                  onChange={(e) => setAssigneeFilter(e.target.value)}
                >
                  <MenuItem value="all">All</MenuItem>
                  {filterOptions.assignees.map(a => (
                    <MenuItem key={a.user_id} value={String(a.user_id)}>{a.username}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            {/* Label Filter */}
            <Grid item xs={6} sm={3} md={2}>
              <FormControl fullWidth size="small">
                <InputLabel>Label</InputLabel>
                <Select
                  value={labelFilter}
                  label="Label"
                  onChange={(e) => setLabelFilter(e.target.value)}
                >
                  <MenuItem value="all">All</MenuItem>
                  {filterOptions.labels.map(l => (
                    <MenuItem key={l} value={l}>{l}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            {/* Due Date Filter */}
            <Grid item xs={6} sm={3} md={2}>
              <FormControl fullWidth size="small">
                <InputLabel>Due Date</InputLabel>
                <Select
                  value={dueDateFilter}
                  label="Due Date"
                  onChange={(e) => setDueDateFilter(e.target.value)}
                >
                  <MenuItem value="all">All</MenuItem>
                  <MenuItem value="overdue">Overdue</MenuItem>
                  <MenuItem value="today">Today</MenuItem>
                  <MenuItem value="week">This Week</MenuItem>
                  <MenuItem value="none">No Due Date</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            {/* Show Completed Toggle */}
            <Grid item xs={6} sm={3} md={1}>
              <Tooltip title={showCompleted ? 'Hide completed cards' : 'Show completed cards'}>
                <Chip
                  label="Done"
                  onClick={() => setShowCompleted(!showCompleted)}
                  color={showCompleted ? 'default' : 'primary'}
                  variant={showCompleted ? 'outlined' : 'filled'}
                  size="small"
                />
              </Tooltip>
            </Grid>

            {/* Clear Filters */}
            {activeFilterCount > 0 && (
              <Grid item>
                <Button
                  size="small"
                  startIcon={<ClearIcon />}
                  onClick={clearFilters}
                >
                  Clear ({activeFilterCount})
                </Button>
              </Grid>
            )}
          </Grid>
        </Paper>
      </Collapse>

      {/* Kanban Columns */}
      <DragDropContext onDragEnd={handleDragEnd}>
        <Droppable droppableId="board" direction="horizontal" type="COLUMN">
          {(provided: DroppableProvided) => (
            <Box
              ref={provided.innerRef}
              {...provided.droppableProps}
              sx={{
                display: 'flex',
                gap: 2,
                overflowX: 'auto',
                flexGrow: 1,
                minHeight: 0,
                pb: 2,
              }}
            >
              {filteredColumns.map((column, index) => (
                <Draggable key={column.id} draggableId={`column-${column.id}`} index={index}>
                  {(provided: DraggableProvided) => (
                    <Paper
                      ref={provided.innerRef}
                      {...provided.draggableProps}
                      sx={{
                        minWidth: 300,
                        maxWidth: 300,
                        bgcolor: 'background.default',
                        display: 'flex',
                        flexDirection: 'column',
                        maxHeight: '100%',
                      }}
                    >
                      {/* Column Header */}
                      <Box
                        {...provided.dragHandleProps}
                        sx={{
                          p: 1.5,
                          borderBottom: 1,
                          borderColor: 'divider',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 1,
                          bgcolor: column.color || defaultColumnColors[column.name] || '#757575',
                          color: 'white',
                          borderRadius: '4px 4px 0 0',
                        }}
                      >
                        <DragIcon fontSize="small" sx={{ opacity: 0.7, cursor: 'grab' }} />
                        <Typography variant="subtitle1" fontWeight={600} sx={{ flexGrow: 1 }}>
                          {column.name}
                        </Typography>
                        <Badge
                          badgeContent={column.cards.length}
                          color={column.wip_limit && column.cards.length >= column.wip_limit ? 'error' : 'default'}
                          sx={{ mr: 1 }}
                        >
                          <Box />
                        </Badge>
                        <IconButton
                          size="small"
                          sx={{ color: 'white' }}
                          onClick={(e) => {
                            setColumnMenuAnchor(e.currentTarget);
                            setMenuColumnId(column.id);
                          }}
                        >
                          <MoreVertIcon fontSize="small" />
                        </IconButton>
                      </Box>
                      
                      {/* WIP Limit Warning */}
                      {column.wip_limit && column.cards.length >= column.wip_limit && (
                        <Alert severity="warning" sx={{ py: 0, px: 1 }}>
                          <Typography variant="caption">
                            WIP limit ({column.wip_limit}) reached
                          </Typography>
                        </Alert>
                      )}
                      
                      {/* Cards */}
                      <Droppable droppableId={String(column.id)} type="CARD">
                        {(provided: DroppableProvided, snapshot) => (
                          <Box
                            ref={provided.innerRef}
                            {...provided.droppableProps}
                            sx={{
                              p: 1,
                              flexGrow: 1,
                              overflowY: 'auto',
                              minHeight: 100,
                              bgcolor: snapshot.isDraggingOver ? 'action.hover' : 'transparent',
                              transition: 'background-color 0.2s',
                            }}
                          >
                            {column.cards.map((card, cardIndex) => (
                              <Draggable key={card.id} draggableId={String(card.id)} index={cardIndex}>
                                {(provided: DraggableProvided, snapshot) => (
                                  <div
                                    ref={provided.innerRef}
                                    {...provided.draggableProps}
                                    {...provided.dragHandleProps}
                                  >
                                    <KanbanCard
                                      card={card}
                                      onClick={() => handleCardClick(card)}
                                      isDragging={snapshot.isDragging}
                                      onFindingClick={onFindingClick}
                                    />
                                  </div>
                                )}
                              </Draggable>
                            ))}
                            {provided.placeholder}
                          </Box>
                        )}
                      </Droppable>
                      
                      {/* Add Card Button */}
                      <Box sx={{ p: 1, borderTop: 1, borderColor: 'divider' }}>
                        <Button
                          fullWidth
                          startIcon={<AddIcon />}
                          onClick={() => {
                            setAddCardColumnId(column.id);
                            setAddCardDialogOpen(true);
                          }}
                          sx={{ justifyContent: 'flex-start', color: 'text.secondary' }}
                        >
                          Add card
                        </Button>
                      </Box>
                    </Paper>
                  )}
                </Draggable>
              ))}
              {provided.placeholder}
            </Box>
          )}
        </Droppable>
      </DragDropContext>
      
      {/* Column Menu */}
      <Menu
        anchorEl={columnMenuAnchor}
        open={Boolean(columnMenuAnchor)}
        onClose={() => setColumnMenuAnchor(null)}
      >
        <MenuItem onClick={() => {
          const column = board.columns.find(c => c.id === menuColumnId);
          if (column) {
            setEditColumnId(column.id);
            setEditColumnName(column.name);
          }
          setColumnMenuAnchor(null);
        }}>
          <ListItemIcon><EditIcon fontSize="small" /></ListItemIcon>
          <ListItemText>Edit Column</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => {
          if (menuColumnId) handleDeleteColumn(menuColumnId);
          setColumnMenuAnchor(null);
        }}>
          <ListItemIcon><DeleteIcon fontSize="small" color="error" /></ListItemIcon>
          <ListItemText>Delete Column</ListItemText>
        </MenuItem>
      </Menu>
      
      {/* Add Column Dialog */}
      <Dialog open={addColumnOpen} onClose={() => setAddColumnOpen(false)}>
        <DialogTitle>Add Column</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            label="Column Name"
            value={newColumnName}
            onChange={(e) => setNewColumnName(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleAddColumn()}
            sx={{ mt: 1 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAddColumnOpen(false)}>Cancel</Button>
          <Button onClick={handleAddColumn} variant="contained" disabled={!newColumnName.trim()}>
            Add
          </Button>
        </DialogActions>
      </Dialog>
      
      {/* Edit Column Dialog */}
      <Dialog open={editColumnId !== null} onClose={() => setEditColumnId(null)}>
        <DialogTitle>Edit Column</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            label="Column Name"
            value={editColumnName}
            onChange={(e) => setEditColumnName(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleEditColumn()}
            sx={{ mt: 1 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditColumnId(null)}>Cancel</Button>
          <Button onClick={handleEditColumn} variant="contained" disabled={!editColumnName.trim()}>
            Save
          </Button>
        </DialogActions>
      </Dialog>
      
      {/* Card Detail Dialog */}
      {selectedCard && board && (
        <CardDetailDialog
          open={true}
          card={selectedCard}
          columns={board.columns}
          projectId={projectId}
          onClose={() => setSelectedCard(null)}
          onUpdate={handleCardUpdate}
          onDelete={() => handleCardDelete(selectedCard.id)}
          onFindingClick={onFindingClick}
        />
      )}
      
      {/* Add Card Dialog */}
      {addCardDialogOpen && addCardColumnId && board && (
        <AddCardDialog
          open={addCardDialogOpen}
          columnId={addCardColumnId}
          columnName={board.columns.find(c => c.id === addCardColumnId)?.name || ''}
          projectId={projectId}
          onClose={() => {
            setAddCardDialogOpen(false);
            setAddCardColumnId(null);
          }}
          onAdd={handleAddCardWithDetails}
        />
      )}
    </Box>
  );
};

export default KanbanBoard;
