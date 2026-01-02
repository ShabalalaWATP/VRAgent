/**
 * KanbanBoard - Main Kanban board component with drag-and-drop
 */
import React, { useState, useCallback, useEffect } from 'react';
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
} from '@mui/material';
import {
  Add as AddIcon,
  MoreVert as MoreVertIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  DragIndicator as DragIcon,
  Refresh as RefreshIcon,
  ViewKanban as KanbanIcon,
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
import { kanbanApi, KanbanBoard as KanbanBoardType, KanbanColumn } from '../../api/client';

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
  const [newCardTitle, setNewCardTitle] = useState('');
  const [selectedCard, setSelectedCard] = useState<CardData | null>(null);
  
  // Menu
  const [columnMenuAnchor, setColumnMenuAnchor] = useState<null | HTMLElement>(null);
  const [menuColumnId, setMenuColumnId] = useState<number | null>(null);
  
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
              {board.columns.map((column, index) => (
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
                        {addCardColumnId === column.id ? (
                          <Box>
                            <TextField
                              fullWidth
                              size="small"
                              placeholder="Enter card title"
                              value={newCardTitle}
                              onChange={(e) => setNewCardTitle(e.target.value)}
                              onKeyPress={(e) => e.key === 'Enter' && handleAddCard()}
                              autoFocus
                              sx={{ mb: 1 }}
                            />
                            <Box sx={{ display: 'flex', gap: 1 }}>
                              <Button
                                variant="contained"
                                size="small"
                                onClick={handleAddCard}
                                disabled={!newCardTitle.trim()}
                              >
                                Add
                              </Button>
                              <Button
                                size="small"
                                onClick={() => {
                                  setAddCardColumnId(null);
                                  setNewCardTitle('');
                                }}
                              >
                                Cancel
                              </Button>
                            </Box>
                          </Box>
                        ) : (
                          <Button
                            fullWidth
                            startIcon={<AddIcon />}
                            onClick={() => setAddCardColumnId(column.id)}
                            sx={{ justifyContent: 'flex-start', color: 'text.secondary' }}
                          >
                            Add card
                          </Button>
                        )}
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
          onClose={() => setSelectedCard(null)}
          onUpdate={handleCardUpdate}
          onDelete={() => handleCardDelete(selectedCard.id)}
          onFindingClick={onFindingClick}
        />
      )}
    </Box>
  );
};

export default KanbanBoard;
