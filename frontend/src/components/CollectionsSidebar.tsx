import React, { useState, useEffect, useCallback } from "react";
import {
  Box,
  Typography,
  Paper,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemButton,
  IconButton,
  Button,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Menu,
  MenuItem,
  Collapse,
  Divider,
  Tooltip,
  CircularProgress,
  Alert,
  Chip,
  InputAdornment,
} from "@mui/material";
import {
  Folder as FolderIcon,
  FolderOpen as FolderOpenIcon,
  InsertDriveFile as RequestIcon,
  Add as AddIcon,
  MoreVert as MoreIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  ContentCopy as DuplicateIcon,
  DriveFileMove as MoveIcon,
  Upload as ImportIcon,
  Download as ExportIcon,
  Search as SearchIcon,
  CreateNewFolder as NewFolderIcon,
  PostAdd as NewRequestIcon,
  Collections as CollectionIcon,
  Refresh as RefreshIcon,
} from "@mui/icons-material";
import {
  apiCollections,
  APICollection,
  APICollectionFolder,
  APICollectionRequest,
} from "../api/client";

// HTTP Method colors
const getMethodColor = (method: string) => {
  switch (method?.toUpperCase()) {
    case "GET": return "#61affe";
    case "POST": return "#49cc90";
    case "PUT": return "#fca130";
    case "DELETE": return "#f93e3e";
    case "PATCH": return "#50e3c2";
    case "OPTIONS": return "#0d5aa7";
    case "HEAD": return "#9012fe";
    default: return "#999";
  }
};

interface CollectionsSidebarProps {
  onSelectRequest: (request: APICollectionRequest, collection: APICollection) => void;
  onSaveCurrentRequest?: (collectionId: number, folderId?: number) => void;
}

export default function CollectionsSidebar({
  onSelectRequest,
  onSaveCurrentRequest,
}: CollectionsSidebarProps) {
  // State
  const [collections, setCollections] = useState<APICollection[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  
  // Expanded state
  const [expandedCollections, setExpandedCollections] = useState<Set<number>>(new Set());
  const [expandedFolders, setExpandedFolders] = useState<Set<number>>(new Set());
  
  // Dialog state
  const [newCollectionOpen, setNewCollectionOpen] = useState(false);
  const [newCollectionName, setNewCollectionName] = useState("");
  const [newCollectionDesc, setNewCollectionDesc] = useState("");
  
  const [newFolderOpen, setNewFolderOpen] = useState(false);
  const [newFolderName, setNewFolderName] = useState("");
  const [newFolderParent, setNewFolderParent] = useState<{ collectionId: number; folderId?: number } | null>(null);
  
  const [editingItem, setEditingItem] = useState<{ type: "collection" | "folder" | "request"; id: number; name: string } | null>(null);
  
  const [importOpen, setImportOpen] = useState(false);
  const [importData, setImportData] = useState("");
  
  // Context menu
  const [contextMenu, setContextMenu] = useState<{
    mouseX: number;
    mouseY: number;
    type: "collection" | "folder" | "request";
    item: APICollection | APICollectionFolder | APICollectionRequest;
    collection?: APICollection;
  } | null>(null);

  // Load collections
  const loadCollections = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await apiCollections.listCollections();
      // Load full contents for each collection
      const fullCollections = await Promise.all(
        result.collections.map(async (c) => {
          try {
            const full = await apiCollections.getCollection(c.id!, true);
            return full.collection;
          } catch {
            return c;
          }
        })
      );
      setCollections(fullCollections);
    } catch (err: any) {
      setError(err.message || "Failed to load collections");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadCollections();
  }, [loadCollections]);

  // Toggle expansion
  const toggleCollection = (id: number) => {
    setExpandedCollections(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleFolder = (id: number) => {
    setExpandedFolders(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Create collection
  const handleCreateCollection = async () => {
    if (!newCollectionName.trim()) return;
    try {
      await apiCollections.createCollection({
        name: newCollectionName.trim(),
        description: newCollectionDesc.trim(),
      });
      setNewCollectionOpen(false);
      setNewCollectionName("");
      setNewCollectionDesc("");
      loadCollections();
    } catch (err: any) {
      setError(err.message);
    }
  };

  // Create folder
  const handleCreateFolder = async () => {
    if (!newFolderName.trim() || !newFolderParent) return;
    try {
      await apiCollections.createFolder({
        collection_id: newFolderParent.collectionId,
        parent_folder_id: newFolderParent.folderId,
        name: newFolderName.trim(),
      });
      setNewFolderOpen(false);
      setNewFolderName("");
      setNewFolderParent(null);
      loadCollections();
    } catch (err: any) {
      setError(err.message);
    }
  };

  // Context menu handlers
  const handleContextMenu = (
    event: React.MouseEvent,
    type: "collection" | "folder" | "request",
    item: APICollection | APICollectionFolder | APICollectionRequest,
    collection?: APICollection
  ) => {
    event.preventDefault();
    event.stopPropagation();
    setContextMenu({
      mouseX: event.clientX + 2,
      mouseY: event.clientY - 6,
      type,
      item,
      collection,
    });
  };

  const handleCloseContextMenu = () => {
    setContextMenu(null);
  };

  const handleDelete = async () => {
    if (!contextMenu) return;
    try {
      switch (contextMenu.type) {
        case "collection":
          await apiCollections.deleteCollection((contextMenu.item as APICollection).id!);
          break;
        case "folder":
          await apiCollections.deleteFolder((contextMenu.item as APICollectionFolder).id!);
          break;
        case "request":
          await apiCollections.deleteRequest((contextMenu.item as APICollectionRequest).id!);
          break;
      }
      loadCollections();
    } catch (err: any) {
      setError(err.message);
    }
    handleCloseContextMenu();
  };

  const handleDuplicate = async () => {
    if (!contextMenu) return;
    try {
      switch (contextMenu.type) {
        case "collection":
          await apiCollections.duplicateCollection((contextMenu.item as APICollection).id!);
          break;
        case "request":
          await apiCollections.duplicateRequest((contextMenu.item as APICollectionRequest).id!);
          break;
      }
      loadCollections();
    } catch (err: any) {
      setError(err.message);
    }
    handleCloseContextMenu();
  };

  const handleExport = async () => {
    if (!contextMenu || contextMenu.type !== "collection") return;
    try {
      const result = await apiCollections.exportCollection(
        (contextMenu.item as APICollection).id!,
        "postman"
      );
      const blob = new Blob([JSON.stringify(result.data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${(contextMenu.item as APICollection).name}.postman_collection.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setError(err.message);
    }
    handleCloseContextMenu();
  };

  const handleImport = async () => {
    try {
      const data = JSON.parse(importData);
      await apiCollections.importCollection(data, "auto");
      setImportOpen(false);
      setImportData("");
      loadCollections();
    } catch (err: any) {
      setError(err.message || "Invalid JSON");
    }
  };

  // Filter by search
  const filterItems = (items: any[], type: string): any[] => {
    if (!searchQuery) return items;
    const query = searchQuery.toLowerCase();
    return items.filter(item => {
      if (item.name?.toLowerCase().includes(query)) return true;
      if (item.url?.toLowerCase().includes(query)) return true;
      if (item.description?.toLowerCase().includes(query)) return true;
      return false;
    });
  };

  // Render folder recursively
  const renderFolder = (folder: APICollectionFolder, collection: APICollection, depth: number = 1) => {
    const isExpanded = expandedFolders.has(folder.id!);
    const hasChildren = (folder.subfolders?.length || 0) > 0 || (folder.requests?.length || 0) > 0;
    const filteredRequests = filterItems(folder.requests || [], "request");
    const filteredSubfolders = filterItems(folder.subfolders || [], "folder");

    return (
      <Box key={folder.id}>
        <ListItemButton
          sx={{ pl: 2 + depth * 2 }}
          onClick={() => toggleFolder(folder.id!)}
          onContextMenu={(e) => handleContextMenu(e, "folder", folder, collection)}
        >
          <ListItemIcon sx={{ minWidth: 32 }}>
            {isExpanded ? <FolderOpenIcon color="primary" /> : <FolderIcon color="primary" />}
          </ListItemIcon>
          <ListItemText
            primary={folder.name}
            primaryTypographyProps={{ variant: "body2" }}
          />
          {hasChildren && (
            isExpanded ? <ExpandLessIcon fontSize="small" /> : <ExpandMoreIcon fontSize="small" />
          )}
        </ListItemButton>
        <Collapse in={isExpanded}>
          {filteredSubfolders.map((sub) => renderFolder(sub, collection, depth + 1))}
          {filteredRequests.map((req) => renderRequest(req, collection, depth + 1))}
        </Collapse>
      </Box>
    );
  };

  // Render request
  const renderRequest = (request: APICollectionRequest, collection: APICollection, depth: number = 1) => (
    <ListItemButton
      key={request.id}
      sx={{ pl: 2 + depth * 2 }}
      onClick={() => onSelectRequest(request, collection)}
      onContextMenu={(e) => handleContextMenu(e, "request", request, collection)}
    >
      <ListItemIcon sx={{ minWidth: 32 }}>
        <Chip
          label={request.method}
          size="small"
          sx={{
            height: 20,
            fontSize: "0.65rem",
            fontWeight: "bold",
            bgcolor: getMethodColor(request.method),
            color: "white",
            minWidth: 45,
          }}
        />
      </ListItemIcon>
      <ListItemText
        primary={request.name}
        secondary={request.url}
        primaryTypographyProps={{ variant: "body2", noWrap: true }}
        secondaryTypographyProps={{ variant: "caption", noWrap: true, sx: { opacity: 0.7 } }}
      />
    </ListItemButton>
  );

  return (
    <Paper
      sx={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <Box sx={{ p: 1.5, borderBottom: 1, borderColor: "divider" }}>
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
          <Typography variant="subtitle1" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <CollectionIcon fontSize="small" color="primary" />
            Collections
          </Typography>
          <Box>
            <Tooltip title="Refresh">
              <IconButton size="small" onClick={loadCollections} disabled={loading}>
                <RefreshIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            <Tooltip title="Import Collection">
              <IconButton size="small" onClick={() => setImportOpen(true)}>
                <ImportIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            <Tooltip title="New Collection">
              <IconButton size="small" onClick={() => setNewCollectionOpen(true)} color="primary">
                <AddIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>
        <TextField
          size="small"
          fullWidth
          placeholder="Search..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon fontSize="small" />
              </InputAdornment>
            ),
          }}
        />
      </Box>

      {/* Error */}
      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ mx: 1, mt: 1 }}>
          {error}
        </Alert>
      )}

      {/* Loading */}
      {loading && (
        <Box sx={{ display: "flex", justifyContent: "center", p: 3 }}>
          <CircularProgress size={24} />
        </Box>
      )}

      {/* Collections List */}
      <Box sx={{ flex: 1, overflow: "auto" }}>
        {!loading && collections.length === 0 && (
          <Box sx={{ p: 3, textAlign: "center" }}>
            <CollectionIcon sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
            <Typography variant="body2" color="text.secondary" gutterBottom>
              No collections yet
            </Typography>
            <Button
              variant="outlined"
              size="small"
              startIcon={<AddIcon />}
              onClick={() => setNewCollectionOpen(true)}
            >
              Create Collection
            </Button>
          </Box>
        )}

        <List dense disablePadding>
          {collections.map((collection) => {
            const isExpanded = expandedCollections.has(collection.id!);
            const filteredFolders = filterItems(collection.folders || [], "folder");
            const filteredRequests = filterItems(collection.requests || [], "request");

            return (
              <Box key={collection.id}>
                <ListItemButton
                  onClick={() => toggleCollection(collection.id!)}
                  onContextMenu={(e) => handleContextMenu(e, "collection", collection)}
                  sx={{ bgcolor: "action.hover" }}
                >
                  <ListItemIcon sx={{ minWidth: 32 }}>
                    <CollectionIcon color="secondary" />
                  </ListItemIcon>
                  <ListItemText
                    primary={collection.name}
                    secondary={`${collection.request_count || 0} requests`}
                    primaryTypographyProps={{ fontWeight: "medium" }}
                    secondaryTypographyProps={{ variant: "caption" }}
                  />
                  {isExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                </ListItemButton>
                <Collapse in={isExpanded}>
                  {/* Add folder/request buttons */}
                  <Box sx={{ pl: 4, py: 0.5 }}>
                    <Button
                      size="small"
                      startIcon={<NewFolderIcon />}
                      onClick={() => {
                        setNewFolderParent({ collectionId: collection.id! });
                        setNewFolderOpen(true);
                      }}
                      sx={{ mr: 1, fontSize: "0.7rem" }}
                    >
                      Folder
                    </Button>
                    {onSaveCurrentRequest && (
                      <Button
                        size="small"
                        startIcon={<NewRequestIcon />}
                        onClick={() => onSaveCurrentRequest(collection.id!)}
                        sx={{ fontSize: "0.7rem" }}
                      >
                        Save Request
                      </Button>
                    )}
                  </Box>
                  {filteredFolders.map((folder) => renderFolder(folder, collection))}
                  {filteredRequests.map((request) => renderRequest(request, collection, 1))}
                </Collapse>
                <Divider />
              </Box>
            );
          })}
        </List>
      </Box>

      {/* Context Menu */}
      <Menu
        open={contextMenu !== null}
        onClose={handleCloseContextMenu}
        anchorReference="anchorPosition"
        anchorPosition={
          contextMenu !== null
            ? { top: contextMenu.mouseY, left: contextMenu.mouseX }
            : undefined
        }
      >
        {contextMenu?.type === "collection" && (
          <MenuItem onClick={() => {
            setNewFolderParent({ collectionId: (contextMenu.item as APICollection).id! });
            setNewFolderOpen(true);
            handleCloseContextMenu();
          }}>
            <ListItemIcon><NewFolderIcon fontSize="small" /></ListItemIcon>
            Add Folder
          </MenuItem>
        )}
        {contextMenu?.type === "folder" && (
          <MenuItem onClick={() => {
            const folder = contextMenu.item as APICollectionFolder;
            setNewFolderParent({ collectionId: folder.collection_id!, folderId: folder.id });
            setNewFolderOpen(true);
            handleCloseContextMenu();
          }}>
            <ListItemIcon><NewFolderIcon fontSize="small" /></ListItemIcon>
            Add Subfolder
          </MenuItem>
        )}
        <MenuItem onClick={() => {
          setEditingItem({
            type: contextMenu!.type,
            id: (contextMenu!.item as any).id,
            name: (contextMenu!.item as any).name,
          });
          handleCloseContextMenu();
        }}>
          <ListItemIcon><EditIcon fontSize="small" /></ListItemIcon>
          Rename
        </MenuItem>
        {contextMenu?.type !== "folder" && (
          <MenuItem onClick={handleDuplicate}>
            <ListItemIcon><DuplicateIcon fontSize="small" /></ListItemIcon>
            Duplicate
          </MenuItem>
        )}
        {contextMenu?.type === "collection" && (
          <MenuItem onClick={handleExport}>
            <ListItemIcon><ExportIcon fontSize="small" /></ListItemIcon>
            Export (Postman)
          </MenuItem>
        )}
        <Divider />
        <MenuItem onClick={handleDelete} sx={{ color: "error.main" }}>
          <ListItemIcon><DeleteIcon fontSize="small" color="error" /></ListItemIcon>
          Delete
        </MenuItem>
      </Menu>

      {/* New Collection Dialog */}
      <Dialog open={newCollectionOpen} onClose={() => setNewCollectionOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create New Collection</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            label="Collection Name"
            value={newCollectionName}
            onChange={(e) => setNewCollectionName(e.target.value)}
            sx={{ mt: 1, mb: 2 }}
          />
          <TextField
            fullWidth
            label="Description (optional)"
            value={newCollectionDesc}
            onChange={(e) => setNewCollectionDesc(e.target.value)}
            multiline
            rows={2}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNewCollectionOpen(false)}>Cancel</Button>
          <Button onClick={handleCreateCollection} variant="contained" disabled={!newCollectionName.trim()}>
            Create
          </Button>
        </DialogActions>
      </Dialog>

      {/* New Folder Dialog */}
      <Dialog open={newFolderOpen} onClose={() => setNewFolderOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create New Folder</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            label="Folder Name"
            value={newFolderName}
            onChange={(e) => setNewFolderName(e.target.value)}
            sx={{ mt: 1 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNewFolderOpen(false)}>Cancel</Button>
          <Button onClick={handleCreateFolder} variant="contained" disabled={!newFolderName.trim()}>
            Create
          </Button>
        </DialogActions>
      </Dialog>

      {/* Rename Dialog */}
      <Dialog open={editingItem !== null} onClose={() => setEditingItem(null)} maxWidth="sm" fullWidth>
        <DialogTitle>Rename {editingItem?.type}</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            label="Name"
            value={editingItem?.name || ""}
            onChange={(e) => setEditingItem(prev => prev ? { ...prev, name: e.target.value } : null)}
            sx={{ mt: 1 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditingItem(null)}>Cancel</Button>
          <Button
            variant="contained"
            disabled={!editingItem?.name?.trim()}
            onClick={async () => {
              if (!editingItem) return;
              try {
                switch (editingItem.type) {
                  case "collection":
                    await apiCollections.updateCollection(editingItem.id, { name: editingItem.name });
                    break;
                  case "folder":
                    await apiCollections.updateFolder(editingItem.id, { name: editingItem.name });
                    break;
                  case "request":
                    await apiCollections.updateRequest(editingItem.id, { name: editingItem.name });
                    break;
                }
                setEditingItem(null);
                loadCollections();
              } catch (err: any) {
                setError(err.message);
              }
            }}
          >
            Save
          </Button>
        </DialogActions>
      </Dialog>

      {/* Import Dialog */}
      <Dialog open={importOpen} onClose={() => setImportOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Import Collection</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Paste a Postman collection JSON or drag & drop a file.
          </Typography>
          <TextField
            fullWidth
            multiline
            rows={12}
            placeholder="Paste collection JSON here..."
            value={importData}
            onChange={(e) => setImportData(e.target.value)}
            sx={{ fontFamily: "monospace" }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setImportOpen(false)}>Cancel</Button>
          <Button onClick={handleImport} variant="contained" disabled={!importData.trim()}>
            Import
          </Button>
        </DialogActions>
      </Dialog>
    </Paper>
  );
}
