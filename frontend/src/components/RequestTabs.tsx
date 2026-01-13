import React, { useState, useCallback } from "react";
import {
  Box,
  Tabs,
  Tab,
  IconButton,
  Typography,
  Chip,
  Tooltip,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Divider,
} from "@mui/material";
import {
  Add as AddIcon,
  Close as CloseIcon,
  MoreVert as MoreIcon,
  ContentCopy as DuplicateIcon,
  ClearAll as CloseAllIcon,
  Save as SaveIcon,
  Folder as FolderIcon,
} from "@mui/icons-material";

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

export interface RequestTab {
  id: string;
  name: string;
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  isDirty?: boolean;
  collectionId?: number;
  requestId?: number;
  response?: {
    status: number;
    statusText: string;
    headers: Record<string, string>;
    body: string;
    time: number;
    size: number;
  };
}

interface RequestTabsProps {
  tabs: RequestTab[];
  activeTabId: string;
  onTabChange: (tabId: string) => void;
  onTabClose: (tabId: string) => void;
  onTabAdd: () => void;
  onTabDuplicate?: (tabId: string) => void;
  onCloseOthers?: (tabId: string) => void;
  onCloseAll?: () => void;
  onSaveTab?: (tabId: string) => void;
  maxTabs?: number;
}

export default function RequestTabs({
  tabs,
  activeTabId,
  onTabChange,
  onTabClose,
  onTabAdd,
  onTabDuplicate,
  onCloseOthers,
  onCloseAll,
  onSaveTab,
  maxTabs = 20,
}: RequestTabsProps) {
  const [menuAnchorEl, setMenuAnchorEl] = useState<null | HTMLElement>(null);
  const [contextTabId, setContextTabId] = useState<string | null>(null);

  // Handle tab context menu
  const handleContextMenu = (event: React.MouseEvent, tabId: string) => {
    event.preventDefault();
    event.stopPropagation();
    setContextTabId(tabId);
    setMenuAnchorEl(event.currentTarget as HTMLElement);
  };

  // Handle close menu
  const handleCloseMenu = () => {
    setMenuAnchorEl(null);
    setContextTabId(null);
  };

  // Get display name for tab
  const getTabLabel = (tab: RequestTab) => {
    if (tab.name && tab.name !== "New Request") {
      return tab.name;
    }
    if (tab.url) {
      try {
        const urlObj = new URL(tab.url);
        return urlObj.pathname || tab.url;
      } catch {
        return tab.url.substring(0, 30) || "New Request";
      }
    }
    return "New Request";
  };

  // Find active tab index
  const activeIndex = tabs.findIndex(t => t.id === activeTabId);

  return (
    <Box sx={{ borderBottom: 1, borderColor: "divider", bgcolor: "background.paper" }}>
      <Box sx={{ display: "flex", alignItems: "center" }}>
        <Tabs
          value={activeIndex >= 0 ? activeIndex : 0}
          onChange={(_, newValue) => {
            if (tabs[newValue]) {
              onTabChange(tabs[newValue].id);
            }
          }}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            flexGrow: 1,
            minHeight: 40,
            "& .MuiTab-root": {
              minHeight: 40,
              py: 0.5,
              px: 1,
              textTransform: "none",
            },
          }}
        >
          {tabs.map((tab) => (
            <Tab
              key={tab.id}
              label={
                <Box
                  sx={{
                    display: "flex",
                    alignItems: "center",
                    gap: 0.5,
                    maxWidth: 200,
                  }}
                  onContextMenu={(e) => handleContextMenu(e, tab.id)}
                >
                  <Chip
                    label={tab.method || "GET"}
                    size="small"
                    sx={{
                      height: 16,
                      fontSize: "0.6rem",
                      fontWeight: "bold",
                      bgcolor: getMethodColor(tab.method),
                      color: "white",
                      "& .MuiChip-label": {
                        px: 0.5,
                      },
                    }}
                  />
                  <Typography
                    variant="body2"
                    sx={{
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      maxWidth: 120,
                      fontSize: "0.8rem",
                    }}
                  >
                    {getTabLabel(tab)}
                  </Typography>
                  {tab.isDirty && (
                    <Box
                      sx={{
                        width: 6,
                        height: 6,
                        borderRadius: "50%",
                        bgcolor: "warning.main",
                      }}
                    />
                  )}
                  <IconButton
                    size="small"
                    onClick={(e) => {
                      e.stopPropagation();
                      onTabClose(tab.id);
                    }}
                    sx={{
                      p: 0.25,
                      ml: 0.5,
                      opacity: 0.6,
                      "&:hover": { opacity: 1 },
                    }}
                  >
                    <CloseIcon sx={{ fontSize: 14 }} />
                  </IconButton>
                </Box>
              }
              sx={{
                bgcolor: tab.id === activeTabId ? "action.selected" : "transparent",
              }}
            />
          ))}
        </Tabs>

        {/* Add new tab button */}
        <Tooltip title="New Request (Ctrl+N)">
          <IconButton
            size="small"
            onClick={onTabAdd}
            disabled={tabs.length >= maxTabs}
            sx={{ mx: 1 }}
          >
            <AddIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>

      {/* Context Menu */}
      <Menu
        anchorEl={menuAnchorEl}
        open={Boolean(menuAnchorEl)}
        onClose={handleCloseMenu}
      >
        <MenuItem
          onClick={() => {
            if (contextTabId) {
              onTabClose(contextTabId);
            }
            handleCloseMenu();
          }}
        >
          <ListItemIcon>
            <CloseIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Close</ListItemText>
        </MenuItem>
        {onCloseOthers && (
          <MenuItem
            onClick={() => {
              if (contextTabId) {
                onCloseOthers(contextTabId);
              }
              handleCloseMenu();
            }}
            disabled={tabs.length <= 1}
          >
            <ListItemIcon>
              <CloseAllIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>Close Others</ListItemText>
          </MenuItem>
        )}
        {onCloseAll && (
          <MenuItem
            onClick={() => {
              onCloseAll();
              handleCloseMenu();
            }}
          >
            <ListItemIcon>
              <CloseAllIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>Close All</ListItemText>
          </MenuItem>
        )}
        <Divider />
        {onTabDuplicate && (
          <MenuItem
            onClick={() => {
              if (contextTabId) {
                onTabDuplicate(contextTabId);
              }
              handleCloseMenu();
            }}
          >
            <ListItemIcon>
              <DuplicateIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>Duplicate</ListItemText>
          </MenuItem>
        )}
        {onSaveTab && (
          <MenuItem
            onClick={() => {
              if (contextTabId) {
                onSaveTab(contextTabId);
              }
              handleCloseMenu();
            }}
          >
            <ListItemIcon>
              <SaveIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>Save to Collection</ListItemText>
          </MenuItem>
        )}
      </Menu>
    </Box>
  );
}

// Helper to generate unique tab IDs
export const generateTabId = () => `tab-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

// Helper to create a new empty tab
export const createNewTab = (): RequestTab => ({
  id: generateTabId(),
  name: "New Request",
  method: "GET",
  url: "",
  headers: {},
  body: "",
  isDirty: false,
});
