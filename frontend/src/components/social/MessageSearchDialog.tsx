import React, { useState, useCallback, useRef } from "react";
import {
  Dialog,
  DialogTitle,
  DialogContent,
  TextField,
  Box,
  Typography,
  List,
  ListItemButton,
  ListItemText,
  CircularProgress,
  InputAdornment,
  Chip,
  IconButton,
  Divider,
} from "@mui/material";
import SearchIcon from "@mui/icons-material/Search";
import CloseIcon from "@mui/icons-material/Close";
import MessageIcon from "@mui/icons-material/Message";
import { socialApi, MessageSearchResult } from "../../api/client";

// Simple relative time formatter
const formatRelativeTime = (dateStr: string): string => {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.round(diffMs / 60000);
  const diffHours = Math.round(diffMs / 3600000);
  const diffDays = Math.round(diffMs / 86400000);
  
  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins} minutes ago`;
  if (diffHours < 24) return `${diffHours} hours ago`;
  if (diffDays < 7) return `${diffDays} days ago`;
  return date.toLocaleDateString();
};

interface MessageSearchDialogProps {
  open: boolean;
  onClose: () => void;
  conversationId?: number;
  onResultClick: (result: MessageSearchResult) => void;
}

export const MessageSearchDialog: React.FC<MessageSearchDialogProps> = ({
  open,
  onClose,
  conversationId,
  onResultClick,
}) => {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<MessageSearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [hasSearched, setHasSearched] = useState(false);
  const [total, setTotal] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const searchTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const performSearch = useCallback(
    async (searchQuery: string, append = false) => {
      if (!searchQuery.trim() || searchQuery.length < 2) {
        setResults([]);
        setTotal(0);
        setHasMore(false);
        setHasSearched(false);
        return;
      }

      setLoading(true);
      try {
        const skip = append ? results.length : 0;
        const response = await socialApi.searchMessages(
          searchQuery,
          conversationId,
          skip,
          30
        );

        if (append) {
          setResults((prev) => [...prev, ...response.results]);
        } else {
          setResults(response.results);
        }
        setTotal(response.total);
        setHasMore(response.has_more);
        setHasSearched(true);
      } catch (err) {
        console.error("Search failed:", err);
      } finally {
        setLoading(false);
      }
    },
    [conversationId, results.length]
  );

  const handleQueryChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newQuery = e.target.value;
    setQuery(newQuery);

    // Debounce search
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current);
    }

    searchTimeoutRef.current = setTimeout(() => {
      performSearch(newQuery);
    }, 300);
  };

  const handleResultClick = (result: MessageSearchResult) => {
    onResultClick(result);
    onClose();
  };

  const handleLoadMore = () => {
    if (!loading && hasMore) {
      performSearch(query, true);
    }
  };

  const handleClose = () => {
    setQuery("");
    setResults([]);
    setHasSearched(false);
    onClose();
  };

  // Render highlighted content
  const renderHighlightedContent = (content: string) => {
    // The backend returns content with <mark> tags for highlighting
    return (
      <Typography
        variant="body2"
        component="span"
        sx={{
          "& mark": {
            bgcolor: "warning.light",
            color: "warning.contrastText",
            px: 0.25,
            borderRadius: 0.5,
          },
        }}
        dangerouslySetInnerHTML={{ __html: content }}
      />
    );
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <SearchIcon color="primary" />
          Search Messages
          {conversationId && (
            <Chip size="small" label="Current conversation" variant="outlined" />
          )}
        </Box>
        <IconButton size="small" onClick={handleClose}>
          <CloseIcon />
        </IconButton>
      </DialogTitle>
      <DialogContent sx={{ p: 0 }}>
        <Box sx={{ px: 2, pb: 2 }}>
          <TextField
            fullWidth
            placeholder="Search for messages..."
            value={query}
            onChange={handleQueryChange}
            autoFocus
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon color="action" />
                </InputAdornment>
              ),
              endAdornment: loading && (
                <InputAdornment position="end">
                  <CircularProgress size={20} />
                </InputAdornment>
              ),
            }}
          />
        </Box>

        <Divider />

        {/* Results */}
        <Box sx={{ maxHeight: 400, overflowY: "auto" }}>
          {hasSearched && results.length === 0 && !loading && (
            <Box sx={{ p: 4, textAlign: "center" }}>
              <Typography color="text.secondary">
                No messages found for "{query}"
              </Typography>
            </Box>
          )}

          {!hasSearched && !loading && (
            <Box sx={{ p: 4, textAlign: "center" }}>
              <Typography color="text.secondary">
                Enter at least 2 characters to search
              </Typography>
            </Box>
          )}

          <List disablePadding>
            {results.map((result, index) => (
              <React.Fragment key={`${result.message_id}-${index}`}>
                <ListItemButton
                  onClick={() => handleResultClick(result)}
                  sx={{ py: 1.5 }}
                >
                  <Box sx={{ display: "flex", gap: 1.5, width: "100%" }}>
                    <MessageIcon color="action" sx={{ mt: 0.5 }} />
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
                        <Typography variant="subtitle2" fontWeight="medium">
                          {result.sender_username}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {formatRelativeTime(result.created_at)}
                        </Typography>
                      </Box>
                      
                      <Box sx={{ mb: 0.5 }}>
                        {renderHighlightedContent(result.highlighted_content)}
                      </Box>

                      {result.conversation_name && (
                        <Chip
                          size="small"
                          label={result.conversation_name}
                          variant="outlined"
                          sx={{ fontSize: "0.7rem", height: 20 }}
                        />
                      )}
                    </Box>
                  </Box>
                </ListItemButton>
                {index < results.length - 1 && <Divider />}
              </React.Fragment>
            ))}
          </List>

          {/* Load more */}
          {hasMore && (
            <Box sx={{ p: 2, textAlign: "center" }}>
              <Typography
                variant="body2"
                color="primary"
                sx={{ cursor: "pointer" }}
                onClick={handleLoadMore}
              >
                {loading ? "Loading..." : `Load more (${total - results.length} remaining)`}
              </Typography>
            </Box>
          )}
        </Box>

        {/* Total count */}
        {hasSearched && total > 0 && (
          <Box sx={{ px: 2, py: 1, borderTop: 1, borderColor: "divider" }}>
            <Typography variant="caption" color="text.secondary">
              {total} message{total !== 1 ? "s" : ""} found
            </Typography>
          </Box>
        )}
      </DialogContent>
    </Dialog>
  );
};

export default MessageSearchDialog;
