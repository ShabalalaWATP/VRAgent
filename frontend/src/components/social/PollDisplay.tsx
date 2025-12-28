import React, { useState } from "react";
import {
  Box,
  Typography,
  LinearProgress,
  Chip,
  Button,
  TextField,
  IconButton,
  Tooltip,
  Avatar,
  AvatarGroup,
  Collapse,
} from "@mui/material";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import RadioButtonUncheckedIcon from "@mui/icons-material/RadioButtonUnchecked";
import CheckBoxIcon from "@mui/icons-material/CheckBox";
import CheckBoxOutlineBlankIcon from "@mui/icons-material/CheckBoxOutlineBlank";
import AddIcon from "@mui/icons-material/Add";
import LockIcon from "@mui/icons-material/Lock";
import TimerIcon from "@mui/icons-material/Timer";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import { socialApi, PollResponse, PollOptionResponse } from "../../api/client";

// Simple relative time formatter
const formatRelativeTime = (dateStr: string): string => {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = date.getTime() - now.getTime();
  const diffMins = Math.round(diffMs / 60000);
  const diffHours = Math.round(diffMs / 3600000);
  const diffDays = Math.round(diffMs / 86400000);
  
  if (diffMs < 0) {
    // Past
    if (diffMins > -60) return `${-diffMins} minutes ago`;
    if (diffHours > -24) return `${-diffHours} hours ago`;
    return `${-diffDays} days ago`;
  } else {
    // Future
    if (diffMins < 60) return `in ${diffMins} minutes`;
    if (diffHours < 24) return `in ${diffHours} hours`;
    return `in ${diffDays} days`;
  }
};

interface PollDisplayProps {
  poll: PollResponse;
  onUpdate?: (poll: PollResponse) => void;
  compact?: boolean;
}

export const PollDisplay: React.FC<PollDisplayProps> = ({
  poll,
  onUpdate,
  compact = false,
}) => {
  const [selectedOptions, setSelectedOptions] = useState<number[]>([]);
  const [hasVoted, setHasVoted] = useState(
    poll.options.some((opt) => opt.has_voted)
  );
  const [loading, setLoading] = useState(false);
  const [newOption, setNewOption] = useState("");
  const [showAddOption, setShowAddOption] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isExpired =
    poll.closes_at && new Date(poll.closes_at) < new Date();
  const isClosed = poll.is_closed || isExpired;

  const handleOptionClick = (optionId: number) => {
    if (isClosed || hasVoted) return;

    if (poll.poll_type === "single") {
      setSelectedOptions([optionId]);
    } else {
      setSelectedOptions((prev) =>
        prev.includes(optionId)
          ? prev.filter((id) => id !== optionId)
          : [...prev, optionId]
      );
    }
  };

  const handleVote = async () => {
    if (selectedOptions.length === 0) return;

    setLoading(true);
    setError(null);
    try {
      const result = await socialApi.voteOnPoll(poll.id, selectedOptions);
      setHasVoted(true);
      onUpdate?.(result.poll);
    } catch (err: any) {
      setError(err.message || "Failed to vote");
    } finally {
      setLoading(false);
    }
  };

  const handleAddOption = async () => {
    if (!newOption.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const result = await socialApi.addPollOption(poll.id, newOption.trim());
      setNewOption("");
      setShowAddOption(false);
      onUpdate?.(result.poll);
    } catch (err: any) {
      setError(err.message || "Failed to add option");
    } finally {
      setLoading(false);
    }
  };

  const handleClosePoll = async () => {
    setLoading(true);
    try {
      const result = await socialApi.closePoll(poll.id);
      onUpdate?.(result.poll);
    } catch (err: any) {
      setError(err.message || "Failed to close poll");
    } finally {
      setLoading(false);
    }
  };

  const renderOption = (option: PollOptionResponse) => {
    const isSelected = selectedOptions.includes(option.id);
    const showResults = hasVoted || isClosed;
    const Icon =
      poll.poll_type === "single"
        ? isSelected || option.has_voted
          ? CheckCircleIcon
          : RadioButtonUncheckedIcon
        : isSelected || option.has_voted
        ? CheckBoxIcon
        : CheckBoxOutlineBlankIcon;

    return (
      <Box
        key={option.id}
        onClick={() => handleOptionClick(option.id)}
        sx={{
          position: "relative",
          p: 1.5,
          mb: 1,
          borderRadius: 1,
          border: 1,
          borderColor: isSelected
            ? "primary.main"
            : option.has_voted
            ? "success.main"
            : "divider",
          bgcolor: "background.default",
          cursor: isClosed || hasVoted ? "default" : "pointer",
          transition: "all 0.2s",
          overflow: "hidden",
          "&:hover": {
            borderColor: isClosed || hasVoted ? undefined : "primary.light",
            bgcolor: isClosed || hasVoted ? undefined : "action.hover",
          },
        }}
      >
        {/* Progress bar background */}
        {showResults && (
          <Box
            sx={{
              position: "absolute",
              top: 0,
              left: 0,
              height: "100%",
              width: `${option.percentage}%`,
              bgcolor: option.has_voted
                ? "success.light"
                : "primary.light",
              opacity: 0.25,
              transition: "width 0.5s ease",
            }}
          />
        )}

        <Box
          sx={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            position: "relative",
            zIndex: 1,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <Icon
              fontSize="small"
              color={option.has_voted ? "success" : isSelected ? "primary" : "action"}
            />
            <Typography variant="body2">{option.text}</Typography>
          </Box>

          {showResults && (
            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              {!poll.is_anonymous && option.voters && option.voters.length > 0 && (
                <AvatarGroup max={3} sx={{ "& .MuiAvatar-root": { width: 20, height: 20, fontSize: "0.65rem" } }}>
                  {option.voters.map((voter) => (
                    <Tooltip key={voter} title={voter}>
                      <Avatar sx={{ width: 20, height: 20, fontSize: "0.65rem" }}>
                        {voter[0].toUpperCase()}
                      </Avatar>
                    </Tooltip>
                  ))}
                </AvatarGroup>
              )}
              <Typography variant="caption" fontWeight="medium">
                {option.percentage.toFixed(0)}%
              </Typography>
              <Typography variant="caption" color="text.secondary">
                ({option.vote_count})
              </Typography>
            </Box>
          )}
        </Box>
      </Box>
    );
  };

  const displayedOptions = compact && !expanded 
    ? poll.options.slice(0, 3) 
    : poll.options;
  const hasMoreOptions = compact && poll.options.length > 3;

  return (
    <Box
      sx={{
        bgcolor: "background.paper",
        borderRadius: 2,
        p: 2,
        border: 1,
        borderColor: "divider",
        maxWidth: 400,
        boxShadow: 1,
        // Ensure proper visibility in both light and dark mode
        "& .MuiTypography-root": {
          color: "text.primary",
        },
        "& .MuiChip-outlined": {
          borderColor: "divider",
          color: "text.secondary",
        },
      }}
    >
      {/* Header */}
      <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 1.5 }}>
        <Typography variant="subtitle1" fontWeight="medium">
          {poll.question}
        </Typography>
        {isClosed && (
          <Chip
            size="small"
            icon={<LockIcon />}
            label="Closed"
            color="default"
            variant="outlined"
          />
        )}
      </Box>

      {/* Meta info */}
      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2 }}>
        {poll.poll_type === "multiple" && (
          <Chip size="small" label="Multiple choice" variant="outlined" />
        )}
        {poll.is_anonymous && (
          <Chip size="small" label="Anonymous" variant="outlined" />
        )}
        {poll.closes_at && !isClosed && (
          <Chip
            size="small"
            icon={<TimerIcon />}
            label={`Closes ${formatRelativeTime(poll.closes_at)}`}
            variant="outlined"
            color="warning"
          />
        )}
      </Box>

      {/* Options */}
      {displayedOptions.map(renderOption)}

      {hasMoreOptions && (
        <Button
          size="small"
          onClick={() => setExpanded(!expanded)}
          endIcon={expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          sx={{ mb: 1 }}
        >
          {expanded ? "Show less" : `Show ${poll.options.length - 3} more`}
        </Button>
      )}

      {/* Add option */}
      {poll.allow_add_options && !isClosed && (
        <Collapse in={showAddOption}>
          <Box sx={{ display: "flex", gap: 1, mb: 1 }}>
            <TextField
              size="small"
              fullWidth
              placeholder="Add new option..."
              value={newOption}
              onChange={(e) => setNewOption(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleAddOption()}
            />
            <Button
              size="small"
              variant="contained"
              onClick={handleAddOption}
              disabled={loading || !newOption.trim()}
            >
              Add
            </Button>
          </Box>
        </Collapse>
      )}

      {error && (
        <Typography color="error" variant="caption" display="block" sx={{ mb: 1 }}>
          {error}
        </Typography>
      )}

      {/* Actions */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mt: 1 }}>
        <Typography variant="caption" color="text.secondary">
          {poll.total_votes} vote{poll.total_votes !== 1 ? "s" : ""} • by {poll.creator_username}
        </Typography>

        <Box sx={{ display: "flex", gap: 1 }}>
          {poll.allow_add_options && !isClosed && !showAddOption && (
            <IconButton size="small" onClick={() => setShowAddOption(true)}>
              <AddIcon fontSize="small" />
            </IconButton>
          )}
          
          {!hasVoted && !isClosed && (
            <Button
              size="small"
              variant="contained"
              onClick={handleVote}
              disabled={loading || selectedOptions.length === 0}
            >
              {loading ? "Voting..." : "Vote"}
            </Button>
          )}
        </Box>
      </Box>
    </Box>
  );
};

export default PollDisplay;
