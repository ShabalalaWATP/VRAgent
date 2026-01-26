import React, { useState } from "react";
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Box,
  IconButton,
  Typography,
  FormControlLabel,
  Switch,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Alert,
  Chip,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import PollIcon from "@mui/icons-material/Poll";
import { socialApi, PollCreate, PollType } from "../../api/client";

interface PollCreatorProps {
  open: boolean;
  onClose: () => void;
  conversationId: number;
  onPollCreated: () => void;
}

export const PollCreator: React.FC<PollCreatorProps> = ({
  open,
  onClose,
  conversationId,
  onPollCreated,
}) => {
  const [question, setQuestion] = useState("");
  const [options, setOptions] = useState<string[]>(["", ""]);
  const [pollType, setPollType] = useState<PollType>("single");
  const [isAnonymous, setIsAnonymous] = useState(false);
  const [allowAddOptions, setAllowAddOptions] = useState(false);
  const [expiresIn, setExpiresIn] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleAddOption = () => {
    if (options.length < 10) {
      setOptions([...options, ""]);
    }
  };

  const handleRemoveOption = (index: number) => {
    if (options.length > 2) {
      setOptions(options.filter((_, i) => i !== index));
    }
  };

  const handleOptionChange = (index: number, value: string) => {
    const newOptions = [...options];
    newOptions[index] = value;
    setOptions(newOptions);
  };

  const handleSubmit = async () => {
    // Validate
    if (!question.trim()) {
      setError("Please enter a question");
      return;
    }

    const validOptions = options.filter((o) => o.trim());
    if (validOptions.length < 2) {
      setError("Please provide at least 2 options");
      return;
    }

    // Validate option lengths (max 200 chars each)
    const MAX_OPTION_LENGTH = 200;
    const tooLongOptions = validOptions.filter((o) => o.trim().length > MAX_OPTION_LENGTH);
    if (tooLongOptions.length > 0) {
      setError(`Poll options must be ${MAX_OPTION_LENGTH} characters or less`);
      return;
    }

    // Check for duplicate options (case-insensitive)
    const normalizedOptions = validOptions.map((o) => o.trim().toLowerCase());
    const uniqueOptions = new Set(normalizedOptions);
    if (uniqueOptions.size !== normalizedOptions.length) {
      setError("Poll options must be unique");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const pollData: PollCreate = {
        question: question.trim(),
        options: validOptions,
        poll_type: pollType,
        is_anonymous: isAnonymous,
        allow_add_options: allowAddOptions,
      };

      if (expiresIn) {
        const closesAt = new Date();
        closesAt.setHours(closesAt.getHours() + expiresIn);
        pollData.closes_at = closesAt.toISOString();
      }

      await socialApi.createPoll(conversationId, pollData);
      onPollCreated();
      handleClose();
    } catch (err: any) {
      setError(err.message || "Failed to create poll");
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setQuestion("");
    setOptions(["", ""]);
    setPollType("single");
    setIsAnonymous(false);
    setAllowAddOptions(false);
    setExpiresIn(null);
    setError(null);
    onClose();
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <PollIcon color="primary" />
        Create Poll
      </DialogTitle>
      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <TextField
          fullWidth
          label="Question"
          placeholder="What would you like to ask?"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          sx={{ mb: 2, mt: 1 }}
          autoFocus
        />

        <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>
          Options
        </Typography>

        {options.map((option, index) => (
          <Box key={index} sx={{ display: "flex", gap: 1, mb: 1.5 }}>
            <TextField
              fullWidth
              size="small"
              placeholder={`Option ${index + 1}`}
              value={option}
              onChange={(e) => handleOptionChange(index, e.target.value)}
            />
            {options.length > 2 && (
              <IconButton
                size="small"
                onClick={() => handleRemoveOption(index)}
                color="error"
              >
                <DeleteIcon fontSize="small" />
              </IconButton>
            )}
          </Box>
        ))}

        {options.length < 10 && (
          <Button
            size="small"
            startIcon={<AddIcon />}
            onClick={handleAddOption}
            sx={{ mb: 2 }}
          >
            Add Option
          </Button>
        )}

        <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 2 }}>
          <FormControl size="small" sx={{ minWidth: 140 }}>
            <InputLabel>Vote Type</InputLabel>
            <Select
              value={pollType}
              label="Vote Type"
              onChange={(e) => setPollType(e.target.value as PollType)}
            >
              <MenuItem value="single">Single Choice</MenuItem>
              <MenuItem value="multiple">Multiple Choice</MenuItem>
            </Select>
          </FormControl>

          <FormControl size="small" sx={{ minWidth: 140 }}>
            <InputLabel>Expires In</InputLabel>
            <Select
              value={expiresIn ?? ""}
              label="Expires In"
              onChange={(e) =>
                setExpiresIn(e.target.value ? Number(e.target.value) : null)
              }
            >
              <MenuItem value="">Never</MenuItem>
              <MenuItem value={1}>1 hour</MenuItem>
              <MenuItem value={6}>6 hours</MenuItem>
              <MenuItem value={24}>1 day</MenuItem>
              <MenuItem value={72}>3 days</MenuItem>
              <MenuItem value={168}>1 week</MenuItem>
            </Select>
          </FormControl>
        </Box>

        <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
          <FormControlLabel
            control={
              <Switch
                checked={isAnonymous}
                onChange={(e) => setIsAnonymous(e.target.checked)}
                size="small"
              />
            }
            label={
              <Box>
                <Typography variant="body2">Anonymous voting</Typography>
                <Typography variant="caption" color="text.secondary">
                  Voters won't see who voted for what
                </Typography>
              </Box>
            }
          />

          <FormControlLabel
            control={
              <Switch
                checked={allowAddOptions}
                onChange={(e) => setAllowAddOptions(e.target.checked)}
                size="small"
              />
            }
            label={
              <Box>
                <Typography variant="body2">Allow adding options</Typography>
                <Typography variant="caption" color="text.secondary">
                  Others can add new options to the poll
                </Typography>
              </Box>
            }
          />
        </Box>

        {/* Preview */}
        <Box sx={{ mt: 2, p: 2, bgcolor: "action.hover", borderRadius: 1 }}>
          <Typography variant="caption" color="text.secondary" display="block" mb={0.5}>
            Preview
          </Typography>
          <Typography variant="body2" fontWeight="medium" mb={1}>
            {question || "Your question here"}
          </Typography>
          <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
            {pollType === "multiple" && (
              <Chip size="small" label="Multiple choice" variant="outlined" />
            )}
            {isAnonymous && (
              <Chip size="small" label="Anonymous" variant="outlined" />
            )}
            {expiresIn && (
              <Chip size="small" label={`Expires in ${expiresIn}h`} variant="outlined" />
            )}
          </Box>
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose} disabled={loading}>
          Cancel
        </Button>
        <Button
          variant="contained"
          onClick={handleSubmit}
          disabled={loading || !question.trim() || options.filter((o) => o.trim()).length < 2}
        >
          {loading ? "Creating..." : "Create Poll"}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default PollCreator;
