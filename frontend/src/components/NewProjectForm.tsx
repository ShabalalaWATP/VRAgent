import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  InputAdornment,
  Stack,
  TextField,
  alpha,
  useTheme,
} from "@mui/material";
import { api, ProjectSummary } from "../api/client";

// Icons
const FolderIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z" />
  </svg>
);

const DescriptionIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z" />
  </svg>
);

const GitIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M2.6 10.59L8.38 4.8l1.69 1.7c-.24.85.15 1.78.93 2.23v5.54c-.6.34-1 .99-1 1.73 0 1.1.9 2 2 2s2-.9 2-2c0-.74-.4-1.39-1-1.73V9.41l1.69 1.7c-.24.85.15 1.78.93 2.23v5.54c-.6.34-1 .99-1 1.73 0 1.1.9 2 2 2s2-.9 2-2c0-.74-.4-1.39-1-1.73v-5.54c.77-.46 1.16-1.38.93-2.23l1.69-1.7 5.78 5.79c.56.56.56 1.47 0 2.03L14.03 21.4c-.56.56-1.47.56-2.03 0L2.6 12.62c-.56-.56-.56-1.47 0-2.03z" />
  </svg>
);

type Props = {
  onCreated?: (project: ProjectSummary) => void;
};

export default function NewProjectForm({ onCreated }: Props) {
  const queryClient = useQueryClient();
  const theme = useTheme();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [gitUrl, setGitUrl] = useState("");

  const mutation = useMutation({
    mutationFn: () => api.createProject({ name, description, git_url: gitUrl }),
    onSuccess: (project) => {
      queryClient.invalidateQueries({ queryKey: ["projects"] });
      onCreated?.(project);
      setName("");
      setDescription("");
      setGitUrl("");
    },
  });

  return (
    <Box
      component="form"
      onSubmit={(e) => {
        e.preventDefault();
        mutation.mutate();
      }}
      sx={{ pt: 1 }}
    >
      <Stack spacing={3}>
        <TextField
          label="Project Name"
          value={name}
          required
          onChange={(e) => setName(e.target.value)}
          placeholder="My Awesome Project"
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <Box sx={{ color: "text.secondary" }}>
                  <FolderIcon />
                </Box>
              </InputAdornment>
            ),
          }}
          sx={{
            "& .MuiOutlinedInput-root": {
              "&:hover fieldset": {
                borderColor: theme.palette.primary.main,
              },
            },
          }}
        />

        <TextField
          label="Description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="A brief description of your project..."
          multiline
          minRows={3}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start" sx={{ alignSelf: "flex-start", mt: 1.5 }}>
                <Box sx={{ color: "text.secondary" }}>
                  <DescriptionIcon />
                </Box>
              </InputAdornment>
            ),
          }}
        />

        <TextField
          label="Git Repository URL (optional)"
          value={gitUrl}
          onChange={(e) => setGitUrl(e.target.value)}
          placeholder="https://github.com/user/repo"
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <Box sx={{ color: "text.secondary" }}>
                  <GitIcon />
                </Box>
              </InputAdornment>
            ),
          }}
          helperText="Link to your code repository for reference"
        />

        <Button
          type="submit"
          variant="contained"
          disabled={mutation.isPending || !name.trim()}
          size="large"
          sx={{
            py: 1.5,
            background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.primary.dark} 100%)`,
            "&:hover": {
              background: `linear-gradient(135deg, ${theme.palette.primary.light} 0%, ${theme.palette.primary.main} 100%)`,
            },
            "&:disabled": {
              background: alpha(theme.palette.primary.main, 0.3),
            },
          }}
        >
          {mutation.isPending ? "Creating Project..." : "Create Project"}
        </Button>

        {mutation.isError && (
          <Alert severity="error">{(mutation.error as Error).message}</Alert>
        )}

        {mutation.isSuccess && (
          <Alert severity="success">Project created successfully!</Alert>
        )}
      </Stack>
    </Box>
  );
}
