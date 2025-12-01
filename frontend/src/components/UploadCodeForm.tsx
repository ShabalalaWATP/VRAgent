import { useState, useRef, useCallback } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Box,
  Button,
  Typography,
  LinearProgress,
  alpha,
  useTheme,
  Tabs,
  Tab,
  Chip,
  Stack,
  keyframes,
} from "@mui/material";
import JSZip from "jszip";
import { uploadZip } from "../api/client";

// Keyframe animations
const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
`;

const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-10px); }
`;

const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

const glow = keyframes`
  0%, 100% { box-shadow: 0 0 20px rgba(99, 102, 241, 0.3); }
  50% { box-shadow: 0 0 40px rgba(99, 102, 241, 0.6), 0 0 60px rgba(34, 211, 238, 0.3); }
`;

// Icons
const FolderIcon = () => (
  <svg width="48" height="48" viewBox="0 0 24 24" fill="currentColor">
    <path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z" />
  </svg>
);

const ZipIcon = () => (
  <svg width="48" height="48" viewBox="0 0 24 24" fill="currentColor">
    <path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zM6 20V4h7v5h5v11H6z" />
    <path d="M10 12h2v2h-2v-2zm0-3h2v2h-2V9zm0 6h2v2h-2v-2z" />
  </svg>
);

const CheckIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" />
  </svg>
);

type Props = {
  projectId: number;
  onUploaded?: () => void;
};

export default function UploadCodeForm({ projectId, onUploaded }: Props) {
  const [isDragOver, setIsDragOver] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState<File[] | null>(null);
  const [uploadMode, setUploadMode] = useState<"zip" | "folder">("folder");
  const [processingStatus, setProcessingStatus] = useState<string>("");
  const [uploadSuccess, setUploadSuccess] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const theme = useTheme();
  const queryClient = useQueryClient();

  const uploadMutation = useMutation({
    mutationFn: (file: File) => uploadZip(projectId, file),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project", projectId] });
      setSelectedFiles(null);
      setProcessingStatus("");
      setUploadSuccess(true);
      onUploaded?.();
    },
  });

  const processAndUpload = async (files: File[]) => {
    if (uploadMode === "zip" && files.length === 1 && files[0].name.endsWith(".zip")) {
      // Direct zip upload
      uploadMutation.mutate(files[0]);
    } else {
      // Create zip from files/folder
      setProcessingStatus("Creating archive...");
      const zip = new JSZip();
      
      for (const file of files) {
        const relativePath = (file as any).webkitRelativePath || file.name;
        const arrayBuffer = await file.arrayBuffer();
        zip.file(relativePath, arrayBuffer);
        setProcessingStatus(`Adding: ${relativePath.split('/').pop()}`);
      }

      setProcessingStatus("Compressing...");
      const zipBlob = await zip.generateAsync({ 
        type: "blob",
        compression: "DEFLATE",
        compressionOptions: { level: 6 }
      }, (metadata) => {
        setProcessingStatus(`Compressing: ${Math.round(metadata.percent)}%`);
      });
      
      const zipFile = new File([zipBlob], "upload.zip", { type: "application/zip" });
      setProcessingStatus("Uploading...");
      uploadMutation.mutate(zipFile);
    }
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);

    const items = e.dataTransfer.items;
    const files: File[] = [];

    // Handle dropped items
    if (items) {
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (item.kind === "file") {
          const file = item.getAsFile();
          if (file) files.push(file);
        }
      }
    }

    if (files.length > 0) {
      if (uploadMode === "zip" && (!files[0].name.endsWith(".zip") || files.length > 1)) {
        // Switch to folder mode if non-zip files are dropped
        setUploadMode("folder");
      }
      setSelectedFiles(files);
    }
  }, [uploadMode]);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      setSelectedFiles(Array.from(files));
    }
  };

  const handleUpload = () => {
    if (selectedFiles && selectedFiles.length > 0) {
      processAndUpload(selectedFiles);
    }
  };

  const getTotalSize = () => {
    if (!selectedFiles) return 0;
    return selectedFiles.reduce((acc, f) => acc + f.size, 0);
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <Box>
      {/* Mode Selector Tabs */}
      <Box
        sx={{
          mb: 3,
          p: 0.5,
          borderRadius: 2,
          background: alpha(theme.palette.background.paper, 0.5),
          backdropFilter: "blur(10px)",
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
        }}
      >
        <Tabs
          value={uploadMode}
          onChange={(_, v) => {
            setUploadMode(v);
            setSelectedFiles(null);
          }}
          variant="fullWidth"
          sx={{
            minHeight: 40,
            "& .MuiTabs-indicator": {
              height: "100%",
              borderRadius: 1.5,
              background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.2)} 0%, ${alpha(theme.palette.secondary.main, 0.2)} 100%)`,
              zIndex: 0,
            },
            "& .MuiTab-root": {
              minHeight: 40,
              zIndex: 1,
              fontWeight: 600,
              fontSize: "0.85rem",
              transition: "all 0.3s ease",
            },
          }}
        >
          <Tab 
            value="folder" 
            label="📁 Folder" 
            sx={{ borderRadius: 1.5 }}
          />
          <Tab 
            value="zip" 
            label="📦 ZIP File" 
            sx={{ borderRadius: 1.5 }}
          />
        </Tabs>
      </Box>

      {/* Hidden file inputs */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".zip"
        hidden
        onChange={handleFileSelect}
        data-testid="upload-input"
      />
      <input
        ref={folderInputRef}
        type="file"
        // @ts-ignore - webkitdirectory is not in React types
        webkitdirectory=""
        directory=""
        multiple
        hidden
        onChange={handleFileSelect}
      />

      {/* Drop Zone */}
      <Box
        onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
        onDragLeave={() => setIsDragOver(false)}
        onDrop={handleDrop}
        onClick={() => {
          if (uploadMode === "zip") {
            fileInputRef.current?.click();
          } else {
            folderInputRef.current?.click();
          }
        }}
        sx={{
          position: "relative",
          p: 4,
          borderRadius: 3,
          cursor: "pointer",
          transition: "all 0.4s cubic-bezier(0.4, 0, 0.2, 1)",
          overflow: "hidden",
          background: isDragOver
            ? `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.15)} 0%, ${alpha(theme.palette.secondary.main, 0.15)} 100%)`
            : `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.8)} 0%, ${alpha(theme.palette.background.paper, 0.6)} 100%)`,
          backdropFilter: "blur(20px)",
          border: `2px dashed ${isDragOver ? theme.palette.primary.main : alpha(theme.palette.divider, 0.3)}`,
          animation: isDragOver ? `${glow} 2s ease-in-out infinite` : "none",
          "&:hover": {
            borderColor: theme.palette.primary.main,
            background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.08)} 0%, ${alpha(theme.palette.secondary.main, 0.08)} 100%)`,
            "& .upload-icon": {
              animation: `${float} 2s ease-in-out infinite`,
            },
          },
          "&::before": {
            content: '""',
            position: "absolute",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: `linear-gradient(90deg, transparent, ${alpha(theme.palette.primary.main, 0.1)}, transparent)`,
            backgroundSize: "200% 100%",
            animation: isDragOver ? `${shimmer} 2s infinite` : "none",
            pointerEvents: "none",
          },
        }}
      >
        {/* Floating particles effect */}
        <Box
          sx={{
            position: "absolute",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            overflow: "hidden",
            pointerEvents: "none",
            opacity: isDragOver ? 1 : 0.3,
            transition: "opacity 0.3s",
          }}
        >
          {[...Array(6)].map((_, i) => (
            <Box
              key={i}
              sx={{
                position: "absolute",
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: `linear-gradient(135deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
                left: `${15 + i * 15}%`,
                top: `${20 + (i % 3) * 25}%`,
                animation: `${float} ${2 + i * 0.5}s ease-in-out infinite`,
                animationDelay: `${i * 0.2}s`,
                opacity: 0.6,
              }}
            />
          ))}
        </Box>

        <Box sx={{ textAlign: "center", position: "relative", zIndex: 1 }}>
          <Box
            className="upload-icon"
            sx={{
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              width: 80,
              height: 80,
              borderRadius: "50%",
              mb: 2,
              background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.2)} 0%, ${alpha(theme.palette.secondary.main, 0.2)} 100%)`,
              color: theme.palette.primary.main,
              transition: "all 0.3s ease",
            }}
          >
            {uploadMode === "zip" ? <ZipIcon /> : <FolderIcon />}
          </Box>
          
          <Typography 
            variant="h6" 
            fontWeight={600} 
            sx={{
              background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              mb: 1,
            }}
          >
            {isDragOver 
              ? "Drop it like it's hot! 🔥"
              : uploadMode === "zip" 
                ? "Drop a ZIP file here"
                : "Drop a folder here"}
          </Typography>
          
          <Typography variant="body2" color="text.secondary">
            or click to {uploadMode === "zip" ? "select a ZIP file" : "select a folder"}
          </Typography>
          
          <Chip
            label={uploadMode === "zip" ? ".zip files" : "entire folders"}
            size="small"
            sx={{
              mt: 2,
              background: alpha(theme.palette.primary.main, 0.1),
              border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
              fontWeight: 500,
            }}
          />
        </Box>
      </Box>

      {/* Selected Files Display */}
      {selectedFiles && selectedFiles.length > 0 && (
        <Box
          sx={{
            mt: 3,
            p: 2,
            borderRadius: 2,
            background: `linear-gradient(135deg, ${alpha(theme.palette.success.main, 0.1)} 0%, ${alpha(theme.palette.primary.main, 0.05)} 100%)`,
            border: `1px solid ${alpha(theme.palette.success.main, 0.3)}`,
            backdropFilter: "blur(10px)",
          }}
        >
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                width: 28,
                height: 28,
                borderRadius: "50%",
                background: alpha(theme.palette.success.main, 0.2),
                color: theme.palette.success.main,
              }}
            >
              <CheckIcon />
            </Box>
            <Typography variant="subtitle2" fontWeight={600}>
              {(() => {
                // For folder uploads, extract the folder name from the first file's path
                const firstFile = selectedFiles[0] as any;
                if (firstFile.webkitRelativePath) {
                  const folderName = firstFile.webkitRelativePath.split('/')[0];
                  return `📁 ${folderName} (${selectedFiles.length} files)`;
                }
                // For single zip file
                if (selectedFiles.length === 1) {
                  return `📦 ${selectedFiles[0].name}`;
                }
                // For multiple files
                return `${selectedFiles.length} files selected`;
              })()}
            </Typography>
          </Stack>
          <Typography variant="caption" color="text.secondary">
            Total size: {formatSize(getTotalSize())}
          </Typography>
        </Box>
      )}

      {/* Progress Status */}
      {(uploadMutation.isPending || processingStatus) && (
        <Box sx={{ mt: 3 }}>
          <Box sx={{ display: "flex", alignItems: "center", mb: 1 }}>
            <Typography 
              variant="caption" 
              sx={{ 
                animation: `${pulse} 1.5s ease-in-out infinite`,
                fontWeight: 500,
              }}
            >
              {processingStatus || "Uploading..."}
            </Typography>
          </Box>
          <LinearProgress 
            sx={{
              height: 6,
              borderRadius: 3,
              background: alpha(theme.palette.primary.main, 0.1),
              "& .MuiLinearProgress-bar": {
                borderRadius: 3,
                background: `linear-gradient(90deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
              },
            }}
          />
        </Box>
      )}

      {/* Upload Button */}
      {selectedFiles && selectedFiles.length > 0 && !uploadMutation.isPending && (
        <Button
          variant="contained"
          fullWidth
          onClick={handleUpload}
          sx={{
            mt: 3,
            py: 1.5,
            fontWeight: 600,
            fontSize: "1rem",
            background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
            boxShadow: `0 4px 20px ${alpha(theme.palette.primary.main, 0.4)}`,
            transition: "all 0.3s ease",
            "&:hover": {
              background: `linear-gradient(135deg, ${theme.palette.primary.light} 0%, ${theme.palette.secondary.light} 100%)`,
              boxShadow: `0 6px 30px ${alpha(theme.palette.primary.main, 0.5)}`,
              transform: "translateY(-2px)",
            },
            "&:active": {
              transform: "translateY(0)",
            },
          }}
        >
          🚀 Upload & Analyze
        </Button>
      )}

      {/* Error Display */}
      {uploadMutation.isError && (
        <Box
          sx={{
            mt: 2,
            p: 2,
            borderRadius: 2,
            background: alpha(theme.palette.error.main, 0.1),
            border: `1px solid ${alpha(theme.palette.error.main, 0.3)}`,
          }}
        >
          <Typography variant="body2" color="error">
            {(uploadMutation.error as Error).message}
          </Typography>
        </Box>
      )}

      {/* Success Message */}
      {uploadSuccess && (
        <Box
          sx={{
            mt: 3,
            p: 3,
            borderRadius: 2,
            background: `linear-gradient(135deg, ${alpha(theme.palette.success.main, 0.15)} 0%, ${alpha(theme.palette.success.light, 0.1)} 100%)`,
            border: `1px solid ${alpha(theme.palette.success.main, 0.4)}`,
            textAlign: "center",
          }}
        >
          <Box
            sx={{
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              width: 48,
              height: 48,
              borderRadius: "50%",
              background: alpha(theme.palette.success.main, 0.2),
              color: theme.palette.success.main,
              mb: 1,
            }}
          >
            <CheckIcon />
          </Box>
          <Typography variant="h6" fontWeight={600} color="success.main" sx={{ mb: 0.5 }}>
            ✅ Upload Successful!
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Your code has been uploaded. You can now start a scan to analyze it.
          </Typography>
        </Box>
      )}
    </Box>
  );
}
