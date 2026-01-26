import React, { useState } from 'react';
import {
  Box,
  IconButton,
  Tooltip,
  Divider,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  alpha,
} from '@mui/material';
import {
  FormatBold as BoldIcon,
  FormatItalic as ItalicIcon,
  StrikethroughS as StrikethroughIcon,
  Code as InlineCodeIcon,
  DataObject as CodeBlockIcon,
  Link as LinkIcon,
  FormatListBulleted as ListIcon,
  FormatQuote as QuoteIcon,
  Image as ImageIcon,
} from '@mui/icons-material';

interface RichTextToolbarProps {
  onInsert: (before: string, after: string, placeholder?: string) => void;
  onInsertCodeBlock: (language: string) => void;
  onImagePaste?: () => void;
  disabled?: boolean;
  compact?: boolean;
}

const CODE_LANGUAGES = [
  { value: 'javascript', label: 'JavaScript' },
  { value: 'typescript', label: 'TypeScript' },
  { value: 'python', label: 'Python' },
  { value: 'java', label: 'Java' },
  { value: 'csharp', label: 'C#' },
  { value: 'cpp', label: 'C++' },
  { value: 'go', label: 'Go' },
  { value: 'rust', label: 'Rust' },
  { value: 'sql', label: 'SQL' },
  { value: 'bash', label: 'Bash' },
  { value: 'json', label: 'JSON' },
  { value: 'yaml', label: 'YAML' },
  { value: 'html', label: 'HTML' },
  { value: 'css', label: 'CSS' },
  { value: '', label: 'Plain Text' },
];

export function RichTextToolbar({
  onInsert,
  onInsertCodeBlock,
  onImagePaste,
  disabled = false,
  compact = false,
}: RichTextToolbarProps) {
  const [codeMenuAnchor, setCodeMenuAnchor] = useState<HTMLElement | null>(null);

  const handleBold = () => onInsert('**', '**', 'bold text');
  const handleItalic = () => onInsert('*', '*', 'italic text');
  const handleStrikethrough = () => onInsert('~~', '~~', 'strikethrough');
  const handleInlineCode = () => onInsert('`', '`', 'code');
  const handleLink = () => onInsert('[', '](url)', 'link text');
  const handleQuote = () => onInsert('> ', '', 'quote');
  const handleList = () => onInsert('- ', '', 'item');

  const handleCodeBlockClick = (event: React.MouseEvent<HTMLElement>) => {
    setCodeMenuAnchor(event.currentTarget);
  };

  const handleCodeLanguageSelect = (language: string) => {
    onInsertCodeBlock(language);
    setCodeMenuAnchor(null);
  };

  const buttonSize = compact ? 'small' : 'medium';
  const iconFontSize = compact ? 18 : 20;

  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 0.25,
        px: 1,
        py: 0.5,
        borderRadius: 2,
        bgcolor: (theme) => alpha(theme.palette.action.hover, 0.3),
        flexWrap: 'wrap',
      }}
    >
      <Tooltip title="Bold (Ctrl+B)">
        <IconButton size={buttonSize} onClick={handleBold} disabled={disabled}>
          <BoldIcon sx={{ fontSize: iconFontSize }} />
        </IconButton>
      </Tooltip>

      <Tooltip title="Italic (Ctrl+I)">
        <IconButton size={buttonSize} onClick={handleItalic} disabled={disabled}>
          <ItalicIcon sx={{ fontSize: iconFontSize }} />
        </IconButton>
      </Tooltip>

      <Tooltip title="Strikethrough">
        <IconButton size={buttonSize} onClick={handleStrikethrough} disabled={disabled}>
          <StrikethroughIcon sx={{ fontSize: iconFontSize }} />
        </IconButton>
      </Tooltip>

      <Divider orientation="vertical" flexItem sx={{ mx: 0.5 }} />

      <Tooltip title="Inline Code">
        <IconButton size={buttonSize} onClick={handleInlineCode} disabled={disabled}>
          <InlineCodeIcon sx={{ fontSize: iconFontSize }} />
        </IconButton>
      </Tooltip>

      <Tooltip title="Code Block">
        <IconButton size={buttonSize} onClick={handleCodeBlockClick} disabled={disabled}>
          <CodeBlockIcon sx={{ fontSize: iconFontSize }} />
        </IconButton>
      </Tooltip>

      <Divider orientation="vertical" flexItem sx={{ mx: 0.5 }} />

      <Tooltip title="Link">
        <IconButton size={buttonSize} onClick={handleLink} disabled={disabled}>
          <LinkIcon sx={{ fontSize: iconFontSize }} />
        </IconButton>
      </Tooltip>

      <Tooltip title="Quote">
        <IconButton size={buttonSize} onClick={handleQuote} disabled={disabled}>
          <QuoteIcon sx={{ fontSize: iconFontSize }} />
        </IconButton>
      </Tooltip>

      <Tooltip title="List">
        <IconButton size={buttonSize} onClick={handleList} disabled={disabled}>
          <ListIcon sx={{ fontSize: iconFontSize }} />
        </IconButton>
      </Tooltip>

      {onImagePaste && (
        <>
          <Divider orientation="vertical" flexItem sx={{ mx: 0.5 }} />
          <Tooltip title="Paste image from clipboard (Ctrl+V)">
            <IconButton size={buttonSize} onClick={onImagePaste} disabled={disabled}>
              <ImageIcon sx={{ fontSize: iconFontSize }} />
            </IconButton>
          </Tooltip>
        </>
      )}

      {/* Code Language Menu */}
      <Menu
        anchorEl={codeMenuAnchor}
        open={Boolean(codeMenuAnchor)}
        onClose={() => setCodeMenuAnchor(null)}
        PaperProps={{
          sx: {
            maxHeight: 300,
            borderRadius: 2,
          },
        }}
      >
        {CODE_LANGUAGES.map((lang) => (
          <MenuItem
            key={lang.value}
            onClick={() => handleCodeLanguageSelect(lang.value)}
            dense
          >
            <ListItemIcon>
              <CodeBlockIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>{lang.label}</ListItemText>
          </MenuItem>
        ))}
      </Menu>
    </Box>
  );
}

export default RichTextToolbar;
