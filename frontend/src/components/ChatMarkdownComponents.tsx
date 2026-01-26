/**
 * Shared ReactMarkdown components for consistent chat formatting across all AI chat widgets.
 *
 * Usage:
 * ```tsx
 * import { createChatMarkdownComponents } from "./ChatMarkdownComponents";
 * import ReactMarkdown from "react-markdown";
 *
 * const components = createChatMarkdownComponents(theme);
 *
 * <ReactMarkdown components={components}>
 *   {message.content}
 * </ReactMarkdown>
 * ```
 */
import React from "react";
import { Box, Typography, Divider, alpha, Theme } from "@mui/material";
import { ChatCodeBlock } from "./ChatCodeBlock";

/**
 * Creates a set of ReactMarkdown components with consistent styling.
 * Pass the MUI theme to get proper colors and styling.
 */
export const createChatMarkdownComponents = (theme: Theme) => ({
  code: ({ className, children }: { className?: string; children?: React.ReactNode }) => (
    <ChatCodeBlock className={className} theme={theme}>
      {children}
    </ChatCodeBlock>
  ),
  p: ({ children }: { children?: React.ReactNode }) => (
    <Typography variant="body2" component="p" sx={{ mb: 1, "&:last-child": { mb: 0 } }}>
      {children}
    </Typography>
  ),
  h1: ({ children }: { children?: React.ReactNode }) => (
    <Typography variant="h6" component="h1" fontWeight={600} sx={{ mt: 1.5, mb: 1 }}>
      {children}
    </Typography>
  ),
  h2: ({ children }: { children?: React.ReactNode }) => (
    <Typography variant="subtitle1" component="h2" fontWeight={600} sx={{ mt: 1.5, mb: 0.75 }}>
      {children}
    </Typography>
  ),
  h3: ({ children }: { children?: React.ReactNode }) => (
    <Typography variant="subtitle2" component="h3" fontWeight={600} sx={{ mt: 1, mb: 0.5 }}>
      {children}
    </Typography>
  ),
  h4: ({ children }: { children?: React.ReactNode }) => (
    <Typography variant="body2" component="h4" fontWeight={600} sx={{ mt: 1, mb: 0.5 }}>
      {children}
    </Typography>
  ),
  ul: ({ children }: { children?: React.ReactNode }) => (
    <Box component="ul" sx={{ pl: 2.5, my: 0.5, listStyleType: "disc" }}>
      {children}
    </Box>
  ),
  ol: ({ children }: { children?: React.ReactNode }) => (
    <Box component="ol" sx={{ pl: 2.5, my: 0.5, listStyleType: "decimal" }}>
      {children}
    </Box>
  ),
  li: ({ children }: { children?: React.ReactNode }) => (
    <Typography component="li" variant="body2" sx={{ mb: 0.25, display: "list-item" }}>
      {children}
    </Typography>
  ),
  a: ({ href, children }: { href?: string; children?: React.ReactNode }) => (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      style={{ color: theme.palette.primary.main, textDecoration: "underline" }}
    >
      {children}
    </a>
  ),
  strong: ({ children }: { children?: React.ReactNode }) => (
    <strong style={{ fontWeight: 600 }}>{children}</strong>
  ),
  em: ({ children }: { children?: React.ReactNode }) => (
    <em style={{ fontStyle: "italic" }}>{children}</em>
  ),
  blockquote: ({ children }: { children?: React.ReactNode }) => (
    <Box
      component="blockquote"
      sx={{
        borderLeft: `3px solid ${alpha(theme.palette.primary.main, 0.5)}`,
        pl: 1.5,
        ml: 0,
        my: 1,
        color: theme.palette.text.secondary,
        fontStyle: "italic",
      }}
    >
      {children}
    </Box>
  ),
  hr: () => <Divider sx={{ my: 1.5 }} />,
  table: ({ children }: { children?: React.ReactNode }) => (
    <Box
      component="table"
      sx={{
        borderCollapse: "collapse",
        width: "100%",
        my: 1,
        fontSize: "0.85rem",
      }}
    >
      {children}
    </Box>
  ),
  th: ({ children }: { children?: React.ReactNode }) => (
    <Box
      component="th"
      sx={{
        border: `1px solid ${theme.palette.divider}`,
        px: 1,
        py: 0.5,
        textAlign: "left",
        bgcolor: alpha(theme.palette.primary.main, 0.1),
        fontWeight: 600,
      }}
    >
      {children}
    </Box>
  ),
  td: ({ children }: { children?: React.ReactNode }) => (
    <Box
      component="td"
      sx={{
        border: `1px solid ${theme.palette.divider}`,
        px: 1,
        py: 0.5,
        textAlign: "left",
      }}
    >
      {children}
    </Box>
  ),
});

/**
 * Standard container styling for markdown content in chat messages.
 * Apply this to the Box wrapping ReactMarkdown for consistent spacing.
 */
export const chatMarkdownContainerSx = {
  wordBreak: "break-word",
  "& p": { margin: 0, mb: 1 },
  "& p:last-child": { mb: 0 },
  "& ul, & ol": { mt: 0.5, mb: 1, pl: 2.5 },
  "& li": { mb: 0.25 },
  "& blockquote": {
    my: 1,
  },
  "& hr": { my: 1.5 },
  "& table": { my: 1 },
};

export default createChatMarkdownComponents;
