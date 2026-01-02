import React, { useMemo, useState, useCallback } from "react";
import { Box, Link, Typography, styled, IconButton, Tooltip, alpha } from "@mui/material";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import CheckIcon from "@mui/icons-material/Check";
import Prism from "prismjs";
import "prismjs/components/prism-javascript";
import "prismjs/components/prism-typescript";
import "prismjs/components/prism-python";
import "prismjs/components/prism-bash";
import "prismjs/components/prism-json";
import "prismjs/components/prism-css";
import "prismjs/components/prism-sql";
import "prismjs/components/prism-java";
import "prismjs/components/prism-c";
import "prismjs/components/prism-cpp";
import "prismjs/components/prism-csharp";
import "prismjs/components/prism-go";
import "prismjs/components/prism-rust";
import "prismjs/components/prism-ruby";
import "prismjs/components/prism-php";
import "prismjs/components/prism-yaml";
import "prismjs/components/prism-markdown";
import "prismjs/components/prism-jsx";
import "prismjs/components/prism-tsx";

// Types
interface MentionInfo {
  userId: number;
  username: string;
  startIndex: number;
  endIndex: number;
}

interface MarkdownRendererProps {
  content: string;
  mentions?: MentionInfo[];
  onMentionClick?: (userId: number, username: string) => void;
  currentUserId?: number;
}

// Styled components
const InlineCode = styled("code")(({ theme }) => ({
  backgroundColor: theme.palette.mode === "dark" ? "#2d2d2d" : "#f5f5f5",
  padding: "2px 6px",
  borderRadius: 4,
  fontFamily: "'Fira Code', 'Consolas', 'Monaco', monospace",
  fontSize: "0.875em",
  color: theme.palette.primary.main,
}));

const CodeBlockWrapper = styled(Box)(({ theme }) => ({
  position: "relative",
  margin: theme.spacing(1, 0),
  borderRadius: theme.shape.borderRadius,
  overflow: "hidden",
  border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
}));

const CodeBlockHeader = styled(Box)(({ theme }) => ({
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  padding: theme.spacing(0.5, 1),
  backgroundColor: theme.palette.mode === "dark" ? "#252526" : "#e8e8e8",
  borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
}));

const CodeBlockPre = styled("pre")(({ theme }) => ({
  backgroundColor: theme.palette.mode === "dark" ? "#1e1e1e" : "#f8f8f8",
  padding: theme.spacing(1.5),
  margin: 0,
  overflow: "auto",
  fontFamily: "'Fira Code', 'Consolas', 'Monaco', monospace",
  fontSize: "0.85em",
  lineHeight: 1.5,
  "& code": {
    backgroundColor: "transparent",
    padding: 0,
    fontFamily: "inherit",
  },
  // Prism theme styles
  "& .token.comment, & .token.prolog, & .token.doctype, & .token.cdata": {
    color: theme.palette.mode === "dark" ? "#6a9955" : "#008000",
  },
  "& .token.punctuation": {
    color: theme.palette.mode === "dark" ? "#d4d4d4" : "#393a34",
  },
  "& .token.property, & .token.tag, & .token.boolean, & .token.number, & .token.constant, & .token.symbol": {
    color: theme.palette.mode === "dark" ? "#b5cea8" : "#36acaa",
  },
  "& .token.selector, & .token.attr-name, & .token.string, & .token.char, & .token.builtin": {
    color: theme.palette.mode === "dark" ? "#ce9178" : "#e3116c",
  },
  "& .token.operator, & .token.entity, & .token.url, & .language-css .token.string, & .style .token.string": {
    color: theme.palette.mode === "dark" ? "#d4d4d4" : "#393a34",
  },
  "& .token.atrule, & .token.attr-value, & .token.keyword": {
    color: theme.palette.mode === "dark" ? "#569cd6" : "#00a4db",
  },
  "& .token.function, & .token.class-name": {
    color: theme.palette.mode === "dark" ? "#dcdcaa" : "#9a050f",
  },
  "& .token.regex, & .token.important, & .token.variable": {
    color: theme.palette.mode === "dark" ? "#d16969" : "#e90",
  },
}));

const MentionSpan = styled("span")<{ isCurrentUser?: boolean }>(
  ({ theme, isCurrentUser }) => ({
    color: isCurrentUser ? theme.palette.warning.main : theme.palette.primary.main,
    backgroundColor: isCurrentUser
      ? theme.palette.mode === "dark"
        ? "rgba(255, 152, 0, 0.15)"
        : "rgba(255, 152, 0, 0.1)"
      : theme.palette.mode === "dark"
      ? "rgba(25, 118, 210, 0.15)"
      : "rgba(25, 118, 210, 0.1)",
    padding: "1px 4px",
    borderRadius: 4,
    fontWeight: 500,
    cursor: "pointer",
    "&:hover": {
      backgroundColor: isCurrentUser
        ? theme.palette.mode === "dark"
          ? "rgba(255, 152, 0, 0.25)"
          : "rgba(255, 152, 0, 0.2)"
        : theme.palette.mode === "dark"
        ? "rgba(25, 118, 210, 0.25)"
        : "rgba(25, 118, 210, 0.2)",
    },
  })
);

// Language display names
const LANGUAGE_NAMES: Record<string, string> = {
  js: "JavaScript",
  javascript: "JavaScript",
  ts: "TypeScript",
  typescript: "TypeScript",
  jsx: "JSX",
  tsx: "TSX",
  py: "Python",
  python: "Python",
  bash: "Bash",
  sh: "Shell",
  shell: "Shell",
  json: "JSON",
  css: "CSS",
  sql: "SQL",
  java: "Java",
  c: "C",
  cpp: "C++",
  csharp: "C#",
  cs: "C#",
  go: "Go",
  rust: "Rust",
  rs: "Rust",
  ruby: "Ruby",
  rb: "Ruby",
  php: "PHP",
  yaml: "YAML",
  yml: "YAML",
  md: "Markdown",
  markdown: "Markdown",
  html: "HTML",
  xml: "XML",
};

// Syntax highlighted code block component
const SyntaxHighlightedCodeBlock: React.FC<{ code: string; language?: string }> = ({ code, language }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  }, [code]);

  // Get highlighted HTML
  const highlightedCode = useMemo(() => {
    const lang = language?.toLowerCase();
    const grammar = lang && Prism.languages[lang];
    if (grammar) {
      return Prism.highlight(code, grammar, lang);
    }
    // Fallback to plain text
    return code.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }, [code, language]);

  const displayLanguage = language ? (LANGUAGE_NAMES[language.toLowerCase()] || language) : "Code";

  return (
    <CodeBlockWrapper>
      <CodeBlockHeader>
        <Typography variant="caption" sx={{ fontFamily: "monospace", opacity: 0.8 }}>
          {displayLanguage}
        </Typography>
        <Tooltip title={copied ? "Copied!" : "Copy code"}>
          <IconButton
            size="small"
            onClick={handleCopy}
            sx={{ p: 0.5 }}
          >
            {copied ? (
              <CheckIcon sx={{ fontSize: 16, color: "success.main" }} />
            ) : (
              <ContentCopyIcon sx={{ fontSize: 16, opacity: 0.7 }} />
            )}
          </IconButton>
        </Tooltip>
      </CodeBlockHeader>
      <CodeBlockPre>
        <code dangerouslySetInnerHTML={{ __html: highlightedCode }} />
      </CodeBlockPre>
    </CodeBlockWrapper>
  );
};

// Token types for parsing
type Token =
  | { type: "text"; content: string }
  | { type: "bold"; content: string }
  | { type: "italic"; content: string }
  | { type: "boldItalic"; content: string }
  | { type: "code"; content: string }
  | { type: "codeBlock"; content: string; language?: string }
  | { type: "strikethrough"; content: string }
  | { type: "link"; text: string; url: string }
  | { type: "mention"; userId: number; username: string }
  | { type: "lineBreak" };

/**
 * Parse markdown content into tokens
 */
function parseMarkdown(content: string, mentions?: MentionInfo[]): Token[] {
  const tokens: Token[] = [];

  // First, handle code blocks (```code```)
  const codeBlockRegex = /```(\w+)?\n?([\s\S]*?)```/g;
  let lastIndex = 0;
  let match;

  const contentWithoutCodeBlocks: { text: string; start: number }[] = [];
  const codeBlocks: { index: number; token: Token }[] = [];
  let blockIndex = 0;

  while ((match = codeBlockRegex.exec(content)) !== null) {
    if (match.index > lastIndex) {
      contentWithoutCodeBlocks.push({
        text: content.slice(lastIndex, match.index),
        start: lastIndex,
      });
    }
    codeBlocks.push({
      index: blockIndex++,
      token: { type: "codeBlock", content: match[2], language: match[1] },
    });
    contentWithoutCodeBlocks.push({ text: `\x00CB${blockIndex - 1}\x00`, start: match.index });
    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < content.length) {
    contentWithoutCodeBlocks.push({
      text: content.slice(lastIndex),
      start: lastIndex,
    });
  }

  const processedContent = contentWithoutCodeBlocks.map((c) => c.text).join("");

  // Parse inline elements
  const inlineTokens = parseInlineMarkdown(processedContent, mentions);

  // Restore code blocks
  for (const token of inlineTokens) {
    if (token.type === "text" && token.content.includes("\x00CB")) {
      const parts = token.content.split(/\x00CB(\d+)\x00/);
      for (let i = 0; i < parts.length; i++) {
        if (i % 2 === 0) {
          if (parts[i]) {
            tokens.push({ type: "text", content: parts[i] });
          }
        } else {
          const blockIdx = parseInt(parts[i], 10);
          const block = codeBlocks.find((b) => b.index === blockIdx);
          if (block) {
            tokens.push(block.token);
          }
        }
      }
    } else {
      tokens.push(token);
    }
  }

  return tokens;
}

/**
 * Parse inline markdown (bold, italic, code, links, mentions)
 */
function parseInlineMarkdown(content: string, mentions?: MentionInfo[]): Token[] {
  const tokens: Token[] = [];

  // Build regex pattern for all inline elements
  // Order matters: bold+italic first, then bold, then italic
  const patterns = [
    { name: "boldItalic", regex: /\*\*\*(.+?)\*\*\*|___(.+?)___/ },
    { name: "bold", regex: /\*\*(.+?)\*\*|__(.+?)__/ },
    { name: "italic", regex: /\*(.+?)\*|_(.+?)_/ },
    { name: "strikethrough", regex: /~~(.+?)~~/ },
    { name: "code", regex: /`([^`]+)`/ },
    { name: "link", regex: /\[([^\]]+)\]\(([^)]+)\)/ },
    { name: "autoLink", regex: /(https?:\/\/[^\s<>]+)/ },
    { name: "mention", regex: /@(\w+)/ },
    { name: "lineBreak", regex: /\n/ },
  ];

  // Combined regex
  const combinedPattern = new RegExp(
    patterns.map((p) => `(${p.regex.source})`).join("|"),
    "g"
  );

  let lastIndex = 0;
  let match;

  while ((match = combinedPattern.exec(content)) !== null) {
    // Add text before match
    if (match.index > lastIndex) {
      tokens.push({ type: "text", content: content.slice(lastIndex, match.index) });
    }

    // Determine which pattern matched
    let groupIndex = 1;
    for (const pattern of patterns) {
      if (match[groupIndex]) {
        switch (pattern.name) {
          case "boldItalic":
            tokens.push({
              type: "boldItalic",
              content: match[groupIndex + 1] || match[groupIndex + 2],
            });
            break;
          case "bold":
            tokens.push({
              type: "bold",
              content: match[groupIndex + 1] || match[groupIndex + 2],
            });
            break;
          case "italic":
            tokens.push({
              type: "italic",
              content: match[groupIndex + 1] || match[groupIndex + 2],
            });
            break;
          case "strikethrough":
            tokens.push({ type: "strikethrough", content: match[groupIndex + 1] });
            break;
          case "code":
            tokens.push({ type: "code", content: match[groupIndex + 1] });
            break;
          case "link":
            tokens.push({
              type: "link",
              text: match[groupIndex + 1],
              url: match[groupIndex + 2],
            });
            break;
          case "autoLink":
            tokens.push({
              type: "link",
              text: match[groupIndex + 1],
              url: match[groupIndex + 1],
            });
            break;
          case "mention": {
            const username = match[groupIndex + 1];
            // Try to find the mention in the provided mentions list
            const mentionInfo = mentions?.find(
              (m) => m.username.toLowerCase() === username.toLowerCase()
            );
            if (mentionInfo) {
              tokens.push({
                type: "mention",
                userId: mentionInfo.userId,
                username: mentionInfo.username,
              });
            } else {
              // Not a valid mention, treat as text
              tokens.push({ type: "text", content: match[0] });
            }
            break;
          }
          case "lineBreak":
            tokens.push({ type: "lineBreak" });
            break;
        }
        break;
      }
      // Move to next group (accounting for capture groups in each pattern)
      groupIndex += 1 + (pattern.regex.source.match(/\(/g)?.length || 0);
    }

    lastIndex = match.index + match[0].length;
  }

  // Add remaining text
  if (lastIndex < content.length) {
    tokens.push({ type: "text", content: content.slice(lastIndex) });
  }

  return tokens;
}

/**
 * Render a single token
 */
function renderToken(
  token: Token,
  index: number,
  onMentionClick?: (userId: number, username: string) => void,
  currentUserId?: number
): React.ReactNode {
  switch (token.type) {
    case "text":
      return <span key={index}>{token.content}</span>;

    case "bold":
      return (
        <strong key={index} style={{ fontWeight: 600 }}>
          {token.content}
        </strong>
      );

    case "italic":
      return (
        <em key={index} style={{ fontStyle: "italic" }}>
          {token.content}
        </em>
      );

    case "boldItalic":
      return (
        <strong key={index} style={{ fontWeight: 600, fontStyle: "italic" }}>
          {token.content}
        </strong>
      );

    case "strikethrough":
      return (
        <span key={index} style={{ textDecoration: "line-through" }}>
          {token.content}
        </span>
      );

    case "code":
      return <InlineCode key={index}>{token.content}</InlineCode>;

    case "codeBlock":
      return (
        <SyntaxHighlightedCodeBlock
          key={index}
          code={token.content}
          language={token.language}
        />
      );

    case "link":
      return (
        <Link
          key={index}
          href={token.url}
          target="_blank"
          rel="noopener noreferrer"
          sx={{ wordBreak: "break-all" }}
        >
          {token.text}
        </Link>
      );

    case "mention":
      return (
        <MentionSpan
          key={index}
          isCurrentUser={currentUserId === token.userId}
          onClick={() => onMentionClick?.(token.userId, token.username)}
        >
          @{token.username}
        </MentionSpan>
      );

    case "lineBreak":
      return <br key={index} />;

    default:
      return null;
  }
}

/**
 * MarkdownRenderer Component
 * Renders markdown-formatted text with support for:
 * - **bold** or __bold__
 * - *italic* or _italic_
 * - ***bold italic*** or ___bold italic___
 * - ~~strikethrough~~
 * - `inline code`
 * - ```code blocks```
 * - [links](url)
 * - @mentions
 */
export const MarkdownRenderer: React.FC<MarkdownRendererProps> = ({
  content,
  mentions,
  onMentionClick,
  currentUserId,
}) => {
  const tokens = useMemo(
    () => parseMarkdown(content, mentions),
    [content, mentions]
  );

  return (
    <Box
      component="span"
      sx={{
        "& > *": { verticalAlign: "baseline" },
        wordBreak: "break-word",
        whiteSpace: "pre-wrap",
      }}
    >
      {tokens.map((token, index) =>
        renderToken(token, index, onMentionClick, currentUserId)
      )}
    </Box>
  );
};

/**
 * Hook to format message content for display
 */
export function useFormattedMessage(
  content: string,
  mentions?: MentionInfo[]
): { formatted: React.ReactNode; hasMentions: boolean } {
  return useMemo(() => {
    const tokens = parseMarkdown(content, mentions);
    const hasMentions = tokens.some((t) => t.type === "mention");
    return {
      formatted: tokens.map((token, index) => renderToken(token, index)),
      hasMentions,
    };
  }, [content, mentions]);
}

/**
 * Utility: Extract plain text from markdown
 */
export function stripMarkdown(content: string): string {
  return content
    .replace(/```[\s\S]*?```/g, "[code]")
    .replace(/\*\*\*(.+?)\*\*\*/g, "$1")
    .replace(/___(.+?)___/g, "$1")
    .replace(/\*\*(.+?)\*\*/g, "$1")
    .replace(/__(.+?)__/g, "$1")
    .replace(/\*(.+?)\*/g, "$1")
    .replace(/_(.+?)_/g, "$1")
    .replace(/~~(.+?)~~/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1");
}

/**
 * Utility: Check if content contains mentions
 */
export function hasMentions(content: string): boolean {
  return /@\w+/.test(content);
}

export default MarkdownRenderer;
