import React, { useState } from "react";
import { Box, IconButton, Tooltip, Typography, alpha, Theme } from "@mui/material";
import Prism from "prismjs";
import "prismjs/themes/prism-tomorrow.css";
import "prismjs/components/prism-javascript";
import "prismjs/components/prism-typescript";
import "prismjs/components/prism-python";
import "prismjs/components/prism-java";
import "prismjs/components/prism-c";
import "prismjs/components/prism-cpp";
import "prismjs/components/prism-csharp";
import "prismjs/components/prism-go";
import "prismjs/components/prism-rust";
import "prismjs/components/prism-ruby";
import "prismjs/components/prism-php";
import "prismjs/components/prism-swift";
import "prismjs/components/prism-kotlin";
import "prismjs/components/prism-sql";
import "prismjs/components/prism-bash";
import "prismjs/components/prism-yaml";
import "prismjs/components/prism-json";
import "prismjs/components/prism-markdown";
import "prismjs/components/prism-css";
import "prismjs/components/prism-scss";

// Icons
const ContentCopyIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z" />
  </svg>
);

const CheckIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" />
  </svg>
);

// Prism language mapping
const getPrismLanguage = (language: string): string => {
  const mapping: Record<string, string> = {
    python: "python",
    py: "python",
    javascript: "javascript",
    js: "javascript",
    javascriptreact: "javascript",
    jsx: "javascript",
    typescript: "typescript",
    ts: "typescript",
    typescriptreact: "typescript",
    tsx: "typescript",
    java: "java",
    c: "c",
    cpp: "cpp",
    "c++": "cpp",
    csharp: "csharp",
    "c#": "csharp",
    cs: "csharp",
    go: "go",
    golang: "go",
    rust: "rust",
    rs: "rust",
    ruby: "ruby",
    rb: "ruby",
    php: "php",
    swift: "swift",
    kotlin: "kotlin",
    kt: "kotlin",
    sql: "sql",
    shell: "bash",
    bash: "bash",
    sh: "bash",
    zsh: "bash",
    powershell: "bash",
    ps1: "bash",
    yaml: "yaml",
    yml: "yaml",
    json: "json",
    jsonc: "json",
    markdown: "markdown",
    md: "markdown",
    css: "css",
    scss: "scss",
    sass: "scss",
    html: "markup",
    xml: "markup",
    plaintext: "clike",
    text: "clike",
  };
  return mapping[language?.toLowerCase()] || "clike";
};

// Syntax highlight code
const highlightCode = (code: string, language: string): string => {
  try {
    const prismLang = getPrismLanguage(language);
    if (Prism.languages[prismLang]) {
      return Prism.highlight(code, Prism.languages[prismLang], prismLang);
    }
  } catch {
    // Fallback to plain text
  }
  return code.replace(/</g, "&lt;").replace(/>/g, "&gt;");
};

interface ChatCodeBlockProps {
  className?: string;
  children?: React.ReactNode;
  theme: Theme;
}

/**
 * Custom code block component for chat messages with syntax highlighting and copy button.
 * Use this component with ReactMarkdown's components prop:
 * 
 * ```tsx
 * <ReactMarkdown
 *   components={{
 *     code: ({ className, children }) => (
 *       <ChatCodeBlock className={className} theme={theme}>
 *         {children}
 *       </ChatCodeBlock>
 *     ),
 *   }}
 * >
 *   {content}
 * </ReactMarkdown>
 * ```
 */
export const ChatCodeBlock: React.FC<ChatCodeBlockProps> = ({ className, children, theme }) => {
  const [copied, setCopied] = useState(false);
  const match = /language-(\w+)/.exec(className || "");
  const language = match ? match[1] : "";
  const code = String(children).replace(/\n$/, "");

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!className) {
    // Inline code
    return (
      <code
        style={{
          backgroundColor: alpha(theme.palette.primary.main, 0.15),
          padding: "2px 6px",
          borderRadius: "4px",
          fontFamily: "'Fira Code', 'Monaco', 'Consolas', monospace",
          fontSize: "0.85em",
        }}
      >
        {children}
      </code>
    );
  }

  // Block code with syntax highlighting
  const highlighted = highlightCode(code, language);

  return (
    <Box
      sx={{
        position: "relative",
        my: 1.5,
        borderRadius: 1,
        overflow: "hidden",
        border: `1px solid ${alpha(theme.palette.divider, 0.3)}`,
      }}
    >
      {/* Header with language label and copy button */}
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          px: 1.5,
          py: 0.5,
          bgcolor: alpha(theme.palette.background.default, 0.8),
          borderBottom: `1px solid ${alpha(theme.palette.divider, 0.3)}`,
        }}
      >
        <Typography
          variant="caption"
          sx={{
            fontFamily: "monospace",
            color: theme.palette.text.secondary,
            textTransform: "uppercase",
            fontWeight: 600,
            fontSize: "0.7rem",
          }}
        >
          {language || "code"}
        </Typography>
        <Tooltip title={copied ? "Copied!" : "Copy code"}>
          <IconButton
            size="small"
            onClick={handleCopy}
            sx={{
              p: 0.5,
              color: copied ? "#22c55e" : theme.palette.text.secondary,
              "&:hover": {
                bgcolor: alpha(theme.palette.primary.main, 0.1),
              },
            }}
          >
            {copied ? <CheckIcon /> : <ContentCopyIcon />}
          </IconButton>
        </Tooltip>
      </Box>
      <pre
        style={{
          margin: 0,
          padding: "12px 16px",
          backgroundColor: "#1e1e1e",
          overflow: "auto",
          maxHeight: "400px",
        }}
      >
        <code
          className={`language-${language}`}
          dangerouslySetInnerHTML={{ __html: highlighted }}
          style={{
            fontFamily: "'Fira Code', 'Monaco', 'Consolas', monospace",
            fontSize: "0.8rem",
            lineHeight: 1.5,
          }}
        />
      </pre>
    </Box>
  );
};

export default ChatCodeBlock;
