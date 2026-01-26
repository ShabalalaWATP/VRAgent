/**
 * HTML sanitization utilities for safe rendering of user-generated content.
 * Uses browser's built-in DOMParser for sanitization without external dependencies.
 */

// Allowed HTML tags for message content
const ALLOWED_TAGS = new Set([
  'mark', 'em', 'strong', 'b', 'i', 'u', 'code', 'pre', 'span',
  'br', 'p', 'div', 'a', 'ul', 'ol', 'li', 'blockquote',
  'h1', 'h2', 'h3', 'h4',
  'table', 'thead', 'tbody', 'tr', 'th', 'td', 'hr',
]);

// Allowed attributes per tag
const ALLOWED_ATTRS: Record<string, Set<string>> = {
  '*': new Set(['class', 'style']),
  'a': new Set(['href', 'title', 'target', 'rel']),
  'span': new Set(['class', 'style']),
  'mark': new Set(['class', 'style']),
};

// Dangerous attribute patterns
const DANGEROUS_PATTERNS = [
  /^javascript:/i,
  /^data:/i,
  /^vbscript:/i,
  /expression\s*\(/i,
  /on\w+\s*=/i,
];

// Safe style properties
const SAFE_STYLE_PROPS = new Set([
  'color', 'background-color', 'background', 'font-weight', 'font-style',
  'text-decoration', 'padding', 'margin', 'border-radius',
]);

/**
 * Check if a URL is safe (http, https, or mailto only)
 *
 * SECURITY: Protocol-relative URLs (//) are NOT allowed as they can be
 * exploited to load resources from attacker-controlled domains.
 */
function isSafeUrl(url: string): boolean {
  try {
    const trimmed = url.trim().toLowerCase();

    // Only allow explicit safe protocols
    if (trimmed.startsWith('https://') || trimmed.startsWith('http://') || trimmed.startsWith('mailto:')) {
      return true;
    }

    // SECURITY: Protocol-relative URLs (//) are NOT safe - they inherit the
    // current page's protocol and can be used for XSS if an attacker controls
    // the domain portion. Block them explicitly.
    if (trimmed.startsWith('//')) {
      return false;
    }

    // Relative URLs (starting with / or #) are safe as they stay on same origin
    if (trimmed.startsWith('/') || trimmed.startsWith('#')) {
      return true;
    }

    // URLs without any protocol (no colon) are relative and safe
    if (!trimmed.includes(':')) {
      return true;
    }

    // Block all other protocols (javascript:, data:, vbscript:, etc.)
    return false;
  } catch {
    return false;
  }
}

/**
 * Sanitize a style attribute value
 */
function sanitizeStyle(style: string): string {
  const props = style.split(';').filter(Boolean);
  const sanitized: string[] = [];

  for (const prop of props) {
    const [name, ...valueParts] = prop.split(':');
    if (!name || valueParts.length === 0) continue;

    const propName = name.trim().toLowerCase();
    const propValue = valueParts.join(':').trim();

    // Only allow safe style properties
    if (SAFE_STYLE_PROPS.has(propName)) {
      // Check for dangerous patterns in value
      const hasDangerous = DANGEROUS_PATTERNS.some(pattern => pattern.test(propValue));
      if (!hasDangerous) {
        sanitized.push(`${propName}: ${propValue}`);
      }
    }
  }

  return sanitized.join('; ');
}

/**
 * Sanitize an HTML element recursively
 */
function sanitizeElement(element: Element): void {
  const tagName = element.tagName.toLowerCase();

  // Remove element if tag not allowed
  if (!ALLOWED_TAGS.has(tagName)) {
    // Keep text content but remove the element
    const textContent = element.textContent || '';
    element.replaceWith(document.createTextNode(textContent));
    return;
  }

  // Sanitize attributes
  const allowedForTag = ALLOWED_ATTRS[tagName] || new Set();
  const allowedGlobal = ALLOWED_ATTRS['*'] || new Set();
  const attributesToRemove: string[] = [];

  for (const attr of Array.from(element.attributes)) {
    const attrName = attr.name.toLowerCase();

    // Check if attribute is allowed
    if (!allowedForTag.has(attrName) && !allowedGlobal.has(attrName)) {
      attributesToRemove.push(attr.name);
      continue;
    }

    // Sanitize href attributes
    if (attrName === 'href') {
      if (!isSafeUrl(attr.value)) {
        attributesToRemove.push(attr.name);
      } else {
        // Force rel="noopener noreferrer" for external links (http/https only)
        if (tagName === 'a' && attr.value.trim().toLowerCase().startsWith('http')) {
          element.setAttribute('rel', 'noopener noreferrer');
          element.setAttribute('target', '_blank');
        }
      }
      continue;
    }

    // Sanitize style attributes
    if (attrName === 'style') {
      const sanitizedStyle = sanitizeStyle(attr.value);
      if (sanitizedStyle) {
        element.setAttribute('style', sanitizedStyle);
      } else {
        attributesToRemove.push(attr.name);
      }
      continue;
    }

    // Check for dangerous patterns in attribute values
    const hasDangerous = DANGEROUS_PATTERNS.some(pattern => pattern.test(attr.value));
    if (hasDangerous) {
      attributesToRemove.push(attr.name);
    }
  }

  // Remove dangerous attributes
  for (const attr of attributesToRemove) {
    element.removeAttribute(attr);
  }

  // Recursively sanitize child elements
  const children = Array.from(element.children);
  for (const child of children) {
    sanitizeElement(child);
  }
}

/**
 * Sanitize HTML string for safe rendering with dangerouslySetInnerHTML
 * 
 * @param html - The HTML string to sanitize
 * @returns Sanitized HTML string safe for rendering
 */
export function sanitizeHtml(html: string): string {
  if (!html || typeof html !== 'string') {
    return '';
  }

  // Quick check for plain text (no HTML tags)
  if (!html.includes('<')) {
    return escapeHtml(html);
  }

  try {
    // Parse HTML using browser's DOMParser
    const parser = new DOMParser();
    const doc = parser.parseFromString(`<div>${html}</div>`, 'text/html');
    const container = doc.body.firstChild as Element;

    if (!container) {
      return escapeHtml(html);
    }

    // Sanitize all elements
    const children = Array.from(container.children);
    for (const child of children) {
      sanitizeElement(child);
    }

    return container.innerHTML;
  } catch (error) {
    console.error('Error sanitizing HTML:', error);
    // Fallback to escaped text on error
    return escapeHtml(html);
  }
}

/**
 * Escape HTML special characters to prevent XSS
 */
export function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Sanitize content specifically for search result highlighting.
 * Only allows <mark> tags for highlighting.
 */
export function sanitizeSearchHighlight(html: string): string {
  if (!html || typeof html !== 'string') {
    return '';
  }

  // Only allow <mark> tags, escape everything else
  return html
    // Temporarily replace valid mark tags with placeholders
    .replace(/<mark>/gi, '{{MARK_OPEN}}')
    .replace(/<\/mark>/gi, '{{MARK_CLOSE}}')
    // Escape all remaining HTML
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    // Restore mark tags
    .replace(/\{\{MARK_OPEN\}\}/g, '<mark>')
    .replace(/\{\{MARK_CLOSE\}\}/g, '</mark>');
}

/**
 * Safely convert markdown-like content to HTML.
 * First escapes all HTML, then applies markdown formatting.
 * This prevents XSS by ensuring user content can't inject HTML.
 *
 * Supported markdown:
 * - **bold** -> <strong>bold</strong>
 * - *italic* -> <em>italic</em>
 * - `code` -> <code>code</code>
 * - # Heading -> <h1>Heading</h1>
 * - ## Heading -> <h2>Heading</h2>
 * - ### Heading -> <h3>Heading</h3>
 * - - item -> <li>item</li>
 * - Newlines -> <br/>
 *
 * @param content - The markdown-like content to convert
 * @returns Safe HTML string
 */
export function safeMarkdownToHtml(content: string): string {
  if (!content || typeof content !== 'string') {
    return '';
  }

  const codeBlocks: string[] = [];
  const contentWithTokens = content.replace(/```(\w+)?\n([\s\S]*?)```/g, (_, lang, code) => {
    const safeCode = escapeHtml((code || '').trim());
    const classAttr = lang ? ` class="language-${lang}"` : '';
    codeBlocks.push(`<pre><code${classAttr}>${safeCode}</code></pre>`);
    return `@@CODEBLOCK_${codeBlocks.length - 1}@@`;
  });

  const escaped = escapeHtml(contentWithTokens);
  const lines = escaped.split('\n');
  const parts: string[] = [];

  let inUl = false;
  let inOl = false;
  let paragraphBuffer: string[] = [];

  const flushParagraph = () => {
    if (paragraphBuffer.length > 0) {
      const text = paragraphBuffer.join(' ').trim();
      if (text) {
        parts.push(`<p>${text}</p>`);
      }
      paragraphBuffer = [];
    }
  };

  const closeLists = () => {
    if (inUl) {
      parts.push('</ul>');
      inUl = false;
    }
    if (inOl) {
      parts.push('</ol>');
      inOl = false;
    }
  };

  const applyInline = (text: string) => {
    return text
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/\*([^*]+)\*/g, '<em>$1</em>')
      .replace(/`([^`]+)`/g, '<code>$1</code>');
  };

  const splitTableRow = (row: string) => {
    let cells = row.split('|').map(c => c.trim());
    if (cells.length > 1 && cells[0] === '') cells = cells.slice(1);
    if (cells.length > 1 && cells[cells.length - 1] === '') cells = cells.slice(0, -1);
    return cells;
  };

  const isTableSeparator = (row: string) => {
    if (!row.includes('|')) return false;
    const clean = row.replace(/\s/g, '');
    return /^\|?[:\-]+(\|[:\-]+)+\|?$/.test(clean);
  };

  for (let i = 0; i < lines.length; i += 1) {
    const rawLine = lines[i];
    const line = rawLine.trim();

    if (!line) {
      flushParagraph();
      closeLists();
      continue;
    }

    const codeMatch = line.match(/^@@CODEBLOCK_(\d+)@@$/);
    if (codeMatch) {
      flushParagraph();
      closeLists();
      parts.push(codeBlocks[parseInt(codeMatch[1], 10)] || '');
      continue;
    }

    if (/^---+$/.test(line)) {
      flushParagraph();
      closeLists();
      parts.push('<hr/>');
      continue;
    }

    // Table detection
    const nextLine = (lines[i + 1] || '').trim();
    if (line.includes('|') && isTableSeparator(nextLine)) {
      flushParagraph();
      closeLists();

      const headerCells = splitTableRow(line).map(applyInline);
      i += 1; // skip separator

      const bodyRows: string[] = [];
      while (i + 1 < lines.length) {
        const bodyLine = (lines[i + 1] || '').trim();
        if (!bodyLine || !bodyLine.includes('|')) break;
        const cells = splitTableRow(bodyLine).map(applyInline);
        bodyRows.push(`<tr>${cells.map(c => `<td>${c}</td>`).join('')}</tr>`);
        i += 1;
      }

      const thead = `<thead><tr>${headerCells.map(c => `<th>${c}</th>`).join('')}</tr></thead>`;
      const tbody = `<tbody>${bodyRows.join('')}</tbody>`;
      parts.push(`<table>${thead}${tbody}</table>`);
      continue;
    }

    const headingMatch = line.match(/^(#{1,4})\s+(.*)$/);
    if (headingMatch) {
      flushParagraph();
      closeLists();
      const level = headingMatch[1].length;
      const text = applyInline(headingMatch[2]);
      parts.push(`<h${level}>${text}</h${level}>`);
      continue;
    }

    const orderedMatch = line.match(/^\d+\.\s+(.*)$/);
    if (orderedMatch) {
      flushParagraph();
      if (!inOl) {
        closeLists();
        parts.push('<ol>');
        inOl = true;
      }
      parts.push(`<li>${applyInline(orderedMatch[1])}</li>`);
      continue;
    }

    const unorderedMatch = line.match(/^[-*]\s+(.*)$/);
    if (unorderedMatch) {
      flushParagraph();
      if (!inUl) {
        closeLists();
        parts.push('<ul>');
        inUl = true;
      }
      parts.push(`<li>${applyInline(unorderedMatch[1])}</li>`);
      continue;
    }

    paragraphBuffer.push(applyInline(line));
  }

  flushParagraph();
  closeLists();

  let html = parts.join('');
  html = html.replace(/@@CODEBLOCK_(\d+)@@/g, (_, idx) => codeBlocks[parseInt(idx, 10)] || '');
  return html;
}

/**
 * Format markdown content with proper sanitization.
 * Use this for rendering AI-generated reports or user content.
 *
 * @param content - The content to format
 * @returns Sanitized HTML string safe for dangerouslySetInnerHTML
 */
export function formatMarkdownSafe(content: string): string {
  // Convert markdown to HTML safely
  const html = safeMarkdownToHtml(content);
  // Run through sanitizer as extra protection
  return sanitizeHtml(html);
}

export default sanitizeHtml;
