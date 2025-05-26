/**
 * Regular expressions for detecting common XSS attack vectors.
 * These patterns are used to identify and remove or neutralize malicious code.
 */
export const DANGEROUS_PATTERNS: ReadonlyArray<RegExp> = [
  // Matches javascript:, jscript:, vbscript:, livescript:, expression: protocols
  /(javascript|jscript|js|vbscript|livescript|expression)\s*:/i,
  // Matches data: protocol, often used for base64 encoded payloads
  /data\s*:/i,
  // Matches <script> tags and their content
  /(<script[^>]*>([\s\S]*?)<\/script>)/i,
  // Matches on<event> handlers like onclick, onerror, etc.
  /on\w+\s*=/i,
  // Matches style, href, or src attributes containing "script:" or "data:"
  /((style|href|src)\s*=\s*['"]?\s*[^'">]*(?:script|data):)/i,
  // Matches SVG onload attributes
  /<svg[^>]*onload[^=]*=/i,
  // Matches style attributes with CSS expressions
  /<\w+[^>]*style\s*=\s*['"]?[^'">]*expression\s*\([^)]*\)[^'">]*['"]?/i,
  // Matches style attributes with url(javascript:...)
  /<\w+[^>]*style\s*=\s*['"]?[^'">]*url\s*\([^)]*javascript:[^)]*\)[^'">]*['"]?/i,
];
