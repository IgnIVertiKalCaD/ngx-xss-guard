/**
 * Regular expressions for detecting common XSS attack vectors.
 * These patterns are used to identify and remove or neutralize malicious code.
 */
export const DANGEROUS_PATTERNS: RegExp[] = [
  // 1. CSS Expressions (усиленный для пробелов и комментариев)
  /(?:\/\*[\s\S]*?\*\/)?(?:\s|%[0-9a-fA-F]{2})*expression[\s\u00A0]*\((?:[^(){};]+|\((?:[^(){};]+|\([^(){};]*\))*\))*\)/gi,
  // 2. "on..." event handler attributes (NBSP-aware)
  /[\s\u00A0]*on\w+(?:\/\*.*?\*\/)?[\s\u00A0]*=[\s\u00A0]*(?:"(?:(?!"|\\).)*?"|'(?:(?!'|\\).)*?'|[^\s>]*)/gi,

  // 3. Script tags - более полный паттерн
  /<\s*s(?:[\s%0-9a-fA-F]*?)c(?:[\s%0-9a-fA-F]*?)r(?:[\s%0-9a-fA-F]*?)i(?:[\s%0-9a-fA-F]*?)p(?:[\s%0-9a-fA-F]*?)t\b[^>]*>[\s\S]*?<\s*\/\s*s(?:[\s%0-9a-fA-F]*?)c(?:[\s%0-9a-fA-F]*?)r(?:[\s%0-9a-fA-F]*?)i(?:[\s%0-9a-fA-F]*?)p(?:[\s%0-9a-fA-F]*?)t\s*>/gi,
  //    3-б) Одиночные <script …> или </script>
  /<\s*\/?\s*s(?:[\s%0-9a-fA-F]*?)c(?:[\s%0-9a-fA-F]*?)r(?:[\s%0-9a-fA-F]*?)i(?:[\s%0-9a-fA-F]*?)p(?:[\s%0-9a-fA-F]*?)t\b[^>]*>/gi,

  /<\/?javascript[^>]*>[\s\S]*?<\/javascript[^>]*>/gi,
  /<javascript[^>]*>/gi,
  /<\/javascript[^>]*>/gi,

  // 4. JavaScript protocol (обновленный для Unicode обфускации)
  /(?<=href[\s\u00A0]*=[\s\u00A0]*(?:"|')?)\s*(?:ja(?:\/\*.*?\*\/)?va(?:\/\*.*?\*\/)?script|\\u006a\\u0061\\u0076\\u0061script):(?:[^"'>\s\u00A0]|&colon;)+/gi,
  /(?<=src[\s\u00A0]*=[\s\u00A0]*(?:"|')?)\s*(?:ja(?:\/\*.*?\*\/)?va(?:\/\*.*?\*\/)?script|\\u006a\\u0061\\u0076\\u0061script):(?:[^"'>\s\u00A0]|&colon;)+/gi,
  /(?<=action[\s\u00A0]*=[\s\u00A0]*(?:"|')?)\s*(?:ja(?:\/\*.*?\*\/)?va(?:\/\*.*?\*\/)?script|\\u006a\\u0061\\u0076\\u0061script):(?:[^"'>\s\u00A0]|&colon;)+/gi,
  /(?<=formaction[\s\u00A0]*=[\s\u00A0]*(?:"|')?)\s*(?:ja(?:\/\*.*?\*\/)?va(?:\/\*.*?\*\/)?script|\\u006a\\u0061\\u0076\\u0061script):(?:[^"'>\s\u00A0]|&colon;)+/gi,

  // Простые версии для javascript:
  /javascript[\s\u00A0]*:/gi,
  /\\u006a\\u0061\\u0076\\u0061script[\s\u00A0]*:/gi,

  // 5. data: protocol для опасных MIME-типов
  /(?<=href[\s\u00A0]*=[\s\u00A0]*(?:"|')?)\s*data:(?:text\/(?:html|xml)|application\/(?:xml|xhtml\+xml|javascript|json|rss\+xml)|image\/svg\+xml)[^"'>\s,]*,[^"'>\s\u00A0]*/gi,
  /(?<=src[\s\u00A0]*=[\s\u00A0]*(?:"|')?)\s*data:(?:text\/(?:html|xml)|application\/(?:xml|xhtml\+xml|javascript|json|rss\+xml)|image\/svg\+xml)[^"'>\s,]*,[^"'>\s\u00A0]*/gi,
  /(?<=srcdoc[\s\u00A0]*=[\s\u00A0]*(?:"|')?)\s*data:(?:text\/(?:html|xml)|application\/(?:xml|xhtml\+xml|javascript|json|rss\+xml)|image\/svg\+xml)[^"'>\s,]*,[^"'>\s\u00A0]*/gi,

  // Общий data: для hasXssRisks
  /\bdata:/gi,
  /\\u0064\\u0061\\u0054\\u0061:/gi, // Unicode обфускация для data:

  // 6. Дополнительные паттерны для iframe srcdoc
  /srcdoc[\s\u00A0]*=[\s\u00A0]*(?:"[^"]*(?:script|onerror|onload)[^"]*"|'[^']*(?:script|onerror|onload)[^']*')/gi,

  // 7. HTML комментарии с script
  /<!--[\s\S]*?<\s*\/?\s*s\s*?c\s*?r\s*?i\s*?p\s*?t\b[\s\S]*?-->/gi,
];
