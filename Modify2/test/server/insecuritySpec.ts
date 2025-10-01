"// Hardened HTML sanitization to prevent XSS via surviving <iframe> / javascript: URLs
const SAFE_HTML_CONFIG = {
  // Keep a minimal, non-interactive whitelist; explicitly exclude <iframe>, <script>, etc.
  allowedTags: ['b', 'i', 'em', 'strong', 'u', 'br', 'p', 'ul', 'ol', 'li', 'span', 'div', 'code', 'pre', 'blockquote', 'a'],
  allowedAttributes: {
    a: ['href', 'name', 'target', 'rel']
  },
  // Disallow dangerous URL schemes (notably ""javascript:"", ""data:"" for non-img)
  allowedSchemes: ['http', 'https', 'mailto', 'tel'],
  allowProtocolRelative: false,
  // Drop anything not explicitly allowed
  disallowedTagsMode: 'discard'
} as any

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html, SAFE_HTML_CONFIG)

// Make legacy sanitizer safe against tag-splitting tricks (e.g., '<<a|ascript>' → '<script>')
export const sanitizeLegacy = (input = '') => {
  // 1) Normalize repeated ""<"" so crafted inputs cannot form new tags after stripping
  const normalized = input.replace(/<+/g, '<')
  // 2) Remove both opening and closing tags robustly (no partial cuts)
  return normalized.replace(/<\/?[^>]+>/g, '')
}
"