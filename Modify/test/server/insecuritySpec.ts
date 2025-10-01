"// lib/insecurity.ts
// Hardened sanitizers to prevent XSS via non-recursive and legacy routines.
// Public API (function names/exports) preserved.

export function sanitizeHtml(input: string): string {
  if (input == null) return ''

  // Normalize input and remove any NUL bytes
  let html = String(input).replace(/\u0000/g, '')

  // 0) De-obfuscate basic evasion like ""<<script>""
  //    Collapse multiple consecutive ""<"" to a single ""<"" when they start a tag-like token
  html = html.replace(/<\s*<+/g, '<')

  // 1) Remove SCRIPT blocks entirely (robust against attributes / spacing)
  html = html.replace(/<\s*script\b[^>]*>[\s\S]*?<\s*\/\s*script\s*>/gi, '')

  // 2) Neutralize any stray opening/closing <script ...> tags that slipped through
  html = html.replace(/<\s*\/?\s*script\b/gi, '&lt;script')

  // 3) Strip event handler attributes (onload=, onclick=, etc.)
  //    Handles quoted and unquoted values.
  html = html.replace(
    /\s+on[a-z0-9_-]+\s*=\s*(?:""[^""]*""|'[^']*'|[^\s>]+)/gi,
    ''
  )

  // 4) Sanitize inline styles: drop if they contain ""expression("" or ""javascript:""
  html = html.replace(
    /\sstyle\s*=\s*(['""])([\s\S]*?)\1/gi,
    (_m, q, val: string) => {
      const v = String(val).toLowerCase()
      if (v.includes('expression(') || v.includes('javascript:') || v.includes('url(javascript:')) {
        return ''
      }
      return ` style=${q}${val}${q}`
    }
  )

  // 5) Block dangerous URI schemes on href/src/xlink:href and similar attributes.
  //    Replace with about:blank (safe inert target).
  const ATTRS = ['href', 'src', 'xlink:href', 'formaction']
  for (const attr of ATTRS) {
    const re = new RegExp(
      String.raw`(\s${attr}\s*=\s*)(['""]?)(\s*javascript:[^'"">\s]*)\2`,
      'gi'
    )
    html = html.replace(re, (_m, p1, q) => `${p1}${q}about:blank${q}`)
  }

  // 6) IFRAME hardening:
  //    - Allow only http:, https:, or about:blank sources
  //    - Drop <iframe> tag if its src is missing or uses a blocked scheme
  html = html.replace(
    /<\s*iframe\b([^>]*)>([\s\S]*?)<\s*\/\s*iframe\s*>/gi,
    (_m, attrs: string, inner: string) => {
      // Extract src (if any)
      const m = /\bsrc\s*=\s*(['""]?)([^'"">\s]+)\1/i.exec(attrs || '')
      if (!m) {
        // no src -> drop entire iframe to be safe
        return ''
      }
      const src = m[2].trim().toLowerCase()
      if (
        src.startsWith('http:') ||
        src.startsWith('https:') ||
        src === 'about:blank'
      ) {
        // Keep iframe but re-emit with sanitized attributes (remove any events/styles that slipped)
        let clean = ' ' + attrs

        // remove event handlers inside attributes
        clean = clean.replace(
          /\s+on[a-z0-9_-]+\s*=\s*(?:""[^""]*""|'[^']*'|[^\s>]+)/gi,
          ''
        )
        // sanitize style attribute again
        clean = clean.replace(
          /\sstyle\s*=\s*(['""])([\s\S]*?)\1/gi,
          (_m2, q, val: string) => {
            const v = String(val).toLowerCase()
            if (v.includes('expression(') || v.includes('javascript:') || v.includes('url(javascript:')) {
              return ''
            }
            return ` style=${q}${val}${q}`
          }
        )
        // block javascript: in any remaining href/src-like attributes on the iframe
        for (const attr of ATTRS) {
          const re = new RegExp(
            String.raw`(\s${attr}\s*=\s*)(['""]?)(\s*javascript:[^'"">\s]*)\2`,
            'gi'
          )
          clean = clean.replace(re, (_mm, p1, q) => `${p1}${q}about:blank${q}`)
        }

        return `<iframe${clean}>${inner}</iframe>`
      }
      // Unsafe scheme -> drop the iframe entirely
      return ''
    }
  )

  // 7) Final defense-in-depth: break any remaining ""javascript:"" tokens inside tags
  //    (e.g., malformed tags or attributes we didn't match)
  html = html.replace(/(<[^>]*)(javascript:)/gi, (_m, p1, _p2) => `${p1}javascript&#58;`)

  return html
}

/**
 * Legacy sanitizer: previously a naive tag-strip that attackers could bypass to yield working <script> payloads.
 * We keep the function signature but make it safe by HTML-encoding risky characters globally.
 */
export function sanitizeLegacy(input: string): string {
  if (input == null) return ''
  const s = String(input).replace(/\u0000/g, '')
  // Encode &, <, >, "" and ' to neutralize any HTML/script contexts.
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/""/g, '&quot;')
    .replace(/'/g, '&#39;')
}

// Preserve default export shape if other modules import the whole object.
export default {
  sanitizeHtml,
  sanitizeLegacy
}
"