"// src/server/servePublicFiles.ts
import path from 'path'
import fs from 'fs'
import type { Request, Response, NextFunction } from 'express'

/**
 * Securely serves files from the public FTP directory.
 * Keeps the public API the same: `servePublicFiles()` returns an Express middleware.
 */
export function servePublicFiles () {
  // Resolve once at module load
  const baseDir = path.resolve(__dirname, '..', '..', 'ftp')

  // A conservative allow-list of file extensions we actually intend to serve publicly.
  // (Add more if your app previously allowed them; this is the minimal safe set.)
  const ALLOWED_EXTS = new Set([
    '.md', '.txt', '.html', '.htm',
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg',
    '.css', '.js', '.json', // keep if these were already publicly available assets
    '.pdf'
  ])

  // Extensions that must never be served even if someone tries to hide them
  // behind fake suffixes or poison-null bytes.
  const BLOCKED_EXTS = [
    '.bak', '.yml', '.yaml', '.env', '.config', '.conf', '.ini',
    '.pem', '.crt', '.key', '.kdb', '.p12', '.pfx',
    '.lock', '.log', '.db', '.sqlite', '.sqlite3'
  ]

  return (req: Request, res: Response, next: NextFunction) => {
    try {
      let raw = String((req.params as any).file ?? '')

      // Decode percent-encodings once (e.g., ""%00"" → ""\u0000"")
      try { raw = decodeURIComponent(raw) } catch { /* ignore malformed encodings */ }

      // 1) Poison-null-byte hard stop (CWE-158)
      // Any NUL present means the user is attempting to truncate the real path on some layers.
      if (raw.includes('\u0000')) {
        return res.status(400).send('Invalid file name.')
      }

      // 2) Normalize and contain to base directory (no traversal / symlink escape)
      //    - Strip leading separators to force a relative path before resolve.
      const candidateRel = path.normalize(raw).replace(/^([/\\])+/, '')
      const absPath = path.resolve(baseDir, candidateRel)

      // Ensure final path is still inside baseDir
      const baseWithSep = baseDir.endsWith(path.sep) ? baseDir : baseDir + path.sep
      if (!absPath.startsWith(baseWithSep)) {
        return res.status(403).send('Forbidden.')
      }

      // 3) Deny hidden dotfiles and editor/backup conventions even if nested
      const baseName = path.basename(absPath)
      if (
        baseName.startsWith('.') ||              // .env, .gitignore, etc.
        baseName.endsWith('~') ||                // editor backups
        baseName.toLowerCase().includes('.bak')  // stray backups like file.json.bak
      ) {
        return res.status(403).send('Forbidden.')
      }

      // 4) Enforce allow-list on the *actual* resolved path’s extension (prevents %00 bypass)
      const ext = path.extname(absPath).toLowerCase()

      // Block explicitly sensitive extensions regardless of allow-list
      if (BLOCKED_EXTS.some(bad => baseName.toLowerCase().endsWith(bad))) {
        return res.status(403).send('Forbidden.')
      }

      if (!ALLOWED_EXTS.has(ext)) {
        return res.status(403).send('Forbidden.')
      }

      // 5) Finally, ensure the target exists and is a regular file
      let stat: fs.Stats
      try {
        stat = fs.statSync(absPath)
      } catch {
        return res.status(404).send('Not found.')
      }
      if (!stat.isFile()) {
        return res.status(404).send('Not found.')
      }

      // 6) Serve the file
      return res.sendFile(absPath)
    } catch (err) {
      return next(err)
    }
  }
}

export default servePublicFiles
"