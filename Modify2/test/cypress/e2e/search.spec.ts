"export const publicKey = (() => {
  try {
    if (fs && fs.existsSync('encryptionkeys/jwt.pub')) {
      return fs.readFileSync('encryptionkeys/jwt.pub', 'utf8')
    }
  } catch (err: any) {
    // Don't crash tests or dev runs; fall back to env or placeholder
    // Logging helps debugging when key file is missing
    // (avoid exposing sensitive contents in logs)
    // eslint-disable-next-line no-console
    console.warn('Could not read public key from encryptionkeys/jwt.pub:', err?.message || err)
  }
  return process.env.JWT_PUBLIC_KEY || 'placeholder-public-key'
})()

// IMPORTANT: Do NOT hard-code private keys in source. Load from a secure source.
// Prefer an environment variable (e.g., set via secrets manager) or a protected file with strict FS permissions.
const privateKey = (() => {
  // 1) Prefer explicit environment variable (use secrets manager in production)
  if (process.env.JWT_PRIVATE_KEY && process.env.JWT_PRIVATE_KEY.trim() !== '') {
    return process.env.JWT_PRIVATE_KEY
  }

  // 2) Fallback to a file (ensure file has strict permissions and is not checked into VCS)
  try {
    if (fs && fs.existsSync('encryptionkeys/jwt.key')) {
      return fs.readFileSync('encryptionkeys/jwt.key', 'utf8')
    }
  } catch (err: any) {
    // eslint-disable-next-line no-console
    console.warn('Could not read private key from encryptionkeys/jwt.key:', err?.message || err)
  }

  // 3) Fail closed in production to avoid running with an insecure placeholder
  if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT private key not configured (set JWT_PRIVATE_KEY or provide encryptionkeys/jwt.key)')
  }

  // Non-production fallback (tests/dev) — explicit placeholder to keep API compatibility
  return 'placeholder-private-key'
})()

// ... rest of the file ...

put: (token: string, user: ResponseWithUser) => void
"