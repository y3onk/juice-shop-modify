"//including 23:7
export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'

//including 44:39
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// Prefer externalized secret; fall back to file, then legacy constant (kept for backward-compat only)
const readIfExists = (p: string) => {
  try { return fs ? fs.readFileSync(p, 'utf8').trim() : undefined } catch { return undefined }
}
const LEGACY_HMAC_SECRET = 'pa4qacea4VK9t9nGv7yZtwmj' // DEPRECATED: kept to avoid breaking existing hashes
const HMAC_SECRET =
  process.env.HMAC_SECRET ||
  readIfExists('encryptionkeys/hmac.secret') ||
  LEGACY_HMAC_SECRET

export const hmac = (data: string) =>
  crypto.createHmac('sha256', HMAC_SECRET).update(data).digest('hex')

//including 54:14
// Restrict algorithm to asymmetric RS256 to prevent alg confusion (HS*/RS* swap)
export const isAuthorized = () =>
  expressJwt(({ secret: publicKey, algorithms: ['RS256'] }) as any)

//including 138:26
export const isRedirectAllowed = (url: string) => {
  // Relative paths stay within the app — allow them.
  if (!/^https?:\/\//i.test(url)) return true

  let allowed = false
  let target: URL
  try {
    target = new URL(url)
  } catch {
    return false
  }

  for (const allowedUrl of redirectAllowlist) {
    try {
      const a = new URL(allowedUrl)
      // require exact origin match AND path-prefix match (no substring smuggling)
      if (target.origin === a.origin && target.pathname.startsWith(a.pathname)) {
        allowed = true
        break
      }
    } catch {
      // If an entry isn't a full URL (e.g., ""/account""), treat it as an absolute path-prefix.
      if (target.pathname.startsWith(allowedUrl)) {
        allowed = true
        break
      }
    }
  }
  return allowed
}

//including 191:5
export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token) {
    // Verify strictly with RS256 to avoid accepting HS* tokens signed with the public key
    jwt.verify(token, publicKey, { algorithms: ['RS256'] }, (err: Error | null, decoded: any) => {
      if (!err && decoded) {
        if (authenticatedUsers.get(token) === undefined) {
          authenticatedUsers.put(token, decoded)
          res.cookie('token', token)
        }
      }
    })
  }
  next()
}
"