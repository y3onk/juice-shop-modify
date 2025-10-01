"// 1) Enforce auth on product updates (fix CWE-306)
app.put('/api/Products/:id', security.isAuthorized())

// 2) Sanitize stored product descriptions before rendering (fix CWE-079)
if (name === 'Product') {
  resource.list.fetch.after((req: Request, res: Response, context: { instance: any[], continue: any }) => {
    for (let i = 0; i < context.instance.length; i++) {
      context.instance[i].name = req.__(context.instance[i].name)
      // ⬇️ sanitize potentially stored HTML/XSS before sending to clients
      context.instance[i].description = security.sanitizeSecure(req.__(context.instance[i].description))
    }
    return context.continue
  })
  resource.read.send.before((req: Request, res: Response, context: { instance: { name: string, description: string }, continue: any }) => {
    context.instance.name = req.__(context.instance.name)
    // ⬇️ sanitize single-item read as well
    context.instance.description = security.sanitizeSecure(req.__(context.instance.description))
    return context.continue
  })
}

// 3) Neutralize header-based XSS vector before handler (fix CWE-079 for /rest/saveLoginIp)
app.get(
  '/rest/saveLoginIp',
  (req: Request, _res: Response, next: NextFunction) => {
    // Node lowercases header names; sanitize both common client-IP headers
    const keys = ['true-client-ip', 'x-forwarded-for'] as const
    for (const k of keys) {
      const v = req.headers[k]
      if (typeof v === 'string') {
        // strip tags/JS URLs via legacy-safe stripper to keep plain text semantics
        req.headers[k] = security.sanitizeLegacy(v)
      } else if (Array.isArray(v)) {
        req.headers[k] = v.map((s) => (typeof s === 'string' ? security.sanitizeLegacy(s) : s)) as any
      }
    }
    next()
  },
  saveLoginIp()
)
"