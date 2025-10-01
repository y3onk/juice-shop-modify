"export function serveMetrics () {
  return async (req: Request, res: Response, next: NextFunction) => {
    challengeUtils.solveIf(challenges.exposedMetricsChallenge, () => {
      const userAgent = req.headers['user-agent'] ?? ''
      const ignoredUserAgents = config.get<string[]>('challenges.metricsIgnoredUserAgents')
      return !ignoredUserAgents.some((ignoredUserAgent) => userAgent.includes(ignoredUserAgent))
    })

    // --- AuthZ guard (optional, backwards compatible) ---
    try {
      const authEnabled = config.has('metrics.auth.enabled') && Boolean(config.get<boolean>('metrics.auth.enabled'))
      if (authEnabled) {
        const expected = config.get<string>('metrics.auth.token')
        const headerToken = (req.headers['x-metrics-token'] as string | undefined)?.trim()
        const queryToken = typeof req.query.token === 'string' ? req.query.token.trim() : undefined
        const provided = headerToken || queryToken

        if (!expected || !provided || provided !== expected) {
          res.status(401).type('text/plain').end('Unauthorized')
          return
        }
      }
    } catch {
      // Fail safe: do not expose metrics if config is inconsistent
      res.status(500).type('text/plain').end('Metrics configuration error')
      return
    }
    // ----------------------------------------------------

    res.set('Content-Type', register.contentType)
    res.set('Cache-Control', 'no-store')
    res.end(await register.metrics())
  }
}
"