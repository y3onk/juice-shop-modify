export function serveMetrics () {
  return async (req: Request, res: Response, next: NextFunction) => {
    challengeUtils.solveIf(challenges.exposedMetricsChallenge, () => {
      const userAgent = req.headers['user-agent'] ?? ''
      const ignoredUserAgents = config.get<string[]>('challenges.metricsIgnoredUserAgents')
      return !ignoredUserAgents.some((ignoredUserAgent) => userAgent.includes(ignoredUserAgent))
    })
    res.set('Content-Type', register.contentType)
    res.end(await register.metrics())
  }
}