"// --- (A) Fix: rate limiting key derivation must not trust spoofable headers ---
// vuln-code-snippet start resetPasswordMortyChallenge
/* Rate limiting */
app.enable('trust proxy')
app.use('/rest/user/reset-password', rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 100,
  // ❌ was: ({ headers, ip }) => headers['X-Forwarded-For'] ?? ip
  // ✅ do not trust spoofable header; Express' `ip` already honors `trust proxy`
  keyGenerator ({ ip }: { ip: string }) { return ip }
}))
// vuln-code-snippet end resetPasswordMortyChallenge

// --- (B) Fix: protect /metrics to prevent unauthenticated exposure ---
// vuln-code-snippet start exposedMetricsChallenge
/* Serve metrics */
let metricsUpdateLoop: any
const Metrics = metrics.observeMetrics() // vuln-code-snippet neutral-line exposedMetricsChallenge

// ❌ was: app.get('/metrics', metrics.serveMetrics()) // vuln-code-snippet vuln-line exposedMetricsChallenge
// ✅ restrict to localhost and rate-limit to reduce scraping abuse
app.get(
  '/metrics',
  IpFilter(['127.0.0.1', '::1'], { mode: 'allow' }),
  rateLimit({ windowMs: 60 * 1000, max: 60, validate: false }),
  metrics.serveMetrics()
)

errorhandler.title = `${config.get<string>('application.name')} (Express ${utils.version('express')})`
// vuln-code-snippet end exposedMetricsChallenge
"