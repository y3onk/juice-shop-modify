"function storeVerdict (challengeKey: ChallengeKey, phase: Phase, verdict: boolean) {
  // Guard against prototype-polluting keys
  const isUnsafeKey = (k: unknown) =>
    typeof k === 'string' && (/^(?:__proto__|prototype|constructor|proto)$/).test(k)

  // Only allow the two known phases
  const allowedPhases = new Set(['find it', 'fix it'])

  if (isUnsafeKey(challengeKey) || !allowedPhases.has(phase as any)) {
    // silently ignore unsafe/malformed inputs to preserve external behavior
    return
  }

  // Initialize per-challenge bucket using objects without a prototype
  if (!Object.prototype.hasOwnProperty.call(solves, challengeKey) || typeof (solves as any)[challengeKey] !== 'object') {
    ;(solves as any)[challengeKey] = Object.assign(Object.create(null), {
      'find it': false,
      'fix it': false,
      attempts: Object.assign(Object.create(null), { 'find it': 0, 'fix it': 0 })
    })
  }

  const entry = (solves as any)[challengeKey]
  // Defensive: ensure attempts exists and is a plain dictionary
  if (!entry.attempts || typeof entry.attempts !== 'object') {
    entry.attempts = Object.assign(Object.create(null), { 'find it': 0, 'fix it': 0 })
  }

  if (!entry[phase]) {
    entry[phase] = verdict
    entry.attempts[phase]++
  }
}
"