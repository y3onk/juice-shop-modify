"function storeVerdict (challengeKey: ChallengeKey, phase: Phase, verdict: boolean) {
  // Guard against prototype-polluting keys
  const isDangerousKey = (k: unknown): boolean =>
    typeof k === 'string' && (k === '__proto__' || k === 'prototype' || k === 'constructor')
  if (isDangerousKey(challengeKey) || isDangerousKey(phase)) {
    return
  }

  const hasOwn = (obj: any, key: string) => Object.prototype.hasOwnProperty.call(obj, key)

  // Initialize entry using dictionaries without Object.prototype to avoid inherited props
  if (!hasOwn(solves, challengeKey) || !solves[challengeKey]) {
    const attempts = Object.create(null) as Record<Phase, number>
    attempts['find it'] = 0
    attempts['fix it'] = 0

    solves[challengeKey] = Object.assign(Object.create(null), {
      'find it': false,
      'fix it': false,
      attempts
    }) as any
  }

  const entry = solves[challengeKey] as any

  // Only write if not already set for this phase
  if (!hasOwn(entry, phase) || !entry[phase]) {
    entry[phase] = verdict
    entry.attempts[phase] = (entry.attempts[phase] || 0) + 1
  }
}
"