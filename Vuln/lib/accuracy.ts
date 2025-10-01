"function storeVerdict (challengeKey: ChallengeKey, phase: Phase, verdict: boolean) {
  if (!solves[challengeKey]) {
    solves[challengeKey] = { 'find it': false, 'fix it': false, attempts: { 'find it': 0, 'fix it': 0 } }
  }
  if (!solves[challengeKey][phase]) {
    solves[challengeKey][phase] = verdict
    solves[challengeKey].attempts[phase]++
  }
}"