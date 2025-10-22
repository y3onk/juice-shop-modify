// function storeVerdict (challengeKey: ChallengeKey, phase: Phase, verdict: boolean) {
//   // Guard against prototype-polluting keys
//   const isUnsafeKey = (k: unknown) =>
//     typeof k === 'string' && (/^(?:__proto__|prototype|constructor|proto)$/).test(k)

//   // Only allow the two known phases
//   const allowedPhases = new Set(['find it', 'fix it'])

//   if (isUnsafeKey(challengeKey) || !allowedPhases.has(phase as any)) {
//     // silently ignore unsafe/malformed inputs to preserve external behavior
//     return
//   }

//   // Initialize per-challenge bucket using objects without a prototype
//   if (!Object.prototype.hasOwnProperty.call(solves, challengeKey) || typeof (solves as any)[challengeKey] !== 'object') {
//     ;(solves as any)[challengeKey] = Object.assign(Object.create(null), {
//       'find it': false,
//       'fix it': false,
//       attempts: Object.assign(Object.create(null), { 'find it': 0, 'fix it': 0 })
//     })
//   }

//   const entry = (solves as any)[challengeKey]
//   // Defensive: ensure attempts exists and is a plain dictionary
//   if (!entry.attempts || typeof entry.attempts !== 'object') {
//     entry.attempts = Object.assign(Object.create(null), { 'find it': 0, 'fix it': 0 })
//   }

//   if (!entry[phase]) {
//     entry[phase] = verdict
//     entry.attempts[phase]++
//   }
// }
//---------------------
/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

import { type ChallengeKey } from 'models/challenge'
import logger from './logger'
import colors from 'colors/safe'
const solves: Record<string, { 'find it': boolean, 'fix it': boolean, attempts: { 'find it': number, 'fix it': number } }> = {}

type Phase = 'find it' | 'fix it'

export const storeFindItVerdict = (challengeKey: ChallengeKey, verdict: boolean) => {
  storeVerdict(challengeKey, 'find it', verdict)
}

export const storeFixItVerdict = (challengeKey: ChallengeKey, verdict: boolean) => {
  storeVerdict(challengeKey, 'fix it', verdict)
}

export const calculateFindItAccuracy = (challengeKey: ChallengeKey) => {
  return calculateAccuracy(challengeKey, 'find it')
}

export const calculateFixItAccuracy = (challengeKey: ChallengeKey) => {
  return calculateAccuracy(challengeKey, 'fix it')
}

export const totalFindItAccuracy = () => {
  return totalAccuracy('find it')
}

export const totalFixItAccuracy = () => {
  return totalAccuracy('fix it')
}

export const getFindItAttempts = (challengeKey: ChallengeKey) => {
  return solves[challengeKey] ? solves[challengeKey].attempts['find it'] : 0
}

function totalAccuracy (phase: Phase) {
  let sumAccuracy = 0
  let totalSolved = 0
  Object.entries(solves).forEach(([key, value]) => {
    if (value[phase]) {
      sumAccuracy += 1 / value.attempts[phase]
      totalSolved++
    }
  })
  return sumAccuracy / totalSolved
}

function calculateAccuracy (challengeKey: ChallengeKey, phase: Phase) {
  let accuracy = 0
  if (solves[challengeKey][phase]) {
    accuracy = 1 / solves[challengeKey].attempts[phase]
  }
  logger.info(`Accuracy for '${phase === 'fix it' ? 'Fix It' : 'Find It'}' phase of coding challenge ${colors.cyan(challengeKey)}: ${accuracy > 0.5 ? colors.green(accuracy.toString()) : (accuracy > 0.25 ? colors.yellow(accuracy.toString()) : colors.red(accuracy.toString()))}`)
  return accuracy
}

function storeVerdict (challengeKey: ChallengeKey, phase: Phase, verdict: boolean) {
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
