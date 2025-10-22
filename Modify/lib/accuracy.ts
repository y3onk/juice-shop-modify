// function storeVerdict (challengeKey: ChallengeKey, phase: Phase, verdict: boolean) {
//   // Guard against prototype-polluting keys
//   const isDangerousKey = (k: unknown): boolean =>
//     typeof k === 'string' && (k === '__proto__' || k === 'prototype' || k === 'constructor')
//   if (isDangerousKey(challengeKey) || isDangerousKey(phase)) {
//     return
//   }

//   const hasOwn = (obj: any, key: string) => Object.prototype.hasOwnProperty.call(obj, key)

//   // Initialize entry using dictionaries without Object.prototype to avoid inherited props
//   if (!hasOwn(solves, challengeKey) || !solves[challengeKey]) {
//     const attempts = Object.create(null) as Record<Phase, number>
//     attempts['find it'] = 0
//     attempts['fix it'] = 0

//     solves[challengeKey] = Object.assign(Object.create(null), {
//       'find it': false,
//       'fix it': false,
//       attempts
//     }) as any
//   }

//   const entry = solves[challengeKey] as any

//   // Only write if not already set for this phase
//   if (!hasOwn(entry, phase) || !entry[phase]) {
//     entry[phase] = verdict
//     entry.attempts[phase] = (entry.attempts[phase] || 0) + 1
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
