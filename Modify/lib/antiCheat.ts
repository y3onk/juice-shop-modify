"// Redact sensitive password-related challenge keys before logging to avoid clear-text exposure
const _sensitiveChallengeKeys = new Set<string>([
  'changePasswordBenderChallenge',
  'weakPasswordChallenge',
  'dlpPasswordSprayingChallenge',
  'oauthUserPasswordChallenge',
  'resetPasswordJimChallenge',
  'resetPasswordBenderChallenge',
  'resetPasswordBjoernChallenge',
  'resetPasswordMortyChallenge',
  'resetPasswordBjoernOwaspChallenge',
  'resetPasswordUvoginChallenge',
  'passwordRepeatChallenge'
])
const _safeKey = _sensitiveChallengeKeys.has(challenge.key) ? '[REDACTED]' : challenge.key

logger.info(
  `Cheat score for ${areCoupled(challenge, previous().challenge) ? 'coupled ' : (isTrivial(challenge) ? 'trivial ' : '')}${
    challenge.tutorialOrder ? 'tutorial ' : ''
  }${colors.cyan(_safeKey)} solved in ${Math.round(minutesSincePreviousSolve)}min (expected ~${minutesExpectedToSolve}min) with${
    config.get('challenges.showHints') ? '' : 'out'
  } hints allowed${
    percentPrecedingInteraction > -1 ? ' and ' + percentPrecedingInteraction * 100 + '% expected preceding URL interaction' : ''
  }: ${
    cheatScore < 0.33
      ? colors.green(cheatScore.toString())
      : cheatScore < 0.66
      ? colors.yellow(cheatScore.toString())
      : colors.red(cheatScore.toString())
  }`
)
"