"description: {
  type: DataTypes.STRING,
  set (description: string) {
    const raw = typeof description === 'string' ? description : String(description ?? '')

    // Keep challenge detection logic (reads the original input)
    if (utils.isChallengeEnabled(challenges.restfulXssChallenge)) {
      challengeUtils.solveIf(challenges.restfulXssChallenge, () => {
        return utils.contains(
          raw,
          '<iframe src=""javascript:alert(`xss`)"">'
        )
      })
    }

    // Always sanitize before storing to prevent stored XSS
    const sanitized = security.sanitizeSecure(raw)
    this.setDataValue('description', sanitized)
  }
},
"