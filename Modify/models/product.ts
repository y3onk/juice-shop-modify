"description: {
  type: DataTypes.STRING,
  set (description: string) {
    // keep original user input for challenge detection, but ALWAYS store a sanitized value
    const rawDescription = description
    const safeDescription = security.sanitizeSecure(description)

    if (utils.isChallengeEnabled(challenges.restfulXssChallenge)) {
      // evaluate challenge condition using the RAW input, but do NOT store raw input
      challengeUtils.solveIf(challenges.restfulXssChallenge, () => {
        return utils.contains(
          rawDescription,
          '<iframe src=""javascript:alert(`xss`)"">'
        )
      })
    }

    // Always save the sanitized value to the database to prevent stored XSS
    this.setDataValue('description', safeDescription)
  }
},
"