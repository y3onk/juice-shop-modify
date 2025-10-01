"username: {
  type: DataTypes.STRING,
  defaultValue: '',
  set (username: string) {
    // Always apply the modern, secure sanitizer before persisting.
    username = security.sanitizeSecure(username)

    // If the persisted-XSS challenge is enabled, still attempt to mark the challenge solved
    // based on the original user input pattern (use sanitized value for safety of checks).
    if (utils.isChallengeEnabled(challenges.persistedXssUserChallenge)) {
      challengeUtils.solveIf(challenges.persistedXssUserChallenge, () => {
        return utils.contains(
          username,
          '<iframe src=""javascript:alert(`xss`)"">'
        )
      })
    }

    this.setDataValue('username', username)
  }
},
email: {
  type: DataTypes.STRING,
  unique: true,
  set (email: string) {
    const rawEmail = email

    // If the persisted-XSS challenge is enabled, perform the challenge check using the raw input.
    if (utils.isChallengeEnabled(challenges.persistedXssUserChallenge)) {
      challengeUtils.solveIf(challenges.persistedXssUserChallenge, () => {
        return utils.contains(
          rawEmail,
          '<iframe src=""javascript:alert(`xss`)"">'
        )
      })
    }

    // Always sanitize with the secure sanitizer before persisting.
    email = security.sanitizeSecure(email)

    this.setDataValue('email', email)
  }
},
"
