username: {
  type: DataTypes.STRING,
  defaultValue: '',
  set (username: string) {
    if (utils.isChallengeEnabled(challenges.persistedXssUserChallenge)) {
      username = security.sanitizeLegacy(username)
    } else {
      username = security.sanitizeSecure(username)
    }
    this.setDataValue('username', username)
  }
},
email: {
  type: DataTypes.STRING,
  unique: true,
  set (email: string) {
    if (utils.isChallengeEnabled(challenges.persistedXssUserChallenge)) {
      challengeUtils.solveIf(challenges.persistedXssUserChallenge, () => {
        return utils.contains(
          email,
          '<iframe src="javascript:alert(`xss`)">'
        )
      })
    } else {
      email = security.sanitizeSecure(email)
    }
    this.setDataValue('email', email)
  }
},