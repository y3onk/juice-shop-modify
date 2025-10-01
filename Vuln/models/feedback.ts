comment: {
  type: DataTypes.STRING,
  set (comment: string) {
    let sanitizedComment: string
    if (utils.isChallengeEnabled(challenges.persistedXssFeedbackChallenge)) {
      sanitizedComment = security.sanitizeHtml(comment)
      challengeUtils.solveIf(challenges.persistedXssFeedbackChallenge, () => {
        return utils.contains(
          sanitizedComment,
          '<iframe src="javascript:alert(`xss`)">'
        )
      })
    } else {
      sanitizedComment = security.sanitizeSecure(comment)
    }
    this.setDataValue('comment', sanitizedComment)
  }
}
