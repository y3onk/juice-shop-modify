"comment: {
  type: DataTypes.STRING,
  set (comment: string) {
    let sanitizedComment: string
    if (utils.isChallengeEnabled(challenges.persistedXssFeedbackChallenge)) {
      // Use the secure sanitizer for persistence so dangerous constructs cannot survive.
      // Keep the challenge check but test the raw input (not the persisted value) so the challenge
      // can still be detected without storing unsafe HTML/JS.
      sanitizedComment = security.sanitizeSecure(comment)
      challengeUtils.solveIf(challenges.persistedXssFeedbackChallenge, () => {
        return utils.contains(
          comment,
          '<iframe src=""javascript:alert(`xss`)"">'
        )
      })
    } else {
      sanitizedComment = security.sanitizeSecure(comment)
    }
    this.setDataValue('comment', sanitizedComment)
  }
}
"