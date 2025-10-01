"async function createSecurityAnswer (UserId: number, SecurityQuestionId: number, answer: string) {
  return await SecurityAnswerModel.create({ SecurityQuestionId, UserId, answer }).catch((err: unknown) => {
    // Avoid logging sensitive user secret `answer` (CWE-532)
    logger.error(
      `Could not insert SecurityAnswer [REDACTED] mapped to UserId ${UserId} (SecurityQuestionId ${SecurityQuestionId}): ${utils.getErrorMessage(err)}`
    )
  })
}
"