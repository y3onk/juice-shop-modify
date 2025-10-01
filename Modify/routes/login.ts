"return (req: Request, res: Response, next: NextFunction) => {
  verifyPreLoginChallenges(req) // vuln-code-snippet hide-line

  // Minimal, behavior-preserving input guarding
  const email = typeof req.body.email === 'string' ? req.body.email : ''
  const password = typeof req.body.password === 'string' ? req.body.password : ''
  const passwordHash = security.hash(password)

  // ✅ FIX: use a parameterized query (no string interpolation)
  models.sequelize
    .query(
      'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
      {
        model: UserModel,
        plain: true,
        // Named parameters prevent injection
        replacements: { email, password: passwordHash }
      }
    ) // vuln-code-snippet fixed-line loginAdminChallenge loginBenderChallenge loginJimChallenge
    .then((authenticatedUser) => { // vuln-code-snippet neutral-line loginAdminChallenge loginBenderChallenge loginJimChallenge
      const user = utils.queryResultToJson(authenticatedUser)
      if (user.data?.id && user.data.totpSecret !== '') {
        res.status(401).json({
          status: 'totp_token_required',
          data: {
            tmpToken: security.authorize({
              userId: user.data.id,
              type: 'password_valid_needs_second_factor_token'
            })
          }
        })
      } else if (user.data?.id) {
        // @ts-expect-error FIXME some properties missing in user - vuln-code-snippet hide-line
        afterLogin(user, res, next)
      } else {
        res.status(401).send(res.__('Invalid email or password.'))
      }
    })
    .catch((error: Error) => {
      next(error)
    })
}
"