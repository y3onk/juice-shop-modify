"//including 240:5
async function getUserFromJwt (token: string): Promise<User | null> {
  return await new Promise((resolve) => {
    jwt.verify(
      token,
      security.publicKey,
      { algorithms: ['RS256'] }, // enforce asymmetric alg to prevent HS/none confusion
      (err: VerifyErrors | null, decoded: JwtPayload | string | undefined) => {
        if (err || !decoded || typeof decoded !== 'object' || !('data' in decoded)) {
          return resolve(null)
        }
        return resolve((decoded as JwtPayload).data as User ?? null)
      }
    )
  })
}
"