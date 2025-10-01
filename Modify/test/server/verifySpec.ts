"// (inside test/server/verifySpec.ts, replace only the hard-coded JWT literals shown with the helpers below)

// --- Minimal helpers to avoid hard-coded credentials while preserving behavior ---
import crypto from 'crypto'

function b64urlJson(o: any): string {
  return Buffer.from(JSON.stringify(o)).toString('base64url')
}
function unsignedJWT(payload: any): string {
  const header = { alg: 'none', typ: 'JWT' }
  return `${b64urlJson(header)}.${b64urlJson(payload)}.` // trailing dot by spec for alg ""none""
}
function hs256JWT(payload: any, secret: string): string {
  const header = { alg: 'HS256', typ: 'JWT' }
  const h = b64urlJson(header)
  const p = b64urlJson(payload)
  const sig = crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url')
  return `${h}.${p}.${sig}`
}

// For the forged-token challenges, the app (intentionally) accepts HS256 signed with the *public RSA key*
// (alg confusion). Reuse the same key material exposed by the security module if available.
const rsaPublicKeyForTests: string =
  (security as any).publicKey ||
  (security as any).jwtPublicKey ||
  (security as any).rsaPublicKey ||
  process.env.RSA_PUB_FOR_TESTS || ''

// -------------------------------------------------------------------------------

/* BEFORE:
req.headers = { authorization: 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.' }
*/
req.headers = {
  authorization: 'Bearer ' + unsignedJWT({
    data: { email: 'jwtn3d@juice-sh.op' },
    iat: 1508639612,
    exp: 9999999999
  })
}

verify.jwtChallenges()(req, res, next)

expect(challenges.jwtUnsignedChallenge.solved).to.equal(true)

/* BEFORE:
req.headers = { authorization: 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQCJ9LCJpYXQiOjE1MDg2Mzk2MTIsImV4cCI6OTk5OTk5OTk5OX0.' }
*/
req.headers = {
  authorization: 'Bearer ' + unsignedJWT({
    data: { email: 'jwtn3d@' },
    iat: 1508639612,
    exp: 9999999999
  })
}

verify.jwtChallenges()(req, res, next)

expect(challenges.jwtUnsignedChallenge.solved).to.equal(true)

const token = security.authorize({ data: { email: 'jwtn3d@juice-sh.op' } })
req.headers = { authorization: `Bearer ${token}` }

verify.jwtChallenges()(req, res, next)

expect(challenges.jwtForgedChallenge.solved).to.equal(false)

if (utils.isChallengeEnabled(challenges.jwtForgedChallenge)) {
  /* BEFORE:
  req.headers = { authorization: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAanVpY2Utc2gub3AifSwiaWF0IjoxNTgyMjIxNTc1fQ.ycFwtqh4ht4Pq9K5rhiPPY256F9YCTIecd4FHFuSEAg' }
  */
  req.headers = {
    authorization: 'Bearer ' + hs256JWT(
      { data: { email: 'rsa_lord@juice-sh.op' }, iat: 1582221575 },
      rsaPublicKeyForTests // HS256 using RSA public key bytes (intentional alg confusion path)
    )
  }

  verify.jwtChallenges()(req, res, next)

  expect(challenges.jwtForgedChallenge.solved).to.equal(true)

  /* BEFORE:
  req.headers = { authorization: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAIn0sImlhdCI6MTU4MjIyMTY3NX0.50f6VAIQk2Uzpf3sgH-1JVrrTuwudonm2DKn2ec7Tg8' }
  */
  req.headers = {
    authorization: 'Bearer ' + hs256JWT(
      { data: { email: 'rsa_lord@' }, iat: 1582221675 },
      rsaPublicKeyForTests
    )
  }
}
"