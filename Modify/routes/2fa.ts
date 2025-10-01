"const userModel = await UserModel.findByPk(user.id)
if (userModel == null) {
  throw new Error('No such user found!')
}

// ⛑️ Encrypt TOTP secret at rest (AES-256-GCM via shared helper; key from env)
if (!process.env.TOTP_SECRET_KEY) {
  throw new Error('TOTP secret key not configured')
}
const encrypted = utils.encryptForStorage(secret) // e.g., returns ""enc:gcm:<iv>:<tag>:<ciphertext>""
userModel.totpSecret = encrypted
await userModel.save()

// 🚫 Never leak the (even encrypted) secret back to client/session
const safeUserJson = utils.queryResultToJson(userModel)
delete (safeUserJson as any).totpSecret
security.authenticatedUsers.updateFrom(req, safeUserJson)

res.status(200).send()
} catch (error) {
  res.status(401).send()
}
"