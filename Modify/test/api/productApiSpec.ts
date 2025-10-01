"// ✅ CWE-943 fix: prevent NoSQL operator injection by sending a primitive ID
return frisby.patch(`${REST_URL}/products/reviews`, {
  headers: authHeader,
  body: {
    // Use a concrete numeric/string identifier, not an object with operators like {$ne: -1}
    id: 1,
    message:
      'trololololololololololololololololololololololololololol'
  }
})
// ✅ CWE-798 fix: remove hardcoded secrets; read test creds from environment
const loginEmail = process.env.TEST_USER_EMAIL
const loginPassword = process.env.TEST_USER_PASSWORD
if (!loginEmail || !loginPassword) {
  throw new Error('Set TEST_USER_EMAIL and TEST_USER_PASSWORD for the login test.')
}

return frisby.post(`${REST_URL}/user/login`, {
  headers: jsonHeader,
  body: {
    email: loginEmail,
    password: loginPassword
  }
})

"