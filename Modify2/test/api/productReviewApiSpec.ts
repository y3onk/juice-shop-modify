"// ✅ Replace hard-coded test credential (CWE-798)
password: (process.env.TEST_USER_PASSWORD && process.env.TEST_USER_PASSWORD.trim() !== '')
  ? process.env.TEST_USER_PASSWORD
  : (() => { throw new Error('TEST_USER_PASSWORD is not set'); })(),

// ...

// ✅ Use a primitive, validated numeric id to avoid NoSQL injection payloads (CWE-943)
const safeReviewId = Number(process.env.TEST_REVIEW_ID ?? tamperingProductId ?? 0)
if (!Number.isInteger(safeReviewId) || safeReviewId < 0) {
  throw new Error('Invalid test review id')
}

headers: authHeader,
body: {
  id: safeReviewId, // <-- previously { $ne: -1 } (injection); now a validated integer
  message: 'trololololololololololololololololololololololololololol'
}
"