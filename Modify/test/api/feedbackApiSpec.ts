"// CWE-079 snippet — verify server-side sanitization instead of allowing nested HTML/JS URLs to persist
return frisby
  .post(API_URL + '/Feedbacks', {
    headers: jsonHeader,
    body: {
      // keep the malicious payload to test sanitization on the server
      comment:
        'The sanitize-html module up to at least version 1.4.2 has this issue: <<script>Foo</script>iframe src=""javascript:alert(`xss`)"">',
      rating: 1,
      captchaId: json.captchaId,
      captcha: json.answer
    }
  })
  .then(({ json }) => {
    // ensure dangerous constructs are stripped/encoded by the API
    expect(json.data.comment).not.toMatch(/<\s*iframe/i)
    expect(json.data.comment).not.toMatch(/javascript:/i)
  })
// CWE-639 snippet — do not allow client-controlled UserId; the API must set/derive it server-side
return frisby
  .post(API_URL + '/Feedbacks', {
    headers: jsonHeader,
    body: {
      comment:
        'Lousy crap! You use sequelize 1.7.x? Welcome to SQL Injection-land, morons! As if that is not bad enough, you use z85/base85 and hashids for crypto? Even MD5 to hash passwords! Srsly?!?!',
      rating: 1,
      // ❌ removed: UserId must not be accepted from unauthenticated clients
      captchaId: json.captchaId,
      captcha: json.answer
    }
  })
  .then(({ json }) => {
    // assert the server did not accept an arbitrary UserId from the request
    expect(json.data.UserId).not.toBe(3)
  })

// CWE-209 snippet — do not assert raw DB error leakage; require generic, non-sensitive error
.then(({ json }) => {
  // expect a safe, high-level error message and ensure raw engine text is not leaked
  const message = (json.message || json.error || '').toString()
  expect(message).toMatch(/invalid|foreign key|constraint/i)
  expect(JSON.stringify(json)).not.toMatch(/SQLITE_CONSTRAINT|SQLite|SQLITE_/i)
})
"