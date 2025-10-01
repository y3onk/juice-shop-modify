".then(({ json: captchaAnswer }) => {
  // Security fix (CWE-804): never reuse a server-provided CAPTCHA solution.
  // If the endpoint mistakenly returns a solution field, fail fast.
  const leakedSolution = captchaAnswer?.answer ?? captchaAnswer?.solution;
  if (typeof leakedSolution !== 'undefined') {
    throw new Error('Security check failed: /image-captcha must not return the CAPTCHA solution.');
  }

  return frisby.post(REST_URL + '/user/data-export', {
    headers: {
      Authorization: 'Bearer ' + jsonLogin.authentication.token,
      'content-type': 'application/json'
    },
    body: {
      // Intentionally NOT auto-filling from server response.
      // Provide a user/solver-supplied value in higher-level test setup if needed.
      answer: '',
      format: 1
    }
  });
})
"