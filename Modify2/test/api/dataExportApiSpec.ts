".then(({ json: captchaAnswer }) => {
  // Validate and normalize the CAPTCHA answer before sending
  const raw = captchaAnswer && (captchaAnswer.answer ?? captchaAnswer?.data?.answer);
  const normalized = typeof raw === 'string' ? raw.trim() : String(raw ?? '');

  // Only allow short numeric answers (typical arithmetic CAPTCHA range)
  if (!/^\d{1,6}$/.test(normalized)) {
    throw new Error('Invalid CAPTCHA answer');
  }

  const safeAnswer = Number(normalized);

  return frisby.post(REST_URL + '/user/data-export', {
    headers: {
      Authorization: 'Bearer ' + jsonLogin.authentication.token,
      'content-type': 'application/json'
    },
    body: {
      answer: safeAnswer,
      format: 1
    }
  });
})
"