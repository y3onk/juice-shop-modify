"const imageCaptcha = {
  image: captcha.data,
  // answer: captcha.text,  ❌ Do not expose sensitive CAPTCHA solution to the client
  UserId: user.data.id
}
const imageCaptchaInstance = ImageCaptchaModel.build({
  ...imageCaptcha,
  answer: captcha.text // ✅ Store internally in DB for later verification
})
imageCaptchaInstance.save().then(() => {
  // ✅ Only return safe fields to client (no `answer`)
  res.json({
    image: imageCaptcha.image,
    UserId: imageCaptcha.UserId
  })
}).catch(() => {
  res.status(400).send(res.__('Unable to create CAPTCHA. Please try again.'))
})
"
