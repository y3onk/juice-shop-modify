    const imageCaptcha = {
      image: captcha.data,
      answer: captcha.text,
      UserId: user.data.id
    }
    const imageCaptchaInstance = ImageCaptchaModel.build(imageCaptcha)
    imageCaptchaInstance.save().then(() => {
      res.json(imageCaptcha)
    }).catch(() => {
      res.status(400).send(res.__('Unable to create CAPTCHA. Please try again.'))
    })
  }