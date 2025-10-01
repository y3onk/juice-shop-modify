// 72:41 – layout from req.body influences rendering options for res.render (potential LFR via template option injection)
res.render('dataErasureResult', {
  ...req.body
}, (error, html) => {
  if (!html || error) {
    next(new Error(error.message))
  } else {
    const sendlfrResponse: string = html.slice(0, 100) + '......'
    res.send(sendlfrResponse)
    challengeUtils.solveIf(challenges.lfrChallenge, () => { return true })
  }
})

// 87:39 – entire req.body is spread into template locals without sanitization (can control layout and trigger LFR)
res.render('dataErasureResult', {
  ...req.body
})
