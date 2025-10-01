"// Read sensitive fields from the request body (never from URL query string)
const currentPassword =
  typeof req.body?.current === 'string' ? req.body.current : ''

const newPassword =
  typeof req.body?.new === 'string' ? req.body.new : ''

const repeatPassword =
  typeof req.body?.repeat === 'string' ? req.body.repeat : ''
"