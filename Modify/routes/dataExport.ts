"// Enforce that the export only returns the authenticated user's memories
const authUserId = Number(res?.locals?.user?.id ?? req.user?.id) // populated by auth middleware
const requestedUserId = req.body?.UserId !== undefined ? Number(req.body.UserId) : authUserId

if (!Number.isFinite(authUserId)) {
  return res.status(401).send({ error: 'Unauthorized' })
}
if (!Number.isFinite(requestedUserId) || requestedUserId !== authUserId) {
  return res.status(403).send({ error: 'Forbidden: cannot export other users\' data' })
}

const memories = await MemoryModel.findAll({ where: { UserId: authUserId } })
memories.forEach((memory: MemoryModel) => {
  userData.memories.push({
    imageUrl: req.protocol + '://' + req.get('host') + '/' + memory.imagePath,
    caption: memory.caption
  })
})
"