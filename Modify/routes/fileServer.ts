"const baseDir = path.resolve('ftp')
const safePath = path.resolve(baseDir, file)

// Block path traversal / absolute paths
if (!safePath.startsWith(baseDir + path.sep)) {
  res.status(400)
  return next(new Error('Invalid file path!'))
}

res.sendFile(safePath)
"