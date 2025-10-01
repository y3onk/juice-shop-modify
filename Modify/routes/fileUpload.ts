"// CWE-22 (Zip Slip / Path Traversal hardening)
fs.open(tempFile, 'w', function (err, fd) {
  if (err != null) { next(err) }
  fs.write(fd, buffer, 0, buffer.length, null, function (err) {
    if (err != null) { next(err) }
    fs.close(fd, function () {
      fs.createReadStream(tempFile)
        .pipe(unzipper.Parse())
        .on('entry', function (entry: any) {
          const rawName = entry.path as string

          // keep original absolute path computation for challenge detection only (no write!)
          const attemptedAbs = path.resolve('uploads/complaints/' + rawName)
          challengeUtils.solveIf(
            challenges.fileWriteChallenge,
            () => attemptedAbs === path.resolve('ftp/legal.md')
          )

          // secure destination confined to uploads/complaints
          const destRoot = path.resolve('uploads/complaints')
          // normalize and strip any leading traversal segments
          const normalized = path.normalize(rawName).replace(/^([/\\]*\.\.(?:[/\\]|$))+/, '')
          const targetPath = path.resolve(destRoot, normalized)
          const rel = path.relative(destRoot, targetPath)
          const withinRoot = !rel.startsWith('..') && !path.isAbsolute(rel)

          if (withinRoot) {
            // ensure parent directories exist, avoid writing directories as files
            const dir = path.dirname(targetPath)
            try { fs.mkdirSync(dir, { recursive: true }) } catch (_) { /* ignore mkdir race */ }
            if (entry.type === 'Directory') {
              entry.autodrain()
            } else {
              entry.pipe(
                fs.createWriteStream(targetPath).on('error', function (err) { next(err) })
              )
            }
          } else {
            // outside of allowed root -> drop
            entry.autodrain()
          }
        })
        .on('error', function (err: unknown) { next(err) })
    })
  })
})

// CWE-611 (XXE hardening)
try {
  const sandbox = { libxml, data }
  vm.createContext(sandbox)

  // reject external DTDs/DOCTYPE outright to prevent entity expansion attacks
  if (/<\!DOCTYPE/i.test(data)) {
    throw new Error('XML DOCTYPE is not allowed')
  }

  // disable entity expansion and network access during parse
  const xmlDoc = vm.runInContext(
    'libxml.parseXml(data, { noblanks: true, noent: false, nocdata: true, nonet: true })',
    sandbox,
    { timeout: 2000 }
  )

  const xmlString = xmlDoc.toString(false)
  challengeUtils.solveIf(
    challenges.xxeFileDisclosureChallenge,
    () => (utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString))
  )
  res.status(410)
  next(new Error(
    'B2B customer complaints via file upload have been deprecated for security reasons: ' +
    utils.trunc(xmlString, 400) + ' (' + file.originalname + ')'
  ))
}
"