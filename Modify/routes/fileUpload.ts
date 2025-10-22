// CWE-22 (Zip Slip / Path Traversal hardening)
// fs.open(tempFile, 'w', function (err, fd) {
//   if (err != null) { next(err) }
//   fs.write(fd, buffer, 0, buffer.length, null, function (err) {
//     if (err != null) { next(err) }
//     fs.close(fd, function () {
//       fs.createReadStream(tempFile)
//         .pipe(unzipper.Parse())
//         .on('entry', function (entry: any) {
//           const rawName = entry.path as string

//           // keep original absolute path computation for challenge detection only (no write!)
//           const attemptedAbs = path.resolve('uploads/complaints/' + rawName)
//           challengeUtils.solveIf(
//             challenges.fileWriteChallenge,
//             () => attemptedAbs === path.resolve('ftp/legal.md')
//           )

//           // secure destination confined to uploads/complaints
//           const destRoot = path.resolve('uploads/complaints')
//           // normalize and strip any leading traversal segments
//           const normalized = path.normalize(rawName).replace(/^([/\\]*\.\.(?:[/\\]|$))+/, '')
//           const targetPath = path.resolve(destRoot, normalized)
//           const rel = path.relative(destRoot, targetPath)
//           const withinRoot = !rel.startsWith('..') && !path.isAbsolute(rel)

//           if (withinRoot) {
//             // ensure parent directories exist, avoid writing directories as files
//             const dir = path.dirname(targetPath)
//             try { fs.mkdirSync(dir, { recursive: true }) } catch (_) { /* ignore mkdir race */ }
//             if (entry.type === 'Directory') {
//               entry.autodrain()
//             } else {
//               entry.pipe(
//                 fs.createWriteStream(targetPath).on('error', function (err) { next(err) })
//               )
//             }
//           } else {
//             // outside of allowed root -> drop
//             entry.autodrain()
//           }
//         })
//         .on('error', function (err: unknown) { next(err) })
//     })
//   })
// })

// CWE-611 (XXE hardening)
// try {
//   const sandbox = { libxml, data }
//   vm.createContext(sandbox)

//   // reject external DTDs/DOCTYPE outright to prevent entity expansion attacks
//   if (/<\!DOCTYPE/i.test(data)) {
//     throw new Error('XML DOCTYPE is not allowed')
//   }

//   // disable entity expansion and network access during parse
//   const xmlDoc = vm.runInContext(
//     'libxml.parseXml(data, { noblanks: true, noent: false, nocdata: true, nonet: true })',
//     sandbox,
//     { timeout: 2000 }
//   )

//   const xmlString = xmlDoc.toString(false)
//   challengeUtils.solveIf(
//     challenges.xxeFileDisclosureChallenge,
//     () => (utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString))
//   )
//   res.status(410)
//   next(new Error(
//     'B2B customer complaints via file upload have been deprecated for security reasons: ' +
//     utils.trunc(xmlString, 400) + ' (' + file.originalname + ')'
//   ))
// }

// --------------------------------
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'node:os'
import fs from 'node:fs'
import vm from 'node:vm'
import path from 'node:path'
import yaml from 'js-yaml'
import libxml from 'libxmljs2'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
      const buffer = file.buffer
      const filename = file.originalname.toLowerCase()
      const tempFile = path.join(os.tmpdir(), filename)
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
    }
    res.status(204).end()
  } else {
    next()
  }
}

function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    challengeUtils.solveIf(challenges.uploadSizeChallenge, () => { return file?.size > 100000 })
  }
  next()
}

function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
  challengeUtils.solveIf(challenges.uploadTypeChallenge, () => {
    return !(fileType === 'pdf' || fileType === 'xml' || fileType === 'zip' || fileType === 'yml' || fileType === 'yaml')
  })
  next()
}

function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
      const data = file.buffer.toString()
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
      } catch (err: any) { // TODO: Remove any
        if (utils.contains(err.message, 'Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.xxeDosChallenge)) {
            challengeUtils.solve(challenges.xxeDosChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + err.message + ' (' + file.originalname + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  next()
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) {
      const data = file.buffer.toString()
      try {
        const sandbox = { yaml, data }
        vm.createContext(sandbox)
        const yamlString = vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 })
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(yamlString, 400) + ' (' + file.originalname + ')'))
      } catch (err: any) { // TODO: Remove any
        if (utils.contains(err.message, 'Invalid string length') || utils.contains(err.message, 'Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.yamlBombChallenge)) {
            challengeUtils.solve(challenges.yamlBombChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + err.message + ' (' + file.originalname + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  res.status(204).end()
}

export {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload
}
