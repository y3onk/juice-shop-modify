// sanitize and whitelist template locals to prevent template-object injection / path traversal
const allowedLayouts = new Set(['default', 'compact', 'minimal']) // explicit whitelist of allowed layout names
const sanitizeString = (v: unknown) => {
  if (typeof v !== 'string') return ''
  // trim, limit length, and remove suspicious control chars
  return v.trim().slice(0, 1000).replace(/[\0\r\n\x00-\x1f\x7f]/g, '')
}

// Build safe locals by filtering keys and excluding dangerous template-control keys (e.g., layout)
const safeLocals: Record<string, unknown> = {}
for (const key of Object.keys(req.body || {})) {
  // reject keys that are not simple alphanumeric/_ names (prevents prototype pollution, weird keys)
  if (!/^[A-Za-z0-9_]+$/.test(key)) continue
  if (key === 'layout') continue // never allow direct layout override from request body
  safeLocals[key] = sanitizeString((req.body as any)[key])
}

// If the client provided a layout, map it only if it's in the explicit whitelist
if (typeof req.body?.layout === 'string' && allowedLayouts.has(req.body.layout)) {
  // pass only a safe, pre-approved layout token (do not pass arbitrary paths)
  safeLocals.layout = req.body.layout
}

// render with the sanitized, whitelisted locals (no spreading of entire req.body)
res.render('dataErasureResult', safeLocals, (error, html) => {
  if (!html || error) {
    next(new Error(error?.message || 'render error'))
  } else {
    const sendlfrResponse: string = html.slice(0, 100) + '......'
    res.send(sendlfrResponse)
    challengeUtils.solveIf(challenges.lfrChallenge, () => { return true })
  }
})

// second render (no callback) — use the same safeLocals construction approach
res.render('dataErasureResult', safeLocals)
// ----------------

/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import express, { type NextFunction, type Request, type Response } from 'express'
import path from 'node:path'

import { SecurityQuestionModel } from '../models/securityQuestion'
import { PrivacyRequestModel } from '../models/privacyRequests'
import { SecurityAnswerModel } from '../models/securityAnswer'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

const router = express.Router()

router.get('/', async (req: Request, res: Response, next: NextFunction) => {
  const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
  if (!loggedInUser) {
    next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    return
  }
  const email = loggedInUser.data.email

  try {
    const answer = await SecurityAnswerModel.findOne({
      include: [{
        model: UserModel,
        where: { email }
      }]
    })
    if (answer == null) {
      throw new Error('No answer found!')
    }
    const question = await SecurityQuestionModel.findByPk(answer.SecurityQuestionId)
    if (question == null) {
      throw new Error('No question found!')
    }

    res.render('dataErasureForm', { userEmail: email, securityQuestion: question.question })
  } catch (error) {
    next(error)
  }
})

interface DataErasureRequestParams {
  layout?: string
  email: string
  securityAnswer: string
}

// eslint-disable-next-line @typescript-eslint/no-misused-promises
router.post('/', async (req: Request<Record<string, unknown>, Record<string, unknown>, DataErasureRequestParams>, res: Response, next: NextFunction): Promise<void> => {
  const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
  if (!loggedInUser) {
    next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    return
  }

  try {
    await PrivacyRequestModel.create({
      UserId: loggedInUser.data.id,
      deletionRequested: true
    })

    res.clearCookie('token')
    if (req.body.layout) {
      const filePath: string = path.resolve(req.body.layout).toLowerCase()
      const isForbiddenFile: boolean = (filePath.includes('ftp') || filePath.includes('ctf.key') || filePath.includes('encryptionkeys'))
      if (!isForbiddenFile) {
        // sanitize & whitelist
        const allowedLayouts = new Set(['default', 'compact', 'minimal'])
        const sanitizeString = (v: unknown) => {
          if (typeof v !== 'string') return ''
          return v.trim().slice(0, 1000).replace(/[\0\r\n\x00-\x1f\x7f]/g, '')
        }

        const safeLocals: Record<string, unknown> = {}
        for (const key of Object.keys(req.body || {})) {
          if (!/^[A-Za-z0-9_]+$/.test(key)) continue
          if (key === 'layout') continue
          safeLocals[key] = sanitizeString((req.body as any)[key])
        }

        if (typeof req.body?.layout === 'string' && allowedLayouts.has(req.body.layout)) {
          safeLocals.layout = req.body.layout
        }

        res.render('dataErasureResult', safeLocals, (error, html) => {
          if (!html || error) {
            next(new Error(error?.message || 'render error'))
          } else {
            const sendlfrResponse: string = html.slice(0, 100) + '......'
            res.send(sendlfrResponse)
            challengeUtils.solveIf(challenges.lfrChallenge, () => { return true })
          }
        })

      } else {
        next(new Error('File access not allowed'))
      }
    } else {
      // sanitize & whitelist
      const allowedLayouts = new Set(['default', 'compact', 'minimal'])
      const sanitizeString = (v: unknown) => {
        if (typeof v !== 'string') return ''
        return v.trim().slice(0, 1000).replace(/[\0\r\n\x00-\x1f\x7f]/g, '')
      }

      const safeLocals: Record<string, unknown> = {}
      for (const key of Object.keys(req.body || {})) {
        if (!/^[A-Za-z0-9_]+$/.test(key)) continue
        if (key === 'layout') continue
        safeLocals[key] = sanitizeString((req.body as any)[key])
      }

      if (typeof req.body?.layout === 'string' && allowedLayouts.has(req.body.layout)) {
        safeLocals.layout = req.body.layout
      }

      res.render('dataErasureResult', safeLocals)
    }
  } catch (error) {
    next(error)
  }
})

export default router
