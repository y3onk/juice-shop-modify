// return async (req: Request, res: Response, next: NextFunction) => {
//   const { ObjectId } = require('mongodb')

//   const idRaw = req.body.id
//   const user = security.authenticatedUsers.from(req)
//   if (!user) {
//     return res.status(401).json({ error: 'Unauthorized' })
//   }

//   // ✅ Validate & cast the selector _id to prevent operator injection / mass-update
//   if (typeof idRaw !== 'string' || !ObjectId.isValid(idRaw)) {
//     return res.status(400).json({ error: 'Wrong Params' })
//   }
//   const selector = { _id: new ObjectId(idRaw) }

//   try {
//     const review = await db.reviewsCollection.findOne(selector)
//     if (!review) {
//       return res.status(404).json({ error: 'Not found' })
//     }

//     const likedBy = review.likedBy
//     if (likedBy.includes(user.data.email)) {
//       return res.status(403).json({ error: 'Not allowed' })
//     }

//     await db.reviewsCollection.update(
//       selector,
//       { $inc: { likesCount: 1 } }
//     )

//     // Artificial wait for timing attack challenge
//     await sleep(150)
//     try {
//       const updatedReview: Review = await db.reviewsCollection.findOne(selector)
//       const updatedLikedBy = updatedReview.likedBy
//       updatedLikedBy.push(user.data.email)

//       const count = updatedLikedBy.filter(email => email === user.data.email).length
//       challengeUtils.solveIf(challenges.timingAttackChallenge, () => count > 2)

//       const result = await db.reviewsCollection.update(
//         selector,
//         { $set: { likedBy: updatedLikedBy } }
//       )
//       res.json(result)
//     } catch (err) {
//       res.status(500).json(err)
//     }
//   } catch (err) {
//     res.status(400).json({ error: 'Wrong Params' })
//   }
// }
// --------------------------------
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from '../data/types'
import * as db from '../data/mongodb'

const sleep = async (ms: number) => await new Promise(resolve => setTimeout(resolve, ms))

export function likeProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const { ObjectId } = require('mongodb')

    const idRaw = req.body.id
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    // ✅ Validate & cast the selector _id to prevent operator injection / mass-update
    if (typeof idRaw !== 'string' || !ObjectId.isValid(idRaw)) {
      return res.status(400).json({ error: 'Wrong Params' })
    }
    const selector = { _id: new ObjectId(idRaw) }

    try {
      const review = await db.reviewsCollection.findOne(selector)
      if (!review) {
        return res.status(404).json({ error: 'Not found' })
      }

      const likedBy = review.likedBy
      if (likedBy.includes(user.data.email)) {
        return res.status(403).json({ error: 'Not allowed' })
      }

      await db.reviewsCollection.update(
        selector,
        { $inc: { likesCount: 1 } }
      )

      // Artificial wait for timing attack challenge
      await sleep(150)
      try {
        const updatedReview: Review = await db.reviewsCollection.findOne(selector)
        const updatedLikedBy = updatedReview.likedBy
        updatedLikedBy.push(user.data.email)

        const count = updatedLikedBy.filter(email => email === user.data.email).length
        challengeUtils.solveIf(challenges.timingAttackChallenge, () => count > 2)

        const result = await db.reviewsCollection.update(
          selector,
          { $set: { likedBy: updatedLikedBy } }
        )
        res.json(result)
      } catch (err) {
        res.status(500).json(err)
      }
    } catch (err) {
      res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
