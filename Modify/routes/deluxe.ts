// export function upgradeToDeluxe () {
//   return async (req: Request, res: Response, next: NextFunction) => {
//     try {
//       // ✅ Authorization & ID binding: ensure caller can only upgrade *their own* account
//       const token = utils.jwtFrom(req)
//       const verified = security.verify(token) as any | undefined
//       const authUserId = (verified?.data?.id ?? verified?.id ?? verified?.userId) as number | undefined
//       if (typeof authUserId !== 'number' || Number(req.body.UserId) !== authUserId) {
//         res.status(403).json({ status: 'error', error: 'Not authorized for this user.' })
//         return
//       }

//       const user = await UserModel.findOne({ where: { id: authUserId, role: security.roles.customer } })
//       if (user == null) {
//         res.status(400).json({ status: 'error', error: 'Something went wrong. Please try again!' })
//         return
//       }

//       if (req.body.paymentMode === 'wallet') {
//         const wallet = await WalletModel.findOne({ where: { UserId: authUserId } })
//         // ✅ Enforce wallet existence and balance before debit
//         if (wallet == null || wallet.balance < 49) {
//           res.status(400).json({ status: 'error', error: 'Insuffienct funds in Wallet' })
//           return
//         }
//         await WalletModel.decrement({ balance: 49 }, { where: { UserId: authUserId } })
//       }

//       if (req.body.paymentMode === 'card') {
//         const card = await CardModel.findOne({ where: { id: req.body.paymentId, UserId: authUserId } })
//         if ((card == null) || card.expYear < new Date().getFullYear() || (card.expYear === new Date().getFullYear() && card.expMonth - 1 < new Date().getMonth())) {
//           res.status(400).json({ status: 'error', error: 'Invalid Card' })
//           return
//         }
//       }

//       try {
//         const updatedUser = await user.update({ role: security.roles.deluxe, deluxeToken: security.deluxeToken(user.email) })
//         challengeUtils.solveIf(challenges.freeDeluxeChallenge, () => {
//           return security.verify(utils.jwtFrom(req)) && req.body.paymentMode !== 'wallet' && req.body.paymentMode !== 'card'
//         })
//         const userWithStatus = utils.queryResultToJson(updatedUser)
//         const updatedToken = security.authorize(userWithStatus)
//         security.authenticatedUsers.put(updatedToken, userWithStatus)
//         res.status(200).json({ status: 'success', data: { confirmation: 'Congratulations! You are now a deluxe member!', token: updatedToken } })
//       } catch (error) {
//         res.status(400).json({ status: 'error', error: 'Something went wrong. Please try again!' })
//       }
//     } catch (err: unknown) {
//       res.status(400).json({ status: 'error', error: 'Something went wrong: ' + utils.getErrorMessage(err) })
//     }
//   }
// }
// ------------------------------
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { WalletModel } from '../models/wallet'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import { CardModel } from '../models/card'
import * as utils from '../lib/utils'

export function upgradeToDeluxe () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // ✅ Authorization & ID binding: ensure caller can only upgrade *their own* account
      const token = utils.jwtFrom(req)
      const verified = security.verify(token) as any | undefined
      const authUserId = (verified?.data?.id ?? verified?.id ?? verified?.userId) as number | undefined
      if (typeof authUserId !== 'number' || Number(req.body.UserId) !== authUserId) {
        res.status(403).json({ status: 'error', error: 'Not authorized for this user.' })
        return
      }

      const user = await UserModel.findOne({ where: { id: authUserId, role: security.roles.customer } })
      if (user == null) {
        res.status(400).json({ status: 'error', error: 'Something went wrong. Please try again!' })
        return
      }

      if (req.body.paymentMode === 'wallet') {
        const wallet = await WalletModel.findOne({ where: { UserId: authUserId } })
        // ✅ Enforce wallet existence and balance before debit
        if (wallet == null || wallet.balance < 49) {
          res.status(400).json({ status: 'error', error: 'Insuffienct funds in Wallet' })
          return
        }
        await WalletModel.decrement({ balance: 49 }, { where: { UserId: authUserId } })
      }

      if (req.body.paymentMode === 'card') {
        const card = await CardModel.findOne({ where: { id: req.body.paymentId, UserId: authUserId } })
        if ((card == null) || card.expYear < new Date().getFullYear() || (card.expYear === new Date().getFullYear() && card.expMonth - 1 < new Date().getMonth())) {
          res.status(400).json({ status: 'error', error: 'Invalid Card' })
          return
        }
      }

      try {
        const updatedUser = await user.update({ role: security.roles.deluxe, deluxeToken: security.deluxeToken(user.email) })
        challengeUtils.solveIf(challenges.freeDeluxeChallenge, () => {
          return security.verify(utils.jwtFrom(req)) && req.body.paymentMode !== 'wallet' && req.body.paymentMode !== 'card'
        })
        const userWithStatus = utils.queryResultToJson(updatedUser)
        const updatedToken = security.authorize(userWithStatus)
        security.authenticatedUsers.put(updatedToken, userWithStatus)
        res.status(200).json({ status: 'success', data: { confirmation: 'Congratulations! You are now a deluxe member!', token: updatedToken } })
      } catch (error) {
        res.status(400).json({ status: 'error', error: 'Something went wrong. Please try again!' })
      }
    } catch (err: unknown) {
      res.status(400).json({ status: 'error', error: 'Something went wrong: ' + utils.getErrorMessage(err) })
    }
  }
}

export function deluxeMembershipStatus () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (security.isCustomer(req)) {
      res.status(200).json({ status: 'success', data: { membershipCost: 49 } })
    } else if (security.isDeluxe(req)) {
      res.status(400).json({ status: 'error', error: 'You are already a deluxe member!' })
    } else {
      res.status(400).json({ status: 'error', error: 'You are not eligible for deluxe membership!' })
    }
  }
}
