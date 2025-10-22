// export function retrieveBasket () {
//   return (req: Request, res: Response, next: NextFunction) => {
//     // Validate and normalize the basket id
//     const rawId = req.params.id
//     const id = Number.parseInt(rawId, 10)
//     if (!Number.isFinite(id) || id <= 0) {
//       return res.status(400).json({ error: 'Invalid basket id' })
//     }

//     const user = security.authenticatedUsers.from(req)

//     /* jshint eqeqeq:false */
//     // Keep challenge trigger logic intact (does not leak data anymore due to auth checks below)
//     challengeUtils.solveIf(challenges.basketAccessChallenge, () => {
//       return user && rawId && rawId !== 'undefined' && rawId !== 'null' && rawId !== 'NaN' && user.bid && Number(user?.bid) != id // eslint-disable-line eqeqeq
//     })

//     // Authorization: only the owner can access their basket
//     if (!user || typeof user.bid === 'undefined' || user.bid === null) {
//       return res.status(401).json({ error: 'Authentication required' })
//     }
//     if (Number(user.bid) !== id) {
//       return res.status(403).json({ error: 'Forbidden: cannot access another user\'s basket' })
//     }

//     BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
//       .then((basket: BasketModel | null) => {
//         if ((basket?.Products) && basket.Products.length > 0) {
//           for (let i = 0; i < basket.Products.length; i++) {
//             basket.Products[i].name = req.__(basket.Products[i].name)
//           }
//         }
//         res.json(utils.queryResultToJson(basket))
//       }).catch((error: Error) => {
//         next(error)
//       })
//   }
// }
// --------------------------------
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'
import * as challengeUtils from '../lib/challengeUtils'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'

export function retrieveBasket () {
  return (req: Request, res: Response, next: NextFunction) => {
    // Validate and normalize the basket id
    const rawId = req.params.id
    const id = Number.parseInt(rawId, 10)
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ error: 'Invalid basket id' })
    }

    const user = security.authenticatedUsers.from(req)

    /* jshint eqeqeq:false */
    // Keep challenge trigger logic intact (does not leak data anymore due to auth checks below)
    challengeUtils.solveIf(challenges.basketAccessChallenge, () => {
      return user && rawId && rawId !== 'undefined' && rawId !== 'null' && rawId !== 'NaN' && user.bid && Number(user?.bid) != id // eslint-disable-line eqeqeq
    })

    // Authorization: only the owner can access their basket
    if (!user || typeof user.bid === 'undefined' || user.bid === null) {
      return res.status(401).json({ error: 'Authentication required' })
    }
    if (Number(user.bid) !== id) {
      return res.status(403).json({ error: 'Forbidden: cannot access another user\'s basket' })
    }

    BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
      .then((basket: BasketModel | null) => {
        if ((basket?.Products) && basket.Products.length > 0) {
          for (let i = 0; i < basket.Products.length; i++) {
            basket.Products[i].name = req.__(basket.Products[i].name)
          }
        }
        res.json(utils.queryResultToJson(basket))
      }).catch((error: Error) => {
        next(error)
      })
  }
}

