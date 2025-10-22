// description: {
//   type: DataTypes.STRING,
//   set (description: string) {
//     // keep original user input for challenge detection, but ALWAYS store a sanitized value
//     const rawDescription = description
//     const safeDescription = security.sanitizeSecure(description)

//     if (utils.isChallengeEnabled(challenges.restfulXssChallenge)) {
//       // evaluate challenge condition using the RAW input, but do NOT store raw input
//       challengeUtils.solveIf(challenges.restfulXssChallenge, () => {
//         return utils.contains(
//           rawDescription,
//           '<iframe src=""javascript:alert(`xss`)"">'
//         )
//       })
//     }

//     // Always save the sanitized value to the database to prevent stored XSS
//     this.setDataValue('description', safeDescription)
//   }
// },

// -----------------
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* jslint node: true */
import * as utils from '../lib/utils'
import * as challengeUtils from '../lib/challengeUtils'
import {
  Model,
  type InferAttributes,
  type InferCreationAttributes,
  DataTypes,
  type CreationOptional,
  type Sequelize
} from 'sequelize'
import { type BasketItemModel } from './basketitem'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

class Product extends Model<
InferAttributes<Product>,
InferCreationAttributes<Product>
> {
  declare id: CreationOptional<number>
  declare name: string
  declare description: string
  declare price: number
  declare deluxePrice: number
  declare image: string
  declare BasketItem?: CreationOptional<BasketItemModel> // Note this is optional since it's only populated when explicitly requested in code
}

const ProductModelInit = (sequelize: Sequelize) => {
  Product.init(
    {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      name: DataTypes.STRING,
      description: {
        type: DataTypes.STRING,
        set (description: string) {
          // keep original user input for challenge detection, but ALWAYS store a sanitized value
          const rawDescription = description
          const safeDescription = security.sanitizeSecure(description)

          if (utils.isChallengeEnabled(challenges.restfulXssChallenge)) {
            // evaluate challenge condition using the RAW input, but do NOT store raw input
            challengeUtils.solveIf(challenges.restfulXssChallenge, () => {
              return utils.contains(
                rawDescription,
                '<iframe src=""javascript:alert(`xss`)"">'
              )
            })
          }

          // Always save the sanitized value to the database to prevent stored XSS
          this.setDataValue('description', safeDescription)
        }
      },
      price: DataTypes.DECIMAL,
      deluxePrice: DataTypes.DECIMAL,
      image: DataTypes.STRING
    },
    {
      tableName: 'Products',
      sequelize,
      paranoid: true
    }
  )
}

export { Product as ProductModel, ProductModelInit }
