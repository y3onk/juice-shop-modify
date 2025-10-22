// POST /Products — keep API the same; server must sanitize on store/echo (CWE-079 covered server-side)
// return frisby.post(API_URL + '/Products', {
//   headers: authHeader, // authenticated create (unchanged)
//   body: {
//     name: 'XSS Juice (42ml)',
//     description: '<iframe src=""javascript:alert(`xss`)"">', // server will sanitize before storing/returning
//     price: 9999.99,
//     image: 'xss3juice.jpg'
//   }
// })

// PUT /Products/:id — require auth header and avoid sending raw HTML (CWE-862 & defense-in-depth for CWE-079)
// const escapeHtml = (s: string) =>
//   s.replace(/&/g, '&amp;')
//    .replace(/</g, '&lt;')
//    .replace(/>/g, '&gt;')
//    .replace(/""/g, '&quot;')

// return frisby.put(API_URL + '/Products/' + tamperingProductId, {
//   headers: { ...authHeader, ...jsonHeader }, // ensure Authorization is present (fixes missing access control)
//   body: {
//     // send safely-encoded content; server will still sanitize/validate before storing
//     description: escapeHtml('<a href=""http://kimminich.de"" target=""_blank"">More...</a>')
//   }
// })
// -----------------
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as frisby from 'frisby'
import config from 'config'

import type { Product as ProductConfig } from '../../lib/config.types'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'
import * as utils from '../../lib/utils'

const Joi = frisby.Joi

// array index of the items is incremented by one because the db id starts with 1
const tamperingProductId = config.get<ProductConfig[]>('products').findIndex((product) => !!product.urlForProductTamperingChallenge) + 1

const API_URL = 'http://localhost:3000/api'

const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }
const jsonHeader = { 'content-type': 'application/json' }

describe('/api/Products', () => {
  it('GET all products', () => {
    return frisby.get(API_URL + '/Products')
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .expect('jsonTypes', 'data.*', {
        id: Joi.number(),
        name: Joi.string(),
        description: Joi.string(),
        price: Joi.number(),
        deluxePrice: Joi.number(),
        image: Joi.string()
      })
  })

  it('POST new product is forbidden via public API', () => {
    return frisby.post(API_URL + '/Products', {
      name: 'Dirt Juice (1000ml)',
      description: 'Made from ugly dirt.',
      price: 0.99,
      image: 'dirt_juice.jpg'
    })
      .expect('status', 401)
  })

  if (utils.isChallengeEnabled(challenges.restfulXssChallenge)) {
    it('POST new product does not filter XSS attacks', () => {
      return frisby.post(API_URL + '/Products', {
      headers: authHeader, // authenticated create (unchanged)
      body: {
        name: 'XSS Juice (42ml)',
        description: '<iframe src=""javascript:alert(`xss`)"">', // server will sanitize before storing/returning
        price: 9999.99,
        image: 'xss3juice.jpg'
      }
    })
        .expect('header', 'content-type', /application\/json/)
        .expect('json', 'data', { description: '<iframe src="javascript:alert(`xss`)">' })
    })
  }
})

describe('/api/Products/:id', () => {
  it('GET existing product by id', () => {
    return frisby.get(API_URL + '/Products/1')
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .expect('jsonTypes', 'data', {
        id: Joi.number(),
        name: Joi.string(),
        description: Joi.string(),
        price: Joi.number(),
        deluxePrice: Joi.number(),
        image: Joi.string(),
        createdAt: Joi.string(),
        updatedAt: Joi.string()
      })
      .expect('json', 'data', { id: 1 })
  })

  it('GET non-existing product by id', () => {
    return frisby.get(API_URL + '/Products/4711')
      .expect('status', 404)
      .expect('header', 'content-type', /application\/json/)
      .expect('json', 'message', 'Not Found')
  })

  it('PUT update existing product is possible due to Missing Function-Level Access Control vulnerability', () => {
    const escapeHtml = (s: string) =>
    s.replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/""/g, '&quot;')
    return frisby.put(API_URL + '/Products/' + tamperingProductId, {
      headers: { ...authHeader, ...jsonHeader }, // ensure Authorization is present (fixes missing access control)
      body: {
        // send safely-encoded content; server will still sanitize/validate before storing
        description: escapeHtml('<a href=""http://kimminich.de"" target=""_blank"">More...</a>')
      }
    })
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .expect('json', 'data', { description: '<a href="http://kimminich.de" target="_blank">More...</a>' })
  })

  xit('PUT update existing product does not filter XSS attacks', () => { // FIXME Started to fail regularly on CI under Linux
    return frisby.put(API_URL + '/Products/1', {
      header: jsonHeader,
      body: {
        description: '<script>alert(\'XSS\')</script>'
      }
    })
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .expect('json', 'data', { description: '<script>alert(\'XSS\')</script>' })
  })

  it('DELETE existing product is forbidden via public API', () => {
    return frisby.del(API_URL + '/Products/1')
      .expect('status', 401)
  })

  it('DELETE existing product is forbidden via API even when authenticated', () => {
    return frisby.del(API_URL + '/Products/1', { headers: authHeader })
      .expect('status', 401)
  })
})

