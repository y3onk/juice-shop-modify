/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import locales from '../data/static/locales.json'
import fs from 'node:fs'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function getLanguageList () { // TODO Refactor and extend to also load backend translations from /i18n/*json and calculate joint percentage/gauge
  return (req: Request, res: Response, next: NextFunction) => {
    const languages: Array<{ key: string, lang: any, icons: string[], shortKey: string, percentage: unknown, gauge: string }> = []
    let count = 0
    let enContent: any

    const i18nDir = path.join('frontend', 'dist', 'frontend', 'assets', 'i18n')
    const enPath = path.join(i18nDir, 'en.json')

    fs.readFile(enPath, 'utf-8', (err, content) => {
      if (err != null) {
        return next(new Error(`Unable to retrieve en.json language file: ${err.message}`))
      }

      try {
        enContent = JSON.parse(content)
      } catch (e: any) {
        return next(new Error(`Invalid JSON in en.json: ${e?.message ?? e}`))
      }

      fs.readdir(i18nDir, (err, languageFiles) => {
        if (err != null) {
          return next(new Error(`Unable to read i18n directory: ${err.message}`))
        }

        // Process only safe *.json files located directly in i18nDir (no subpaths)
        const files = languageFiles
          .filter((f) => f.endsWith('.json') && !f.includes(path.sep))

        if (files.length === 0) {
          // Fallback: still return English so UI remains functional
          languages.push({ key: 'en', icons: ['gb', 'us'], shortKey: 'EN', lang: 'English', percentage: 100, gauge: 'full' })
          languages.sort((a, b) => a.lang.localeCompare(b.lang))
          return res.status(200).json(languages)
        }

        files.forEach((fileName) => {
          const filePath = path.join(i18nDir, fileName)
          // eslint-disable-next-line @typescript-eslint/no-misused-promises
          fs.readFile(filePath, 'utf-8', async (err, content) => {
            if (err != null) {
              count++
              if (count === files.length) {
                languages.push({ key: 'en', icons: ['gb', 'us'], shortKey: 'EN', lang: 'English', percentage: 100, gauge: 'full' })
                languages.sort((a, b) => a.lang.localeCompare(b.lang))
                return res.status(200).json(languages)
              }
              return next(new Error(`Unable to retrieve ${fileName} language file: ${err.message}`))
            }

            let fileContent: any
            try {
              fileContent = JSON.parse(content)
            } catch (e: any) {
              count++
              if (count === files.length) {
                languages.push({ key: 'en', icons: ['gb', 'us'], shortKey: 'EN', lang: 'English', percentage: 100, gauge: 'full' })
                languages.sort((a, b) => a.lang.localeCompare(b.lang))
                return res.status(200).json(languages)
              }
              return next(new Error(`Invalid JSON in ${fileName}: ${e?.message ?? e}`))
            }

            const percentage = await calcPercentage(fileContent, enContent)
            const key = fileName.substring(0, fileName.indexOf('.'))
            const locale = locales.find((l) => l.key === key)
            const lang: any = {
              key,
              lang: fileContent.LANGUAGE,
              icons: locale?.icons ?? [],
              shortKey: locale?.shortKey ?? key.toUpperCase(),
              percentage,
              gauge: (percentage > 90 ? 'full' : (percentage > 70 ? 'three-quarters' : (percentage > 50 ? 'half' : (percentage > 30 ? 'quarter' : 'empty'))))
            }

            if (!(fileName === 'en.json' || fileName === 'tlh_AA.json')) {
              languages.push(lang)
            }

            count++
            if (count === files.length) {
              languages.push({ key: 'en', icons: ['gb', 'us'], shortKey: 'EN', lang: 'English', percentage: 100, gauge: 'full' })
              languages.sort((a, b) => a.lang.localeCompare(b.lang))
              return res.status(200).json(languages)
            }
          })
        })
      })
    })

    async function calcPercentage (fileContent: any, enContent: any): Promise<number> {
      const totalStrings = Object.keys(enContent).length
      let differentStrings = 0
      return await new Promise((resolve, reject) => {
        try {
          for (const key in fileContent) {
            if (Object.prototype.hasOwnProperty.call(fileContent, key) && fileContent[key] !== enContent[key]) {
              differentStrings++
            }
          }
          resolve((differentStrings / totalStrings) * 100)
        } catch (err) {
          reject(err)
        }
      })
    }
  }
}
// --------------------------------