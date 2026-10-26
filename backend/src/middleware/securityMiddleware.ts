import cors from 'cors'
import type { Express } from 'express'
import express from 'express'
import { rateLimit } from 'express-rate-limit'
import helmet from 'helmet'
import { apiRateLimit, allowedCorsMethods, requestBodyLimits } from '../config/security.js'
import type { EnvironmentConfig } from '../config/environment.js'
import { HttpError } from '../types/http.js'
import { logger } from '../utils/logger.js'

export function configureSecurityMiddleware(app: Express, environment: EnvironmentConfig): void {
  app.disable('x-powered-by')
  app.use(helmet())
  app.use(cors({
    origin(origin, callback) {
      if (!origin || origin === environment.corsOrigin) {
        callback(null, true)
        return
      }
      logger.warn({ event: 'security.cors_origin_rejected' }, 'Rejected request from an unconfigured origin')
      callback(new HttpError(403, 'Request origin is not allowed'))
    },
    methods: [...allowedCorsMethods],
    credentials: true,
    optionsSuccessStatus: 204,
  }))
  app.use(express.json({ limit: requestBodyLimits.json, strict: true }))
  app.use(express.urlencoded({ extended: false, limit: requestBodyLimits.urlEncoded }))
}

export const apiRateLimiter = rateLimit({
  windowMs: apiRateLimit.windowMs,
  limit: apiRateLimit.limit,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler(_request, response) {
    logger.warn({ event: 'security.rate_limit_exceeded' }, 'API request rate limit exceeded')
    response.status(429).json({
      success: false,
      message: 'Too many requests. Please try again later.',
    })
  },
})
