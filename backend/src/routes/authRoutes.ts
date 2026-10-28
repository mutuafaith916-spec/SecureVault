import { Router } from 'express'
import { rateLimit } from 'express-rate-limit'
import type { DataSource } from 'typeorm'
import type { EnvironmentConfig } from '../config/environment.js'
import { createAuthMiddleware } from '../middleware/authMiddleware.js'
import {
  createCurrentSessionController,
  createForgotPasswordController,
  createLogoutController,
  createLoginController,
  createEmailMfaRequestController,
  createEmailMfaVerifyController,
  createRefreshSessionController,
  createRegisterController,
  createResetPasswordController,
} from '../controllers/authController.js'

const passwordResetRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many password reset attempts. Please try again later.',
  },
})

const mfaRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 6,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many verification attempts. Please sign in again later.',
  },
})

const mfaEmailRequestRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 6,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many email-code requests. Please sign in again later.',
  },
})

const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many sign-in attempts. Please try again later.',
  },
})

export function createAuthRoutes(
  dataSource: DataSource,
  environment: EnvironmentConfig,
): Router {
  const router = Router()

  router.post('/register', createRegisterController(dataSource))
  router.post('/login', loginRateLimit, createLoginController(dataSource, environment))
  router.post('/mfa/email/request', mfaEmailRequestRateLimit, createEmailMfaRequestController(dataSource, environment))
  router.post('/mfa/email/verify', mfaRateLimit, createEmailMfaVerifyController(dataSource, environment))
  router.post('/refresh', createRefreshSessionController(dataSource, environment))
  router.post('/logout', createLogoutController(dataSource, environment))
  router.get(
    '/session',
    createAuthMiddleware(environment, dataSource),
    createCurrentSessionController(dataSource),
  )
  router.post('/forgot-password', passwordResetRateLimit, createForgotPasswordController(dataSource, environment))
  router.post('/reset-password', passwordResetRateLimit, createResetPasswordController(dataSource))

  return router
}
