import { Router } from 'express'
import { rateLimit } from 'express-rate-limit'
import type { DataSource } from 'typeorm'
import type { EnvironmentConfig } from '../config/environment.js'
import { createChangeUserRoleController } from '../controllers/adminController.js'
import { createAuthMiddleware } from '../middleware/authMiddleware.js'

const roleChangeRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many role changes. Please try again later.',
  },
})

export function createAdminRoutes(dataSource: DataSource, environment: EnvironmentConfig): Router {
  const router = Router()
  router.patch(
    '/users/:userId/role',
    roleChangeRateLimit,
    createAuthMiddleware(environment, dataSource),
    createChangeUserRoleController(dataSource, environment),
  )
  return router
}
