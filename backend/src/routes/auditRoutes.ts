import { Router } from 'express'
import type { DataSource } from 'typeorm'
import type { EnvironmentConfig } from '../config/environment.js'
import { createListAuditLogsController } from '../controllers/auditController.js'
import { createAuditIntegrityController } from '../controllers/adminController.js'
import { createAuthMiddleware } from '../middleware/authMiddleware.js'

export function createAuditRoutes(dataSource: DataSource, environment: EnvironmentConfig): Router {
  const router = Router()
  router.get(
    '/integrity',
    createAuthMiddleware(environment, dataSource),
    createAuditIntegrityController(dataSource, environment),
  )
  router.get(
    '/',
    createAuthMiddleware(environment, dataSource),
    createListAuditLogsController(dataSource),
  )
  return router
}
