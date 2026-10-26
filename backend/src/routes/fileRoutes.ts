import { Router } from 'express'
import { rateLimit } from 'express-rate-limit'
import type { DataSource } from 'typeorm'
import type { EnvironmentConfig } from '../config/environment.js'
import { fileUploadRateLimit } from '../config/security.js'
import {
  createFileShareController,
  createListFileSharesController,
  createRevokeFileShareController,
} from '../controllers/fileShareController.js'
import {
  createFileUploadController,
  createListFilesController,
  createDownloadFileController,
  createDeleteFileController,
  createListDeletedFilesController,
  createListFileBackupsController,
  createRestoreFileBackupController,
} from '../controllers/fileController.js'
import { createAuthMiddleware } from '../middleware/authMiddleware.js'
import { createDataExportController } from '../controllers/dataExportController.js'

const uploadRateLimiter = rateLimit({
  windowMs: fileUploadRateLimit.windowMs,
  limit: fileUploadRateLimit.limit,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many uploads. Please try again later.',
  },
})

export function createFileRoutes(
  dataSource: DataSource,
  environment: EnvironmentConfig,
): Router {
  const router = Router()
  router.get(
    '/export',
    createAuthMiddleware(environment, dataSource),
    createDataExportController(dataSource, environment),
  )
  router.get(
    '/',
    createAuthMiddleware(environment, dataSource),
    createListFilesController(dataSource),
  )
  router.get(
    '/trash',
    createAuthMiddleware(environment, dataSource),
    createListDeletedFilesController(dataSource),
  )
  router.post(
    '/',
    uploadRateLimiter,
    createAuthMiddleware(environment, dataSource),
    createFileUploadController(dataSource, environment),
  )
  router.post(
    '/:id/shares',
    createAuthMiddleware(environment, dataSource),
    createFileShareController(dataSource),
  )
  router.get(
    '/:id/shares',
    createAuthMiddleware(environment, dataSource),
    createListFileSharesController(dataSource),
  )
  router.get(
    '/:id/backups',
    createAuthMiddleware(environment, dataSource),
    createListFileBackupsController(dataSource),
  )
  router.post(
    '/:id/backups/:backupId/restore',
    createAuthMiddleware(environment, dataSource),
    createRestoreFileBackupController(dataSource, environment),
  )
  router.delete(
    '/:id/shares/:shareId',
    createAuthMiddleware(environment, dataSource),
    createRevokeFileShareController(dataSource),
  )
  router.get(
    '/:id/download',
    createAuthMiddleware(environment, dataSource),
    createDownloadFileController(dataSource, environment),
  )
  router.delete('/:id', createAuthMiddleware(environment, dataSource), createDeleteFileController(dataSource, environment))
  return router
}
