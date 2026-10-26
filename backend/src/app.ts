import express from 'express'
import type { DataSource } from 'typeorm'
import type { EnvironmentConfig } from './config/environment.js'
import { errorMiddleware, notFoundMiddleware } from './middleware/errorMiddleware.js'
import { apiRateLimiter, configureSecurityMiddleware } from './middleware/securityMiddleware.js'
import { createAuthRoutes } from './routes/authRoutes.js'
import { createAuditRoutes } from './routes/auditRoutes.js'
import { createAdminRoutes } from './routes/adminRoutes.js'
import { createFileRoutes } from './routes/fileRoutes.js'
import { createHealthRoutes } from './routes/healthRoutes.js'

export function createApp(environment: EnvironmentConfig, dataSource: DataSource) {
  const app = express()

  configureSecurityMiddleware(app, environment) 
  app.use('/api/v1', apiRateLimiter)
  app.use('/api/v1', createHealthRoutes(environment, dataSource))
  app.use('/api/v1/auth', createAuthRoutes(dataSource, environment))
  app.use('/api/v1/audit', createAuditRoutes(dataSource, environment))
  app.use('/api/v1/admin', createAdminRoutes(dataSource, environment))
  app.use('/api/v1/files', createFileRoutes(dataSource, environment))
  app.use(notFoundMiddleware)
  app.use(errorMiddleware)

  return app
}
