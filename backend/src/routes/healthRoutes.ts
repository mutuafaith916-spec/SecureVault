import { Router } from 'express'
import type { EnvironmentConfig } from '../config/environment.js'
import type { DataSource } from 'typeorm'
import { createHealthController } from '../controllers/healthController.js'

export function createHealthRoutes(environment: EnvironmentConfig, dataSource: DataSource): Router {
  const router = Router()
  router.get('/health', createHealthController(environment, dataSource))
  return router
}
