import type { RequestHandler } from 'express'
import type { EnvironmentConfig } from '../config/environment.js'
import type { DataSource } from 'typeorm'
import { getHealthStatus } from '../services/healthService.js'
import { logger } from '../utils/logger.js'

export function createHealthController(
  environment: EnvironmentConfig,
  dataSource: DataSource,
): RequestHandler {
  return async (_request, response) => {
    const status = await getHealthStatus(environment.nodeEnv, dataSource)
    if (status.database === 'unhealthy') {
      logger.warn({ event: 'database.health_check_failed' }, 'Database health check failed')
      response.status(503).json({
        success: false,
        message: 'Database is unavailable',
        data: status,
      })
      return
    }

    response.status(200).json({
      success: true,
      data: status,
    })
  }
}
