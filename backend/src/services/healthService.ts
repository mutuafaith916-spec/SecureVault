import type { NodeEnvironment } from '../config/environment.js'
import type { DataSource } from 'typeorm'

export interface HealthStatus {
  readonly api: 'healthy'
  readonly database: 'healthy' | 'unhealthy'
  readonly environment: NodeEnvironment
  readonly timestamp: string
}

export async function getHealthStatus(
  environment: NodeEnvironment,
  dataSource: DataSource,
): Promise<HealthStatus> {
  let database: HealthStatus['database'] = 'unhealthy'
  if (dataSource.isInitialized) {
    try {
      await dataSource.query('SELECT 1')
      database = 'healthy'
    } catch {
      database = 'unhealthy'
    }
  }

  return {
    api: 'healthy',
    database,
    environment,
    timestamp: new Date().toISOString(),
  }
}
