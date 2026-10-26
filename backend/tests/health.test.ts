import 'dotenv/config'
import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { DataSource } from 'typeorm'
import type { EnvironmentConfig } from '../src/config/environment.js'
import { createApp } from '../src/app.js'

const configuredDatabaseUrl = process.env.DATABASE_URL?.trim()
const environment: EnvironmentConfig = {
  nodeEnv: 'test',
  port: 0,
  corsOrigin: 'http://localhost:5173',
  databaseUrl: configuredDatabaseUrl ?? '',
  securityAlertEmails: [],
}
const dataSource = configuredDatabaseUrl
  ? new DataSource({ type: 'postgres', url: configuredDatabaseUrl })
  : new DataSource({ type: 'postgres' })
const server = createServer(createApp(environment, dataSource))
let baseUrl: string

before(async () => {
  if (configuredDatabaseUrl) {
    await dataSource.initialize()
  }
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject)
      const address = server.address() as AddressInfo
      baseUrl = `http://127.0.0.1:${address.port}`
      resolve()
    })
  })
})

after(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error)
      else resolve()
    })
  })
  if (dataSource.isInitialized) {
    await dataSource.destroy()
  }
})

test('GET /api/v1/health reports the actual database connection status', async () => {
  const response = await fetch(`${baseUrl}/api/v1/health`)
  const body = await response.json() as {
    success: boolean
    data: {
      api: string
      database: string
      environment: string
      timestamp: string
    }
    message?: string
  }

  assert.equal(body.data.api, 'healthy')
  assert.equal(body.data.environment, 'test')
  assert.match(body.data.timestamp, /^\d{4}-\d{2}-\d{2}T/)
  if (configuredDatabaseUrl) {
    assert.equal(response.status, 200)
    assert.equal(body.success, true)
    assert.equal(body.data.database, 'healthy')
  } else {
    assert.equal(response.status, 503)
    assert.equal(body.success, false)
    assert.equal(body.data.database, 'unhealthy')
    assert.equal(body.message, 'Database is unavailable')
  }
})

test('configured frontend origin is allowed and security headers are present', async () => {
  const response = await fetch(`${baseUrl}/api/v1/missing`, {
    headers: { Origin: environment.corsOrigin },
  })

  assert.equal(response.status, 404)
  assert.equal(response.headers.get('access-control-allow-origin'), environment.corsOrigin)
  assert.equal(response.headers.get('access-control-allow-credentials'), 'true')
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff')
  assert.ok(response.headers.get('strict-transport-security'))
  assert.equal(response.headers.get('x-powered-by'), null)
})

test('unconfigured browser origins are rejected with a safe JSON error', async () => {
  const response = await fetch(`${baseUrl}/api/v1/health`, {
    headers: { Origin: 'https://untrusted.example' },
  })

  assert.equal(response.status, 403)
  assert.deepEqual(await response.json(), {
    success: false,
    message: 'Request origin is not allowed',
  })
})

test('unknown routes return a consistent JSON 404', async () => {
  const response = await fetch(`${baseUrl}/api/v1/missing`)

  assert.equal(response.status, 404)
  assert.deepEqual(await response.json(), {
    success: false,
    message: 'Route not found',
  })
})

test('refresh requires a refresh cookie and does not touch the database', async () => {
  const response = await fetch(`${baseUrl}/api/v1/auth/refresh`, { method: 'POST' })

  assert.equal(response.status, 401)
  assert.deepEqual(await response.json(), {
    success: false,
    message: 'Your session has expired. Please sign in again.',
  })
})

test('password reset reports missing SMTP setup without querying account data', async () => {
  const response = await fetch(`${baseUrl}/api/v1/auth/forgot-password`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'person@example.test' }),
  })

  assert.equal(response.status, 503)
  assert.deepEqual(await response.json(), {
    success: false,
    message: 'Password reset email is not configured. Please contact support.',
  })
})
