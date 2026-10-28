import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import type { Request } from 'express'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import jwt from 'jsonwebtoken'
import type { DataSource } from 'typeorm'
import type { EnvironmentConfig } from '../src/config/environment.js'
import { createApp } from '../src/app.js'
import { requireAdminId } from '../src/middleware/adminAuthorization.js'
import { User } from '../src/entities/User.js'
import { HttpError } from '../src/types/http.js'

function requestWithUser(user: { id: string; role: 'USER' | 'ADMIN' } | undefined): Request {
  return { user } as Request
}

test('admin authorization accepts an authenticated administrator', () => {
  assert.equal(
    requireAdminId(requestWithUser({ id: 'admin-id', role: 'ADMIN' })),
    'admin-id',
  )
})

test('admin authorization rejects an authenticated regular user', () => {
  assert.throws(
    () => requireAdminId(requestWithUser({ id: 'user-id', role: 'USER' })),
    (error: unknown) => error instanceof HttpError && error.statusCode === 403,
  )
})

test('admin authorization rejects a request without an authenticated user', () => {
  assert.throws(
    () => requireAdminId(requestWithUser(undefined)),
    (error: unknown) => error instanceof HttpError && error.statusCode === 401,
  )
})

const accessSecret = 'securevault-admin-authz-test-secret'
const environment: EnvironmentConfig = {
  nodeEnv: 'test',
  port: 0,
  corsOrigin: 'http://localhost:5173',
  databaseUrl: '',
  jwtAccessSecret: accessSecret,
  securityAlertEmails: [],
}
const fakeDataSource = {
  getRepository(entity: unknown) {
    assert.equal(entity, User)
    return {
      findOne: async () => ({ id: 'regular-user', role: 'USER', authVersion: 0 }),
    }
  },
} as unknown as DataSource
const server = createServer(createApp(environment, fakeDataSource))
let baseUrl: string

before(async () => {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject)
      baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
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
})

test('regular-user tokens are denied by protected admin data routes', async () => {
  const token = jwt.sign(
    { role: 'USER', tokenType: 'access', authVersion: 0 },
    accessSecret,
    { subject: 'regular-user', expiresIn: '1m' },
  )
  for (const path of ['/api/v1/admin/overview', '/api/v1/admin/users', '/api/v1/admin/alerts']) {
    const response = await fetch(`${baseUrl}${path}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    assert.equal(response.status, 403)
    assert.deepEqual(await response.json(), {
      success: false,
      message: 'Administrator access is required.',
    })
  }
  const roleChangeResponse = await fetch(
    `${baseUrl}/api/v1/admin/users/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/role`,
    {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ role: 'ADMIN' }),
    },
  )
  assert.equal(roleChangeResponse.status, 403)
  assert.deepEqual(await roleChangeResponse.json(), {
    success: false,
    message: 'Administrator access is required.',
  })

  const alertStatusResponse = await fetch(
    `${baseUrl}/api/v1/admin/alerts/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/status`,
    {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ status: 'RESOLVED' }),
    },
  )
  assert.equal(alertStatusResponse.status, 403)
  assert.deepEqual(await alertStatusResponse.json(), {
    success: false,
    message: 'Administrator access is required.',
  })
})

test('security alert data routes reject requests without an authenticated session', async () => {
  const response = await fetch(`${baseUrl}/api/v1/admin/alerts`)
  assert.equal(response.status, 401)

  const statusResponse = await fetch(
    `${baseUrl}/api/v1/admin/alerts/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/status`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'RESOLVED' }),
    },
  )
  assert.equal(statusResponse.status, 401)
})
