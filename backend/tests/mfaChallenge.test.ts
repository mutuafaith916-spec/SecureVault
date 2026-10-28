import assert from 'node:assert/strict'
import { test } from 'node:test'
import jwt from 'jsonwebtoken'
import type { DataSource } from 'typeorm'
import type { EnvironmentConfig } from '../src/config/environment.js'
import { completeEmailMfaLogin } from '../src/services/auth.service.js'
import { HttpError } from '../src/types/http.js'

const accessSecret = 'securevault-mfa-challenge-test-secret'
const environment: EnvironmentConfig = {
  nodeEnv: 'test',
  port: 3000,
  corsOrigin: 'http://localhost:5173',
  databaseUrl: '',
  jwtAccessSecret: accessSecret,
  jwtRefreshSecret: 'securevault-mfa-refresh-test-secret',
  securityAlertEmails: [],
}
const unusedDataSource = {} as DataSource
const challengeId = 'c110c2cb-0e76-4621-b740-847769d915be'

function challengeToken(secret: string, expiresIn: string) {
  return jwt.sign(
    { tokenType: 'mfa-challenge', authVersion: 0, persistent: false },
    secret,
    { subject: 'user-id', jwtid: challengeId, expiresIn },
  )
}

test('expired email MFA challenge tokens report expiration', async () => {
  await assert.rejects(
    completeEmailMfaLogin(
      unusedDataSource,
      environment,
      challengeToken(accessSecret, '-1s'),
      '123456',
    ),
    (error: unknown) =>
      error instanceof HttpError &&
      error.statusCode === 401 &&
      error.message === 'Your sign-in challenge has expired. Please sign in again.',
  )
})

test('email MFA challenge tokens signed with a different key report an invalid challenge', async () => {
  await assert.rejects(
    completeEmailMfaLogin(
      unusedDataSource,
      environment,
      challengeToken('another-mfa-challenge-test-secret', '5m'),
      '123456',
    ),
    (error: unknown) =>
      error instanceof HttpError &&
      error.statusCode === 401 &&
      error.message === 'Your sign-in challenge is invalid. Please sign in again.',
  )
})
