import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { test } from 'node:test'
import jwt from 'jsonwebtoken'
import type { DataSource } from 'typeorm'
import type { EnvironmentConfig } from '../src/config/environment.js'
import { EmailMfaChallenge } from '../src/entities/EmailMfaChallenge.js'
import { RefreshToken } from '../src/entities/RefreshToken.js'
import { User, UserRole } from '../src/entities/User.js'
import { completeEmailMfaLogin, hashUserPassword, loginUser } from '../src/services/auth.service.js'
import { HttpError } from '../src/types/http.js'

const accessSecret = 'securevault-email-mfa-access-test-secret'
const environment: EnvironmentConfig = {
  nodeEnv: 'test',
  port: 3000,
  corsOrigin: 'http://localhost:5173',
  databaseUrl: '',
  jwtAccessSecret: accessSecret,
  jwtRefreshSecret: 'securevault-email-mfa-refresh-test-secret',
  securityAlertEmails: [],
}
const userId = 'c213a2f9-3d3d-4c12-9abe-541022f860de'
const challengeId = 'b807b4f1-0254-4f48-a470-7cac4ddcd883'

function createChallengeToken() {
  return jwt.sign(
    { tokenType: 'mfa-challenge', authVersion: 4, persistent: false },
    accessSecret,
    { subject: userId, jwtid: challengeId, expiresIn: '5m' },
  )
}

function codeHash(code: string) {
  return createHmac('sha256', accessSecret)
    .update(`securevault-email-mfa:${challengeId}:${code}`)
    .digest('hex')
}

function createDataSource(options: { codeHash?: string; expiresAt?: Date } = {}) {
  const user = {
    id: userId,
    fullName: 'Test User',
    email: 'test@example.com',
    role: UserRole.USER,
    authVersion: 4,
    mfaSecret: 'encrypted-existing-secret',
    mfaEnabled: true,
    mfaLastUsedStep: '12345',
    failedLoginAttempts: 0,
    loginLockedUntil: null,
  } as User
  const challenge = {
    id: 'email-challenge-id',
    challengeId,
    userId,
    codeHash: options.codeHash ?? codeHash('123456'),
    expiresAt: options.expiresAt ?? new Date(Date.now() + 60_000),
    sentAt: new Date(),
    sendCount: 1,
    attempts: 0,
    consumedAt: null,
  } as EmailMfaChallenge
  const userRepository = {
    async findOne() {
      return user
    },
    async save(value: User) {
      return value
    },
  }
  const challengeRepository = {
    async findOne() {
      return challenge
    },
    async save(value: EmailMfaChallenge) {
      return value
    },
  }
  const refreshRepository = {
    create(value: Partial<RefreshToken>) {
      return value
    },
    async save(value: Partial<RefreshToken>) {
      return value
    },
  }
  const manager = {
    getRepository(entity: typeof User | typeof EmailMfaChallenge) {
      return entity === User ? userRepository : challengeRepository
    },
  }
  const dataSource = {
    async transaction<T>(callback: (transactionManager: typeof manager) => Promise<T>) {
      return callback(manager)
    },
    getRepository(entity: typeof RefreshToken) {
      assert.equal(entity, RefreshToken)
      return refreshRepository
    },
  } as unknown as DataSource
  return { dataSource, user, challenge }
}

test('email MFA success consumes its code without requiring or changing legacy authenticator state', async () => {
  const { dataSource, user, challenge } = createDataSource()
  user.mfaEnabled = false

  const result = await completeEmailMfaLogin(dataSource, environment, createChallengeToken(), '123456')

  assert.equal(result.user.id, userId)
  assert.equal(challenge.consumedAt instanceof Date, true)
  assert.equal(user.mfaEnabled, false)
  assert.equal(user.mfaSecret, 'encrypted-existing-secret')
  assert.equal(user.mfaLastUsedStep, '12345')
  assert.ok(result.accessToken)
  assert.ok(result.refreshToken)
})

test('password login issues an email challenge without creating or changing an authenticator secret', async () => {
  const passwordHash = await hashUserPassword('test-password')
  const user = {
    id: userId,
    fullName: 'Test User',
    email: 'test@example.com',
    passwordHash,
    role: UserRole.USER,
    authVersion: 4,
    mfaSecret: null,
    mfaEnabled: false,
    mfaLastUsedStep: '-1',
    failedLoginAttempts: 0,
    loginLockedUntil: null,
  } as User
  const queryBuilder = {
    addSelect: () => queryBuilder,
    setLock: () => queryBuilder,
    where: () => queryBuilder,
    getOne: async () => user,
  }
  const repository = {
    createQueryBuilder: () => queryBuilder,
    save: async (value: User) => value,
  }
  const manager = { getRepository: () => repository }
  const dataSource = {
    async transaction<T>(callback: (transactionManager: typeof manager) => Promise<T>) {
      return callback(manager)
    },
  } as unknown as DataSource

  const result = await loginUser(dataSource, environment, user.email, 'test-password')
  const payload = jwt.verify(result.challengeToken, accessSecret)

  assert.equal(result.mfaRequired, true)
  assert.equal('provisioningUri' in result, false)
  assert.equal('manualSecret' in result, false)
  assert.equal(user.mfaEnabled, false)
  assert.equal(user.mfaSecret, null)
  assert.equal(typeof payload, 'object')
  assert.equal(payload.tokenType, 'mfa-challenge')
  assert.equal(typeof payload.jti, 'string')
})

test('a successfully used email MFA code cannot be replayed', async () => {
  const { dataSource, challenge } = createDataSource()
  const token = createChallengeToken()

  await completeEmailMfaLogin(dataSource, environment, token, '123456')
  await assert.rejects(
    completeEmailMfaLogin(dataSource, environment, token, '123456'),
    (error: unknown) => error instanceof HttpError && error.statusCode === 401,
  )

  assert.equal(challenge.consumedAt instanceof Date, true)
})

test('invalid email MFA codes increment attempt counters and do not create a session', async () => {
  const { dataSource, user, challenge } = createDataSource()

  await assert.rejects(
    completeEmailMfaLogin(dataSource, environment, createChallengeToken(), '000000'),
    (error: unknown) =>
      error instanceof HttpError &&
      error.statusCode === 401 &&
      error.message === 'The email verification code is invalid or expired. Please try again.',
  )

  assert.equal(challenge.attempts, 1)
  assert.equal(user.failedLoginAttempts, 1)
  assert.equal(challenge.consumedAt, null)
})

test('email MFA attempts are capped and trigger the existing login lockout', async () => {
  const { dataSource, user, challenge } = createDataSource()
  const token = createChallengeToken()

  for (let attempt = 0; attempt < 5; attempt += 1) {
    await assert.rejects(
      completeEmailMfaLogin(dataSource, environment, token, '000000'),
      (error: unknown) => error instanceof HttpError && error.statusCode === 401,
    )
  }

  assert.equal(challenge.attempts, 5)
  assert.equal(user.failedLoginAttempts, 5)
  assert.ok(user.loginLockedUntil instanceof Date)
  await assert.rejects(
    completeEmailMfaLogin(dataSource, environment, token, '123456'),
    (error: unknown) => error instanceof HttpError && error.statusCode === 401,
  )
})

test('expired email MFA codes cannot complete sign-in', async () => {
  const { dataSource, challenge } = createDataSource({
    expiresAt: new Date(Date.now() - 1_000),
  })

  await assert.rejects(
    completeEmailMfaLogin(dataSource, environment, createChallengeToken(), '123456'),
    (error: unknown) => error instanceof HttpError && error.statusCode === 401,
  )

  assert.equal(challenge.consumedAt, null)
})

test('email MFA challenge tokens must carry a valid challenge identifier', async () => {
  const tokenWithoutChallengeId = jwt.sign(
    { tokenType: 'mfa-challenge', authVersion: 4, persistent: false },
    accessSecret,
    { subject: userId, expiresIn: '5m' },
  )

  await assert.rejects(
    completeEmailMfaLogin(createDataSource().dataSource, environment, tokenWithoutChallengeId, '123456'),
    (error: unknown) => error instanceof HttpError && error.statusCode === 401,
  )
})
