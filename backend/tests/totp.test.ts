import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { test } from 'node:test'
import type { DataSource, EntityManager } from 'typeorm'
import jwt from 'jsonwebtoken'
import { loadEnvironment } from '../src/config/environment.js'
import { User } from '../src/entities/User.js'
import { completeMfaLogin, hashUserPassword, loginUser } from '../src/services/auth.service.js'
import {
  createTotpProvisioningUri,
  createTotpSecret,
  decryptTotpSecret,
  encryptTotpSecret,
  verifyTotp,
} from '../src/services/totp.service.js'

const environment = loadEnvironment({
  NODE_ENV: 'test',
  PORT: '3000',
  CORS_ORIGIN: 'http://localhost:5173',
  DATABASE_URL: 'postgres://localhost:5432/securevault_test',
  JWT_ACCESS_SECRET: 'test-access-secret-that-is-long-enough-for-validation',
  JWT_REFRESH_SECRET: 'test-refresh-secret-that-is-long-enough-for-validation',
  ENCRYPTION_MASTER_KEY: Buffer.alloc(32, 9).toString('base64'),
})

function decodeReferenceBase32(secret: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let value = 0n
  let bits = 0
  const bytes: number[] = []
  for (const character of secret.toUpperCase().replace(/=+$/, '')) {
    const digit = alphabet.indexOf(character)
    assert.notEqual(digit, -1)
    value = (value << 5n) | BigInt(digit)
    bits += 5
    if (bits >= 8) {
      bits -= 8
      bytes.push(Number((value >> BigInt(bits)) & 0xffn))
      value &= (1n << BigInt(bits)) - 1n
    }
  }
  return Buffer.from(bytes)
}

function generateReferenceTotp(secret: string, timestamp: number): string {
  const secretBytes = decodeReferenceBase32(secret)
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(timestamp / 30_000)))
  const digest = createHmac('sha1', secretBytes).update(counter).digest()
  const offset = digest[digest.length - 1] & 0x0f
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff)
  return String(binary % 1_000_000).padStart(6, '0')
}

test('TOTP verification follows the RFC 6238 SHA-1 test vector', () => {
  assert.equal(verifyTotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '287082', 59_000), 1)
  assert.equal(verifyTotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '000000', 59_000), undefined)
})

test('an independently generated fixed-time TOTP verifies only with its enrollment secret', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
  const timestamp = 59_000
  const code = generateReferenceTotp(secret, timestamp)

  assert.equal(code, '287082')
  assert.equal(verifyTotp(secret, code, timestamp), 1)
  assert.equal(verifyTotp(secret, '000000', timestamp), undefined)
  assert.equal(verifyTotp('JBSWY3DPEHPK3PXP', code, timestamp), undefined)
  assert.equal(verifyTotp(`${secret.toLowerCase()}====`, code, timestamp), 1)
})

test('TOTP accepts only the current and adjacent 30-second steps', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
  assert.equal(verifyTotp(secret, '287082', 30_000), 1)
  assert.equal(verifyTotp(secret, '287082', 89_000), 1)
  assert.equal(verifyTotp(secret, '755224', 59_000), 0)
  assert.equal(verifyTotp(secret, '755224', 60_000), undefined)
  assert.equal(verifyTotp(secret, '287082', 90_000), undefined)
  assert.equal(verifyTotp(secret, '12a456', 59_000), undefined)
})

test('MFA secrets are randomly generated and encrypted at rest', () => {
  const secret = createTotpSecret()
  const encrypted = encryptTotpSecret(secret, environment)
  assert.notEqual(encrypted, secret)
  assert.equal(decryptTotpSecret(encrypted, environment), secret)
  assert.throws(() => decryptTotpSecret(`${encrypted.slice(0, -1)}x`, environment))
})

test('authenticator provisioning URI includes the issuer and account label', () => {
  const uri = new URL(createTotpProvisioningUri('ABC234', 'user@example.test'))
  assert.equal(uri.protocol, 'otpauth:')
  assert.equal(uri.hostname, 'totp')
  assert.equal(uri.searchParams.get('secret'), 'ABC234')
  assert.equal(uri.searchParams.get('issuer'), 'SecureVault')
  assert.equal(uri.searchParams.get('algorithm'), 'SHA1')
  assert.equal(uri.searchParams.get('digits'), '6')
  assert.equal(uri.searchParams.get('period'), '30')
  assert.ok(decodeURIComponent(uri.pathname).includes('user@example.test'))
})

test('pending enrollment keeps its secret stable until an explicit restart', async () => {
  const passwordHash = await hashUserPassword('test-password')
  const firstUser = {
    id: '00000000-0000-4000-8000-000000000001',
    fullName: 'First User',
    email: 'first@example.test',
    passwordHash,
    role: 'USER',
    authVersion: 0,
    failedLoginAttempts: 0,
    loginLockedUntil: null,
    mfaSecret: null,
    mfaEnabled: false,
    mfaLastUsedStep: '-1',
  } as User
  const otherUser = {
    ...firstUser,
    id: '00000000-0000-4000-8000-000000000002',
    email: 'other@example.test',
    mfaSecret: null,
  } as User
  const usersByEmail = new Map([
    [firstUser.email, firstUser],
    [otherUser.email, otherUser],
  ])
  let selectedEmail = ''
  const queryBuilder = {
    addSelect: () => queryBuilder,
    setLock: () => queryBuilder,
    where: (_condition: string, parameters: { email: string }) => {
      selectedEmail = parameters.email
      return queryBuilder
    },
    getOne: async () => usersByEmail.get(selectedEmail) ?? null,
  }
  const repository = {
    createQueryBuilder: () => queryBuilder,
    save: async (user: User) => user,
  }
  const manager = {
    getRepository: () => repository,
  } as unknown as EntityManager
  const dataSource = {
    transaction: async <T>(operation: (transactionManager: EntityManager) => Promise<T>) =>
      operation(manager),
  } as unknown as DataSource

  const initialResult = await loginUser(dataSource, environment, firstUser.email, 'test-password')
  const initialSecret = decryptTotpSecret(firstUser.mfaSecret!, environment)
  const repeatedResult = await loginUser(dataSource, environment, firstUser.email, 'test-password')
  const repeatedSecret = decryptTotpSecret(firstUser.mfaSecret!, environment)
  const restartedResult = await loginUser(
    dataSource,
    environment,
    firstUser.email,
    'test-password',
    false,
    true,
  )
  const restartedSecret = decryptTotpSecret(firstUser.mfaSecret!, environment)
  const timestamp = 1_700_000_000_000
  const enrollmentCode = generateReferenceTotp(restartedSecret, timestamp)

  assert.equal(firstUser.mfaEnabled, false)
  assert.notEqual(firstUser.mfaSecret, null)
  assert.equal(new URL(initialResult.provisioningUri!).searchParams.get('secret'), initialSecret)
  assert.equal(new URL(repeatedResult.provisioningUri!).searchParams.get('secret'), initialSecret)
  assert.equal(repeatedSecret, initialSecret)
  assert.notEqual(restartedSecret, initialSecret)
  assert.equal(new URL(restartedResult.provisioningUri!).searchParams.get('secret'), restartedSecret)
  assert.equal(
    verifyTotp(restartedSecret, enrollmentCode, timestamp),
    Math.floor(timestamp / 30_000),
  )
  assert.equal(otherUser.mfaSecret, null)
})

test('MFA enrollment remains pending on invalid code and completes only after valid verification', async () => {
  const user = {
    id: '00000000-0000-4000-8000-000000000003',
    fullName: 'Pending User',
    email: 'pending@example.test',
    role: 'USER',
    authVersion: 0,
    failedLoginAttempts: 0,
    loginLockedUntil: null,
    mfaSecret: encryptTotpSecret('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', environment),
    mfaEnabled: false,
    mfaLastUsedStep: '-1',
  } as User
  let updateValues: Partial<User> = {}
  const updateBuilder = {
    update: () => updateBuilder,
    set: (values: Partial<User>) => {
      updateValues = values
      return updateBuilder
    },
    where: () => updateBuilder,
    execute: async () => {
      const requestedStep = Number(updateValues.mfaLastUsedStep)
      if (Number(user.mfaLastUsedStep) >= requestedStep) {
        return { affected: 0 }
      }
      Object.assign(user, updateValues)
      return { affected: 1 }
    },
  }
  const userQueryBuilder = {
    addSelect: () => userQueryBuilder,
    where: () => userQueryBuilder,
    getOne: async () => user,
  }
  const userRepository = {
    createQueryBuilder: () => userQueryBuilder,
    findOneBy: async () => user,
  }
  const transactionRepository = {
    createQueryBuilder: () => updateBuilder,
    findOne: async () => user,
    save: async (updatedUser: User) => Object.assign(user, updatedUser),
  }
  const refreshTokenRepository = {
    create: (refreshToken: object) => refreshToken,
    save: async (refreshToken: object) => refreshToken,
  }
  const dataSource = {
    getRepository: (entity: typeof User | Function) =>
      entity === User ? userRepository : refreshTokenRepository,
    transaction: async (operation: (manager: EntityManager) => Promise<unknown>) =>
      operation({ getRepository: () => transactionRepository } as unknown as EntityManager),
  } as unknown as DataSource
  const challengeToken = jwt.sign(
    { tokenType: 'mfa-challenge', authVersion: user.authVersion, persistent: false },
    environment.jwtAccessSecret!,
    { subject: user.id, expiresIn: '5m' },
  )
  const timestamp = Date.now()
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
  const validCode = generateReferenceTotp(secret, timestamp)
  const invalidCode = String((Number(validCode) + 1) % 1_000_000).padStart(6, '0')

  await assert.rejects(
    completeMfaLogin(dataSource, environment, challengeToken, invalidCode),
    /verification code is invalid/i,
  )
  assert.equal(user.mfaEnabled, false)

  const result = await completeMfaLogin(dataSource, environment, challengeToken, validCode)
  assert.equal(user.mfaEnabled, true)
  assert.equal(user.mfaLastUsedStep, String(Math.floor(timestamp / 30_000)))
  assert.equal(result.user.id, user.id)
})
