import {
  createHash,
  randomBytes,
  scrypt,
  timingSafeEqual,
} from 'node:crypto'
import type { DataSource } from 'typeorm'
import { IsNull } from 'typeorm'
import jwt from 'jsonwebtoken'
import type { EnvironmentConfig } from '../config/environment.js'
import { RefreshToken } from '../entities/RefreshToken.js'
import { User } from '../entities/User.js'
import { HttpError } from '../types/http.js'
import {
  createTotpProvisioningUri,
  createTotpSecret,
  decryptTotpSecret,
  encryptTotpSecret,
  verifyTotp,
} from './totp.service.js'

const passwordKeyLength = 64
const accessTokenLifetime = '15m'
const mfaChallengeLifetime = '5m'
const persistentRefreshLifetimeMs = 7 * 24 * 60 * 60 * 1000
const sessionRefreshLifetimeMs = 12 * 60 * 60 * 1000
const maximumFailedLogins = 5
const loginLockoutMs = 15 * 60 * 1000

function derivePasswordKey(
  password: string,
  salt: string,
  keyLength: number,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keyLength, (error, key) => {
      if (error) {
        reject(error)
        return
      }

      resolve(key as Buffer)
    })
  })
}

async function verifyPassword(
  password: string,
  storedHash: string,
): Promise<boolean> {
  const parts = storedHash.split('$')

  if (
    parts.length !== 3 ||
    parts[0] !== 'scrypt' ||
    !/^[a-f0-9]{32}$/i.test(parts[1]) ||
    !/^[a-f0-9]{128}$/i.test(parts[2])
  ) {
    return false
  }

  const [, salt, savedKeyHex] = parts
  const savedKey = Buffer.from(savedKeyHex, 'hex')
  const suppliedKey = await derivePasswordKey(
    password,
    salt,
    passwordKeyLength,
  )

  return timingSafeEqual(savedKey, suppliedKey)
}

export async function hashUserPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString('hex')
  const key = await derivePasswordKey(password, salt, passwordKeyLength)
  return `scrypt$${salt}$${key.toString('hex')}`
}

function hashRefreshToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}

export async function loginUser(
  dataSource: DataSource,
  environment: EnvironmentConfig,
  email: string,
  password: string,
  rememberMe = false,
  restartMfaSetup = false,
) {
  if (!environment.jwtAccessSecret || !environment.jwtRefreshSecret) {
    throw new HttpError(503, 'Authentication is not configured yet.')
  }

  const loginResult = await dataSource.transaction(async (manager) => {
    const user = await manager
      .getRepository(User)
      .createQueryBuilder('user')
      .addSelect('user.passwordHash')
      .addSelect('user.mfaSecret')
      .setLock('pessimistic_write')
      .where('user.email = :email', { email: email.trim().toLowerCase() })
      .getOne()

    if (!user) {
      return { authenticated: false as const }
    }

    const now = new Date()
    if (user.loginLockedUntil && user.loginLockedUntil > now) {
      return { authenticated: false as const }
    }
    if (user.loginLockedUntil) {
      user.failedLoginAttempts = 0
      user.loginLockedUntil = null
    }

    if (!(await verifyPassword(password, user.passwordHash))) {
      user.failedLoginAttempts += 1
      if (user.failedLoginAttempts >= maximumFailedLogins) {
        user.loginLockedUntil = new Date(now.getTime() + loginLockoutMs)
      }
      await manager.getRepository(User).save(user)
      return { authenticated: false as const }
    }

    user.failedLoginAttempts = 0
    user.loginLockedUntil = null
    if (!user.mfaEnabled && (!user.mfaSecret || restartMfaSetup)) {
      user.mfaSecret = encryptTotpSecret(createTotpSecret(), environment)
    }
    await manager.getRepository(User).save(user)

    return { authenticated: true as const, user }
  })

  if (!loginResult.authenticated) {
    throw new HttpError(401, 'Invalid email or password.')
  }

  const user = loginResult.user
  const mfaSecret = decryptTotpSecret(user.mfaSecret!, environment)
  const challengeToken = jwt.sign(
    {
      tokenType: 'mfa-challenge',
      authVersion: user.authVersion,
      persistent: rememberMe,
    },
    environment.jwtAccessSecret,
    { subject: user.id, expiresIn: mfaChallengeLifetime },
  )

  return {
    mfaRequired: true as const,
    mfaSetupRequired: !user.mfaEnabled,
    challengeToken,
    ...(user.mfaEnabled
      ? {}
      : {
          provisioningUri: createTotpProvisioningUri(mfaSecret, user.email),
          manualSecret: mfaSecret,
        }),
    persistent: rememberMe,
  }
}

async function createSession(
  dataSource: DataSource,
  environment: EnvironmentConfig,
  user: User,
  rememberMe: boolean,
) {
  if (!environment.jwtAccessSecret || !environment.jwtRefreshSecret) {
    throw new HttpError(503, 'Authentication is not configured yet.')
  }
  const accessToken = jwt.sign(
    { role: user.role, tokenType: 'access', authVersion: user.authVersion },
    environment.jwtAccessSecret,
    { subject: user.id, expiresIn: accessTokenLifetime },
  )
  const refreshExpiresAt = new Date(
    Date.now() + (rememberMe ? persistentRefreshLifetimeMs : sessionRefreshLifetimeMs),
  )
  const refreshToken = jwt.sign(
    {
      role: user.role,
      tokenType: 'refresh',
      persistent: rememberMe,
      authVersion: user.authVersion,
    },
    environment.jwtRefreshSecret,
    {
      subject: user.id,
      jwtid: randomBytes(16).toString('hex'),
      expiresIn: Math.floor((refreshExpiresAt.getTime() - Date.now()) / 1000),
    },
  )

  const refreshTokens = dataSource.getRepository(RefreshToken)

  const savedToken = refreshTokens.create({
    userId: user.id,
    tokenHash: hashRefreshToken(refreshToken),
    expiresAt: refreshExpiresAt,
    revokedAt: null,
    persistent: rememberMe,
  })

  await refreshTokens.save(savedToken)

  return {
    user: {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      role: user.role,
    },
    accessToken,
    refreshToken,
    refreshExpiresAt,
    persistent: rememberMe,
  }
}

export async function completeMfaLogin(
  dataSource: DataSource,
  environment: EnvironmentConfig,
  challengeToken: string,
  code: string,
) {
  if (!environment.jwtAccessSecret || !environment.jwtRefreshSecret) {
    throw new HttpError(503, 'Authentication is not configured yet.')
  }
  let payload: jwt.JwtPayload
  try {
    const verified = jwt.verify(challengeToken, environment.jwtAccessSecret)
    if (typeof verified === 'string') {
      throw new Error('Invalid MFA challenge payload')
    }
    payload = verified
  } catch {
    throw new HttpError(401, 'Your sign-in challenge has expired. Please sign in again.')
  }

  if (
    typeof payload.sub !== 'string' ||
    payload.tokenType !== 'mfa-challenge' ||
    typeof payload.persistent !== 'boolean' ||
    typeof payload.authVersion !== 'number'
  ) {
    throw new HttpError(401, 'Your sign-in challenge is invalid. Please sign in again.')
  }

  const users = dataSource.getRepository(User)
  const user = await users
    .createQueryBuilder('user')
    .addSelect('user.mfaSecret')
    .where('user.id = :id', { id: payload.sub })
    .getOne()
  if (
    !user ||
    user.authVersion !== payload.authVersion ||
    !user.mfaSecret ||
    (user.loginLockedUntil !== null && user.loginLockedUntil > new Date())
  ) {
    throw new HttpError(401, 'Your sign-in challenge is invalid. Please sign in again.')
  }

  const secret = decryptTotpSecret(user.mfaSecret, environment)
  const matchedStep = verifyTotp(secret, code)
  if (matchedStep === undefined) {
    await dataSource.transaction(async (manager) => {
      const lockedUser = await manager.getRepository(User).findOne({
        where: { id: user.id },
        lock: { mode: 'pessimistic_write' },
      })
      if (!lockedUser || (lockedUser.loginLockedUntil && lockedUser.loginLockedUntil > new Date())) {
        return
      }
      if (lockedUser.loginLockedUntil) {
        lockedUser.failedLoginAttempts = 0
        lockedUser.loginLockedUntil = null
      }
      lockedUser.failedLoginAttempts += 1
      if (lockedUser.failedLoginAttempts >= maximumFailedLogins) {
        lockedUser.loginLockedUntil = new Date(Date.now() + loginLockoutMs)
      }
      await manager.getRepository(User).save(lockedUser)
    })
    throw new HttpError(401, 'The verification code is invalid. Please try again.')
  }

  await dataSource.transaction(async (manager) => {
    const result = await manager.getRepository(User).createQueryBuilder()
      .update(User)
      .set({
        mfaEnabled: true,
        mfaLastUsedStep: String(matchedStep),
        failedLoginAttempts: 0,
        loginLockedUntil: null,
      })
      .where('"id" = :id AND "auth_version" = :authVersion AND "mfa_last_used_step" < :step', {
        id: user.id,
        authVersion: payload.authVersion,
        step: matchedStep,
      })
      .execute()
    if (result.affected !== 1) {
      throw new HttpError(401, 'This verification code has already been used. Please try the current code.')
    }
  })

  const updatedUser = await users.findOneBy({ id: user.id })
  if (!updatedUser) {
    throw new HttpError(401, 'Your account is unavailable. Please sign in again.')
  }
  return createSession(dataSource, environment, updatedUser, payload.persistent)
}

export async function refreshUserSession(
  dataSource: DataSource,
  environment: EnvironmentConfig,
  refreshToken: string,
) {
  if (!environment.jwtAccessSecret || !environment.jwtRefreshSecret) {
    throw new HttpError(503, 'Authentication is not configured yet.')
  }

  let payload: jwt.JwtPayload
  try {
    const verified = jwt.verify(refreshToken, environment.jwtRefreshSecret)
    if (typeof verified === 'string') {
      throw new Error('Invalid refresh token payload')
    }
    payload = verified
  } catch {
    throw new HttpError(401, 'Your session has expired. Please sign in again.')
  }

  if (
    typeof payload.sub !== 'string' ||
    (payload.role !== 'USER' && payload.role !== 'ADMIN') ||
    payload.tokenType !== 'refresh' ||
    typeof payload.persistent !== 'boolean' ||
    typeof payload.authVersion !== 'number'
  ) {
    throw new HttpError(401, 'Your session is invalid. Please sign in again.')
  }

  const now = new Date()
  const refreshTokens = dataSource.getRepository(RefreshToken)
  const currentToken = await refreshTokens.findOneBy({
    tokenHash: hashRefreshToken(refreshToken),
    revokedAt: IsNull(),
  })
  if (
    !currentToken ||
    currentToken.expiresAt <= now ||
    currentToken.persistent !== payload.persistent
  ) {
    throw new HttpError(401, 'Your session has expired. Please sign in again.')
  }

  const user = await dataSource.getRepository(User).findOneBy({ id: currentToken.userId })
  if (
    !user ||
    user.id !== payload.sub ||
    user.role !== payload.role ||
    user.authVersion !== payload.authVersion
  ) {
    throw new HttpError(401, 'Your session is invalid. Please sign in again.')
  }

  const remainingLifetimeSeconds = Math.floor((currentToken.expiresAt.getTime() - now.getTime()) / 1000)
  if (remainingLifetimeSeconds <= 0) {
    throw new HttpError(401, 'Your session has expired. Please sign in again.')
  }

  const nextRefreshToken = jwt.sign(
    {
      role: user.role,
      tokenType: 'refresh',
      persistent: currentToken.persistent,
      authVersion: user.authVersion,
    },
    environment.jwtRefreshSecret,
    {
      subject: user.id,
      jwtid: randomBytes(16).toString('hex'),
      expiresIn: remainingLifetimeSeconds,
    },
  )
  const accessToken = jwt.sign(
    { role: user.role, tokenType: 'access', authVersion: user.authVersion },
    environment.jwtAccessSecret,
    { subject: user.id, expiresIn: accessTokenLifetime },
  )

  await dataSource.transaction(async (manager) => {
    const result = await manager.getRepository(RefreshToken).update(
      { id: currentToken.id, revokedAt: IsNull() },
      { revokedAt: now },
    )
    if (result.affected !== 1) {
      throw new HttpError(401, 'Your session has already been refreshed. Please sign in again.')
    }
    await manager.getRepository(RefreshToken).save(
      manager.getRepository(RefreshToken).create({
        userId: user.id,
        tokenHash: hashRefreshToken(nextRefreshToken),
        expiresAt: currentToken.expiresAt,
        revokedAt: null,
        persistent: currentToken.persistent,
      }),
    )
  })

  return {
    user: { id: user.id, fullName: user.fullName, email: user.email, role: user.role },
    accessToken,
    refreshToken: nextRefreshToken,
    refreshExpiresAt: currentToken.expiresAt,
    persistent: currentToken.persistent,
  }
}

export async function revokeRefreshToken(
  dataSource: DataSource,
  refreshToken: string | undefined,
): Promise<string | undefined> {
  if (!refreshToken) {
    return undefined
  }
  const refreshTokens = dataSource.getRepository(RefreshToken)
  const token = await refreshTokens.findOneBy({ tokenHash: hashRefreshToken(refreshToken) })
  if (!token || token.revokedAt) {
    return undefined
  }
  const now = new Date()
  return dataSource.transaction(async (manager) => {
    const result = await manager.getRepository(RefreshToken).update(
      { userId: token.userId, revokedAt: IsNull() },
      { revokedAt: now },
    )
    if (!result.affected) {
      return undefined
    }
    await manager.getRepository(User).createQueryBuilder()
      .update(User)
      .set({ authVersion: () => '"auth_version" + 1' })
      .where('"id" = :userId', { userId: token.userId })
      .execute()
    return token.userId
  })
}
