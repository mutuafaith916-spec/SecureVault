import {
  createHmac,
  createHash,
  randomBytes,
  randomInt,
  randomUUID,
  scrypt,
  timingSafeEqual,
} from 'node:crypto'
import type { DataSource } from 'typeorm'
import { IsNull } from 'typeorm'
import jwt from 'jsonwebtoken'
import nodemailer from 'nodemailer'
import type { EnvironmentConfig } from '../config/environment.js'
import { EmailMfaChallenge } from '../entities/EmailMfaChallenge.js'
import { RefreshToken } from '../entities/RefreshToken.js'
import { User } from '../entities/User.js'
import { HttpError } from '../types/http.js'
import { logger } from '../utils/logger.js'

const passwordKeyLength = 64
const accessTokenLifetime = '15m'
const mfaChallengeLifetime = '5m'
const emailMfaCodeLifetimeMs = 5 * 60 * 1000
const emailMfaResendDelayMs = 60 * 1000
const maximumEmailMfaSends = 3
const maximumEmailMfaAttempts = 5
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
) {
  if (!environment.jwtAccessSecret || !environment.jwtRefreshSecret) {
    throw new HttpError(503, 'Authentication is not configured yet.')
  }

  const loginResult = await dataSource.transaction(async (manager) => {
    const user = await manager
      .getRepository(User)
      .createQueryBuilder('user')
      .addSelect('user.passwordHash')
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
    await manager.getRepository(User).save(user)

    return { authenticated: true as const, user }
  })

  if (!loginResult.authenticated) {
    throw new HttpError(401, 'Invalid email or password.')
  }
  const user = loginResult.user
  const challengeToken = jwt.sign(
    {
      tokenType: 'mfa-challenge',
      authVersion: user.authVersion,
      persistent: rememberMe,
    },
    environment.jwtAccessSecret,
    { subject: user.id, jwtid: randomUUID(), expiresIn: mfaChallengeLifetime },
  )

  return {
    mfaRequired: true as const,
    challengeToken,
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

type VerifiedEmailMfaChallenge = jwt.JwtPayload & {
  sub: string
  jti: string
  authVersion: number
  persistent: boolean
}

function verifyEmailMfaChallenge(
  environment: EnvironmentConfig,
  challengeToken: string,
): VerifiedEmailMfaChallenge {
  if (!environment.jwtAccessSecret) {
    throw new HttpError(503, 'Authentication is not configured yet.')
  }

  let verified: string | jwt.JwtPayload
  try {
    verified = jwt.verify(challengeToken, environment.jwtAccessSecret)
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new HttpError(401, 'Your sign-in challenge has expired. Please sign in again.')
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new HttpError(401, 'Your sign-in challenge is invalid. Please sign in again.')
    }
    throw error
  }

  if (
    typeof verified === 'string' ||
    typeof verified.sub !== 'string' ||
    typeof verified.jti !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(verified.jti) ||
    verified.tokenType !== 'mfa-challenge' ||
    typeof verified.authVersion !== 'number' ||
    typeof verified.persistent !== 'boolean'
  ) {
    throw new HttpError(401, 'Your sign-in challenge is invalid. Please sign in again.')
  }
  return {
    ...verified,
    sub: verified.sub,
    jti: verified.jti,
    authVersion: verified.authVersion,
    persistent: verified.persistent,
  }
}

function hashEmailMfaCode(secret: string, challengeId: string, code: string): string {
  return createHmac('sha256', secret)
    .update(`securevault-email-mfa:${challengeId}:${code}`)
    .digest('hex')
}

function emailMfaCodeMatches(
  secret: string,
  challengeId: string,
  code: string,
  storedHash: string,
): boolean {
  if (!/^[a-f0-9]{64}$/i.test(storedHash)) return false
  const expected = Buffer.from(hashEmailMfaCode(secret, challengeId, code), 'hex')
  const actual = Buffer.from(storedHash, 'hex')
  return timingSafeEqual(expected, actual)
}

function getEmailMfaSmtpConfig(environment: EnvironmentConfig) {
  const { smtpHost, smtpPort, smtpUser, smtpPassword, smtpFrom } = environment
  if (!smtpHost || !smtpPort || !smtpUser || !smtpPassword || !smtpFrom) {
    throw new HttpError(503, 'Email verification is not configured. Please contact support.')
  }
  return { host: smtpHost, port: smtpPort, user: smtpUser, password: smtpPassword, from: smtpFrom }
}

export async function requestEmailMfaCode(
  dataSource: DataSource,
  environment: EnvironmentConfig,
  challengeToken: string,
): Promise<void> {
  const payload = verifyEmailMfaChallenge(environment, challengeToken)
  const smtp = getEmailMfaSmtpConfig(environment)
  const secret = environment.jwtAccessSecret
  if (!secret) {
    throw new HttpError(503, 'Authentication is not configured yet.')
  }
  const now = new Date()
  const code = randomInt(0, 1_000_000).toString().padStart(6, '0')

  const email = await dataSource.transaction(async (manager) => {
    const user = await manager.getRepository(User).findOne({
      where: { id: payload.sub },
      lock: { mode: 'pessimistic_write' },
    })
    if (
      !user ||
      user.authVersion !== payload.authVersion ||
      (user.loginLockedUntil !== null && user.loginLockedUntil > now)
    ) {
      throw new HttpError(401, 'Your sign-in challenge is invalid. Please sign in again.')
    }

    const challenges = manager.getRepository(EmailMfaChallenge)
    const existing = await challenges.findOne({
      where: { challengeId: payload.jti, userId: user.id },
      lock: { mode: 'pessimistic_write' },
    })
    if (existing) {
      if (existing.consumedAt || existing.expiresAt <= now || existing.attempts >= maximumEmailMfaAttempts) {
        throw new HttpError(401, 'Your sign-in challenge is invalid. Please sign in again.')
      }
      if (now.getTime() - existing.sentAt.getTime() < emailMfaResendDelayMs) {
        throw new HttpError(429, 'Please wait before requesting another email code.')
      }
      if (existing.sendCount >= maximumEmailMfaSends) {
        throw new HttpError(429, 'No more email codes can be sent for this sign-in. Please sign in again.')
      }
      existing.codeHash = hashEmailMfaCode(secret, payload.jti, code)
      existing.expiresAt = new Date(now.getTime() + emailMfaCodeLifetimeMs)
      existing.sentAt = now
      existing.sendCount += 1
      await challenges.save(existing)
    } else {
      await challenges.save(challenges.create({
        challengeId: payload.jti,
        userId: user.id,
        codeHash: hashEmailMfaCode(secret, payload.jti, code),
        expiresAt: new Date(now.getTime() + emailMfaCodeLifetimeMs),
        sentAt: now,
        sendCount: 1,
        attempts: 0,
        consumedAt: null,
      }))
    }
    return user.email
  })

  const transport = nodemailer.createTransport({
    host: smtp.host,
    port: smtp.port,
    secure: smtp.port === 465,
    requireTLS: smtp.port !== 465,
    auth: { user: smtp.user, pass: smtp.password },
  })
  try {
    await transport.sendMail({
      from: smtp.from,
      to: email,
      subject: 'Your SecureVault sign-in code',
      text: `Your SecureVault sign-in code is ${code}. It expires in five minutes. If you did not request this code, you can ignore this message.`,
      html: `<p>Your SecureVault sign-in code is:</p><p><strong>${code}</strong></p><p>It expires in five minutes. If you did not request this code, you can ignore this message.</p>`,
    })
  } catch (error) {
    logger.error(
      {
        event: 'mfa_email.delivery_failed',
        errorType: error instanceof Error ? error.name : 'UnknownError',
      },
      'Email MFA code could not be delivered',
    )
    throw new HttpError(503, 'The verification email could not be sent. Please try again later.')
  } finally {
    transport.close()
  }
}

export async function completeEmailMfaLogin(
  dataSource: DataSource,
  environment: EnvironmentConfig,
  challengeToken: string,
  code: string,
) {
  if (!environment.jwtAccessSecret || !environment.jwtRefreshSecret) {
    throw new HttpError(503, 'Authentication is not configured yet.')
  }
  const secret = environment.jwtAccessSecret
  const payload = verifyEmailMfaChallenge(environment, challengeToken)
  const result = await dataSource.transaction(async (manager) => {
    const user = await manager.getRepository(User).findOne({
      where: { id: payload.sub },
      lock: { mode: 'pessimistic_write' },
    })
    const challenge = await manager.getRepository(EmailMfaChallenge).findOne({
      where: { challengeId: payload.jti, userId: payload.sub },
      lock: { mode: 'pessimistic_write' },
    })
    const now = new Date()
    if (
      !user ||
      user.authVersion !== payload.authVersion ||
      (user.loginLockedUntil !== null && user.loginLockedUntil > now) ||
      !challenge ||
      challenge.consumedAt ||
      challenge.expiresAt <= now ||
      challenge.attempts >= maximumEmailMfaAttempts
    ) {
      return { authenticated: false as const }
    }

    if (!emailMfaCodeMatches(secret, payload.jti, code, challenge.codeHash)) {
      challenge.attempts += 1
      user.failedLoginAttempts += 1
      if (user.failedLoginAttempts >= maximumFailedLogins) {
        user.loginLockedUntil = new Date(now.getTime() + loginLockoutMs)
      }
      await manager.getRepository(EmailMfaChallenge).save(challenge)
      await manager.getRepository(User).save(user)
      return { authenticated: false as const }
    }

    challenge.consumedAt = now
    user.failedLoginAttempts = 0
    user.loginLockedUntil = null
    await manager.getRepository(EmailMfaChallenge).save(challenge)
    await manager.getRepository(User).save(user)
    return { authenticated: true as const, user }
  })

  if (!result.authenticated) {
    throw new HttpError(401, 'The email verification code is invalid or expired. Please try again.')
  }
  return createSession(dataSource, environment, result.user, payload.persistent)
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
