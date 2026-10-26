import type { RequestHandler } from 'express'
import type { DataSource } from 'typeorm'
import type { AuthenticatedRequest } from '../middleware/authMiddleware.js'
import type { EnvironmentConfig } from '../config/environment.js'
import { AuditAction } from '../entities/AuditLog.js'
import { User } from '../entities/User.js'
import {
  hashUserPassword,
  loginUser,
  completeMfaLogin,
  refreshUserSession,
  revokeRefreshToken,
} from '../services/auth.service.js'
import {
  clearSessionCookies,
  getRequestCookie,
  refreshCookieName,
  setSessionCookies,
} from '../utils/authCookies.js'
import {
  requestPasswordReset,
  resetUserPassword,
} from '../services/passwordReset.service.js'
import { writeAuditLog } from '../services/auditLog.service.js'
import { HttpError } from '../types/http.js'

function parseRegistrationBody(body: unknown): { fullName: string; email: string; password: string } {
  if (typeof body !== 'object' || body === null) {
    throw new HttpError(400, 'Please provide your name, email address, and password.')
  }

  const { fullName, email, password } = body as Record<string, unknown>
  if (typeof fullName !== 'string' || typeof email !== 'string' || typeof password !== 'string') {
    throw new HttpError(400, 'Please provide your name, email address, and password.')
  }

  const normalizedName = fullName.trim()
  const normalizedEmail = email.trim().toLowerCase()
  if (!normalizedName || normalizedName.length > 160) {
    throw new HttpError(400, 'Your name must be between 1 and 160 characters.')
  }
  if (
    normalizedEmail.length > 320 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)
  ) {
    throw new HttpError(400, 'Please enter a valid email address.')
  }
  if (password.length < 8 || password.length > 128) {
    throw new HttpError(400, 'Your password must be between 8 and 128 characters.')
  }

  return { fullName: normalizedName, email: normalizedEmail, password }
}

function isUniqueConstraintViolation(error: unknown): boolean {
  if (typeof error !== 'object' || error === null || !('driverError' in error)) {
    return false
  }
  const { driverError } = error
  return (
    typeof driverError === 'object' &&
    driverError !== null &&
    'code' in driverError &&
    driverError.code === '23505'
  )
}

export function createRegisterController(dataSource: DataSource): RequestHandler {
  return async (request, response) => {
    const { fullName, email, password } = parseRegistrationBody(request.body)
    try {
      const user = await dataSource.transaction(async (manager) => {
        const users = manager.getRepository(User)
        if (await users.existsBy({ email })) {
          throw new HttpError(409, 'An account with this email already exists. Try logging in instead.')
        }
        const savedUser = await users.save(users.create({
          fullName,
          email,
          passwordHash: await hashUserPassword(password),
        }))
        await writeAuditLog(manager, request, AuditAction.REGISTER, savedUser.id)
        return savedUser
      })

      response.status(201).json({
        success: true,
        message: 'Your SecureVault account has been created successfully.',
        user: {
          id: user.id,
          fullName: user.fullName,
          email: user.email,
        },
      })
    } catch (error) {
      if (isUniqueConstraintViolation(error)) {
        throw new HttpError(409, 'An account with this email already exists. Try logging in instead.')
      }
      throw error
    }
  }
}

export function createLoginController(
  dataSource: DataSource,
  environment: EnvironmentConfig,
): RequestHandler {
  return async (request, response) => {
    if (typeof request.body !== 'object' || request.body === null) {
      throw new HttpError(400, 'Please provide your email address and password.')
    }

    const { email, password, rememberMe, restartMfaSetup } = request.body as Record<string, unknown>
    if (
      typeof email !== 'string' ||
      email.length > 320 ||
      typeof password !== 'string' ||
      password.length > 128 ||
      !email.trim() ||
      !password ||
      (rememberMe !== undefined && typeof rememberMe !== 'boolean') ||
      (restartMfaSetup !== undefined && typeof restartMfaSetup !== 'boolean')
    ) {
      throw new HttpError(400, 'Please provide your email address and password.')
    }

    let result: Awaited<ReturnType<typeof loginUser>>
    try {
      result = await loginUser(
        dataSource,
        environment,
        email,
        password,
        rememberMe === true,
        restartMfaSetup === true,
      )
    } catch (error) {
      if (error instanceof HttpError && error.statusCode === 401) {
        await dataSource.transaction((manager) =>
          writeAuditLog(manager, request, AuditAction.LOGIN_FAILED, null, null, environment),
        )
      }
      throw error
    }
    response.status(200).json({
      success: true,
      message: result.mfaSetupRequired
        ? 'Set up an authenticator app to finish signing in.'
        : 'Enter your authenticator code to finish signing in.',
      mfaRequired: true,
      mfaSetupRequired: result.mfaSetupRequired,
      challengeToken: result.challengeToken,
      ...(result.provisioningUri
        ? {
            provisioningUri: result.provisioningUri,
            manualSecret: result.manualSecret,
          }
        : {}),
    })
  }
}

export function createMfaVerifyController(
  dataSource: DataSource,
  environment: EnvironmentConfig,
): RequestHandler {
  return async (request, response) => {
    const body = request.body as Record<string, unknown> | null
    if (
      !body ||
      typeof body.challengeToken !== 'string' ||
      body.challengeToken.length > 4096 ||
      typeof body.code !== 'string' ||
      !/^\d{6}$/.test(body.code)
    ) {
      throw new HttpError(400, 'Enter the six-digit code from your authenticator app.')
    }

    let result: Awaited<ReturnType<typeof completeMfaLogin>>
    try {
      result = await completeMfaLogin(dataSource, environment, body.challengeToken, body.code)
    } catch (error) {
      if (error instanceof HttpError && error.statusCode === 401) {
        await dataSource.transaction((manager) =>
          writeAuditLog(manager, request, AuditAction.LOGIN_FAILED, null, null, environment),
        )
      }
      throw error
    }
    await dataSource.transaction((manager) =>
      writeAuditLog(manager, request, AuditAction.LOGIN, result.user.id),
    )
    setSessionCookies(
      response,
      result.accessToken,
      result.refreshToken,
      environment.nodeEnv === 'production',
      result.persistent,
      result.refreshExpiresAt,
    )
    response.status(200).json({
      success: true,
      message: 'You have signed in successfully.',
      user: result.user,
    })
  }
}

export function createRefreshSessionController(
  dataSource: DataSource,
  environment: EnvironmentConfig,
): RequestHandler {
  return async (request, response) => {
    const refreshToken = getRequestCookie(request, refreshCookieName)
    if (!refreshToken) {
      throw new HttpError(401, 'Your session has expired. Please sign in again.')
    }
    const result = await refreshUserSession(dataSource, environment, refreshToken)
    setSessionCookies(
      response,
      result.accessToken,
      result.refreshToken,
      environment.nodeEnv === 'production',
      result.persistent,
      result.refreshExpiresAt,
    )
    response.status(200).json({ success: true, user: result.user })
  }
}

export function createLogoutController(dataSource: DataSource, environment: EnvironmentConfig): RequestHandler {
  return async (request, response) => {
    const refreshToken = getRequestCookie(request, refreshCookieName)
    const userId = await revokeRefreshToken(dataSource, refreshToken)
    if (userId) {
      await dataSource.transaction((manager) =>
        writeAuditLog(manager, request, AuditAction.LOGOUT, userId),
      )
    }
    clearSessionCookies(response, environment.nodeEnv === 'production')
    response.status(200).json({ success: true, message: 'You have signed out successfully.' })
  }
}

export function createCurrentSessionController(dataSource: DataSource): RequestHandler {
  return async (request, response) => {
    const userId = (request as AuthenticatedRequest).user?.id
    if (!userId) {
      throw new HttpError(401, 'Please log in to continue.')
    }
    const user = await dataSource.getRepository(User).findOne({
      where: { id: userId },
      select: { id: true, fullName: true, email: true, role: true },
    })
    if (!user) {
      throw new HttpError(401, 'Your session is invalid. Please sign in again.')
    }
    response.status(200).json({
      success: true,
      user: { id: user.id, fullName: user.fullName, email: user.email, role: user.role },
    })
  }
}

export function createForgotPasswordController(
  dataSource: DataSource,
  environment: EnvironmentConfig,
): RequestHandler {
  return async (request, response) => {
    const email = typeof request.body === 'object' && request.body !== null
      ? (request.body as Record<string, unknown>).email
      : undefined
    if (
      typeof email !== 'string' ||
      email.length > 320 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
    ) {
      throw new HttpError(400, 'Please enter a valid email address.')
    }

    await requestPasswordReset(dataSource, environment, email)
    response.status(202).json({
      success: true,
      message: 'If an account exists for that email, a password reset link will be sent shortly.',
    })
  }
}

export function createResetPasswordController(dataSource: DataSource): RequestHandler {
  return async (request, response) => {
    const body = request.body as Record<string, unknown> | null
    const token = body?.token
    const password = body?.password
    if (typeof token !== 'string' || typeof password !== 'string') {
      throw new HttpError(400, 'A valid reset link and new password are required.')
    }
    if (password.length < 8 || password.length > 128) {
      throw new HttpError(400, 'Your password must be between 8 and 128 characters.')
    }

    await resetUserPassword(dataSource, token, password, request)
    response.status(200).json({
      success: true,
      message: 'Your password has been reset. Please sign in with your new password.',
    })
  }
}
