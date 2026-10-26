import { createHash, randomBytes } from 'node:crypto'
import type { Request } from 'express'
import nodemailer from 'nodemailer'
import type { DataSource } from 'typeorm'
import { IsNull, MoreThan } from 'typeorm'
import type { EnvironmentConfig } from '../config/environment.js'
import { PasswordResetToken } from '../entities/PasswordResetToken.js'
import { AuditAction } from '../entities/AuditLog.js'
import { RefreshToken } from '../entities/RefreshToken.js'
import { User } from '../entities/User.js'
import { HttpError } from '../types/http.js'
import { logger } from '../utils/logger.js'
import { writeAuditLog } from './auditLog.service.js'
import { hashUserPassword } from './auth.service.js'

const resetTokenLifetimeMs = 60 * 60 * 1000

function getSmtpConfig(environment: EnvironmentConfig) {
  const { smtpHost, smtpPort, smtpUser, smtpPassword, smtpFrom } = environment
  if (!smtpHost || !smtpPort || !smtpUser || !smtpPassword || !smtpFrom) {
    throw new HttpError(503, 'Password reset email is not configured. Please contact support.')
  }
  return { host: smtpHost, port: smtpPort, user: smtpUser, password: smtpPassword, from: smtpFrom }
}

function hashResetToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}

export async function requestPasswordReset(
  dataSource: DataSource,
  environment: EnvironmentConfig,
  email: string,
): Promise<void> {
  const smtp = getSmtpConfig(environment)
  const normalizedEmail = email.trim().toLowerCase()
  const user = await dataSource.getRepository(User).findOneBy({ email: normalizedEmail })

  if (!user) {
    return
  }

  const token = randomBytes(32).toString('hex')
  const tokenHash = hashResetToken(token)
  const expiresAt = new Date(Date.now() + resetTokenLifetimeMs)
  const resetTokens = dataSource.getRepository(PasswordResetToken)

  await resetTokens.update(
    { userId: user.id, usedAt: IsNull() },
    { usedAt: new Date() },
  )
  await resetTokens.save(resetTokens.create({
    userId: user.id,
    tokenHash,
    expiresAt,
    usedAt: null,
  }))

  const resetUrl = new URL('/reset-password', environment.corsOrigin)
  resetUrl.searchParams.set('token', token)
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
      to: user.email,
      subject: 'Reset your SecureVault password',
      text: `Use this link within one hour to reset your SecureVault password:\n\n${resetUrl.toString()}\n\nIf you did not request a password reset, you can ignore this message.`,
      html: `<p>Use this link within one hour to reset your SecureVault password:</p><p><a href="${resetUrl.toString()}">Reset password</a></p><p>If you did not request a password reset, you can ignore this message.</p>`,
    })
  } catch (error) {
    await resetTokens.update({ tokenHash }, { usedAt: new Date() })
    logger.error(
      {
        event: 'password_reset.email_delivery_failed',
        errorType: error instanceof Error ? error.name : 'UnknownError',
      },
      'Password reset email could not be delivered',
    )
    throw new HttpError(503, 'The password reset email could not be sent. Please try again later.')
  } finally {
    transport.close()
  }
}

export async function resetUserPassword(
  dataSource: DataSource,
  token: string,
  password: string,
  request: Request,
): Promise<void> {
  if (!/^[a-f0-9]{64}$/i.test(token)) {
    throw new HttpError(400, 'This password reset link is invalid or expired.')
  }

  const tokenHash = hashResetToken(token)
  const now = new Date()
  const passwordHash = await hashUserPassword(password)

  await dataSource.transaction(async (manager) => {
    const resetTokens = manager.getRepository(PasswordResetToken)
    const resetToken = await resetTokens.findOne({
      where: {
        tokenHash,
        usedAt: IsNull(),
        expiresAt: MoreThan(now),
      },
      lock: { mode: 'pessimistic_write' },
    })
    if (!resetToken) {
      throw new HttpError(400, 'This password reset link is invalid or expired.')
    }

    await manager.getRepository(User).update(
      { id: resetToken.userId },
      {
        passwordHash,
        authVersion: () => '"auth_version" + 1',
        failedLoginAttempts: 0,
        loginLockedUntil: null,
      },
    )
    await resetTokens.update({ id: resetToken.id, usedAt: IsNull() }, { usedAt: now })
    await manager.getRepository(RefreshToken).update(
      { userId: resetToken.userId, revokedAt: IsNull() },
      { revokedAt: now },
    )
    await writeAuditLog(manager, request, AuditAction.PASSWORD_RESET, resetToken.userId)
  })
}
