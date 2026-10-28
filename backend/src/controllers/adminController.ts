import type { RequestHandler } from 'express'
import type { DataSource } from 'typeorm'
import { IsNull } from 'typeorm'
import type { EnvironmentConfig } from '../config/environment.js'
import { AuditAction } from '../entities/AuditLog.js'
import { RefreshToken } from '../entities/RefreshToken.js'
import { User, UserRole } from '../entities/User.js'
import { requireAdminId } from '../middleware/adminAuthorization.js'
import { writeAuditLog, verifyAuditLogIntegrity } from '../services/auditLog.service.js'
import { dispatchSecurityAlert } from '../services/securityAlert.service.js'
import { HttpError } from '../types/http.js'
import { logger } from '../utils/logger.js'

const roleChangeLockId = 8192442

export function createAuditIntegrityController(
  dataSource: DataSource,
  environment: EnvironmentConfig,
): RequestHandler {
  return async (request, response) => {
    requireAdminId(request)
    const result = await verifyAuditLogIntegrity(dataSource.manager)
    if (!result.valid) {
      logger.error(
        {
          event: 'security.audit_integrity_failure',
          entriesChecked: result.entriesChecked,
          firstInvalidId: result.firstInvalidId,
        },
        'Audit log hash chain verification failed',
      )
      if (environment.securityAlertEmails.length > 0) {
        const alertClaim = await dataSource.query(
          `INSERT INTO "security_alert_suppressions" ("alert_key", "last_alert_at")
           VALUES ('audit-integrity:chain', now())
           ON CONFLICT ("alert_key") DO UPDATE
             SET "last_alert_at" = EXCLUDED."last_alert_at"
             WHERE "security_alert_suppressions"."last_alert_at" < now() - interval '15 minutes'
           RETURNING "alert_key"`,
        ) as Array<{ alert_key: string }>
        if (alertClaim.length > 0) {
          dispatchSecurityAlert(
            environment,
            'Audit log integrity failure',
            'The audit log hash chain failed integrity verification.',
            {
              entriesChecked: result.entriesChecked,
              firstInvalidId: result.firstInvalidId,
            },
          )
        }
      }
    }
    response.status(200).json({ success: true, integrity: result })
  }
}

export function createChangeUserRoleController(
  dataSource: DataSource,
  environment: EnvironmentConfig,
): RequestHandler {
  return async (request, response) => {
    const adminId = requireAdminId(request)
    const targetId = request.params.userId
    const role = typeof request.body === 'object' && request.body !== null
      ? (request.body as Record<string, unknown>).role
      : undefined
    if (
      typeof targetId !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(targetId) ||
      (role !== UserRole.USER && role !== UserRole.ADMIN)
    ) {
      throw new HttpError(400, 'Provide a valid account identifier and role.')
    }
    if (targetId === adminId) {
      throw new HttpError(400, 'Administrators cannot change their own role.')
    }

    const result = await dataSource.transaction(async (manager) => {
      await manager.query('SELECT pg_advisory_xact_lock($1)', [roleChangeLockId])
      const users = manager.getRepository(User)
      const target = await users.findOne({
        where: { id: targetId },
        lock: { mode: 'pessimistic_write' },
      })
      if (!target) {
        throw new HttpError(404, 'The account could not be found.')
      }
      if (target.role === role) {
        return { changed: false, previousRole: target.role, role: target.role }
      }
      if (target.role === UserRole.ADMIN && role === UserRole.USER) {
        const administratorCount = await users.countBy({ role: UserRole.ADMIN })
        if (administratorCount <= 1) {
          throw new HttpError(409, 'The last administrator cannot be demoted.')
        }
      }

      const previousRole = target.role
      await users.createQueryBuilder()
        .update(User)
        .set({ role, authVersion: () => '"auth_version" + 1' })
        .where('"id" = :targetId', { targetId })
        .execute()
      await manager.getRepository(RefreshToken).update(
        { userId: targetId, revokedAt: IsNull() },
        { revokedAt: new Date() },
      )
      await writeAuditLog(
        manager,
        request,
        AuditAction.PRIVILEGE_CHANGED,
        adminId,
        null,
        environment,
        { targetUserId: targetId, previousRole, newRole: role },
      )
      return { changed: true, previousRole, role }
    })

    response.status(200).json({
      success: true,
      message: result.changed ? 'The account role was updated.' : 'The account already has that role.',
      userId: targetId,
      previousRole: result.previousRole,
      role: result.role,
    })
  }
}
