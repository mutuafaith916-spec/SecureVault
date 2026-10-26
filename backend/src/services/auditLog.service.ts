import { randomUUID } from 'node:crypto'
import type { Request } from 'express'
import type { EntityManager } from 'typeorm'
import { MoreThan } from 'typeorm'
import type { EnvironmentConfig } from '../config/environment.js'
import { AuditAction, AuditLog } from '../entities/AuditLog.js'
import { calculateAuditHash, initialAuditHash } from '../utils/auditHash.js'
import { dispatchSecurityAlert } from './securityAlert.service.js'

const auditChainLockId = 8192441
const alertCooldownMs = 15 * 60 * 1000

export type AuditDetails = Record<string, string | number | boolean | null>

interface AuditRowForValidation extends AuditLog {
  previousHash: string
  entryHash: string
}

export async function writeAuditLog(
  manager: EntityManager,
  request: Pick<Request, 'ip' | 'get'>,
  action: AuditAction,
  userId: string | null,
  fileId: string | null = null,
  environment?: EnvironmentConfig,
  details: AuditDetails = {},
): Promise<void> {
  await manager.query('SELECT pg_advisory_xact_lock($1)', [auditChainLockId])
  const repository = manager.getRepository(AuditLog)
  const [previousEntry] = await repository.find({
    select: { entryHash: true, chainPosition: true },
    order: { chainPosition: 'DESC' },
    take: 1,
  })
  const previousHash = previousEntry?.entryHash ?? initialAuditHash
  const addressResult = await manager.query(
    'SELECT $1::inet::text AS ip_address',
    [request.ip ?? null],
  ) as Array<{ ip_address: string | null }>
  const record = repository.create({
    id: randomUUID(),
    userId,
    action,
    fileId,
    ipAddress: addressResult[0]?.ip_address ?? null,
    userAgent: request.get('user-agent')?.slice(0, 512) ?? null,
    details,
    previousHash,
    createdAt: new Date(),
  })
  record.entryHash = calculateAuditHash(previousHash, record)
  await repository.save(record)

  if (environment) {
    await detectAndDispatchAlert(manager, record, environment)
  }
}

async function detectAndDispatchAlert(
  manager: EntityManager,
  record: AuditLog,
  environment: EnvironmentConfig,
): Promise<void> {
  if (environment.securityAlertEmails.length === 0) {
    return
  }

  const since = new Date(Date.now() - 10 * 60 * 1000)
  let alertKey: string | undefined
  let subject: string | undefined
  let message: string | undefined

  if (record.action === AuditAction.PRIVILEGE_CHANGED) {
    alertKey = `privilege:${record.id}`
    subject = 'Administrator privilege change'
    message = 'A user account role was changed.'
  } else if (record.action === AuditAction.UNAUTHORIZED_ACCESS) {
    alertKey = `unauthorized:${record.ipAddress ?? record.id}`
    subject = 'Unauthorized access attempt'
    message = 'An unauthorized access event was recorded.'
  } else if (record.action === AuditAction.LOGIN_FAILED && record.ipAddress) {
    const failedAttempts = await manager.getRepository(AuditLog).count({
      where: {
        action: AuditAction.LOGIN_FAILED,
        ipAddress: record.ipAddress,
        createdAt: MoreThan(since),
      },
    })
    if (failedAttempts >= 5) {
      alertKey = `login-failures:${record.ipAddress}`
      subject = 'Repeated failed sign-ins'
      message = `At least ${failedAttempts} failed sign-in attempts were recorded from one IP address in 10 minutes.`
    }
  } else if (record.action === AuditAction.FILE_DOWNLOADED && record.userId) {
    const downloads = await manager.getRepository(AuditLog).count({
      where: {
        action: AuditAction.FILE_DOWNLOADED,
        userId: record.userId,
        createdAt: MoreThan(new Date(Date.now() - 5 * 60 * 1000)),
      },
    })
    if (downloads >= 10) {
      alertKey = `rapid-downloads:${record.userId}`
      subject = 'Unusual download activity'
      message = `At least ${downloads} files were downloaded by one account in 5 minutes.`
    }
  }

  if (!alertKey || !subject || !message) {
    return
  }

  const claim = await manager.query(
    `INSERT INTO "security_alert_suppressions" ("alert_key", "last_alert_at")
     VALUES ($1, now())
     ON CONFLICT ("alert_key") DO UPDATE
       SET "last_alert_at" = EXCLUDED."last_alert_at"
       WHERE "security_alert_suppressions"."last_alert_at" < now() - ($2 * interval '1 millisecond')
     RETURNING "alert_key"`,
    [alertKey, alertCooldownMs],
  ) as Array<{ alert_key: string }>

  if (claim.length > 0) {
    dispatchSecurityAlert(environment, subject, message, {
      eventId: record.id,
      userId: record.userId,
      ipAddress: record.ipAddress,
      fileId: record.fileId,
    })
  }
}

export async function verifyAuditLogIntegrity(
  manager: EntityManager,
): Promise<{ valid: boolean; entriesChecked: number; firstInvalidId: string | null }> {
  const repository = manager.getRepository(AuditLog)
  const pageSize = 500
  let offset = 0
  let previousHash = initialAuditHash
  let entriesChecked = 0

  while (true) {
    const page = await repository.find({
      select: {
        id: true,
        userId: true,
        action: true,
        fileId: true,
        ipAddress: true,
        userAgent: true,
        details: true,
        previousHash: true,
        entryHash: true,
        chainPosition: true,
        createdAt: true,
      },
      order: { chainPosition: 'ASC' },
      skip: offset,
      take: pageSize,
    }) as AuditRowForValidation[]

    if (page.length === 0) {
      return { valid: true, entriesChecked, firstInvalidId: null }
    }

    for (const record of page) {
      const expectedHash = calculateAuditHash(previousHash, record)
      if (record.previousHash !== previousHash || record.entryHash !== expectedHash) {
        return { valid: false, entriesChecked, firstInvalidId: record.id }
      }
      previousHash = record.entryHash
      entriesChecked += 1
    }
    offset += page.length
  }
}
