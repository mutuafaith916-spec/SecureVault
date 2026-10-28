import { createHash, randomUUID } from 'node:crypto'
import type { EntityManager } from 'typeorm'
import type { EnvironmentConfig, SecurityDetectionConfig } from '../config/environment.js'
import { AuditAction, type AuditLog } from '../entities/AuditLog.js'
import type { SecurityAlertSeverity } from '../entities/SecurityAlert.js'

interface DetectionCandidate {
  ruleId: string
  severity: SecurityAlertSeverity
  dimension: string
  occurrenceCount: number
  evidence: Record<string, string | number | boolean | null>
}

interface CountResult {
  count: string | number
}

const defaults: SecurityDetectionConfig = {
  failedLoginThreshold: 5,
  mfaFailureThreshold: 6,
  unauthorizedAccessThreshold: 4,
  distinctFileAccessThreshold: 5,
  downloadThreshold: 10,
  shareChangeThreshold: 8,
  cooldownMinutes: 15,
}

function getDetectionConfig(environment: EnvironmentConfig): SecurityDetectionConfig {
  return environment.securityDetection ?? defaults
}

async function queryCount(
  manager: EntityManager,
  sql: string,
  parameters: unknown[],
): Promise<number> {
  const [row] = await manager.query(sql, parameters) as CountResult[]
  return Number(row?.count ?? 0)
}

async function findDetectionCandidate(
  manager: EntityManager,
  record: AuditLog,
  config: SecurityDetectionConfig,
): Promise<DetectionCandidate | null> {
  const eventTime = new Date(record.createdAt)
  if (record.action === AuditAction.PRIVILEGE_CHANGED) {
    return {
      ruleId: 'admin.privilege-change',
      severity: 'HIGH',
      dimension: record.id,
      occurrenceCount: 1,
      evidence: {
        targetUserId: record.details.targetUserId as string ?? null,
        previousRole: record.details.previousRole as string ?? null,
        newRole: record.details.newRole as string ?? null,
      },
    }
  }

  if (record.action === AuditAction.LOGIN_FAILED && record.ipAddress) {
    const authenticationFactor = record.details.authenticationFactor
    const isMfaFailure = authenticationFactor === 'MFA' || authenticationFactor === 'MFA_EMAIL'
    const threshold = isMfaFailure ? config.mfaFailureThreshold : config.failedLoginThreshold
    const windowMinutes = 10
    const count = await queryCount(
      manager,
      `SELECT COUNT(*) AS count FROM "audit_logs"
       WHERE "action" = $1 AND "ip_address" = $2 AND "created_at" >= $3
         AND ("details"->>'authenticationFactor' IS NOT DISTINCT FROM $4)`,
      [
        AuditAction.LOGIN_FAILED,
        record.ipAddress,
        new Date(eventTime.getTime() - windowMinutes * 60_000),
        isMfaFailure ? authenticationFactor : null,
      ],
    )
    if (count >= threshold) {
      return {
        ruleId: isMfaFailure ? 'auth.repeated-mfa-failures' : 'auth.repeated-login-failures',
        severity: isMfaFailure ? 'HIGH' : 'MEDIUM',
        dimension: record.ipAddress,
        occurrenceCount: count,
        evidence: { threshold, windowMinutes },
      }
    }
  }

  if (record.action === AuditAction.UNAUTHORIZED_ACCESS && record.ipAddress) {
    const windowMinutes = 5
    const windowStart = new Date(eventTime.getTime() - windowMinutes * 60_000)
    const count = await queryCount(
      manager,
      `SELECT COUNT(*) AS count FROM "audit_logs"
       WHERE "action" = $1 AND "ip_address" = $2 AND "created_at" >= $3`,
      [AuditAction.UNAUTHORIZED_ACCESS, record.ipAddress, windowStart],
    )
    const distinctResources = await queryCount(
      manager,
      `SELECT COUNT(DISTINCT "details"->>'attemptedFileId') AS count FROM "audit_logs"
       WHERE "action" = $1 AND "ip_address" = $2 AND "created_at" >= $3`,
      [AuditAction.UNAUTHORIZED_ACCESS, record.ipAddress, windowStart],
    )
    if (count >= config.unauthorizedAccessThreshold) {
      return {
        ruleId: 'files.repeated-unauthorized-access',
        severity: 'HIGH',
        dimension: record.ipAddress,
        occurrenceCount: count,
        evidence: {
          threshold: config.unauthorizedAccessThreshold,
          windowMinutes,
          distinctResourceCount: distinctResources,
        },
      }
    }
    if (distinctResources >= config.distinctFileAccessThreshold) {
      return {
        ruleId: 'files.multiple-resource-probing',
        severity: 'HIGH',
        dimension: record.ipAddress,
        occurrenceCount: count,
        evidence: {
          distinctResourceThreshold: config.distinctFileAccessThreshold,
          windowMinutes,
          distinctResourceCount: distinctResources,
        },
      }
    }
  }

  if (record.action === AuditAction.FILE_DOWNLOADED && record.userId) {
    const windowMinutes = 5
    const count = await queryCount(
      manager,
      `SELECT COUNT(*) AS count FROM "audit_logs"
       WHERE "action" = $1 AND "user_id" = $2 AND "created_at" >= $3`,
      [
        AuditAction.FILE_DOWNLOADED,
        record.userId,
        new Date(eventTime.getTime() - windowMinutes * 60_000),
      ],
    )
    if (count >= config.downloadThreshold) {
      return {
        ruleId: 'files.download-burst',
        severity: 'MEDIUM',
        dimension: record.userId,
        occurrenceCount: count,
        evidence: { threshold: config.downloadThreshold, windowMinutes },
      }
    }
  }

  if (
    (record.action === AuditAction.FILE_SHARED || record.action === AuditAction.SHARE_REVOKED) &&
    record.userId
  ) {
    const windowMinutes = 10
    const count = await queryCount(
      manager,
      `SELECT COUNT(*) AS count FROM "audit_logs"
       WHERE "action" IN ($1, $2) AND "user_id" = $3 AND "created_at" >= $4`,
      [
        AuditAction.FILE_SHARED,
        AuditAction.SHARE_REVOKED,
        record.userId,
        new Date(eventTime.getTime() - windowMinutes * 60_000),
      ],
    )
    if (count >= config.shareChangeThreshold) {
      return {
        ruleId: 'sharing.permission-change-burst',
        severity: 'MEDIUM',
        dimension: record.userId,
        occurrenceCount: count,
        evidence: { threshold: config.shareChangeThreshold, windowMinutes },
      }
    }
  }

  return null
}

export async function recordSuspiciousActivityAlert(
  manager: EntityManager,
  record: AuditLog,
  environment: EnvironmentConfig,
): Promise<void> {
  const config = getDetectionConfig(environment)
  const candidate = await findDetectionCandidate(manager, record, config)
  if (!candidate) return

  const cooldownMs = config.cooldownMinutes * 60_000
  const bucket = Math.floor(new Date(record.createdAt).getTime() / cooldownMs)
  const keyMaterial = `${candidate.ruleId}:${candidate.dimension}:${bucket}`
  const alertKey = createHash('sha256').update(keyMaterial).digest('hex')
  await manager.query(
    `INSERT INTO "security_alerts" (
       "id", "alert_key", "rule_id", "event_type", "severity", "status",
       "actor_id", "source_ip", "evidence", "occurrence_count", "last_seen_at",
       "created_at", "updated_at"
     ) VALUES ($1, $2, $3, $4, $5, 'OPEN', $6, $7, $8::jsonb, $9, $10, now(), now())
     ON CONFLICT ("alert_key") DO UPDATE SET
       "occurrence_count" = GREATEST("security_alerts"."occurrence_count", EXCLUDED."occurrence_count"),
       "last_seen_at" = EXCLUDED."last_seen_at",
       "evidence" = EXCLUDED."evidence",
       "updated_at" = now()
     WHERE "security_alerts"."status" != 'RESOLVED'`,
    [
      randomUUID(),
      alertKey,
      candidate.ruleId,
      record.action,
      candidate.severity,
      record.userId,
      record.ipAddress,
      JSON.stringify(candidate.evidence),
      candidate.occurrenceCount,
      record.createdAt,
    ],
  )
}
