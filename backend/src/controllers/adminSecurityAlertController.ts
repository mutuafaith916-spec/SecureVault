import type { RequestHandler } from 'express'
import type { DataSource } from 'typeorm'
import type { EnvironmentConfig } from '../config/environment.js'
import { AuditAction } from '../entities/AuditLog.js'
import { SecurityAlert } from '../entities/SecurityAlert.js'
import { requireAdminId } from '../middleware/adminAuthorization.js'
import { writeAuditLog } from '../services/auditLog.service.js'
import { HttpError } from '../types/http.js'

const maximumPageSize = 100
const maximumPage = 10_000

function parsePageValue(value: unknown, defaultValue: number, maximum: number): number {
  if (value === undefined) return defaultValue
  if (typeof value !== 'string' || !/^\d+$/.test(value)) {
    throw new HttpError(400, 'Pagination values must be positive integers.')
  }
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw new HttpError(400, 'Pagination value is outside the supported range.')
  }
  return parsed
}

export function createAdminSecurityAlertsController(dataSource: DataSource): RequestHandler {
  return async (request, response) => {
    requireAdminId(request)
    const page = parsePageValue(request.query.page, 1, maximumPage)
    const pageSize = parsePageValue(request.query.pageSize, 25, maximumPageSize)
    const severity = request.query.severity
    const status = request.query.status
    if (
      severity !== undefined &&
      severity !== 'LOW' &&
      severity !== 'MEDIUM' &&
      severity !== 'HIGH' &&
      severity !== 'CRITICAL'
    ) {
      throw new HttpError(400, 'Severity must be LOW, MEDIUM, HIGH, or CRITICAL.')
    }
    if (
      status !== undefined &&
      status !== 'OPEN' &&
      status !== 'REVIEWED' &&
      status !== 'RESOLVED'
    ) {
      throw new HttpError(400, 'Status must be OPEN, REVIEWED, or RESOLVED.')
    }

    const query = dataSource.getRepository(SecurityAlert).createQueryBuilder('alert')
      .leftJoinAndSelect('alert.actor', 'actor')
      .leftJoinAndSelect('alert.reviewer', 'reviewer')
    if (severity) query.andWhere('alert.severity = :severity', { severity })
    if (status) query.andWhere('alert.status = :status', { status })
    const [alerts, total] = await query
      .select([
        'alert.id',
        'alert.ruleId',
        'alert.eventType',
        'alert.severity',
        'alert.status',
        'alert.sourceIp',
        'alert.evidence',
        'alert.occurrenceCount',
        'alert.lastSeenAt',
        'alert.reviewedAt',
        'alert.resolvedAt',
        'alert.createdAt',
        'actor.id',
        'actor.fullName',
        'actor.email',
        'reviewer.id',
        'reviewer.fullName',
        'reviewer.email',
      ])
      .orderBy('alert.lastSeenAt', 'DESC')
      .skip((page - 1) * pageSize)
      .take(pageSize)
      .getManyAndCount()

    response.status(200).json({
      success: true,
      alerts: alerts.map((alert) => ({
        id: alert.id,
        ruleId: alert.ruleId,
        eventType: alert.eventType,
        severity: alert.severity,
        status: alert.status,
        sourceIp: alert.sourceIp,
        evidence: alert.evidence,
        occurrenceCount: alert.occurrenceCount,
        lastSeenAt: alert.lastSeenAt,
        reviewedAt: alert.reviewedAt,
        reviewedBy: alert.reviewer
          ? { fullName: alert.reviewer.fullName, email: alert.reviewer.email }
          : null,
        resolvedAt: alert.resolvedAt,
        createdAt: alert.createdAt,
        actor: alert.actor
          ? { fullName: alert.actor.fullName, email: alert.actor.email }
          : null,
      })),
      pagination: { page, pageSize, total },
    })
  }
}

export function createAdminSecurityAlertStatusController(
  dataSource: DataSource,
  environment: EnvironmentConfig,
): RequestHandler {
  return async (request, response) => {
    const adminId = requireAdminId(request)
    const alertId = request.params.alertId
    const status = typeof request.body === 'object' && request.body !== null
      ? (request.body as Record<string, unknown>).status
      : undefined
    if (
      typeof alertId !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(alertId) ||
      (status !== 'REVIEWED' && status !== 'RESOLVED')
    ) {
      throw new HttpError(400, 'Provide a valid alert identifier and status.')
    }

    const updated = await dataSource.transaction(async (manager) => {
      const alert = await manager.getRepository(SecurityAlert).findOne({
        where: { id: alertId },
        lock: { mode: 'pessimistic_write' },
      })
      if (!alert) throw new HttpError(404, 'The security alert could not be found.')
      if (alert.status === 'RESOLVED') {
        if (status === 'RESOLVED') return alert
        throw new HttpError(409, 'A resolved alert cannot be reopened.')
      }
      if (alert.status === status) return alert

      const now = new Date()
      alert.status = status
      alert.reviewedAt ??= now
      alert.reviewedBy ??= adminId
      if (status === 'RESOLVED') alert.resolvedAt = now
      const savedAlert = await manager.getRepository(SecurityAlert).save(alert)
      await writeAuditLog(
        manager,
        request,
        status === 'RESOLVED'
          ? AuditAction.SECURITY_ALERT_RESOLVED
          : AuditAction.SECURITY_ALERT_REVIEWED,
        adminId,
        null,
        environment,
        { alertId, ruleId: alert.ruleId, severity: alert.severity },
      )
      return savedAlert
    })

    response.status(200).json({
      success: true,
      message: status === 'RESOLVED' ? 'The alert was resolved.' : 'The alert was marked as reviewed.',
      alert: { id: updated.id, status: updated.status },
    })
  }
}
