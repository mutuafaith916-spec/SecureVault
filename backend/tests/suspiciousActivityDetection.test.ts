import assert from 'node:assert/strict'
import { test } from 'node:test'
import type { EntityManager } from 'typeorm'
import type { EnvironmentConfig } from '../src/config/environment.js'
import { AuditAction, type AuditLog } from '../src/entities/AuditLog.js'
import { recordSuspiciousActivityAlert } from '../src/services/suspiciousActivityDetection.js'

const environment: EnvironmentConfig = {
  nodeEnv: 'test',
  port: 3000,
  corsOrigin: 'http://localhost:5173',
  databaseUrl: '',
  securityAlertEmails: [],
  securityDetection: {
    failedLoginThreshold: 5,
    mfaFailureThreshold: 6,
    unauthorizedAccessThreshold: 4,
    distinctFileAccessThreshold: 5,
    downloadThreshold: 10,
    shareChangeThreshold: 8,
    cooldownMinutes: 15,
  },
}

function failedLoginRecord(
  details: AuditLog['details'],
  createdAt = new Date('2026-01-01T00:00:00.000Z'),
): AuditLog {
  return {
    id: 'event-id',
    action: AuditAction.LOGIN_FAILED,
    userId: null,
    fileId: null,
    ipAddress: '203.0.113.10',
    details,
    createdAt,
  } as AuditLog
}

function detectionManager(count: number) {
  const queries: Array<{ sql: string; parameters: unknown[] }> = []
  const manager = {
    async query(sql: string, parameters: unknown[]) {
      queries.push({ sql, parameters })
      if (sql.includes('SELECT COUNT(*)')) return [{ count }]
      return []
    },
  } as unknown as EntityManager
  return { manager, queries }
}

test('repeated password failures create a deduplicated alert with threshold evidence', async () => {
  const { manager, queries } = detectionManager(5)
  const record = failedLoginRecord({})

  await recordSuspiciousActivityAlert(manager, record, environment)
  await recordSuspiciousActivityAlert(manager, record, environment)

  assert.equal(queries.length, 4)
  assert.equal(queries[0].parameters[3], null)
  assert.equal(queries[1].parameters[2], 'auth.repeated-login-failures')
  assert.equal(queries[1].parameters[1], queries[3].parameters[1])
  assert.equal(queries[1].parameters[8], 5)
  assert.equal(queries[1].parameters[7], JSON.stringify({ threshold: 5, windowMinutes: 10 }))
})

test('MFA failures use their own threshold and alert rule', async () => {
  const { manager, queries } = detectionManager(6)
  await recordSuspiciousActivityAlert(
    manager,
    failedLoginRecord({ authenticationFactor: 'MFA' }),
    environment,
  )

  assert.equal(queries[0].parameters[3], 'MFA')
  assert.equal(queries[1].parameters[2], 'auth.repeated-mfa-failures')
  assert.equal(queries[1].parameters[7], JSON.stringify({ threshold: 6, windowMinutes: 10 }))
})

test('email MFA failures use the second-factor failure threshold', async () => {
  const { manager, queries } = detectionManager(6)
  await recordSuspiciousActivityAlert(
    manager,
    failedLoginRecord({ authenticationFactor: 'MFA_EMAIL' }),
    environment,
  )

  assert.equal(queries[0].parameters[3], 'MFA_EMAIL')
  assert.equal(queries[1].parameters[2], 'auth.repeated-mfa-failures')
})

test('events below configured thresholds do not create alerts', async () => {
  const { manager, queries } = detectionManager(4)
  await recordSuspiciousActivityAlert(manager, failedLoginRecord({}), environment)

  assert.equal(queries.length, 1)
  assert.match(queries[0].sql, /SELECT COUNT\(\*\)/)
})
