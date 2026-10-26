import assert from 'node:assert/strict'
import { test } from 'node:test'
import { calculateAuditHash, initialAuditHash } from '../src/utils/auditHash.js'

const auditEntry = {
  id: 'test-entry',
  userId: 'user-1',
  action: 'LOGIN',
  fileId: null,
  ipAddress: '127.0.0.1',
  userAgent: 'SecureVault test',
  createdAt: new Date('2026-10-20T10:00:00.000Z'),
  details: { role: 'USER', nested: { second: 2, first: 1 } },
}

test('audit hashes are deterministic and normalize object key order', () => {
  const expected = calculateAuditHash(initialAuditHash, auditEntry)
  assert.equal(
    calculateAuditHash(initialAuditHash, {
      ...auditEntry,
      details: { nested: { first: 1, second: 2 }, role: 'USER' },
    }),
    expected,
  )
})

test('audit hashes bind the previous entry and all event fields', () => {
  const initial = calculateAuditHash(initialAuditHash, auditEntry)
  assert.notEqual(calculateAuditHash('f'.repeat(64), auditEntry), initial)
  assert.notEqual(
    calculateAuditHash(initialAuditHash, { ...auditEntry, action: 'LOGIN_FAILED' }),
    initial,
  )
})
