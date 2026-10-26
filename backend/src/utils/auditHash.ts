import { createHash } from 'node:crypto'

export const initialAuditHash = '0'.repeat(64)

export interface AuditHashFields {
  id: string
  userId: string | null
  action: string
  fileId: string | null
  ipAddress: string | null
  userAgent: string | null
  createdAt: Date
  details: Record<string, string | number | boolean | null>
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(stableValue)
  }
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([first], [second]) => first.localeCompare(second))
        .map(([key, item]) => [key, stableValue(item)]),
    )
  }
  return value
}

export function calculateAuditHash(previousHash: string, fields: AuditHashFields): string {
  const canonicalEntry = JSON.stringify([
    fields.id,
    fields.userId,
    fields.action,
    fields.fileId,
    fields.ipAddress,
    fields.userAgent,
    fields.createdAt.toISOString(),
    stableValue(fields.details),
  ])
  return createHash('sha256').update(previousHash).update(canonicalEntry).digest('hex')
}
