import assert from 'node:assert/strict'
import { test } from 'node:test'
import { AuditLog } from '../src/entities/AuditLog.js'
import { Backup } from '../src/entities/Backup.js'
import { FileEntity } from '../src/entities/File.js'
import { FileShare } from '../src/entities/FileShare.js'
import { PasswordResetToken } from '../src/entities/PasswordResetToken.js'
import { RefreshToken } from '../src/entities/RefreshToken.js'
import { SecurityAlert } from '../src/entities/SecurityAlert.js'
import { User } from '../src/entities/User.js'

test('all TypeORM entities load despite their bidirectional relations', () => {
  assert.deepEqual(
    [AuditLog, Backup, FileEntity, FileShare, PasswordResetToken, RefreshToken, SecurityAlert, User]
      .map((entity) => entity.name)
      .sort(),
    [
      'AuditLog',
      'Backup',
      'FileEntity',
      'FileShare',
      'PasswordResetToken',
      'RefreshToken',
      'SecurityAlert',
      'User',
    ].sort(),
  )
})
