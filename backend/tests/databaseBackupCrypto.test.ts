import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { test } from 'node:test'
import {
  createDatabaseBackupCipher,
  createDatabaseBackupDecipher,
  databaseBackupMagic,
  validateDatabaseBackupKey,
} from '../src/services/databaseBackupCrypto.js'

test('database backup ciphertext decrypts only with the dedicated backup key and valid tag', () => {
  const encodedKey = randomBytes(32).toString('base64')
  const key = validateDatabaseBackupKey(encodedKey)
  const plaintext = Buffer.from('PostgreSQL custom-format backup data')
  const { iv, cipher } = createDatabaseBackupCipher(key)
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const header = Buffer.concat([databaseBackupMagic, iv])
  const authTag = cipher.getAuthTag()
  const decipher = createDatabaseBackupDecipher(key, header, authTag)

  assert.deepEqual(Buffer.concat([decipher.update(ciphertext), decipher.final()]), plaintext)

  const tamperedTag = Buffer.from(authTag)
  tamperedTag[0] ^= 1
  const tamperedDecipher = createDatabaseBackupDecipher(key, header, tamperedTag)
  assert.throws(() => {
    tamperedDecipher.update(ciphertext)
    tamperedDecipher.final()
  })
})

test('database backup encryption key must be a canonical base64-encoded 32-byte key', () => {
  assert.throws(() => validateDatabaseBackupKey(undefined), /must be configured/)
  assert.throws(() => validateDatabaseBackupKey(randomBytes(16).toString('base64')), /32-byte key/)
})
