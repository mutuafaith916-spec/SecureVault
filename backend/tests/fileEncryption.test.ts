import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { test } from 'node:test'
import type { EnvironmentConfig } from '../src/config/environment.js'
import { decryptFile, encryptFile } from '../src/services/fileEncryptionService.js'
import { HttpError } from '../src/types/http.js'

const environment: EnvironmentConfig = {
  nodeEnv: 'test',
  port: 3000,
  corsOrigin: 'http://localhost:5173',
  databaseUrl: 'postgresql://test:test@localhost:5432/securevault_test',
  encryptionMasterKey: randomBytes(32).toString('base64'),
  securityAlertEmails: [],
}

test('files encrypt to authenticated ciphertext and decrypt to the original content', () => {
  const original = Buffer.from('SecureVault file encryption validation')
  const encrypted = encryptFile(original, environment)

  assert.notDeepEqual(encrypted.encryptedData, original)
  assert.deepEqual(
    decryptFile(encrypted.encryptedData, encrypted.iv, encrypted.authTag, environment),
    original,
  )
})

test('tampered file ciphertext fails authenticated decryption', () => {
  const encrypted = encryptFile(Buffer.from('private file content'), environment)
  encrypted.encryptedData[0] ^= 1

  assert.throws(
    () => decryptFile(encrypted.encryptedData, encrypted.iv, encrypted.authTag, environment),
    (error) => error instanceof HttpError && error.statusCode === 400,
  )
})

test('tampered authentication tags and encryption metadata are rejected', () => {
  const encrypted = encryptFile(Buffer.from('private file content'), environment)
  const changedTag = Buffer.from(encrypted.authTag, 'base64')
  changedTag[0] ^= 1

  assert.throws(
    () => decryptFile(encrypted.encryptedData, encrypted.iv, changedTag.toString('base64'), environment),
    (error) => error instanceof HttpError && error.statusCode === 400,
  )
  assert.throws(
    () => decryptFile(encrypted.encryptedData, 'invalid-iv', encrypted.authTag, environment),
    (error) => error instanceof HttpError && error.statusCode === 400,
  )
})

test('file encryption rejects a missing or invalid AES-256 master key', () => {
  const withoutKey = { ...environment, encryptionMasterKey: undefined }
  const invalidKey = { ...environment, encryptionMasterKey: Buffer.alloc(16).toString('base64') }

  assert.throws(
    () => encryptFile(Buffer.from('file'), withoutKey),
    (error) => error instanceof HttpError && error.statusCode === 503,
  )
  assert.throws(
    () => encryptFile(Buffer.from('file'), invalidKey),
    (error) => error instanceof HttpError && error.statusCode === 503,
  )
})
