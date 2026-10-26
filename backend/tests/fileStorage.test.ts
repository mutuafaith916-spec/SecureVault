import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { test } from 'node:test'
import type { EnvironmentConfig } from '../src/config/environment.js'
import { decryptFile, encryptFile } from '../src/services/fileEncryptionService.js'
import {
  deleteEncryptedBackup,
  deleteEncryptedFile,
  readEncryptedBackup,
  readEncryptedFile,
  restoreEncryptedFile,
  saveEncryptedBackup,
  saveEncryptedFile,
} from '../src/services/fileStorageService.js'

const environment: EnvironmentConfig = {
  nodeEnv: 'test',
  port: 3000,
  corsOrigin: 'http://localhost:5173',
  databaseUrl: 'postgresql://localhost:5432/securevault_test',
  storageProvider: 'local',
  encryptionMasterKey: randomBytes(32).toString('base64'),
  securityAlertEmails: [],
}

test('encrypted local backups can restore the original ciphertext and plaintext', async () => {
  const original = Buffer.from('Encrypted backup recovery test')
  const encrypted = encryptFile(original, environment)
  const storedFile = await saveEncryptedFile(encrypted.encryptedData, environment)
  const backupPath = await saveEncryptedBackup(encrypted.encryptedData, environment)

  try {
    const backupData = await readEncryptedBackup(backupPath, environment)
    assert.deepEqual(backupData, encrypted.encryptedData)
    assert.deepEqual(
      decryptFile(backupData, encrypted.iv, encrypted.authTag, environment),
      original,
    )

    await restoreEncryptedFile(storedFile.storedName, Buffer.from('corrupt'), environment)
    await restoreEncryptedFile(storedFile.storedName, backupData, environment)
    assert.deepEqual(await readEncryptedFile(storedFile.storedName, environment), encrypted.encryptedData)
  } finally {
    await Promise.all([
      deleteEncryptedFile(storedFile.storedName, environment),
      deleteEncryptedBackup(backupPath, environment),
    ])
  }
})
