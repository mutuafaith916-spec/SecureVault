import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  type CipherGCM,
  type DecipherGCM,
} from 'node:crypto'

export const databaseBackupMagic = Buffer.from('SVDBAK01')
export const databaseBackupHeaderLength = databaseBackupMagic.length + 12
export const databaseBackupAuthTagLength = 16

export function validateDatabaseBackupKey(encodedKey: string | undefined): Buffer {
  if (!encodedKey) {
    throw new Error('DATABASE_BACKUP_ENCRYPTION_KEY must be configured.')
  }
  const key = Buffer.from(encodedKey, 'base64')
  if (key.length !== 32 || key.toString('base64') !== encodedKey) {
    throw new Error('DATABASE_BACKUP_ENCRYPTION_KEY must be a base64-encoded 32-byte key.')
  }
  return key
}

export function createDatabaseBackupCipher(key: Buffer): {
  iv: Buffer
  cipher: CipherGCM
} {
  const iv = randomBytes(12)
  return {
    iv,
    cipher: createCipheriv('aes-256-gcm', key, iv),
  }
}

export function createDatabaseBackupDecipher(
  key: Buffer,
  header: Buffer,
  authTag: Buffer,
): DecipherGCM {
  if (
    header.length !== databaseBackupHeaderLength ||
    !header.subarray(0, databaseBackupMagic.length).equals(databaseBackupMagic) ||
    authTag.length !== databaseBackupAuthTagLength
  ) {
    throw new Error('The encrypted database backup header or authentication tag is invalid.')
  }
  const decipher = createDecipheriv(
    'aes-256-gcm',
    key,
    header.subarray(databaseBackupMagic.length),
  )
  decipher.setAuthTag(authTag)
  return decipher
}
