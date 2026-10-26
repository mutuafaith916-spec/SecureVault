
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from 'node:crypto'
import type { EnvironmentConfig } from '../config/environment.js'
import { HttpError } from '../types/http.js'

const algorithm = 'aes-256-gcm'
const ivLength = 12
const authTagLength = 16
const keyLength = 32

function getEncryptionKey(environment: EnvironmentConfig): Buffer {
  const configuredKey = environment.encryptionMasterKey

  if (!configuredKey) {
    throw new HttpError(503, 'File encryption is not configured yet.')
  }

  const key = Buffer.from(configuredKey, 'base64')

  if (key.length !== keyLength) {
    throw new HttpError(503, 'The file encryption key is invalid.')
  }

  return key
}

export interface EncryptedFile {
  encryptedData: Buffer
  iv: string
  authTag: string
}

export function encryptFile(
  data: Buffer,
  environment: EnvironmentConfig,
): EncryptedFile {
  if (!Buffer.isBuffer(data)) {
    throw new HttpError(400, 'Invalid file data.')
  }

  const key = getEncryptionKey(environment)
  const iv = randomBytes(ivLength)
  const cipher = createCipheriv(algorithm, key, iv)

  const encryptedData = Buffer.concat([
    cipher.update(data),
    cipher.final(),
  ])

  return {
    encryptedData,
    iv: iv.toString('base64'),
    authTag: cipher.getAuthTag().toString('base64'),
  }
}

export function decryptFile(
  encryptedData: Buffer,
  ivBase64: string,
  authTagBase64: string,
  environment: EnvironmentConfig,
): Buffer {
  if (!Buffer.isBuffer(encryptedData)) {
    throw new HttpError(400, 'Invalid encrypted file data.')
  }

  const key = getEncryptionKey(environment)
  const iv = Buffer.from(ivBase64, 'base64')
  const authTag = Buffer.from(authTagBase64, 'base64')

  if (
    iv.length !== ivLength ||
    authTag.length !== authTagLength ||
    iv.toString('base64') !== ivBase64 ||
    authTag.toString('base64') !== authTagBase64
  ) {
    throw new HttpError(400, 'Invalid encryption metadata.')
  }

  try {
    const decipher = createDecipheriv(algorithm, key, iv)
    decipher.setAuthTag(authTag)

    return Buffer.concat([
      decipher.update(encryptedData),
      decipher.final(),
    ])
  } catch {
    throw new HttpError(400, 'File decryption failed. The file may be corrupted or modified.')
  }
}
