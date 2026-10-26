import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto'
import type { EnvironmentConfig } from '../config/environment.js'
import { HttpError } from '../types/http.js'

const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const totpPeriodSeconds = 30

function getMasterKey(environment: EnvironmentConfig): Buffer {
  if (!environment.encryptionMasterKey) {
    throw new HttpError(503, 'MFA is not configured. Please contact support.')
  }
  const key = Buffer.from(environment.encryptionMasterKey, 'base64')
  if (key.length !== 32) {
    throw new HttpError(503, 'MFA encryption is not configured correctly.')
  }
  return key
}

function encodeBase32(bytes: Buffer): string {
  let bits = 0
  let value = 0
  let encoded = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      encoded += base32Alphabet[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) {
    encoded += base32Alphabet[(value << (5 - bits)) & 31]
  }
  return encoded
}

function decodeBase32(secret: string): Buffer {
  let bits = 0
  let value = 0
  const bytes: number[] = []
  for (const character of secret.toUpperCase().replace(/=+$/, '')) {
    const index = base32Alphabet.indexOf(character)
    if (index < 0) {
      throw new HttpError(500, 'The stored MFA secret is invalid.')
    }
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Buffer.from(bytes)
}

export function createTotpSecret(): string {
  return encodeBase32(randomBytes(20))
}

export function encryptTotpSecret(secret: string, environment: EnvironmentConfig): string {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', getMasterKey(environment), iv)
  const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()])
  return [
    iv.toString('base64'),
    cipher.getAuthTag().toString('base64'),
    encrypted.toString('base64'),
  ].join('.')
}

export function decryptTotpSecret(value: string, environment: EnvironmentConfig): string {
  const [ivEncoded, tagEncoded, encryptedEncoded, ...extra] = value.split('.')
  if (!ivEncoded || !tagEncoded || !encryptedEncoded || extra.length > 0) {
    throw new HttpError(500, 'The stored MFA secret is invalid.')
  }
  try {
    const iv = Buffer.from(ivEncoded, 'base64')
    const authTag = Buffer.from(tagEncoded, 'base64')
    const encrypted = Buffer.from(encryptedEncoded, 'base64')
    if (iv.length !== 12 || authTag.length !== 16) {
      throw new Error('Invalid MFA secret metadata')
    }
    const decipher = createDecipheriv('aes-256-gcm', getMasterKey(environment), iv)
    decipher.setAuthTag(authTag)
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8')
  } catch {
    throw new HttpError(503, 'The stored MFA secret could not be decrypted.')
  }
}

function getTotp(secret: string, step: number): string {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(step))
  const digest = createHmac('sha1', decodeBase32(secret)).update(counter).digest()
  const offset = digest[digest.length - 1] & 0x0f
  const number = (
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff)
  ) % 1_000_000
  return number.toString().padStart(6, '0')
}

export function verifyTotp(
  secret: string,
  code: string,
  now = Date.now(),
): number | undefined {
  if (!/^\d{6}$/.test(code)) {
    return undefined
  }
  const currentStep = Math.floor(now / 1000 / totpPeriodSeconds)
  const supplied = Buffer.from(code)
  for (const step of [currentStep - 1, currentStep, currentStep + 1]) {
    const expected = Buffer.from(getTotp(secret, step))
    if (timingSafeEqual(supplied, expected)) {
      return step
    }
  }
  return undefined
}

export function createTotpProvisioningUri(secret: string, email: string): string {
  const label = encodeURIComponent(`SecureVault:${email}`)
  const query = new URLSearchParams({
    secret,
    issuer: 'SecureVault',
    algorithm: 'SHA1',
    digits: '6',
    period: String(totpPeriodSeconds),
  })
  return `otpauth://totp/${label}?${query.toString()}`
}
