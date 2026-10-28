import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { test } from 'node:test'
import { loadEnvironment } from '../src/config/environment.js'
import {
  createTotpProvisioningUri,
  createTotpSecret,
  decryptTotpSecret,
  encryptTotpSecret,
  verifyTotp,
} from '../src/services/totp.service.js'

const environment = loadEnvironment({
  NODE_ENV: 'test',
  PORT: '3000',
  CORS_ORIGIN: 'http://localhost:5173',
  DATABASE_URL: 'postgres://localhost:5432/securevault_test',
  JWT_ACCESS_SECRET: 'test-access-secret-that-is-long-enough-for-validation',
  JWT_REFRESH_SECRET: 'test-refresh-secret-that-is-long-enough-for-validation',
  ENCRYPTION_MASTER_KEY: Buffer.alloc(32, 9).toString('base64'),
})

function decodeReferenceBase32(secret: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let value = 0n
  let bits = 0
  const bytes: number[] = []
  for (const character of secret.toUpperCase().replace(/=+$/, '')) {
    const digit = alphabet.indexOf(character)
    assert.notEqual(digit, -1)
    value = (value << 5n) | BigInt(digit)
    bits += 5
    if (bits >= 8) {
      bits -= 8
      bytes.push(Number((value >> BigInt(bits)) & 0xffn))
      value &= (1n << BigInt(bits)) - 1n
    }
  }
  return Buffer.from(bytes)
}

function generateReferenceTotp(secret: string, timestamp: number): string {
  const secretBytes = decodeReferenceBase32(secret)
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(timestamp / 30_000)))
  const digest = createHmac('sha1', secretBytes).update(counter).digest()
  const offset = digest[digest.length - 1] & 0x0f
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff)
  return String(binary % 1_000_000).padStart(6, '0')
}

test('TOTP verification follows the RFC 6238 SHA-1 test vector', () => {
  assert.equal(verifyTotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '287082', 59_000), 1)
  assert.equal(verifyTotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '000000', 59_000), undefined)
})

test('an independently generated fixed-time TOTP verifies only with its enrollment secret', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
  const timestamp = 59_000
  const code = generateReferenceTotp(secret, timestamp)

  assert.equal(code, '287082')
  assert.equal(verifyTotp(secret, code, timestamp), 1)
  assert.equal(verifyTotp(secret, '000000', timestamp), undefined)
  assert.equal(verifyTotp('JBSWY3DPEHPK3PXP', code, timestamp), undefined)
  assert.equal(verifyTotp(`${secret.toLowerCase()}====`, code, timestamp), 1)
})

test('TOTP accepts only the current and adjacent 30-second steps', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
  assert.equal(verifyTotp(secret, '287082', 30_000), 1)
  assert.equal(verifyTotp(secret, '287082', 89_000), 1)
  assert.equal(verifyTotp(secret, '755224', 59_000), 0)
  assert.equal(verifyTotp(secret, '755224', 60_000), undefined)
  assert.equal(verifyTotp(secret, '287082', 90_000), undefined)
  assert.equal(verifyTotp(secret, '12a456', 59_000), undefined)
})

test('MFA secrets are randomly generated and encrypted at rest', () => {
  const secret = createTotpSecret()
  const encrypted = encryptTotpSecret(secret, environment)
  assert.notEqual(encrypted, secret)
  const decrypted = decryptTotpSecret(encrypted, environment)
  assert.equal(decrypted, secret)
  const timestamp = Date.now()
  const code = generateReferenceTotp(decrypted, timestamp)
  assert.equal(verifyTotp(decrypted, code, timestamp), Math.floor(timestamp / 30_000))
  assert.throws(() => decryptTotpSecret(`${encrypted.slice(0, -1)}x`, environment))
})

test('authenticator provisioning URI includes the issuer and account label', () => {
  const uri = new URL(createTotpProvisioningUri('ABC234', 'user@example.test'))
  assert.equal(uri.protocol, 'otpauth:')
  assert.equal(uri.hostname, 'totp')
  assert.equal(uri.searchParams.get('secret'), 'ABC234')
  assert.equal(uri.searchParams.get('issuer'), 'SecureVault')
  assert.equal(uri.searchParams.get('algorithm'), 'SHA1')
  assert.equal(uri.searchParams.get('digits'), '6')
  assert.equal(uri.searchParams.get('period'), '30')
  assert.ok(decodeURIComponent(uri.pathname).includes('user@example.test'))
})
