import assert from 'node:assert/strict'
import { test } from 'node:test'
import { loadEnvironment } from '../src/config/environment.js'

const baseEnvironment = {
  NODE_ENV: 'test',
  PORT: '3000',
  CORS_ORIGIN: 'http://localhost:5173',
  DATABASE_URL: 'postgresql://test:test@localhost:5432/securevault_test',
}

test('SMTP settings remain optional when password reset mail is not configured', () => {
  const environment = loadEnvironment(baseEnvironment)
  assert.equal(environment.smtpHost, undefined)
  assert.equal(environment.smtpPort, undefined)
  assert.equal(environment.malwareScannerEnabled, false)
  assert.equal(environment.malwareScannerCommand, 'clamscan')
  assert.equal(environment.malwareScannerDatabase, undefined)
})

test('malware scanner configuration is strict and required in production', () => {
  assert.equal(
    loadEnvironment({
      ...baseEnvironment,
      MALWARE_SCANNER_ENABLED: 'true',
      MALWARE_SCANNER_COMMAND: 'clamdscan',
      MALWARE_SCANNER_DATABASE: 'C:\\ProgramData\\ClamAV\\database',
    })
      .malwareScannerEnabled,
    true,
  )
  assert.throws(
    () => loadEnvironment({ ...baseEnvironment, MALWARE_SCANNER_ENABLED: 'yes' }),
    /MALWARE_SCANNER_ENABLED must be true or false/,
  )
})

test('SMTP settings must be supplied together and use a valid port', () => {
  assert.throws(
    () => loadEnvironment({ ...baseEnvironment, SMTP_HOST: 'mail.example.test' }),
    /SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, and SMTP_FROM must all be configured together/,
  )
  assert.throws(
    () => loadEnvironment({
      ...baseEnvironment,
      SMTP_HOST: 'mail.example.test',
      SMTP_PORT: 'invalid',
      SMTP_USER: 'user',
      SMTP_PASSWORD: 'password',
      SMTP_FROM: 'SecureVault <no-reply@example.test>',
    }),
    /SMTP_PORT must be an integer between 1 and 65535/,
  )
})

test('security alert recipients must be valid and have SMTP configured', () => {
  const configuredSmtp = {
    SMTP_HOST: 'mail.example.test',
    SMTP_PORT: '587',
    SMTP_USER: 'vault@example.test',
    SMTP_PASSWORD: 'smtp-password',
    SMTP_FROM: 'SecureVault <no-reply@example.test>',
  }
  assert.deepEqual(
    loadEnvironment({
      ...baseEnvironment,
      ...configuredSmtp,
      SECURITY_ALERT_EMAILS: 'admin@example.test, security@example.test',
    })
      .securityAlertEmails,
    ['admin@example.test', 'security@example.test'],
  )
  assert.throws(
    () => loadEnvironment({ ...baseEnvironment, SECURITY_ALERT_EMAILS: 'not-an-email' }),
    /SECURITY_ALERT_EMAILS must contain up to 10 valid comma-separated email addresses/,
  )
  assert.throws(
    () => loadEnvironment({
      ...baseEnvironment,
      SECURITY_ALERT_EMAILS: 'admin@example.test',
    }),
    /SMTP settings are required when SECURITY_ALERT_EMAILS is configured/,
  )
})

test('database backups require their own valid key, credentials, HTTPS endpoint, and separate bucket', () => {
  const backupConfig = {
    DATABASE_BACKUP_ENCRYPTION_KEY: Buffer.alloc(32, 6).toString('base64'),
    DATABASE_BACKUP_ENDPOINT: 'https://backup.example.test',
    DATABASE_BACKUP_BUCKET: 'securevault-postgres',
    DATABASE_BACKUP_ACCESS_KEY_ID: 'backup-access',
    DATABASE_BACKUP_SECRET_ACCESS_KEY: 'backup-secret',
    MALWARE_SCANNER_ENABLED: 'true',
    MALWARE_SCANNER_DATABASE: 'C:\\ProgramData\\ClamAV\\database',
  }
  const environment = loadEnvironment({ ...baseEnvironment, ...backupConfig })
  assert.equal(environment.databaseBackupBucket, 'securevault-postgres')
  assert.equal(environment.databaseBackupEncryptionKey, backupConfig.DATABASE_BACKUP_ENCRYPTION_KEY)
  assert.throws(
    () => loadEnvironment({
      ...baseEnvironment,
      ...backupConfig,
      DATABASE_BACKUP_ENCRYPTION_KEY: Buffer.alloc(16).toString('base64'),
    }),
    /DATABASE_BACKUP_ENCRYPTION_KEY must be a base64-encoded 32-byte key/,
  )
  assert.throws(
    () => loadEnvironment({ ...baseEnvironment, ...backupConfig, DATABASE_BACKUP_ENDPOINT: 'http://backup.example.test' }),
    /DATABASE_BACKUP_ENDPOINT must be an HTTPS origin/,
  )
})

test('S3-compatible storage requires distinct primary and backup buckets', () => {
  const cloudEnvironment = {
    ...baseEnvironment,
    STORAGE_PROVIDER: 's3',
    CLOUD_STORAGE_ENDPOINT: 'https://example-account.r2.cloudflarestorage.com',
    CLOUD_STORAGE_REGION: 'auto',
    CLOUD_STORAGE_BUCKET: 'securevault-files',
    CLOUD_BACKUP_BUCKET: 'securevault-backups',
    CLOUD_STORAGE_ACCESS_KEY_ID: 'test-access-key',
    CLOUD_STORAGE_SECRET_ACCESS_KEY: 'test-secret-key',
  }

  const environment = loadEnvironment(cloudEnvironment)
  assert.equal(environment.storageProvider, 's3')
  assert.equal(environment.cloudStorageBucket, 'securevault-files')
  assert.equal(environment.cloudBackupBucket, 'securevault-backups')
  assert.throws(
    () => loadEnvironment({ ...cloudEnvironment, CLOUD_BACKUP_BUCKET: 'securevault-files' }),
    /CLOUD_BACKUP_BUCKET must be different from CLOUD_STORAGE_BUCKET/,
  )
  assert.throws(
    () => loadEnvironment({ ...cloudEnvironment, CLOUD_STORAGE_SECRET_ACCESS_KEY: undefined }),
    /CLOUD_STORAGE_ENDPOINT, CLOUD_STORAGE_BUCKET, CLOUD_BACKUP_BUCKET, CLOUD_STORAGE_ACCESS_KEY_ID, and CLOUD_STORAGE_SECRET_ACCESS_KEY are required/,
  )
})

test('production environment requires HTTPS, signing keys, encryption key, and SMTP settings', () => {
  const validProduction = {
    ...baseEnvironment,
    NODE_ENV: 'production',
    CORS_ORIGIN: 'https://vault.example.test',
    DATABASE_URL: 'postgres://user:password@db.example.test:5432/securevault?sslmode=verify-full',
    JWT_ACCESS_SECRET: 'a'.repeat(32),
    JWT_REFRESH_SECRET: 'b'.repeat(32),
    ENCRYPTION_MASTER_KEY: Buffer.alloc(32, 7).toString('base64'),
    STORAGE_PROVIDER: 's3',
    CLOUD_STORAGE_ENDPOINT: 'https://example-account.r2.cloudflarestorage.com',
    CLOUD_STORAGE_REGION: 'auto',
    CLOUD_STORAGE_BUCKET: 'securevault-files',
    CLOUD_BACKUP_BUCKET: 'securevault-backups',
    CLOUD_STORAGE_ACCESS_KEY_ID: 'test-access-key',
    CLOUD_STORAGE_SECRET_ACCESS_KEY: 'test-secret-key',
    SMTP_HOST: 'mail.example.test',
    SMTP_PORT: '587',
    SMTP_USER: 'vault@example.test',
    SMTP_PASSWORD: 'smtp-password',
    SMTP_FROM: 'SecureVault <no-reply@example.test>',
    SECURITY_ALERT_EMAILS: 'security@example.test',
    DATABASE_BACKUP_ENCRYPTION_KEY: Buffer.alloc(32, 8).toString('base64'),
    DATABASE_BACKUP_ENDPOINT: 'https://backup.example.test',
    DATABASE_BACKUP_BUCKET: 'securevault-postgres',
    DATABASE_BACKUP_ACCESS_KEY_ID: 'backup-access',
    DATABASE_BACKUP_SECRET_ACCESS_KEY: 'backup-secret',
    MALWARE_SCANNER_ENABLED: 'true',
  }

  assert.equal(loadEnvironment(validProduction).nodeEnv, 'production')
  assert.throws(
    () => loadEnvironment({ ...validProduction, ENCRYPTION_MASTER_KEY: undefined }),
    /ENCRYPTION_MASTER_KEY is required in production/,
  )
  assert.throws(
    () => loadEnvironment({ ...validProduction, CORS_ORIGIN: 'http://vault.example.test' }),
    /CORS_ORIGIN must use HTTPS in production/,
  )
  assert.throws(
    () => loadEnvironment({
      ...validProduction,
      DATABASE_URL: 'postgres://user:password@db.example.test:5432/securevault',
    }),
    /DATABASE_URL must set sslmode=require, verify-ca, or verify-full in production/,
  )
  assert.throws(
    () => loadEnvironment({ ...validProduction, STORAGE_PROVIDER: 'local' }),
    /STORAGE_PROVIDER=s3 is required in production/,
  )
  assert.throws(
    () => loadEnvironment({ ...validProduction, SECURITY_ALERT_EMAILS: undefined }),
    /SECURITY_ALERT_EMAILS is required in production/,
  )
  assert.throws(
    () => loadEnvironment({ ...validProduction, DATABASE_BACKUP_BUCKET: undefined }),
    /DATABASE_BACKUP_ENCRYPTION_KEY, DATABASE_BACKUP_ENDPOINT, DATABASE_BACKUP_BUCKET, DATABASE_BACKUP_ACCESS_KEY_ID, and DATABASE_BACKUP_SECRET_ACCESS_KEY are required in production/,
  )
  assert.throws(
    () => loadEnvironment({ ...validProduction, MALWARE_SCANNER_ENABLED: 'false' }),
    /MALWARE_SCANNER_ENABLED=true is required in production/,
  )
})
