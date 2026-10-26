import dotenv from 'dotenv'

dotenv.config()

export type NodeEnvironment = 'development' | 'test' | 'production'

export interface EnvironmentConfig {
  readonly nodeEnv: NodeEnvironment
  readonly port: number
  readonly corsOrigin: string
  readonly databaseUrl: string
  readonly storageProvider: 'local' | 's3'
  readonly cloudStorageEndpoint?: string
  readonly cloudStorageRegion?: string
  readonly cloudStorageBucket?: string
  readonly cloudBackupBucket?: string
  readonly cloudStorageAccessKeyId?: string
  readonly cloudStorageSecretAccessKey?: string
  readonly jwtAccessSecret?: string
  readonly jwtRefreshSecret?: string
  readonly encryptionMasterKey?: string
  readonly smtpHost?: string
  readonly smtpPort?: number
  readonly smtpUser?: string
  readonly smtpPassword?: string
  readonly smtpFrom?: string
  readonly securityAlertEmails: readonly string[]
  readonly malwareScannerEnabled: boolean
  readonly malwareScannerCommand: string
  readonly malwareScannerDatabase?: string
  readonly databaseBackupEncryptionKey?: string
  readonly databaseBackupEndpoint?: string
  readonly databaseBackupRegion?: string
  readonly databaseBackupBucket?: string
  readonly databaseBackupAccessKeyId?: string
  readonly databaseBackupSecretAccessKey?: string
}

function requiredValue(source: NodeJS.ProcessEnv, key: string): string {
  const value = source[key]?.trim()
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`)
  }
  return value
}

function optionalValue(source: NodeJS.ProcessEnv, key: string): string | undefined {
  const value = source[key]?.trim()
  return value || undefined
}

function parseEnvironmentName(value: string): NodeEnvironment {
  if (value === 'development' || value === 'test' || value === 'production') {
    return value
  }
  throw new Error('NODE_ENV must be development, test, or production')
}

function parsePort(value: string): number {
  const port = Number(value)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be an integer between 1 and 65535')
  }
  return port
}

function optionalPort(source: NodeJS.ProcessEnv, key: string): number | undefined {
  const value = optionalValue(source, key)
  if (!value) {
    return undefined
  }
  const port = Number(value)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${key} must be an integer between 1 and 65535`)
  }
  return port
}

function malwareScannerConfiguration(
  source: NodeJS.ProcessEnv,
  nodeEnv: NodeEnvironment,
): { enabled: boolean; command: string; database?: string } {
  const value = optionalValue(source, 'MALWARE_SCANNER_ENABLED')
  if (value && value !== 'true' && value !== 'false') {
    throw new Error('MALWARE_SCANNER_ENABLED must be true or false')
  }
  const enabled = value === 'true'
  if (nodeEnv === 'production' && !enabled) {
    throw new Error('MALWARE_SCANNER_ENABLED=true is required in production')
  }
  return {
    enabled,
    command: optionalValue(source, 'MALWARE_SCANNER_COMMAND') || 'clamscan',
    database: optionalValue(source, 'MALWARE_SCANNER_DATABASE'),
  }
}

function parseSecurityAlertEmails(source: NodeJS.ProcessEnv): readonly string[] {
  const configured = optionalValue(source, 'SECURITY_ALERT_EMAILS')
  if (!configured) {
    return []
  }
  const recipients = configured.split(',').map((email) => email.trim().toLowerCase())
  if (
    recipients.length > 10 ||
    recipients.some((email) => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
  ) {
    throw new Error('SECURITY_ALERT_EMAILS must contain up to 10 valid comma-separated email addresses')
  }
  return [...new Set(recipients)]
}

function parseCorsOrigin(value: string): string {
  let origin: URL
  try {
    origin = new URL(value)
  } catch {
    throw new Error('CORS_ORIGIN must be a valid HTTP or HTTPS origin')
  }

  if (
    (origin.protocol !== 'http:' && origin.protocol !== 'https:') ||
    origin.username ||
    origin.password ||
    origin.pathname !== '/' ||
    origin.search ||
    origin.hash
  ) {
    throw new Error('CORS_ORIGIN must contain only an HTTP or HTTPS origin')
  }
  return origin.origin
}

function validateOptionalSecrets(source: NodeJS.ProcessEnv, nodeEnv: NodeEnvironment): void {
  for (const key of ['JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET']) {
    const value = optionalValue(source, key)
    if (value && value.length < 32) {
      throw new Error(`${key} must contain at least 32 characters when configured`)
    }
  }

  const masterKey = optionalValue(source, 'ENCRYPTION_MASTER_KEY')
  if (masterKey) {
    const decodedKey = Buffer.from(masterKey, 'base64')
    if (decodedKey.length !== 32 || decodedKey.toString('base64') !== masterKey) {
      throw new Error('ENCRYPTION_MASTER_KEY must be a base64-encoded 32-byte key when configured')
    }
  }

  const smtpValues = [
    optionalValue(source, 'SMTP_HOST'),
    optionalValue(source, 'SMTP_PORT'),
    optionalValue(source, 'SMTP_USER'),
    optionalValue(source, 'SMTP_PASSWORD'),
    optionalValue(source, 'SMTP_FROM'),
  ]
  if (smtpValues.some(Boolean) && smtpValues.some((value) => !value)) {
    throw new Error('SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, and SMTP_FROM must all be configured together')
  }
  const alertEmails = parseSecurityAlertEmails(source)
  if (alertEmails.length > 0 && smtpValues.some((value) => !value)) {
    throw new Error('SMTP settings are required when SECURITY_ALERT_EMAILS is configured')
  }

  const databaseBackupKey = optionalValue(source, 'DATABASE_BACKUP_ENCRYPTION_KEY')
  if (databaseBackupKey) {
    const decodedKey = Buffer.from(databaseBackupKey, 'base64')
    if (decodedKey.length !== 32 || decodedKey.toString('base64') !== databaseBackupKey) {
      throw new Error('DATABASE_BACKUP_ENCRYPTION_KEY must be a base64-encoded 32-byte key when configured')
    }
  }

  if (nodeEnv === 'production') {
    if (!optionalValue(source, 'JWT_ACCESS_SECRET') || !optionalValue(source, 'JWT_REFRESH_SECRET')) {
      throw new Error('JWT_ACCESS_SECRET and JWT_REFRESH_SECRET are required in production')
    }
    if (!masterKey) {
      throw new Error('ENCRYPTION_MASTER_KEY is required in production')
    }
    if (smtpValues.some((value) => !value)) {
      throw new Error('SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, and SMTP_FROM are required in production')
    }
    if (alertEmails.length === 0) {
      throw new Error('SECURITY_ALERT_EMAILS is required in production')
    }
    if (
      !databaseBackupKey ||
      !optionalValue(source, 'DATABASE_BACKUP_ENDPOINT') ||
      !optionalValue(source, 'DATABASE_BACKUP_BUCKET') ||
      !optionalValue(source, 'DATABASE_BACKUP_ACCESS_KEY_ID') ||
      !optionalValue(source, 'DATABASE_BACKUP_SECRET_ACCESS_KEY')
    ) {
      throw new Error('DATABASE_BACKUP_ENCRYPTION_KEY, DATABASE_BACKUP_ENDPOINT, DATABASE_BACKUP_BUCKET, DATABASE_BACKUP_ACCESS_KEY_ID, and DATABASE_BACKUP_SECRET_ACCESS_KEY are required in production')
    }
  }
}

function requiredDatabaseUrl(source: NodeJS.ProcessEnv): string {
  const value = requiredValue(source, 'DATABASE_URL')
  let databaseUrl: URL
  try {
    databaseUrl = new URL(value)
  } catch {
    throw new Error('DATABASE_URL must be a valid PostgreSQL connection URL')
  }

  if (
    (databaseUrl.protocol !== 'postgres:' && databaseUrl.protocol !== 'postgresql:') ||
    !databaseUrl.hostname ||
    !databaseUrl.pathname.slice(1)
  ) {
    throw new Error('DATABASE_URL must include a PostgreSQL host and database name')
  }

  return value
}

function loadStorageConfiguration(source: NodeJS.ProcessEnv, nodeEnv: NodeEnvironment) {
  const storageProvider = optionalValue(source, 'STORAGE_PROVIDER') || 'local'
  if (storageProvider !== 'local' && storageProvider !== 's3') {
    throw new Error('STORAGE_PROVIDER must be local or s3')
  }

  const endpointValue = optionalValue(source, 'CLOUD_STORAGE_ENDPOINT')
  const bucket = optionalValue(source, 'CLOUD_STORAGE_BUCKET')
  const backupBucket = optionalValue(source, 'CLOUD_BACKUP_BUCKET')
  const accessKeyId = optionalValue(source, 'CLOUD_STORAGE_ACCESS_KEY_ID')
  const secretAccessKey = optionalValue(source, 'CLOUD_STORAGE_SECRET_ACCESS_KEY')
  const region = optionalValue(source, 'CLOUD_STORAGE_REGION') || 'auto'

  if (storageProvider === 'local') {
    if (nodeEnv === 'production') {
      throw new Error('STORAGE_PROVIDER=s3 is required in production')
    }
    if ([endpointValue, bucket, backupBucket, accessKeyId, secretAccessKey].some(Boolean)) {
      throw new Error('Cloud storage settings require STORAGE_PROVIDER=s3')
    }
    return { storageProvider } as const
  }

  if ([endpointValue, bucket, backupBucket, accessKeyId, secretAccessKey].some((value) => !value)) {
    throw new Error('CLOUD_STORAGE_ENDPOINT, CLOUD_STORAGE_BUCKET, CLOUD_BACKUP_BUCKET, CLOUD_STORAGE_ACCESS_KEY_ID, and CLOUD_STORAGE_SECRET_ACCESS_KEY are required when STORAGE_PROVIDER=s3')
  }

  let endpoint: URL
  try {
    endpoint = new URL(endpointValue!)
  } catch {
    throw new Error('CLOUD_STORAGE_ENDPOINT must be a valid HTTP or HTTPS URL')
  }
  if (
    (endpoint.protocol !== 'https:' && endpoint.protocol !== 'http:') ||
    endpoint.username ||
    endpoint.password ||
    endpoint.pathname !== '/' ||
    endpoint.search ||
    endpoint.hash
  ) {
    throw new Error('CLOUD_STORAGE_ENDPOINT must be an HTTP or HTTPS origin')
  }
  if (nodeEnv === 'production' && endpoint.protocol !== 'https:') {
    throw new Error('CLOUD_STORAGE_ENDPOINT must use HTTPS in production')
  }

  const validBucketName = (name: string) =>
    name.length >= 3 &&
    name.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(name) &&
    !name.includes('..')
  if (!validBucketName(bucket!) || !validBucketName(backupBucket!)) {
    throw new Error('Cloud storage bucket names must be 3-63 characters and contain only lowercase letters, numbers, dots, or hyphens')
  }
  if (bucket === backupBucket) {
    throw new Error('CLOUD_BACKUP_BUCKET must be different from CLOUD_STORAGE_BUCKET')
  }

  return {
    storageProvider,
    cloudStorageEndpoint: endpoint.origin,
    cloudStorageRegion: region,
    cloudStorageBucket: bucket,
    cloudBackupBucket: backupBucket,
    cloudStorageAccessKeyId: accessKeyId,
    cloudStorageSecretAccessKey: secretAccessKey,
  } as const
}

export function loadEnvironment(source: NodeJS.ProcessEnv = process.env): EnvironmentConfig {
  const nodeEnv = parseEnvironmentName(requiredValue(source, 'NODE_ENV'))
  const port = parsePort(requiredValue(source, 'PORT'))
  const corsOrigin = parseCorsOrigin(requiredValue(source, 'CORS_ORIGIN'))
  if (nodeEnv === 'production' && !corsOrigin.startsWith('https://')) {
    throw new Error('CORS_ORIGIN must use HTTPS in production')
  }
  const databaseUrl = requiredDatabaseUrl(source)
  const databaseSslMode = new URL(databaseUrl).searchParams.get('sslmode')
  if (
    nodeEnv === 'production' &&
    databaseSslMode !== 'require' &&
    databaseSslMode !== 'verify-ca' &&
    databaseSslMode !== 'verify-full'
  ) {
    throw new Error('DATABASE_URL must set sslmode=require, verify-ca, or verify-full in production')
  }
  const storage = loadStorageConfiguration(source, nodeEnv)
  const malwareScanner = malwareScannerConfiguration(source, nodeEnv)
  validateOptionalSecrets(source, nodeEnv)
  const databaseBackup = loadDatabaseBackupConfiguration(source, nodeEnv, storage)

  return Object.freeze({
    nodeEnv,
    port,
    corsOrigin,
    databaseUrl,
    ...storage,
    jwtAccessSecret: optionalValue(source, 'JWT_ACCESS_SECRET'),
    jwtRefreshSecret: optionalValue(source, 'JWT_REFRESH_SECRET'),
    encryptionMasterKey: optionalValue(source, 'ENCRYPTION_MASTER_KEY'),
    smtpHost: optionalValue(source, 'SMTP_HOST'),
    smtpPort: optionalPort(source, 'SMTP_PORT'),
    smtpUser: optionalValue(source, 'SMTP_USER'),
    smtpPassword: optionalValue(source, 'SMTP_PASSWORD'),
    smtpFrom: optionalValue(source, 'SMTP_FROM'),
    securityAlertEmails: parseSecurityAlertEmails(source),
    malwareScannerEnabled: malwareScanner.enabled,
    malwareScannerCommand: malwareScanner.command,
    malwareScannerDatabase: malwareScanner.database,
    ...databaseBackup,
  })
}

function loadDatabaseBackupConfiguration(
  source: NodeJS.ProcessEnv,
  nodeEnv: NodeEnvironment,
  storage: ReturnType<typeof loadStorageConfiguration>,
) {
  const endpointValue = optionalValue(source, 'DATABASE_BACKUP_ENDPOINT')
  const bucket = optionalValue(source, 'DATABASE_BACKUP_BUCKET')
  const accessKeyId = optionalValue(source, 'DATABASE_BACKUP_ACCESS_KEY_ID')
  const secretAccessKey = optionalValue(source, 'DATABASE_BACKUP_SECRET_ACCESS_KEY')
  const encryptionKey = optionalValue(source, 'DATABASE_BACKUP_ENCRYPTION_KEY')
  const configured = [endpointValue, bucket, accessKeyId, secretAccessKey, encryptionKey]
  if (configured.some(Boolean) && configured.some((value) => !value)) {
    throw new Error('DATABASE_BACKUP_ENDPOINT, DATABASE_BACKUP_BUCKET, DATABASE_BACKUP_ACCESS_KEY_ID, DATABASE_BACKUP_SECRET_ACCESS_KEY, and DATABASE_BACKUP_ENCRYPTION_KEY must be configured together')
  }
  if (!bucket) {
    return {}
  }

  let endpoint: URL
  try {
    endpoint = new URL(endpointValue!)
  } catch {
    throw new Error('DATABASE_BACKUP_ENDPOINT must be a valid HTTPS URL')
  }
  if (
    endpoint.protocol !== 'https:' ||
    endpoint.username ||
    endpoint.password ||
    endpoint.pathname !== '/' ||
    endpoint.search ||
    endpoint.hash
  ) {
    throw new Error('DATABASE_BACKUP_ENDPOINT must be an HTTPS origin')
  }
  const validBucketName = (name: string) =>
    name.length >= 3 &&
    name.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(name) &&
    !name.includes('..')
  if (!validBucketName(bucket)) {
    throw new Error('DATABASE_BACKUP_BUCKET must be a valid S3-compatible bucket name')
  }
  if (storage.storageProvider === 's3' && [storage.cloudStorageBucket, storage.cloudBackupBucket].includes(bucket)) {
    throw new Error('DATABASE_BACKUP_BUCKET must be separate from file storage buckets')
  }
  if (nodeEnv === 'production' && !encryptionKey) {
    throw new Error('DATABASE_BACKUP_ENCRYPTION_KEY is required in production')
  }
  return {
    databaseBackupEndpoint: endpoint.origin,
    databaseBackupRegion: optionalValue(source, 'DATABASE_BACKUP_REGION') || 'auto',
    databaseBackupBucket: bucket,
    databaseBackupAccessKeyId: accessKeyId,
    databaseBackupSecretAccessKey: secretAccessKey,
    databaseBackupEncryptionKey: encryptionKey,
  } as const
}
