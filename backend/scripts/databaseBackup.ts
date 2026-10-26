import { spawn } from 'node:child_process'
import { createReadStream, createWriteStream } from 'node:fs'
import { appendFile, mkdir, readdir, rename, rm, stat, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { pipeline } from 'node:stream/promises'
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3'
import { loadEnvironment } from '../src/config/environment.js'
import {
  createDatabaseBackupCipher,
  databaseBackupMagic,
  validateDatabaseBackupKey,
} from '../src/services/databaseBackupCrypto.js'
import { logger } from '../src/utils/logger.js'

function getPgEnvironment(databaseUrl: string): NodeJS.ProcessEnv {
  const database = new URL(databaseUrl)
  if (!database.hostname || !database.pathname.slice(1)) {
    throw new Error('DATABASE_URL must include a PostgreSQL host and database.')
  }
  return {
    ...process.env,
    PGHOST: database.hostname,
    PGPORT: database.port || '5432',
    PGDATABASE: decodeURIComponent(database.pathname.slice(1)),
    PGUSER: decodeURIComponent(database.username),
    PGPASSWORD: decodeURIComponent(database.password),
    PGSSLMODE: database.searchParams.get('sslmode') || (process.env.NODE_ENV === 'production' ? 'verify-full' : 'prefer'),
  }
}

async function removeExpiredLocalBackups(directory: string, retentionDays: number): Promise<void> {
  const expiresBefore = Date.now() - retentionDays * 24 * 60 * 60 * 1000
  for (const name of await readdir(directory)) {
    if (!/^securevault-postgres-\d{8}T\d{6}Z\.svdbak$/.test(name)) {
      continue
    }
    const filePath = path.join(directory, name)
    const information = await stat(filePath)
    if (information.mtimeMs < expiresBefore) {
      await rm(filePath)
    }
  }
}

async function main(): Promise<void> {
  const environment = loadEnvironment()
  const key = validateDatabaseBackupKey(environment.databaseBackupEncryptionKey)
  const bucket = environment.databaseBackupBucket
  const endpoint = environment.databaseBackupEndpoint
  const accessKeyId = environment.databaseBackupAccessKeyId
  const secretAccessKey = environment.databaseBackupSecretAccessKey
  if (!bucket || !endpoint || !accessKeyId || !secretAccessKey) {
    throw new Error('Dedicated database backup bucket settings are required.')
  }

  const directory = path.resolve(process.env.DATABASE_BACKUP_DIRECTORY || 'storage/database-backups')
  const retentionDays = Number(process.env.DATABASE_BACKUP_RETENTION_DAYS || '35')
  if (!Number.isInteger(retentionDays) || retentionDays < 1 || retentionDays > 3650) {
    throw new Error('DATABASE_BACKUP_RETENTION_DAYS must be an integer between 1 and 3650.')
  }
  await mkdir(directory, { recursive: true, mode: 0o700 })

  const timestamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '')
  const filename = `securevault-postgres-${timestamp}.svdbak`
  const destination = path.join(directory, filename)
  const temporaryPath = `${destination}.tmp`
  const { iv, cipher } = createDatabaseBackupCipher(key)
  const child = spawn('pg_dump', ['--format=custom', '--no-password'], {
    env: getPgEnvironment(environment.databaseUrl),
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  })
  let stderr = ''
  child.stderr.setEncoding('utf8')
  child.stderr.on('data', (chunk: string) => {
    if (stderr.length < 4096) stderr += chunk.slice(0, 4096 - stderr.length)
  })
  const exit = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once('error', reject)
    child.once('close', (code, signal) => resolve({ code, signal }))
  })

  try {
    await writeFile(temporaryPath, Buffer.concat([databaseBackupMagic, iv]), { flag: 'wx', mode: 0o600 })
    const [, result] = await Promise.all([
      pipeline(child.stdout, cipher, createWriteStream(temporaryPath, { flags: 'a', mode: 0o600 })),
      exit,
    ])
    if (result.code !== 0) {
      throw new Error(`pg_dump failed (${result.code ?? result.signal}): ${stderr.trim() || 'no details'}`)
    }
    await appendFile(temporaryPath, cipher.getAuthTag())
    await rename(temporaryPath, destination)

    const s3 = new S3Client({
      endpoint,
      region: environment.databaseBackupRegion || 'auto',
      forcePathStyle: true,
      credentials: { accessKeyId, secretAccessKey },
    })
    try {
      const information = await stat(destination)
      await s3.send(new PutObjectCommand({
        Bucket: bucket,
        Key: `postgres/${filename}`,
        Body: createReadStream(destination),
        ContentLength: information.size,
        ContentType: 'application/octet-stream',
        ServerSideEncryption: 'AES256',
      }))
    } finally {
      s3.destroy()
    }

    await removeExpiredLocalBackups(directory, retentionDays)
    logger.info(
      { event: 'backup.postgres.completed', filename, sizeBytes: (await stat(destination)).size },
      'Encrypted PostgreSQL backup uploaded successfully',
    )
  } catch (error) {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill()
    }
    await rm(temporaryPath, { force: true })
    throw error
  }
}

main().catch((error: unknown) => {
  logger.error(
    {
      event: 'backup.postgres.failed',
      errorType: error instanceof Error ? error.name : 'UnknownError',
      message: error instanceof Error ? error.message : 'Unknown backup error',
    },
    'Encrypted PostgreSQL backup failed',
  )
  process.exitCode = 1
})
