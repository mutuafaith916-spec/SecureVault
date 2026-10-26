import { createReadStream, createWriteStream } from 'node:fs'
import { mkdtemp, open, rm } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import { tmpdir } from 'node:os'
import { pipeline } from 'node:stream/promises'
import path from 'node:path'
import { loadEnvironment } from '../src/config/environment.js'
import {
  createDatabaseBackupDecipher,
  databaseBackupAuthTagLength,
  databaseBackupHeaderLength,
  validateDatabaseBackupKey,
} from '../src/services/databaseBackupCrypto.js'
import { logger } from '../src/utils/logger.js'

function getPgEnvironment(databaseUrl: string): { environment: NodeJS.ProcessEnv; databaseName: string } {
  const database = new URL(databaseUrl)
  const databaseName = decodeURIComponent(database.pathname.slice(1))
  if (!database.hostname || !databaseName) {
    throw new Error('DATABASE_URL must include a PostgreSQL host and database.')
  }
  return {
    databaseName,
    environment: {
      ...process.env,
      PGHOST: database.hostname,
      PGPORT: database.port || '5432',
      PGDATABASE: databaseName,
      PGUSER: decodeURIComponent(database.username),
      PGPASSWORD: decodeURIComponent(database.password),
      PGSSLMODE: database.searchParams.get('sslmode') || (process.env.NODE_ENV === 'production' ? 'verify-full' : 'prefer'),
    },
  }
}

async function main(): Promise<void> {
  const backupArgument = process.argv[2]
  if (!backupArgument) {
    throw new Error('Provide the path to an encrypted .svdbak file.')
  }
  const environment = loadEnvironment()
  const key = validateDatabaseBackupKey(environment.databaseBackupEncryptionKey)
  const backupPath = path.resolve(backupArgument)
  const handle = await open(backupPath, 'r')
  let header: Buffer
  let authTag: Buffer
  let fileSize: number
  try {
    const information = await handle.stat()
    fileSize = information.size
    if (fileSize < databaseBackupHeaderLength + databaseBackupAuthTagLength) {
      throw new Error('The encrypted database backup is incomplete.')
    }
    header = Buffer.alloc(databaseBackupHeaderLength)
    authTag = Buffer.alloc(databaseBackupAuthTagLength)
    await handle.read(header, 0, header.length, 0)
    await handle.read(authTag, 0, authTag.length, fileSize - databaseBackupAuthTagLength)
  } finally {
    await handle.close()
  }

  const decipher = createDatabaseBackupDecipher(key, header, authTag)
  const { environment: pgEnvironment, databaseName } = getPgEnvironment(environment.databaseUrl)
  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'securevault-restore-'))
  const plaintextPath = path.join(temporaryDirectory, 'database.dump')
  try {
    await pipeline(
      createReadStream(backupPath, {
        start: databaseBackupHeaderLength,
        end: fileSize - databaseBackupAuthTagLength - 1,
      }),
      decipher,
      createWriteStream(plaintextPath, { flags: 'wx', mode: 0o600 }),
    )

    const child = spawn(
      'pg_restore',
      ['--no-owner', '--exit-on-error', `--dbname=${databaseName}`, plaintextPath],
      { env: pgEnvironment, stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true },
    )
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
      const result = await exit
      if (result.code !== 0) {
        throw new Error(`pg_restore failed (${result.code ?? result.signal}): ${stderr.trim() || 'no details'}`)
      }
    } catch (error) {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill()
      }
      throw error
    }
    logger.info({ event: 'restore.postgres.completed', databaseName }, 'PostgreSQL restore completed successfully')
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true })
  }
}

main().catch((error: unknown) => {
  logger.error(
    {
      event: 'restore.postgres.failed',
      errorType: error instanceof Error ? error.name : 'UnknownError',
      message: error instanceof Error ? error.message : 'Unknown restore error',
    },
    'PostgreSQL restore failed',
  )
  process.exitCode = 1
})
