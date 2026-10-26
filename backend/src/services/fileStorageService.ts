import {
  DeleteObjectCommand,
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3'
import {
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import path from 'node:path'
import type { EnvironmentConfig } from '../config/environment.js'
import { HttpError } from '../types/http.js'

const storageDirectory = path.resolve('storage', 'encrypted-files')
const backupDirectory = path.resolve('storage', 'encrypted-backups')
const s3Clients = new WeakMap<EnvironmentConfig, S3Client>()

function resolveStoredFilePath(storedName: string): string {
  if (!/^[0-9a-f-]{36}\.enc$/i.test(storedName)) {
    throw new HttpError(400, 'Invalid stored file identifier.')
  }

  return path.join(storageDirectory, storedName)
}

function resolveLocalBackupPath(backupName: string): string {
  if (!/^[0-9a-f-]{36}\.enc$/i.test(backupName)) {
    throw new HttpError(400, 'Invalid backup identifier.')
  }

  return path.join(backupDirectory, backupName)
}

function getS3Client(environment: EnvironmentConfig): S3Client {
  if (environment.storageProvider !== 's3') {
    throw new HttpError(503, 'Cloud storage is not configured.')
  }

  const cachedClient = s3Clients.get(environment)
  if (cachedClient) {
    return cachedClient
  }

  if (
    !environment.cloudStorageEndpoint ||
    !environment.cloudStorageRegion ||
    !environment.cloudStorageAccessKeyId ||
    !environment.cloudStorageSecretAccessKey
  ) {
    throw new HttpError(503, 'Cloud storage is not configured.')
  }

  const client = new S3Client({
    endpoint: environment.cloudStorageEndpoint,
    region: environment.cloudStorageRegion,
    forcePathStyle: true,
    credentials: {
      accessKeyId: environment.cloudStorageAccessKeyId,
      secretAccessKey: environment.cloudStorageSecretAccessKey,
    },
  })
  s3Clients.set(environment, client)
  return client
}

async function putObject(
  bucket: string | undefined,
  key: string,
  data: Buffer,
  environment: EnvironmentConfig,
): Promise<void> {
  if (!bucket) {
    throw new HttpError(503, 'Cloud storage is not configured.')
  }

  try {
    await getS3Client(environment).send(new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: data,
      ContentType: 'application/octet-stream',
    }))
  } catch {
    throw new HttpError(503, 'Encrypted file data could not be written to cloud storage.')
  }
}

async function getObject(
  bucket: string | undefined,
  key: string,
  environment: EnvironmentConfig,
): Promise<Buffer> {
  if (!bucket) {
    throw new HttpError(503, 'Cloud storage is not configured.')
  }

  try {
    const result = await getS3Client(environment).send(new GetObjectCommand({
      Bucket: bucket,
      Key: key,
    }))
    if (!result.Body) {
      throw new Error('Cloud storage returned an empty response body.')
    }
    return Buffer.from(await result.Body.transformToByteArray())
  } catch {
    throw new HttpError(503, 'Encrypted file data could not be read from cloud storage.')
  }
}

async function deleteObject(
  bucket: string | undefined,
  key: string,
  environment: EnvironmentConfig,
): Promise<void> {
  if (!bucket) {
    throw new HttpError(503, 'Cloud storage is not configured.')
  }

  try {
    await getS3Client(environment).send(new DeleteObjectCommand({
      Bucket: bucket,
      Key: key,
    }))
  } catch {
    throw new HttpError(503, 'Encrypted file data could not be deleted from cloud storage.')
  }
}

export async function saveEncryptedFile(
  encryptedData: Buffer,
  environment: EnvironmentConfig,
): Promise<{ storedName: string; filePath: string }> {
  if (!Buffer.isBuffer(encryptedData)) {
    throw new HttpError(400, 'Invalid encrypted file data.')
  }

  const storedName = `${randomUUID()}.enc`
  if (environment.storageProvider === 's3') {
    await putObject(environment.cloudStorageBucket, storedName, encryptedData, environment)
    return { storedName, filePath: storedName }
  }

  await mkdir(storageDirectory, { recursive: true })
  const filePath = resolveStoredFilePath(storedName)
  const temporaryPath = `${filePath}.tmp`
  try {
    await writeFile(temporaryPath, encryptedData, { flag: 'wx', mode: 0o600 })
    await rename(temporaryPath, filePath)
  } catch {
    await rm(temporaryPath, { force: true }).catch(() => undefined)
    throw new HttpError(500, 'The encrypted file could not be saved.')
  }

  return { storedName, filePath }
}

export async function saveEncryptedBackup(
  encryptedData: Buffer,
  environment: EnvironmentConfig,
): Promise<string> {
  if (!Buffer.isBuffer(encryptedData)) {
    throw new HttpError(400, 'Invalid encrypted backup data.')
  }

  const backupName = `${randomUUID()}.enc`
  if (environment.storageProvider === 's3') {
    const backupKey = `backups/${backupName}`
    await putObject(environment.cloudBackupBucket, backupKey, encryptedData, environment)
    return backupKey
  }

  await mkdir(backupDirectory, { recursive: true })
  const filePath = resolveLocalBackupPath(backupName)
  const temporaryPath = `${filePath}.tmp`
  try {
    await writeFile(temporaryPath, encryptedData, { flag: 'wx', mode: 0o600 })
    await rename(temporaryPath, filePath)
  } catch {
    await rm(temporaryPath, { force: true }).catch(() => undefined)
    throw new HttpError(500, 'The encrypted backup could not be saved.')
  }
  return backupName
}

export async function readEncryptedFile(
  storedName: string,
  environment: EnvironmentConfig,
): Promise<Buffer> {
  if (environment.storageProvider === 's3') {
    if (!/^[0-9a-f-]{36}\.enc$/i.test(storedName)) {
      throw new HttpError(400, 'Invalid stored file identifier.')
    }
    return getObject(environment.cloudStorageBucket, storedName, environment)
  }

  const filePath = resolveStoredFilePath(storedName)
  try {
    return await readFile(filePath)
  } catch {
    throw new HttpError(404, 'The stored file could not be found.')
  }
}

export async function readEncryptedBackup(
  backupPath: string,
  environment: EnvironmentConfig,
): Promise<Buffer> {
  if (environment.storageProvider === 's3') {
    if (!/^backups\/[0-9a-f-]{36}\.enc$/i.test(backupPath)) {
      throw new HttpError(400, 'Invalid backup identifier.')
    }
    return getObject(environment.cloudBackupBucket, backupPath, environment)
  }

  try {
    return await readFile(resolveLocalBackupPath(backupPath))
  } catch (error) {
    if (error instanceof HttpError) {
      throw error
    }
    throw new HttpError(404, 'The encrypted backup could not be found.')
  }
}

export async function restoreEncryptedFile(
  storedName: string,
  encryptedData: Buffer,
  environment: EnvironmentConfig,
): Promise<void> {
  if (!Buffer.isBuffer(encryptedData)) {
    throw new HttpError(400, 'Invalid encrypted file data.')
  }

  if (environment.storageProvider === 's3') {
    if (!/^[0-9a-f-]{36}\.enc$/i.test(storedName)) {
      throw new HttpError(400, 'Invalid stored file identifier.')
    }
    await putObject(environment.cloudStorageBucket, storedName, encryptedData, environment)
    return
  }

  const filePath = resolveStoredFilePath(storedName)
  const temporaryPath = `${filePath}.${randomUUID()}.tmp`
  try {
    await mkdir(storageDirectory, { recursive: true })
    await writeFile(temporaryPath, encryptedData, { flag: 'wx', mode: 0o600 })
    await rename(temporaryPath, filePath)
  } catch {
    await rm(temporaryPath, { force: true }).catch(() => undefined)
    throw new HttpError(500, 'The encrypted file could not be restored.')
  }
}

export async function deleteEncryptedFile(
  storedName: string,
  environment: EnvironmentConfig,
): Promise<void> {
  if (environment.storageProvider === 's3') {
    if (!/^[0-9a-f-]{36}\.enc$/i.test(storedName)) {
      throw new HttpError(400, 'Invalid stored file identifier.')
    }
    await deleteObject(environment.cloudStorageBucket, storedName, environment)
    return
  }

  try {
    await rm(resolveStoredFilePath(storedName), { force: true })
  } catch {
    throw new HttpError(500, 'The stored file could not be deleted.')
  }
}

export async function deleteEncryptedBackup(
  backupPath: string,
  environment: EnvironmentConfig,
): Promise<void> {
  if (environment.storageProvider === 's3') {
    if (!/^backups\/[0-9a-f-]{36}\.enc$/i.test(backupPath)) {
      throw new HttpError(400, 'Invalid backup identifier.')
    }
    await deleteObject(environment.cloudBackupBucket, backupPath, environment)
    return
  }

  try {
    await rm(resolveLocalBackupPath(backupPath), { force: true })
  } catch {
    throw new HttpError(500, 'The encrypted backup could not be deleted.')
  }
}
