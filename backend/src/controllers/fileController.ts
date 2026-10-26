import type { Request, RequestHandler } from 'express'
import type { DataSource } from 'typeorm'
import { Brackets, In, IsNull, MoreThan, Not } from 'typeorm'
import { AuditAction } from '../entities/AuditLog.js'
import { Backup, BackupStatus } from '../entities/Backup.js'
import { FileEntity } from '../entities/File.js'
import { FileShare } from '../entities/FileShare.js'
import type { EnvironmentConfig } from '../config/environment.js'
import type { AuthenticatedRequest } from '../middleware/authMiddleware.js'
import { decryptFile, encryptFile } from '../services/fileEncryptionService.js'
import {
  deleteEncryptedBackup,
  deleteEncryptedFile,
  readEncryptedBackup,
  readEncryptedFile,
  restoreEncryptedFile,
  saveEncryptedBackup,
  saveEncryptedFile,
} from '../services/fileStorageService.js'
import { writeAuditLog } from '../services/auditLog.service.js'
import { scanUploadForMalware } from '../services/malwareScanner.js'
import { validateUploadFile } from '../services/uploadValidation.js'
import { HttpError } from '../types/http.js'
import { logger } from '../utils/logger.js'

const encryptionVersion = 1
const base64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/

interface UploadBody {
  originalName: string
  mimeType: string
  contentBase64: string
}

function getUserId(request: Request): string {
  const userId = (request as AuthenticatedRequest).user?.id
  if (!userId) {
    throw new HttpError(401, 'Please log in to continue.')
  }
  return userId
}

function parseUploadBody(body: unknown): UploadBody {
  if (typeof body !== 'object' || body === null) {
    throw new HttpError(400, 'Provide a file name, MIME type, and base64-encoded file content.')
  }

  const { originalName, mimeType, contentBase64 } = body as Record<string, unknown>
  if (
    typeof originalName !== 'string' ||
    typeof mimeType !== 'string' ||
    typeof contentBase64 !== 'string'
  ) {
    throw new HttpError(400, 'Provide a file name, MIME type, and base64-encoded file content.')
  }

  const safeName = originalName.trim()
  if (
    !safeName ||
    safeName.length > 1024 ||
    /[\/\\\0]/.test(safeName)
  ) {
    throw new HttpError(400, 'The file name is invalid.')
  }
  if (!mimeType.trim() || mimeType.length > 255) {
    throw new HttpError(400, 'The file MIME type is invalid.')
  }
  if (!contentBase64 || !base64Pattern.test(contentBase64)) {
    throw new HttpError(400, 'The file content must be valid base64 data.')
  }
  const decoded = Buffer.from(contentBase64, 'base64')
  if (
    decoded.toString('base64') !== contentBase64 ||
    decoded.length === 0 ||
    decoded.length > 700 * 1024
  ) {
    throw new HttpError(400, 'The file content must be valid base64 data and no larger than 700 KB.')
  }
  validateUploadFile(safeName, mimeType.trim(), decoded)

  return { originalName: safeName, mimeType: mimeType.trim(), contentBase64 }
}

export function createFileUploadController(
  dataSource: DataSource,
  environment: EnvironmentConfig,
): RequestHandler {
  return async (request, response) => {
    const userId = getUserId(request)
    const { originalName, mimeType, contentBase64 } = parseUploadBody(request.body)
    const fileData = Buffer.from(contentBase64, 'base64')
    await scanUploadForMalware(fileData, environment)
    const encrypted = encryptFile(fileData, environment)
    const storedFile = await saveEncryptedFile(encrypted.encryptedData, environment)
    let backupPath: string | undefined

    try {
      backupPath = await saveEncryptedBackup(encrypted.encryptedData, environment)
      const file = await dataSource.transaction(async (manager) => {
        const fileRecord = manager.getRepository(FileEntity).create({
          ownerId: userId,
          originalName,
          storedName: storedFile.storedName,
          filePath: storedFile.filePath,
          fileSize: String(fileData.length),
          mimeType,
          encryptionVersion,
          encryptionIv: encrypted.iv,
          encryptionAuthTag: encrypted.authTag,
        })
        const savedFile = await manager.getRepository(FileEntity).save(fileRecord)
        await manager.getRepository(Backup).save(manager.getRepository(Backup).create({
          fileId: savedFile.id,
          backupPath,
          status: BackupStatus.COMPLETED,
          encryptionVersion,
          encryptionIv: encrypted.iv,
          encryptionAuthTag: encrypted.authTag,
        }))
        await writeAuditLog(manager, request, AuditAction.FILE_UPLOADED, userId, savedFile.id)
        await writeAuditLog(manager, request, AuditAction.BACKUP_CREATED, userId, savedFile.id)
        return savedFile
      })

      response.status(201).json({
        success: true,
        message: 'File uploaded and encrypted successfully.',
        file: {
          id: file.id,
          originalName: file.originalName,
          fileSize: file.fileSize,
          mimeType: file.mimeType,
          createdAt: file.createdAt,
        },
      })
    } catch (error) {
      const cleanup = await Promise.allSettled([
        deleteEncryptedFile(storedFile.storedName, environment),
        ...(backupPath ? [deleteEncryptedBackup(backupPath, environment)] : []),
      ])
      const cleanupFailures = cleanup.filter((result) => result.status === 'rejected')
      if (cleanupFailures.length > 0) {
        logger.error(
          { event: 'file.upload_cleanup_failed', cleanupFailureCount: cleanupFailures.length },
          'Stored file data could not be fully cleaned up after an upload failure',
        )
      }
      throw error
    }
  }
}

export function createListFilesController(dataSource: DataSource): RequestHandler {
  return async (request, response) => {
    const userId = getUserId(request)
    const fileSelection = {
      id: true,
      originalName: true,
      fileSize: true,
      mimeType: true,
      createdAt: true,
    }
    const ownedFiles = await dataSource.getRepository(FileEntity).find({
      where: { ownerId: userId },
      order: { createdAt: 'DESC' },
      select: fileSelection,
    })
    const now = new Date()
    const sharedFiles = await dataSource.getRepository(FileShare).find({
      where: [
        { sharedWith: userId, expiresAt: IsNull(), file: { deletedAt: IsNull() } },
        { sharedWith: userId, expiresAt: MoreThan(now), file: { deletedAt: IsNull() } },
      ],
      relations: { file: true },
      select: {
        permission: true,
        file: fileSelection,
      },
    })

    const files = [
      ...ownedFiles.map((file) => ({ ...file, access: 'OWNER' as const, permission: 'DOWNLOAD' as const })),
      ...sharedFiles.filter((share) => share.file).map((share) => ({
        ...share.file,
        access: 'SHARED' as const,
        permission: share.permission,
      })),
    ].sort((first, second) => second.createdAt.getTime() - first.createdAt.getTime())

    if (files.length > 0) {
      await dataSource.transaction(async (manager) => {
        for (const file of files) {
          await writeAuditLog(manager, request, AuditAction.FILE_VIEWED, userId, file.id)
        }
      })
    }

    response.status(200).json({ success: true, files })
  }
}

export function createDownloadFileController(
  dataSource: DataSource,
  environment: EnvironmentConfig,
): RequestHandler {
  return async (request, response) => {
    const authenticatedRequest = request as AuthenticatedRequest
    const user = authenticatedRequest.user
    const fileId = request.params.id
    if (!user) {
      throw new HttpError(401, 'Please log in to download files.')
    }

    if (typeof fileId !== 'string' || !fileId) {
      throw new HttpError(400, 'A valid file identifier is required.')
    }

    const now = new Date()
    const file = await dataSource.getRepository(FileEntity)
      .createQueryBuilder('file')
      .where('file.id = :fileId', { fileId })
      .andWhere(new Brackets((query) => {
        query
          .where('file.ownerId = :userId')
          .orWhere(`EXISTS (
            SELECT 1
            FROM "file_shares" "share"
            WHERE "share"."file_id" = "file"."id"
              AND "share"."shared_with" = :userId
              AND "share"."shared_by" = "file"."owner_id"
              AND "share"."permission" = :downloadPermission
              AND ("share"."expires_at" IS NULL OR "share"."expires_at" > :now)
          )`)
      }))
      .setParameters({
        userId: user.id,
        downloadPermission: 'DOWNLOAD',
        now,
      })
      .getOne()
    if (!file) {
      await dataSource.transaction((manager) =>
        writeAuditLog(
          manager,
          request,
          AuditAction.UNAUTHORIZED_ACCESS,
          user.id,
          null,
          environment,
          { attemptedFileId: fileId.slice(0, 128) },
        ),
      )
      throw new HttpError(404, 'The file could not be found.')
    }

    if (file.encryptionVersion !== encryptionVersion) {
      throw new HttpError(400, 'This file uses an unsupported encryption version.')
    }

    const encryptedData = await readEncryptedFile(file.storedName, environment)
    const decryptedData = decryptFile(
      encryptedData,
      file.encryptionIv,
      file.encryptionAuthTag,
      environment,
    )
    await dataSource.transaction((manager) =>
      writeAuditLog(manager, request, AuditAction.FILE_DOWNLOADED, user.id, file.id, environment),
    )

    const safeName = file.originalName
      .replace(/[\r\n"]/g, '_')
      .replace(/[\\/]/g, '_')

    response.status(200)
    response.setHeader('Content-Type', 'application/octet-stream')
    response.setHeader(
      'Content-Disposition',
      `attachment; filename="${safeName}"`,
    )
    response.setHeader('Content-Length', String(decryptedData.length))
    response.send(decryptedData)
  }
}

export function createDeleteFileController(dataSource: DataSource, environment: EnvironmentConfig): RequestHandler {
  return async (request, response) => {
    const userId = getUserId(request)
    const fileId = request.params.id
    if (typeof fileId !== 'string' || !fileId) {
      throw new HttpError(400, 'A file identifier is required.')
    }

    const file = await dataSource.transaction(async (manager) => {
      const files = manager.getRepository(FileEntity)
      const ownedFile = await files.findOneBy({ id: fileId, ownerId: userId })
      if (!ownedFile) {
        throw new HttpError(404, 'The requested file could not be found.')
      }

      await files.softDelete({ id: ownedFile.id, ownerId: userId })
      await writeAuditLog(manager, request, AuditAction.FILE_DELETED, userId, ownedFile.id)
      return ownedFile
    })

    await deleteEncryptedFile(file.storedName, environment)
    response.status(200).json({
      success: true,
      message: 'File deleted successfully.',
    })
  }
}

export function createListFileBackupsController(dataSource: DataSource): RequestHandler {
  return async (request, response) => {
    const userId = getUserId(request)
    const fileId = request.params.id
    if (typeof fileId !== 'string' || !fileId) {
      throw new HttpError(400, 'A valid file identifier is required.')
    }

    const file = await dataSource.getRepository(FileEntity).findOneBy({ id: fileId, ownerId: userId })
    if (!file) {
      throw new HttpError(404, 'The file could not be found.')
    }

    const backups = await dataSource.getRepository(Backup).find({
      where: { fileId, status: BackupStatus.COMPLETED },
      order: { createdAt: 'DESC' },
      select: { id: true, status: true, createdAt: true },
    })
    response.status(200).json({
      success: true,
      backups: backups.map(({ id, status, createdAt }) => ({ id, status, createdAt })),
    })
  }
}

export function createListDeletedFilesController(dataSource: DataSource): RequestHandler {
  return async (request, response) => {
    const userId = getUserId(request)
    const deletedFiles = await dataSource.getRepository(FileEntity).find({
      withDeleted: true,
      where: { ownerId: userId, deletedAt: Not(IsNull()) },
      order: { deletedAt: 'DESC' },
      select: { id: true, originalName: true, fileSize: true, deletedAt: true },
    })
    const fileIds = deletedFiles.map((file) => file.id)
    const backups = fileIds.length > 0
      ? await dataSource.getRepository(Backup).find({
        where: { fileId: In(fileIds), status: BackupStatus.COMPLETED },
        order: { createdAt: 'DESC' },
        select: { id: true, fileId: true, createdAt: true },
      })
      : []
    const latestBackupByFile = new Map<string, Backup>()
    for (const backup of backups) {
      if (!latestBackupByFile.has(backup.fileId)) {
        latestBackupByFile.set(backup.fileId, backup)
      }
    }

    response.status(200).json({
      success: true,
      deletedFiles: deletedFiles.map((file) => ({
        id: file.id,
        originalName: file.originalName,
        fileSize: file.fileSize,
        deletedAt: file.deletedAt,
        backupId: latestBackupByFile.get(file.id)?.id ?? null,
      })),
    })
  }
}

export function createRestoreFileBackupController(
  dataSource: DataSource,
  environment: EnvironmentConfig,
): RequestHandler {
  return async (request, response) => {
    const userId = getUserId(request)
    const fileId = request.params.id
    const backupId = request.params.backupId
    if (typeof fileId !== 'string' || !fileId || typeof backupId !== 'string' || !backupId) {
      throw new HttpError(400, 'A valid file and backup identifier are required.')
    }

    const file = await dataSource.getRepository(FileEntity).findOne({
      where: { id: fileId, ownerId: userId },
      withDeleted: true,
    })
    if (!file) {
      throw new HttpError(404, 'The file could not be found.')
    }
    const backup = await dataSource.getRepository(Backup).findOneBy({
      id: backupId,
      fileId,
      status: BackupStatus.COMPLETED,
    })
    if (!backup) {
      throw new HttpError(404, 'The encrypted backup could not be found.')
    }
    const { encryptionVersion: backupEncryptionVersion, encryptionIv, encryptionAuthTag } = backup
    if (
      backupEncryptionVersion !== encryptionVersion ||
      !encryptionIv ||
      !encryptionAuthTag
    ) {
      throw new HttpError(400, 'This backup does not have supported encryption metadata.')
    }

    const encryptedData = await readEncryptedBackup(backup.backupPath, environment)
    decryptFile(encryptedData, encryptionIv, encryptionAuthTag, environment)
    await restoreEncryptedFile(file.storedName, encryptedData, environment)
    await dataSource.transaction(async (manager) => {
      if (file.deletedAt) {
        await manager.getRepository(FileEntity).recover(file)
      }
      await manager.getRepository(FileEntity).update(
        { id: file.id, ownerId: userId },
        {
          encryptionVersion: backupEncryptionVersion,
          encryptionIv,
          encryptionAuthTag,
        },
      )
      await writeAuditLog(manager, request, AuditAction.FILE_RESTORED, userId, file.id)
    })

    response.status(200).json({ success: true, message: 'The encrypted backup was restored successfully.' })
  }
}
