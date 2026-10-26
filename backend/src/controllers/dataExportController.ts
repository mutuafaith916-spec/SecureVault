import type { RequestHandler } from 'express'
import type { DataSource } from 'typeorm'
import { Backup, BackupStatus } from '../entities/Backup.js'
import { FileEntity } from '../entities/File.js'
import { User } from '../entities/User.js'
import type { AuthenticatedRequest } from '../middleware/authMiddleware.js'
import type { EnvironmentConfig } from '../config/environment.js'
import { AuditAction } from '../entities/AuditLog.js'
import { decryptFile } from '../services/fileEncryptionService.js'
import { readEncryptedBackup, readEncryptedFile } from '../services/fileStorageService.js'
import { writeAuditLog } from '../services/auditLog.service.js'
import { HttpError } from '../types/http.js'

const maximumExportBytes = 50 * 1024 * 1024
const encryptionVersion = 1

export function createDataExportController(
  dataSource: DataSource,
  environment: EnvironmentConfig,
): RequestHandler {
  return async (request, response) => {
    const userId = (request as AuthenticatedRequest).user?.id
    if (!userId) {
      throw new HttpError(401, 'Please sign in to export your data.')
    }

    const [user, files] = await Promise.all([
      dataSource.getRepository(User).findOne({
        where: { id: userId },
        select: { id: true, fullName: true, email: true, role: true, createdAt: true },
      }),
      dataSource.getRepository(FileEntity).find({
        where: { ownerId: userId },
        withDeleted: true,
        order: { createdAt: 'ASC' },
      }),
    ])
    if (!user) {
      throw new HttpError(401, 'Your account is unavailable. Please sign in again.')
    }

    const exportedFiles: Array<{
      originalName: string
      mimeType: string
      fileSize: string
      createdAt: Date
      deletedAt: Date | null
      contentBase64: string
    }> = []
    let totalBytes = 0
    const backupRepository = dataSource.getRepository(Backup)

    for (const file of files) {
      if (file.encryptionVersion !== encryptionVersion) {
        throw new HttpError(409, `The export cannot include ${file.originalName} because its encryption version is unsupported.`)
      }
      let encryptedData: Buffer
      if (file.deletedAt) {
        const backup = await backupRepository.findOne({
          where: { fileId: file.id, status: BackupStatus.COMPLETED },
          order: { createdAt: 'DESC' },
        })
        if (!backup?.encryptionIv || !backup.encryptionAuthTag) {
          throw new HttpError(409, `The export cannot include ${file.originalName} because its recoverable backup is unavailable.`)
        }
        encryptedData = await readEncryptedBackup(backup.backupPath, environment)
        const plaintext = decryptFile(encryptedData, backup.encryptionIv, backup.encryptionAuthTag, environment)
        exportedFiles.push({
          originalName: file.originalName,
          mimeType: file.mimeType,
          fileSize: file.fileSize,
          createdAt: file.createdAt,
          deletedAt: file.deletedAt,
          contentBase64: plaintext.toString('base64'),
        })
        totalBytes += plaintext.length
      } else {
        encryptedData = await readEncryptedFile(file.storedName, environment)
        const plaintext = decryptFile(encryptedData, file.encryptionIv, file.encryptionAuthTag, environment)
        exportedFiles.push({
          originalName: file.originalName,
          mimeType: file.mimeType,
          fileSize: file.fileSize,
          createdAt: file.createdAt,
          deletedAt: null,
          contentBase64: plaintext.toString('base64'),
        })
        totalBytes += plaintext.length
      }
      if (totalBytes > maximumExportBytes) {
        throw new HttpError(413, 'Your data export is larger than 50 MB. Download files individually from your vault.')
      }
    }

    const exportData = {
      format: 'SecureVault user data export',
      version: 1,
      exportedAt: new Date().toISOString(),
      account: user,
      files: exportedFiles,
    }
    const json = JSON.stringify(exportData, null, 2)
    if (Buffer.byteLength(json, 'utf8') > maximumExportBytes) {
      throw new HttpError(413, 'Your data export is larger than 50 MB. Download files individually from your vault.')
    }

    await dataSource.transaction((manager) =>
      writeAuditLog(manager, request, AuditAction.DATA_EXPORTED, userId, null, environment, {
        fileCount: exportedFiles.length,
        plaintextBytes: totalBytes,
      }),
    )

    response.status(200)
    response.setHeader('Content-Type', 'application/json; charset=utf-8')
    response.setHeader('Content-Disposition', 'attachment; filename="securevault-data-export.json"')
    response.setHeader('Cache-Control', 'no-store')
    response.send(json)
  }
}
