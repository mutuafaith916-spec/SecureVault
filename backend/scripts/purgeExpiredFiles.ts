import { LessThan } from 'typeorm'
import { loadEnvironment } from '../src/config/environment.js'
import { createDatabaseDataSource } from '../src/config/database.js'
import { AuditAction } from '../src/entities/AuditLog.js'
import { Backup } from '../src/entities/Backup.js'
import { FileEntity } from '../src/entities/File.js'
import { FileShare } from '../src/entities/FileShare.js'
import { deleteEncryptedBackup, deleteEncryptedFile } from '../src/services/fileStorageService.js'
import { writeAuditLog } from '../src/services/auditLog.service.js'
import { logger } from '../src/utils/logger.js'

const retentionDays = 30

async function main(): Promise<void> {
  const environment = loadEnvironment()
  const dataSource = createDatabaseDataSource(environment)
  await dataSource.initialize()

  try {
    const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000)
    const expiredFiles = await dataSource.getRepository(FileEntity).find({
      withDeleted: true,
      where: { deletedAt: LessThan(cutoff) },
      order: { deletedAt: 'ASC' },
    })
    for (const file of expiredFiles) {
      const backups = await dataSource.getRepository(Backup).findBy({ fileId: file.id })
      await deleteEncryptedFile(file.storedName, environment)
      for (const backup of backups) {
        await deleteEncryptedBackup(backup.backupPath, environment)
      }
      await dataSource.transaction(async (manager) => {
        await manager.getRepository(FileShare).delete({ fileId: file.id })
        await manager.getRepository(Backup).delete({ fileId: file.id })
        await writeAuditLog(
          manager,
          {
            ip: undefined,
            get: (_name: string) => undefined,
          },
          AuditAction.FILE_PURGED,
          file.ownerId,
          file.id,
          environment,
          { retentionDays },
        )
        await manager.getRepository(FileEntity).delete({ id: file.id })
      })
    }
    logger.info(
      { event: 'retention.expired_files_purged', count: expiredFiles.length, retentionDays },
      'Expired deleted-file content and metadata purged',
    )
  } finally {
    await dataSource.destroy()
  }
}

main().catch((error: unknown) => {
  logger.error(
    {
      event: 'retention.expired_files_purge_failed',
      errorType: error instanceof Error ? error.name : 'UnknownError',
      message: error instanceof Error ? error.message : 'Unknown retention cleanup error',
    },
    'Expired deleted files could not be fully purged',
  )
  process.exitCode = 1
})
