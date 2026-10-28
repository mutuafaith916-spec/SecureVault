import type { RequestHandler } from 'express'
import type { DataSource } from 'typeorm'
import { Backup, BackupStatus } from '../entities/Backup.js'
import { FileEntity } from '../entities/File.js'
import { FileShare } from '../entities/FileShare.js'
import { User } from '../entities/User.js'
import type { AuthenticatedRequest } from '../middleware/authMiddleware.js'
import { HttpError } from '../types/http.js'

export function createFileOverviewController(dataSource: DataSource): RequestHandler {
  return async (request, response) => {
    const userId = (request as AuthenticatedRequest).user?.id
    if (!userId) {
      throw new HttpError(401, 'Please sign in to view your account overview.')
    }

    const now = new Date()
    const files = dataSource.getRepository(FileEntity)
    const shares = dataSource.getRepository(FileShare)
    const backups = dataSource.getRepository(Backup)
    const [ownedFiles, storage, sharesGiven, sharesReceived, backupGroups, user] =
      await Promise.all([
        files.countBy({ ownerId: userId }),
        files.createQueryBuilder('file')
          .select('COALESCE(SUM(file.fileSize::numeric), 0)', 'bytes')
          .where('file.ownerId = :userId', { userId })
          .getRawOne<{ bytes: string }>(),
        shares.createQueryBuilder('share')
          .innerJoin('share.file', 'file')
          .where('share.sharedBy = :userId', { userId })
          .andWhere('file.ownerId = :userId', { userId })
          .andWhere('file.deletedAt IS NULL')
          .andWhere('(share.expiresAt IS NULL OR share.expiresAt > :now)', { now })
          .getCount(),
        shares.createQueryBuilder('share')
          .innerJoin('share.file', 'file')
          .where('share.sharedWith = :userId', { userId })
          .andWhere('file.deletedAt IS NULL')
          .andWhere('(share.expiresAt IS NULL OR share.expiresAt > :now)', { now })
          .getCount(),
        backups.createQueryBuilder('backup')
          .innerJoin('backup.file', 'file')
          .select('backup.status', 'status')
          .addSelect('COUNT(backup.id)', 'count')
          .where('file.ownerId = :userId', { userId })
          .andWhere('file.deletedAt IS NULL')
          .groupBy('backup.status')
          .getRawMany<{ status: BackupStatus; count: string }>(),
        dataSource.getRepository(User).findOne({
          where: { id: userId },
          select: { id: true, fullName: true, email: true, role: true, mfaEnabled: true },
        }),
      ])

    if (!user) {
      throw new HttpError(401, 'Your session is invalid. Please sign in again.')
    }
    const backupCounts = {
      completed: 0,
      pending: 0,
      failed: 0,
    }
    for (const group of backupGroups) {
      if (group.status === BackupStatus.COMPLETED) backupCounts.completed = Number(group.count)
      if (group.status === BackupStatus.PENDING) backupCounts.pending = Number(group.count)
      if (group.status === BackupStatus.FAILED) backupCounts.failed = Number(group.count)
    }

    response.status(200).json({
      success: true,
      overview: {
        filesOwned: ownedFiles,
        storageUsedBytes: storage?.bytes ?? '0',
        sharesGiven,
        sharesReceived,
        backups: backupCounts,
        account: {
          fullName: user.fullName,
          email: user.email,
          role: user.role,
          mfaEnabled: user.mfaEnabled,
        },
      },
    })
  }
}
