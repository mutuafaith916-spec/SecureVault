import type { RequestHandler } from 'express'
import type { DataSource } from 'typeorm'
import type { EnvironmentConfig } from '../config/environment.js'
import { Backup, BackupStatus } from '../entities/Backup.js'
import { FileEntity } from '../entities/File.js'
import { FileShare } from '../entities/FileShare.js'
import { User } from '../entities/User.js'
import { requireAdminId } from '../middleware/adminAuthorization.js'
import { getHealthStatus } from '../services/healthService.js'
import { HttpError } from '../types/http.js'

const maximumPageSize = 100
const maximumPage = 10_000

function parsePageValue(value: unknown, defaultValue: number, maximum: number): number {
  if (value === undefined) return defaultValue
  if (typeof value !== 'string' || !/^\d+$/.test(value)) {
    throw new HttpError(400, 'Pagination values must be positive integers.')
  }
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw new HttpError(400, 'Pagination value is outside the supported range.')
  }
  return parsed
}

export function createAdminUsersController(dataSource: DataSource): RequestHandler {
  return async (request, response) => {
    requireAdminId(request)
    const page = parsePageValue(request.query.page, 1, maximumPage)
    const pageSize = parsePageValue(request.query.pageSize, 25, maximumPageSize)
    const search = request.query.search === undefined ? '' : request.query.search
    if (typeof search !== 'string' || search.trim().length > 100) {
      throw new HttpError(400, 'Search must be 100 characters or fewer.')
    }

    const query = dataSource.getRepository(User).createQueryBuilder('user')
    const normalizedSearch = search.trim()
    if (normalizedSearch) {
      query.where('(user.email ILIKE :search OR user.fullName ILIKE :search)', {
        search: `%${normalizedSearch}%`,
      })
    }
    const [users, total] = await query
      .select([
        'user.id',
        'user.fullName',
        'user.email',
        'user.role',
        'user.mfaEnabled',
        'user.loginLockedUntil',
        'user.createdAt',
      ])
      .orderBy('user.createdAt', 'DESC')
      .skip((page - 1) * pageSize)
      .take(pageSize)
      .getManyAndCount()

    response.status(200).json({
      success: true,
      users: users.map((user) => ({
        id: user.id,
        fullName: user.fullName,
        email: user.email,
        role: user.role,
        mfaEnabled: user.mfaEnabled,
        lockedUntil: user.loginLockedUntil && user.loginLockedUntil > new Date()
          ? user.loginLockedUntil
          : null,
        createdAt: user.createdAt,
      })),
      pagination: { page, pageSize, total },
    })
  }
}

export function createAdminOverviewController(
  dataSource: DataSource,
  environment: EnvironmentConfig,
): RequestHandler {
  return async (request, response) => {
    const currentAdminId = requireAdminId(request)
    const [users, activeFiles, storage, activeShares, backupGroups, mfaUsers, health] =
      await Promise.all([
        dataSource.getRepository(User).count(),
        dataSource.getRepository(FileEntity).count(),
        dataSource.getRepository(FileEntity).createQueryBuilder('file')
          .select('COALESCE(SUM(file.fileSize::numeric), 0)', 'bytes')
          .getRawOne<{ bytes: string }>(),
        dataSource.getRepository(FileShare).createQueryBuilder('share')
          .innerJoin('share.file', 'file')
          .where('file.deletedAt IS NULL')
          .andWhere('(share.expiresAt IS NULL OR share.expiresAt > :now)', { now: new Date() })
          .getCount(),
        dataSource.getRepository(Backup).createQueryBuilder('backup')
          .select('backup.status', 'status')
          .addSelect('COUNT(backup.id)', 'count')
          .groupBy('backup.status')
          .getRawMany<{ status: BackupStatus; count: string }>(),
        dataSource.getRepository(User).countBy({ mfaEnabled: true }),
        getHealthStatus(environment.nodeEnv, dataSource),
      ])
    const backupCounts = { completed: 0, pending: 0, failed: 0 }
    for (const group of backupGroups) {
      if (group.status === BackupStatus.COMPLETED) backupCounts.completed = Number(group.count)
      if (group.status === BackupStatus.PENDING) backupCounts.pending = Number(group.count)
      if (group.status === BackupStatus.FAILED) backupCounts.failed = Number(group.count)
    }

    const s3ConfigurationComplete = Boolean(
      environment.cloudStorageEndpoint &&
      environment.cloudStorageRegion &&
      environment.cloudStorageBucket &&
      environment.cloudBackupBucket &&
      environment.cloudStorageAccessKeyId &&
      environment.cloudStorageSecretAccessKey,
    )
    response.status(200).json({
      success: true,
      currentAdminId,
      overview: {
        users,
        usersWithMfa: mfaUsers,
        activeFiles,
        storageUsedBytes: storage?.bytes ?? '0',
        activeShares,
        backups: backupCounts,
        health: {
          api: health.api,
          database: health.database,
          storage: {
            provider: environment.storageProvider,
            configuration: environment.storageProvider === 'local' || s3ConfigurationComplete
              ? 'configured'
              : 'incomplete',
            connectivity: 'not_checked',
          },
        },
      },
    })
  }
}
