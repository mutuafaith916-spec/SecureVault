import 'reflect-metadata'
import { DataSource } from 'typeorm'
import { AuditLog } from '../entities/AuditLog.js'
import { Backup } from '../entities/Backup.js'
import { FileEntity } from '../entities/File.js'
import { FileShare } from '../entities/FileShare.js'
import { RefreshToken } from '../entities/RefreshToken.js'
import { PasswordResetToken } from '../entities/PasswordResetToken.js'
import { User } from '../entities/User.js'
import { InitialSecureVaultSchema1760000000000 } from '../migrations/1760000000000-InitialSecureVaultSchema.js'
import { AddPasswordResetTokens1760724000000 } from '../migrations/1760724000000-AddPasswordResetTokens.js'
import { AddPasswordResetAuditAction1760725000000 } from '../migrations/1760725000000-AddPasswordResetAuditAction.js'
import { AddEncryptedCloudBackups1792350000000 } from '../migrations/1792350000000-AddEncryptedCloudBackups.js'
import { AddAuthenticationSecurityControls1792440000000 } from '../migrations/1792440000000-AddAuthenticationSecurityControls.js'
import { AddAuditIntegrityAndAlerts1792441000000 } from '../migrations/1792441000000-AddAuditIntegrityAndAlerts.js'
import { AddFileRetentionAndExportAudit1792442000000 } from '../migrations/1792442000000-AddFileRetentionAndExportAudit.js'
import type { EnvironmentConfig } from './environment.js'
import { loadEnvironment } from './environment.js'

export function createDatabaseDataSource(environment: EnvironmentConfig): DataSource {
  return new DataSource({
    type: 'postgres',
    url: environment.databaseUrl,
    entities: [User, FileEntity, FileShare, AuditLog, RefreshToken, PasswordResetToken, Backup],
    migrations: [
      InitialSecureVaultSchema1760000000000,
      AddPasswordResetTokens1760724000000,
      AddPasswordResetAuditAction1760725000000,
      AddEncryptedCloudBackups1792350000000,
      AddAuthenticationSecurityControls1792440000000,
      AddAuditIntegrityAndAlerts1792441000000,
      AddFileRetentionAndExportAudit1792442000000,
    ],
    migrationsTableName: 'typeorm_migrations',
    migrationsRun: false,
    migrationsTransactionMode: 'all',
    synchronize: false,
    logging: false,
    poolSize: 10,
    connectTimeoutMS: 10_000,
  })
}

const AppDataSource = createDatabaseDataSource(loadEnvironment())

export default AppDataSource
