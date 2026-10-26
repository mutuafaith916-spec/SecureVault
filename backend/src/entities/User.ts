import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm'
import { AuditLog } from './AuditLog.js'
import { FileEntity } from './File.js'
import { FileShare } from './FileShare.js'
import { RefreshToken } from './RefreshToken.js'

export enum UserRole {
  USER = 'USER',
  ADMIN = 'ADMIN',
}

@Entity({ name: 'users' })
@Index('UQ_users_email', ['email'], { unique: true })
export class User {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ name: 'full_name', type: 'varchar', length: 160 })
  fullName!: string

  @Column({ type: 'varchar', length: 320 })
  email!: string

  @Column({ name: 'password_hash', type: 'varchar', length: 255, select: false })
  passwordHash!: string

  @Column({ type: 'enum', enum: UserRole, enumName: 'user_role_enum', default: UserRole.USER })
  role!: UserRole

  @Column({ name: 'auth_version', type: 'integer', default: 0 })
  authVersion!: number

  @Column({ name: 'failed_login_attempts', type: 'integer', default: 0 })
  failedLoginAttempts!: number

  @Column({ name: 'login_locked_until', type: 'timestamptz', nullable: true })
  loginLockedUntil!: Date | null

  @Column({ name: 'mfa_secret', type: 'text', nullable: true, select: false })
  mfaSecret!: string | null

  @Column({ name: 'mfa_enabled', type: 'boolean', default: false })
  mfaEnabled!: boolean

  @Column({ name: 'mfa_last_used_step', type: 'bigint', default: -1 })
  mfaLastUsedStep!: string

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt!: Date

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt!: Date

  @OneToMany(() => FileEntity, (file) => file.owner)
  files!: FileEntity[]

  @OneToMany(() => AuditLog, (auditLog) => auditLog.user)
  auditLogs!: AuditLog[]

  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
  refreshTokens!: RefreshToken[]

  @OneToMany(() => FileShare, (fileShare) => fileShare.sharedByUser)
  sharesCreated!: FileShare[]

  @OneToMany(() => FileShare, (fileShare) => fileShare.sharedWithUser)
  sharesReceived!: FileShare[]
}
