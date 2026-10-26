import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm'
import { FileEntity } from './File.js'
import { User } from './User.js'

export enum AuditAction {
  REGISTER = 'REGISTER',
  LOGIN = 'LOGIN',
  LOGIN_FAILED = 'LOGIN_FAILED',
  PASSWORD_RESET = 'PASSWORD_RESET',
  LOGOUT = 'LOGOUT',
  TOKEN_REFRESH = 'TOKEN_REFRESH',
  FILE_UPLOADED = 'FILE_UPLOADED',
  BACKUP_CREATED = 'BACKUP_CREATED',
  FILE_RESTORED = 'FILE_RESTORED',
  FILE_VIEWED = 'FILE_VIEWED',
  FILE_DOWNLOADED = 'FILE_DOWNLOADED',
  FILE_RENAMED = 'FILE_RENAMED',
  FILE_DELETED = 'FILE_DELETED',
  FILE_SHARED = 'FILE_SHARED',
  SHARE_REVOKED = 'SHARE_REVOKED',
  UNAUTHORIZED_ACCESS = 'UNAUTHORIZED_ACCESS',
  PRIVILEGE_CHANGED = 'PRIVILEGE_CHANGED',
  DATA_EXPORTED = 'DATA_EXPORTED',
  FILE_PURGED = 'FILE_PURGED',
}

@Entity({ name: 'audit_logs' })
@Index('IDX_audit_logs_user_created_at', ['userId', 'createdAt'])
@Index('IDX_audit_logs_file_created_at', ['fileId', 'createdAt'])
export class AuditLog {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ name: 'user_id', type: 'uuid', nullable: true })
  userId!: string | null

  @Column({ type: 'enum', enum: AuditAction, enumName: 'audit_action_enum' })
  action!: AuditAction

  @Column({ name: 'file_id', type: 'uuid', nullable: true })
  fileId!: string | null

  @Column({ name: 'ip_address', type: 'inet', nullable: true })
  ipAddress!: string | null

  @Column({ name: 'user_agent', type: 'text', nullable: true })
  userAgent!: string | null

  @Column({ type: 'jsonb', default: () => "'{}'::jsonb" })
  details!: Record<string, string | number | boolean | null>

  @Column({ name: 'previous_hash', type: 'varchar', length: 64 })
  previousHash!: string

  @Column({ name: 'entry_hash', type: 'varchar', length: 64 })
  entryHash!: string

  @Column({ name: 'chain_position', type: 'bigint' })
  chainPosition!: string

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt!: Date

  @ManyToOne(() => User, (user) => user.auditLogs, { nullable: true, onDelete: 'SET NULL' })
  @JoinColumn({ name: 'user_id', foreignKeyConstraintName: 'FK_audit_logs_user' })
  user!: User | null

  @ManyToOne(() => FileEntity, (file) => file.auditLogs, { nullable: true, onDelete: 'SET NULL' })
  @JoinColumn({ name: 'file_id', foreignKeyConstraintName: 'FK_audit_logs_file' })
  file!: FileEntity | null
}
