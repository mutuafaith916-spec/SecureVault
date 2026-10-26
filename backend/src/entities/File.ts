import {
  Column,
  CreateDateColumn,
  DeleteDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm'
import { AuditLog } from './AuditLog.js'
import { Backup } from './Backup.js'
import { FileShare } from './FileShare.js'
import { User } from './User.js'

@Entity({ name: 'files' })
@Index('IDX_files_owner_created_at', ['ownerId', 'createdAt'])
export class FileEntity {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ name: 'owner_id', type: 'uuid' })
  ownerId!: string

  @Column({ name: 'original_name', type: 'varchar', length: 1024 })
  originalName!: string

  @Column({ name: 'stored_name', type: 'varchar', length: 255 })
  storedName!: string

  @Column({ name: 'file_path', type: 'text' })
  filePath!: string

  @Column({ name: 'file_size', type: 'bigint' })
  fileSize!: string

  @Column({ name: 'mime_type', type: 'varchar', length: 255 })
  mimeType!: string

  @Column({ name: 'encryption_version', type: 'smallint' })
  encryptionVersion!: number

  @Column({ name: 'encryption_iv', type: 'varchar', length: 128 })
  encryptionIv!: string

  @Column({ name: 'encryption_auth_tag', type: 'varchar', length: 128 })
  encryptionAuthTag!: string

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt!: Date

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt!: Date

  @DeleteDateColumn({ name: 'deleted_at', type: 'timestamptz', nullable: true })
  deletedAt!: Date | null

  @ManyToOne(() => User, (user) => user.files, { nullable: false, onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'owner_id', foreignKeyConstraintName: 'FK_files_owner' })
  owner!: User

  @OneToMany(() => FileShare, (fileShare) => fileShare.file)
  shares!: FileShare[]

  @OneToMany(() => AuditLog, (auditLog) => auditLog.file)
  auditLogs!: AuditLog[]

  @OneToMany(() => Backup, (backup) => backup.file)
  backups!: Backup[]
}
