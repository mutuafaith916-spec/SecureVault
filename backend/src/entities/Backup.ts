import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  type Relation,
} from 'typeorm'
import { FileEntity } from './File.js'

export enum BackupStatus {
  PENDING = 'PENDING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
}

@Entity({ name: 'backups' })
@Index('IDX_backups_file_created_at', ['fileId', 'createdAt'])
export class Backup {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ name: 'file_id', type: 'uuid' })
  fileId!: string

  @Column({ name: 'backup_path', type: 'text' })
  backupPath!: string

  @Column({ name: 'encryption_version', type: 'smallint', nullable: true })
  encryptionVersion!: number | null

  @Column({ name: 'encryption_iv', type: 'varchar', length: 128, nullable: true })
  encryptionIv!: string | null

  @Column({ name: 'encryption_auth_tag', type: 'varchar', length: 128, nullable: true })
  encryptionAuthTag!: string | null

  @Column({ type: 'enum', enum: BackupStatus, enumName: 'backup_status_enum', default: BackupStatus.PENDING })
  status!: BackupStatus

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt!: Date

  @ManyToOne(() => FileEntity, (file) => file.backups, { nullable: false, onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'file_id', foreignKeyConstraintName: 'FK_backups_file' })
  file!: Relation<FileEntity>
}
