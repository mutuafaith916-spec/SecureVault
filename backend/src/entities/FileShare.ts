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
import { User } from './User.js'

export enum FileSharePermission {
  VIEW = 'VIEW',
  DOWNLOAD = 'DOWNLOAD',
}

@Entity({ name: 'file_shares' })
@Index('IDX_file_shares_file_recipient', ['fileId', 'sharedWith'])
@Index('IDX_file_shares_recipient_expiry', ['sharedWith', 'expiresAt'])
export class FileShare {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ name: 'file_id', type: 'uuid' })
  fileId!: string

  @Column({ name: 'shared_by', type: 'uuid' })
  sharedBy!: string

  @Column({ name: 'shared_with', type: 'uuid' })
  sharedWith!: string

  @Column({
    type: 'enum',
    enum: FileSharePermission,
    enumName: 'file_share_permission_enum',
  })
  permission!: FileSharePermission

  @Column({ name: 'expires_at', type: 'timestamptz', nullable: true })
  expiresAt!: Date | null

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt!: Date

  @ManyToOne(() => FileEntity, (file) => file.shares, { nullable: false, onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'file_id', foreignKeyConstraintName: 'FK_file_shares_file' })
  file!: Relation<FileEntity>

  @ManyToOne(() => User, (user) => user.sharesCreated, { nullable: false, onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'shared_by', foreignKeyConstraintName: 'FK_file_shares_shared_by' })
  sharedByUser!: Relation<User>

  @ManyToOne(() => User, (user) => user.sharesReceived, { nullable: false, onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'shared_with', foreignKeyConstraintName: 'FK_file_shares_shared_with' })
  sharedWithUser!: Relation<User>
}
