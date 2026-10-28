import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  type Relation,
  UpdateDateColumn,
} from 'typeorm'
import { User } from './User.js'

@Entity({ name: 'email_mfa_challenges' })
@Index('UQ_email_mfa_challenges_challenge_id', ['challengeId'], { unique: true })
@Index('IDX_email_mfa_challenges_user_expiry', ['userId', 'expiresAt'])
export class EmailMfaChallenge {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ name: 'challenge_id', type: 'uuid' })
  challengeId!: string

  @Column({ name: 'user_id', type: 'uuid' })
  userId!: string

  @Column({ name: 'code_hash', type: 'varchar', length: 64 })
  codeHash!: string

  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt!: Date

  @Column({ name: 'sent_at', type: 'timestamptz' })
  sentAt!: Date

  @Column({ name: 'send_count', type: 'smallint', default: 1 })
  sendCount!: number

  @Column({ type: 'smallint', default: 0 })
  attempts!: number

  @Column({ name: 'consumed_at', type: 'timestamptz', nullable: true })
  consumedAt!: Date | null

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt!: Date

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt!: Date

  @ManyToOne(() => User, { nullable: false, onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id', foreignKeyConstraintName: 'FK_email_mfa_challenges_user' })
  user!: Relation<User>
}
