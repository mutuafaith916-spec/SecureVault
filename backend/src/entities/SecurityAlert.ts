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

export type SecurityAlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type SecurityAlertStatus = 'OPEN' | 'REVIEWED' | 'RESOLVED'

@Entity({ name: 'security_alerts' })
@Index('UQ_security_alerts_alert_key', ['alertKey'], { unique: true })
@Index('IDX_security_alerts_status_created_at', ['status', 'createdAt'])
@Index('IDX_security_alerts_severity_created_at', ['severity', 'createdAt'])
export class SecurityAlert {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ name: 'alert_key', type: 'varchar', length: 64 })
  alertKey!: string

  @Column({ name: 'rule_id', type: 'varchar', length: 100 })
  ruleId!: string

  @Column({ name: 'event_type', type: 'varchar', length: 64 })
  eventType!: string

  @Column({ type: 'varchar', length: 16 })
  severity!: SecurityAlertSeverity

  @Column({ type: 'varchar', length: 16, default: 'OPEN' })
  status!: SecurityAlertStatus

  @Column({ name: 'actor_id', type: 'uuid', nullable: true })
  actorId!: string | null

  @Column({ name: 'source_ip', type: 'inet', nullable: true })
  sourceIp!: string | null

  @Column({ type: 'jsonb', default: () => "'{}'::jsonb" })
  evidence!: Record<string, string | number | boolean | null>

  @Column({ name: 'occurrence_count', type: 'integer', default: 1 })
  occurrenceCount!: number

  @Column({ name: 'last_seen_at', type: 'timestamptz' })
  lastSeenAt!: Date

  @Column({ name: 'reviewed_at', type: 'timestamptz', nullable: true })
  reviewedAt!: Date | null

  @Column({ name: 'reviewed_by', type: 'uuid', nullable: true })
  reviewedBy!: string | null

  @Column({ name: 'resolved_at', type: 'timestamptz', nullable: true })
  resolvedAt!: Date | null

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt!: Date

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt!: Date

  @ManyToOne(() => User, { nullable: true, onDelete: 'SET NULL' })
  @JoinColumn({ name: 'actor_id', foreignKeyConstraintName: 'FK_security_alerts_actor' })
  actor!: Relation<User | null>

  @ManyToOne(() => User, { nullable: true, onDelete: 'SET NULL' })
  @JoinColumn({ name: 'reviewed_by', foreignKeyConstraintName: 'FK_security_alerts_reviewer' })
  reviewer!: Relation<User | null>
}
