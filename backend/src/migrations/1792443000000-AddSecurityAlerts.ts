import type { MigrationInterface, QueryRunner } from 'typeorm'

export class AddSecurityAlerts1792443000000 implements MigrationInterface {
  name = 'AddSecurityAlerts1792443000000'

  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TYPE "audit_action_enum" ADD VALUE IF NOT EXISTS 'SECURITY_ALERT_REVIEWED'`)
    await queryRunner.query(`ALTER TYPE "audit_action_enum" ADD VALUE IF NOT EXISTS 'SECURITY_ALERT_RESOLVED'`)
    await queryRunner.query(`CREATE TABLE "security_alerts" (
      "id" uuid NOT NULL DEFAULT gen_random_uuid(),
      "alert_key" character varying(64) NOT NULL,
      "rule_id" character varying(100) NOT NULL,
      "event_type" character varying(64) NOT NULL,
      "severity" character varying(16) NOT NULL,
      "status" character varying(16) NOT NULL DEFAULT 'OPEN',
      "actor_id" uuid,
      "source_ip" inet,
      "evidence" jsonb NOT NULL DEFAULT '{}'::jsonb,
      "occurrence_count" integer NOT NULL DEFAULT 1,
      "last_seen_at" timestamptz NOT NULL,
      "reviewed_at" timestamptz,
      "reviewed_by" uuid,
      "resolved_at" timestamptz,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      "updated_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "PK_security_alerts" PRIMARY KEY ("id"),
      CONSTRAINT "UQ_security_alerts_alert_key" UNIQUE ("alert_key"),
      CONSTRAINT "CHK_security_alerts_severity" CHECK ("severity" IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      CONSTRAINT "CHK_security_alerts_status" CHECK ("status" IN ('OPEN', 'REVIEWED', 'RESOLVED')),
      CONSTRAINT "CHK_security_alerts_occurrence_count" CHECK ("occurrence_count" > 0),
      CONSTRAINT "FK_security_alerts_actor" FOREIGN KEY ("actor_id") REFERENCES "users"("id") ON DELETE SET NULL,
      CONSTRAINT "FK_security_alerts_reviewer" FOREIGN KEY ("reviewed_by") REFERENCES "users"("id") ON DELETE SET NULL
    )`)
    await queryRunner.query(`CREATE INDEX "IDX_security_alerts_status_created_at"
      ON "security_alerts" ("status", "created_at" DESC)`)
    await queryRunner.query(`CREATE INDEX "IDX_security_alerts_severity_created_at"
      ON "security_alerts" ("severity", "created_at" DESC)`)
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE "security_alerts"`)
  }
}
