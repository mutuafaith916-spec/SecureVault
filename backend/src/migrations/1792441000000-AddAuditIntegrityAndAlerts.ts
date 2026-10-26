import type { MigrationInterface, QueryRunner } from 'typeorm'
import { calculateAuditHash, initialAuditHash } from '../utils/auditHash.js'

interface AuditRow {
  id: string
  user_id: string | null
  action: string
  file_id: string | null
  ip_address: string | null
  user_agent: string | null
  created_at: Date | string
  details: Record<string, string | number | boolean | null> | null
  chain_position: string
}

export class AddAuditIntegrityAndAlerts1792441000000 implements MigrationInterface {
  name = 'AddAuditIntegrityAndAlerts1792441000000'

  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "audit_logs"
      ADD "details" jsonb NOT NULL DEFAULT '{}'::jsonb,
      ADD "previous_hash" character varying(64),
      ADD "entry_hash" character varying(64),
      ADD "chain_position" bigint`)
    await queryRunner.query(`ALTER TYPE "audit_action_enum" ADD VALUE IF NOT EXISTS 'PRIVILEGE_CHANGED'`)

    const rows = await queryRunner.query(`SELECT
      "id", "user_id", "action", "file_id", "ip_address"::text AS "ip_address",
      "user_agent", "created_at", "details"
      FROM "audit_logs"
      ORDER BY "created_at" ASC, "id" ASC`) as AuditRow[]
    let previousHash = initialAuditHash
    let chainPosition = 0
    for (const row of rows) {
      chainPosition += 1
      const details = row.details ?? {}
      const createdAt = row.created_at instanceof Date ? row.created_at : new Date(row.created_at)
      const entryHash = calculateAuditHash(previousHash, {
        id: row.id,
        userId: row.user_id,
        action: row.action,
        fileId: row.file_id,
        ipAddress: row.ip_address,
        userAgent: row.user_agent,
        createdAt,
        details,
      })
      await queryRunner.query(
        `UPDATE "audit_logs"
         SET "details" = $1, "previous_hash" = $2, "entry_hash" = $3, "chain_position" = $4
         WHERE "id" = $5`,
        [JSON.stringify(details), previousHash, entryHash, chainPosition, row.id],
      )
      previousHash = entryHash
    }

    await queryRunner.query(`ALTER TABLE "audit_logs"
      ALTER COLUMN "previous_hash" SET NOT NULL,
      ALTER COLUMN "entry_hash" SET NOT NULL,
      ALTER COLUMN "chain_position" SET NOT NULL`)
    await queryRunner.query(`CREATE SEQUENCE "audit_logs_chain_position_seq" START WITH ${chainPosition + 1}`)
    await queryRunner.query(`ALTER TABLE "audit_logs"
      ALTER COLUMN "chain_position" SET DEFAULT nextval('"audit_logs_chain_position_seq"')`)
    await queryRunner.query(`ALTER SEQUENCE "audit_logs_chain_position_seq" OWNED BY "audit_logs"."chain_position"`)
    await queryRunner.query(`CREATE UNIQUE INDEX "UQ_audit_logs_chain_position" ON "audit_logs" ("chain_position")`)
    await queryRunner.query(`CREATE TABLE "security_alert_suppressions" (
      "alert_key" varchar(255) NOT NULL,
      "last_alert_at" timestamptz NOT NULL,
      CONSTRAINT "PK_security_alert_suppressions" PRIMARY KEY ("alert_key")
    )`)
    await queryRunner.query(`CREATE FUNCTION "reject_audit_log_mutation"() RETURNS trigger
      LANGUAGE plpgsql AS $$
      BEGIN
        RAISE EXCEPTION 'audit_logs is append-only';
      END;
      $$`)
    await queryRunner.query(`CREATE TRIGGER "TR_audit_logs_append_only"
      BEFORE UPDATE OR DELETE ON "audit_logs"
      FOR EACH ROW EXECUTE FUNCTION "reject_audit_log_mutation"()`)
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TRIGGER IF EXISTS "TR_audit_logs_append_only" ON "audit_logs"`)
    await queryRunner.query(`DROP FUNCTION IF EXISTS "reject_audit_log_mutation"()`)
    await queryRunner.query(`DROP TABLE "security_alert_suppressions"`)
    await queryRunner.query(`ALTER TABLE "audit_logs"
      DROP COLUMN "entry_hash",
      DROP COLUMN "previous_hash",
      DROP COLUMN "details",
      DROP COLUMN "chain_position"`)
  }
}
