import type { MigrationInterface, QueryRunner } from 'typeorm'

export class AddFileRetentionAndExportAudit1792442000000 implements MigrationInterface {
  name = 'AddFileRetentionAndExportAudit1792442000000'

  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TYPE "audit_action_enum" ADD VALUE IF NOT EXISTS 'DATA_EXPORTED'`)
    await queryRunner.query(`ALTER TYPE "audit_action_enum" ADD VALUE IF NOT EXISTS 'FILE_PURGED'`)
    await queryRunner.query(`ALTER TABLE "audit_logs" DROP CONSTRAINT "FK_audit_logs_file"`)
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "audit_logs"
      ADD CONSTRAINT "FK_audit_logs_file"
      FOREIGN KEY ("file_id") REFERENCES "files"("id") ON DELETE SET NULL ON UPDATE NO ACTION`)
  }
}
