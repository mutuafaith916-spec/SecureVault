import type { MigrationInterface, QueryRunner } from 'typeorm'

export class AddEncryptedCloudBackups1792350000000 implements MigrationInterface {
  name = 'AddEncryptedCloudBackups1792350000000'

  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "backups" ADD "encryption_version" smallint`)
    await queryRunner.query(`ALTER TABLE "backups" ADD "encryption_iv" character varying(128)`)
    await queryRunner.query(`ALTER TABLE "backups" ADD "encryption_auth_tag" character varying(128)`)
    await queryRunner.query(`ALTER TYPE "audit_action_enum" ADD VALUE IF NOT EXISTS 'BACKUP_CREATED'`)
    await queryRunner.query(`ALTER TYPE "audit_action_enum" ADD VALUE IF NOT EXISTS 'FILE_RESTORED'`)
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "backups" DROP COLUMN "encryption_auth_tag"`)
    await queryRunner.query(`ALTER TABLE "backups" DROP COLUMN "encryption_iv"`)
    await queryRunner.query(`ALTER TABLE "backups" DROP COLUMN "encryption_version"`)
  }
}
