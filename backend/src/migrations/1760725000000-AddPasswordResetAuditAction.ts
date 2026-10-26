import type { MigrationInterface, QueryRunner } from 'typeorm'

export class AddPasswordResetAuditAction1760725000000 implements MigrationInterface {
  name = 'AddPasswordResetAuditAction1760725000000'

  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TYPE "audit_action_enum" ADD VALUE IF NOT EXISTS 'PASSWORD_RESET'`)
  }

  async down(): Promise<void> {
    // PostgreSQL does not support removing an enum value without recreating the type.
  }
}
