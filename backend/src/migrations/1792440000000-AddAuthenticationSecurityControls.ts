import type { MigrationInterface, QueryRunner } from 'typeorm'

export class AddAuthenticationSecurityControls1792440000000 implements MigrationInterface {
  name = 'AddAuthenticationSecurityControls1792440000000'

  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "users"
      ADD "auth_version" integer NOT NULL DEFAULT 0,
      ADD "failed_login_attempts" integer NOT NULL DEFAULT 0,
      ADD "login_locked_until" timestamptz,
      ADD "mfa_secret" text,
      ADD "mfa_enabled" boolean NOT NULL DEFAULT false,
      ADD "mfa_last_used_step" bigint NOT NULL DEFAULT -1`)
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "users"
      DROP COLUMN "mfa_last_used_step",
      DROP COLUMN "mfa_enabled",
      DROP COLUMN "mfa_secret",
      DROP COLUMN "login_locked_until",
      DROP COLUMN "failed_login_attempts",
      DROP COLUMN "auth_version"`)
  }
}
