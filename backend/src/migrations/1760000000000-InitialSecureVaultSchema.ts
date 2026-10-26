import type { MigrationInterface, QueryRunner } from 'typeorm'

export class InitialSecureVaultSchema1760000000000 implements MigrationInterface {
  name = 'InitialSecureVaultSchema1760000000000'

  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE TYPE "user_role_enum" AS ENUM ('USER', 'ADMIN')`)
    await queryRunner.query(`CREATE TYPE "file_share_permission_enum" AS ENUM ('VIEW', 'DOWNLOAD')`)
    await queryRunner.query(`CREATE TYPE "audit_action_enum" AS ENUM (
      'REGISTER',
      'LOGIN',
      'LOGIN_FAILED',
      'LOGOUT',
      'TOKEN_REFRESH',
      'FILE_UPLOADED',
      'FILE_VIEWED',
      'FILE_DOWNLOADED',
      'FILE_RENAMED',
      'FILE_DELETED',
      'FILE_SHARED',
      'SHARE_REVOKED',
      'UNAUTHORIZED_ACCESS'
    )`)
    await queryRunner.query(`CREATE TYPE "backup_status_enum" AS ENUM ('PENDING', 'COMPLETED', 'FAILED')`)

    await queryRunner.query(`CREATE TABLE "users" (
      "id" uuid NOT NULL DEFAULT gen_random_uuid(),
      "full_name" varchar(160) NOT NULL,
      "email" varchar(320) NOT NULL,
      "password_hash" varchar(255) NOT NULL,
      "role" "user_role_enum" NOT NULL DEFAULT 'USER',
      "created_at" timestamptz NOT NULL DEFAULT now(),
      "updated_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "PK_users_id" PRIMARY KEY ("id"),
      CONSTRAINT "UQ_users_email" UNIQUE ("email")
    )`)

    await queryRunner.query(`CREATE TABLE "files" (
      "id" uuid NOT NULL DEFAULT gen_random_uuid(),
      "owner_id" uuid NOT NULL,
      "original_name" varchar(1024) NOT NULL,
      "stored_name" varchar(255) NOT NULL,
      "file_path" text NOT NULL,
      "file_size" bigint NOT NULL,
      "mime_type" varchar(255) NOT NULL,
      "encryption_version" smallint NOT NULL,
      "encryption_iv" varchar(128) NOT NULL,
      "encryption_auth_tag" varchar(128) NOT NULL,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      "updated_at" timestamptz NOT NULL DEFAULT now(),
      "deleted_at" timestamptz,
      CONSTRAINT "PK_files_id" PRIMARY KEY ("id"),
      CONSTRAINT "FK_files_owner" FOREIGN KEY ("owner_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE NO ACTION
    )`)

    await queryRunner.query(`CREATE TABLE "file_shares" (
      "id" uuid NOT NULL DEFAULT gen_random_uuid(),
      "file_id" uuid NOT NULL,
      "shared_by" uuid NOT NULL,
      "shared_with" uuid NOT NULL,
      "permission" "file_share_permission_enum" NOT NULL,
      "expires_at" timestamptz,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "PK_file_shares_id" PRIMARY KEY ("id"),
      CONSTRAINT "FK_file_shares_file" FOREIGN KEY ("file_id") REFERENCES "files"("id") ON DELETE RESTRICT ON UPDATE NO ACTION,
      CONSTRAINT "FK_file_shares_shared_by" FOREIGN KEY ("shared_by") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE NO ACTION,
      CONSTRAINT "FK_file_shares_shared_with" FOREIGN KEY ("shared_with") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE NO ACTION
    )`)

    await queryRunner.query(`CREATE TABLE "audit_logs" (
      "id" uuid NOT NULL DEFAULT gen_random_uuid(),
      "user_id" uuid,
      "action" "audit_action_enum" NOT NULL,
      "file_id" uuid,
      "ip_address" inet,
      "user_agent" text,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "PK_audit_logs_id" PRIMARY KEY ("id"),
      CONSTRAINT "FK_audit_logs_user" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE NO ACTION,
      CONSTRAINT "FK_audit_logs_file" FOREIGN KEY ("file_id") REFERENCES "files"("id") ON DELETE SET NULL ON UPDATE NO ACTION
    )`)

    await queryRunner.query(`CREATE TABLE "refresh_tokens" (
      "id" uuid NOT NULL DEFAULT gen_random_uuid(),
      "user_id" uuid NOT NULL,
      "token_hash" varchar(255) NOT NULL,
      "expires_at" timestamptz NOT NULL,
      "revoked_at" timestamptz,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "PK_refresh_tokens_id" PRIMARY KEY ("id"),
      CONSTRAINT "FK_refresh_tokens_user" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE NO ACTION
    )`)

    await queryRunner.query(`CREATE TABLE "backups" (
      "id" uuid NOT NULL DEFAULT gen_random_uuid(),
      "file_id" uuid NOT NULL,
      "backup_path" text NOT NULL,
      "status" "backup_status_enum" NOT NULL DEFAULT 'PENDING',
      "created_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "PK_backups_id" PRIMARY KEY ("id"),
      CONSTRAINT "FK_backups_file" FOREIGN KEY ("file_id") REFERENCES "files"("id") ON DELETE RESTRICT ON UPDATE NO ACTION
    )`)

    await queryRunner.query(`CREATE INDEX "IDX_files_owner_created_at" ON "files" ("owner_id", "created_at")`)
    await queryRunner.query(`CREATE INDEX "IDX_file_shares_file_recipient" ON "file_shares" ("file_id", "shared_with")`)
    await queryRunner.query(`CREATE INDEX "IDX_file_shares_recipient_expiry" ON "file_shares" ("shared_with", "expires_at")`)
    await queryRunner.query(`CREATE INDEX "IDX_audit_logs_user_created_at" ON "audit_logs" ("user_id", "created_at")`)
    await queryRunner.query(`CREATE INDEX "IDX_audit_logs_file_created_at" ON "audit_logs" ("file_id", "created_at")`)
    await queryRunner.query(`CREATE UNIQUE INDEX "UQ_refresh_tokens_token_hash" ON "refresh_tokens" ("token_hash")`)
    await queryRunner.query(`CREATE INDEX "IDX_refresh_tokens_user_expiry" ON "refresh_tokens" ("user_id", "expires_at")`)
    await queryRunner.query(`CREATE INDEX "IDX_refresh_tokens_expires_at" ON "refresh_tokens" ("expires_at")`)
    await queryRunner.query(`CREATE INDEX "IDX_backups_file_created_at" ON "backups" ("file_id", "created_at")`)
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE "backups"`)
    await queryRunner.query(`DROP TABLE "refresh_tokens"`)
    await queryRunner.query(`DROP TABLE "audit_logs"`)
    await queryRunner.query(`DROP TABLE "file_shares"`)
    await queryRunner.query(`DROP TABLE "files"`)
    await queryRunner.query(`DROP TABLE "users"`)
    await queryRunner.query(`DROP TYPE "backup_status_enum"`)
    await queryRunner.query(`DROP TYPE "audit_action_enum"`)
    await queryRunner.query(`DROP TYPE "file_share_permission_enum"`)
    await queryRunner.query(`DROP TYPE "user_role_enum"`)
  }
}
