import type { MigrationInterface, QueryRunner } from 'typeorm'

export class AddPasswordResetTokens1760724000000 implements MigrationInterface {
  name = 'AddPasswordResetTokens1760724000000'

  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "refresh_tokens" ADD "persistent" boolean NOT NULL DEFAULT false`)
    await queryRunner.query(`CREATE TABLE "password_reset_tokens" (
      "id" uuid NOT NULL DEFAULT gen_random_uuid(),
      "user_id" uuid NOT NULL,
      "token_hash" varchar(64) NOT NULL,
      "expires_at" timestamptz NOT NULL,
      "used_at" timestamptz,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "PK_password_reset_tokens_id" PRIMARY KEY ("id"),
      CONSTRAINT "FK_password_reset_tokens_user" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION
    )`)
    await queryRunner.query(`CREATE UNIQUE INDEX "UQ_password_reset_tokens_token_hash" ON "password_reset_tokens" ("token_hash")`)
    await queryRunner.query(`CREATE INDEX "IDX_password_reset_tokens_user_expiry" ON "password_reset_tokens" ("user_id", "expires_at")`)
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE "password_reset_tokens"`)
    await queryRunner.query(`ALTER TABLE "refresh_tokens" DROP COLUMN "persistent"`)
  }
}
