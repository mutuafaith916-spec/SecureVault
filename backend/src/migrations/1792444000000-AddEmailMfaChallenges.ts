import type { MigrationInterface, QueryRunner } from 'typeorm'

export class AddEmailMfaChallenges1792444000000 implements MigrationInterface {
  name = 'AddEmailMfaChallenges1792444000000'

  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE TABLE "email_mfa_challenges" (
      "id" uuid NOT NULL DEFAULT gen_random_uuid(),
      "challenge_id" uuid NOT NULL,
      "user_id" uuid NOT NULL,
      "code_hash" character varying(64) NOT NULL,
      "expires_at" timestamptz NOT NULL,
      "sent_at" timestamptz NOT NULL,
      "send_count" smallint NOT NULL DEFAULT 1,
      "attempts" smallint NOT NULL DEFAULT 0,
      "consumed_at" timestamptz,
      "created_at" timestamptz NOT NULL DEFAULT now(),
      "updated_at" timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT "PK_email_mfa_challenges" PRIMARY KEY ("id"),
      CONSTRAINT "UQ_email_mfa_challenges_challenge_id" UNIQUE ("challenge_id"),
      CONSTRAINT "CHK_email_mfa_challenges_send_count" CHECK ("send_count" BETWEEN 1 AND 3),
      CONSTRAINT "CHK_email_mfa_challenges_attempts" CHECK ("attempts" BETWEEN 0 AND 5),
      CONSTRAINT "FK_email_mfa_challenges_user" FOREIGN KEY ("user_id")
        REFERENCES "users"("id") ON DELETE CASCADE
    )`)
    await queryRunner.query(`CREATE INDEX "IDX_email_mfa_challenges_user_expiry"
      ON "email_mfa_challenges" ("user_id", "expires_at")`)
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE "email_mfa_challenges"`)
  }
}
