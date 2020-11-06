BEGIN;

ALTER TABLE "companies"
    ADD COLUMN "authz_member" VARCHAR(255),
    ADD COLUMN "authz_admin" VARCHAR(255);

ALTER TABLE "repositories"
    ADD COLUMN "authz_member" VARCHAR(255),
    ADD COLUMN "authz_admin" VARCHAR(255),
    ADD COLUMN "authz_supervisor" VARCHAR(255);

ALTER TABLE "accounts" ALTER COLUMN "password" DROP NOT NULL;

COMMIT;