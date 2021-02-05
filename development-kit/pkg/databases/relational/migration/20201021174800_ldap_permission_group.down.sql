BEGIN;

ALTER TABLE companies
    DROP COLUMN IF EXISTS authz_member,
    DROP COLUMN IF EXISTS authz_admin;

ALTER TABLE repositories
    DROP COLUMN IF EXISTS authz_member,
    DROP COLUMN IF EXISTS authz_admin,
    DROP COLUMN IF EXISTS authz_supervisor;

ALTER TABLE "accounts" ALTER COLUMN "password" SET NOT NULL;

COMMIT;