BEGIN;

ALTER TABLE "companies"
DROP COLUMN "authz_member", "authz_admin", "authz_supervisor";

ALTER TABLE "repositories"
DROP COLUMN "authz_member", "authz_admin", "authz_supervisor";

ALTER TABLE "accounts" ALTER COLUMN "password" SET NOT NULL;

COMMIT;