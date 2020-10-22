BEGIN;

ALTER TABLE "companies"
ADD COLUMN
    "authz_member" VARCHAR(255),
    "authz_admin" VARCHAR(255),
    "authz_supervisor" VARCHAR(255);

ALTER TABLE "repositories"
ADD COLUMN
    "authz_member" VARCHAR(255),
    "authz_admin" VARCHAR(255),
    "authz_supervisor" VARCHAR(255);

COMMIT;