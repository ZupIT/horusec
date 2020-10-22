BEGIN;

ALTER TABLE "companies"
ADD 
    "authz_member" VARCHAR(255),
    "authz_admin" VARCHAR(255),
    "authz_supervisor" VARCHAR(255);

ALTER TABLE "repositories"
ADD 
    "authz_member" VARCHAR(255),
    "authz_admin" VARCHAR(255),
    "authz_supervisor" VARCHAR(255);

COMMIT;