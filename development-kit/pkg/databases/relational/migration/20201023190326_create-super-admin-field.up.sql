BEGIN;

ALTER TABLE accounts ADD COLUMN "is_application_admin" boolean NOT NULL DEFAULT false;

COMMIT;