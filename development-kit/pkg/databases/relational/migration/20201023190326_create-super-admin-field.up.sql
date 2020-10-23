BEGIN;

ALTER TABLE accounts ADD COLUMN "is_super_admin" boolean NOT NULL DEFAULT false;

COMMIT;