BEGIN;

ALTER TABLE accounts DROP COLUMN "is_super_admin";

COMMIT;