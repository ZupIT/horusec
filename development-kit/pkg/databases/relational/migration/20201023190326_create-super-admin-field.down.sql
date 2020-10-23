BEGIN;

ALTER TABLE accounts DROP COLUMN "is_application_admin";

COMMIT;