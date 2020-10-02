BEGIN;

ALTER TABLE accounts DROP CONSTRAINT uk_accounts_username;

COMMIT;