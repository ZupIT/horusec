BEGIN;

ALTER TABLE accounts ADD CONSTRAINT uk_accounts_username UNIQUE (username);

COMMIT;